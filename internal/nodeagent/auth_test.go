// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ingressd/ingressd/pkg/nodeproto"
	"github.com/ingressd/ingressd/test/fakepanel"
)

type fakeAccess struct {
	mu      sync.Mutex
	revokes []nodeproto.AuthRevoke
	allows  []nodeproto.L4Allow
}

func (f *fakeAccess) ApplyRemoteRevoke(_ context.Context, r nodeproto.AuthRevoke) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes = append(f.revokes, r)
	return nil
}

func (f *fakeAccess) ApplyRemoteL4Allow(_ context.Context, a nodeproto.L4Allow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allows = append(f.allows, a)
	return nil
}

func TestHostedAccessRelay(t *testing.T) {
	h := newHarness(t)
	h.start()
	defer h.stop()
	rx := &fakeAccess{}
	SetAccess(rx)
	defer SetAccess(nil)
	ctx := h.ctx()

	// OTP round trips are correlated by envelope id.
	res, err := h.agent.OTPStart(ctx, nodeproto.AuthOTPStart{Email: "a@x.test", Label: "web", ClientIP: "198.51.100.7", Host: "auth.x.test", Length: 6})
	if err != nil || !res.OK {
		t.Fatalf("start = %+v, %v", res, err)
	}
	code := h.panel.OTPCode("a@x.test")
	if len(code) != 6 {
		t.Fatalf("code %q", code)
	}
	if v, err := h.agent.OTPVerify(ctx, nodeproto.AuthOTPVerify{Email: "a@x.test", Code: "000000"}); err != nil || v.OK || v.Code != nodeproto.OTPInvalid {
		t.Fatalf("wrong code = %+v, %v", v, err)
	}
	if v, err := h.agent.OTPVerify(ctx, nodeproto.AuthOTPVerify{Email: "a@x.test", Code: code}); err != nil || !v.OK || v.Email != "a@x.test" {
		t.Fatalf("verify = %+v, %v", v, err)
	}

	// Node → panel reports.
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := h.agent.ReportL4Allow(nodeproto.L4Allow{Service: "mc", IP: "198.51.100.7", Email: "a@x.test", Expires: exp}); err != nil {
		t.Fatal(err)
	}
	if err := h.agent.ReportRevoke(nodeproto.AuthRevoke{SID: "sid1", Email: "a@x.test"}); err != nil {
		t.Fatal(err)
	}
	s := h.wait("reports", func(s fakepanel.State) bool { return len(s.L4Allows) == 1 && len(s.Revokes) == 1 })
	if !s.L4Allows[0].Expires.Equal(exp) || s.Revokes[0].SID != "sid1" {
		t.Fatalf("reports %+v %+v", s.L4Allows, s.Revokes)
	}

	// Panel → node relays reach the registered receiver.
	if err := h.panel.Send(ctx, nodeproto.TypeL4Allow, "", nodeproto.L4Allow{Service: "mc", IP: "203.0.113.5", Origin: "nod_other"}); err != nil {
		t.Fatal(err)
	}
	if err := h.panel.Send(ctx, nodeproto.TypeAuthRevoke, "", nodeproto.AuthRevoke{SID: "sid2"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rx.mu.Lock()
		ok := len(rx.allows) == 1 && len(rx.revokes) == 1
		rx.mu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relays not applied: %+v %+v", rx.allows, rx.revokes)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rx.allows[0].IP != "203.0.113.5" || rx.revokes[0].SID != "sid2" {
		t.Fatalf("relayed %+v %+v", rx.allows, rx.revokes)
	}
}

func TestHostedAccessOffline(t *testing.T) {
	h := newHarness(t)
	a, err := New(h.opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.OTPStart(context.Background(), nodeproto.AuthOTPStart{Email: "a@x.test"}); err == nil {
		t.Fatal("OTPStart without a panel connection succeeded")
	}
}
