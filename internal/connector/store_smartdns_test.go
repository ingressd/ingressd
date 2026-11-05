// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

func TestStoreSmartDNSUsageAndRecent(t *testing.T) {
	s := NewStore(t.TempDir())
	rep := func(u []nodeproto.ServiceUsage, recent int) {
		t.Helper()
		h := proto.Health{Time: time.Now(), SmartDNSUsage: u, SmartDNS: &nodeproto.ConnectorSmartDNS{}}
		for i := 0; i < recent; i++ {
			h.SmartDNS.Recent = append(h.SmartDNS.Recent, nodeproto.RecentLookup{Name: "n", Type: "A"})
		}
		if err := s.Report("home", h); err != nil {
			t.Fatal(err)
		}
	}
	rep([]nodeproto.ServiceUsage{{Service: "npo", Bytes: 100, Conns: 1}}, 3)
	rep([]nodeproto.ServiceUsage{{Service: "npo", Bytes: 50, Conns: 2}, {Service: "bbc", Bytes: 7, Conns: 1}, {Service: "bad", Bytes: -1}}, maxRecentLookups+50)

	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if h := st.Connectors["home"].Health; len(h.SmartDNSUsage) != 0 {
		t.Errorf("usage kept in health: %+v", h.SmartDNSUsage)
	}
	u, err := s.TakeSmartDNSUsage()
	if err != nil {
		t.Fatal(err)
	}
	if len(u) != 2 || u[0] != (nodeproto.ServiceUsage{Site: "home", Service: "npo", Bytes: 150, Conns: 3}) || u[1].Service != "bbc" {
		t.Errorf("usage %+v", u)
	}
	if again, _ := s.TakeSmartDNSUsage(); len(again) != 0 {
		t.Errorf("usage taken twice: %+v", again)
	}
	r, err := s.SmartDNSRecent("home", 0)
	if err != nil || len(r) != maxRecentLookups {
		t.Errorf("recent %d (%v)", len(r), err)
	}
	if r, _ := s.SmartDNSRecent("home", 5); len(r) != 5 {
		t.Errorf("limited recent %d", len(r))
	}
	if r, _ := s.SmartDNSRecent("away", 5); r == nil || len(r) != 0 {
		t.Errorf("unknown site recent %v", r)
	}
}
