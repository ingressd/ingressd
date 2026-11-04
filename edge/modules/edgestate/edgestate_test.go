// SPDX-License-Identifier: Apache-2.0

package edgestate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleState(t *testing.T) {
	post := func(body string) (int, string) {
		w := httptest.NewRecorder()
		err := handleState(w, httptest.NewRequest("POST", "/ingressd/state", strings.NewReader(body)))
		if err != nil {
			return 400, err.Error()
		}
		return w.Code, w.Body.String()
	}
	v0 := global.Snapshot().Version
	code, body := post(`{"sticky_key":"MDEyMzQ1Njc4OWFiY2RlZg==","pools":{"web":{"tier":2,"origins":{"a":{"healthy":false,"state":"draining"}}}}}`)
	if code != 200 || !strings.Contains(body, `"version"`) {
		t.Fatalf("POST = %d %s", code, body)
	}
	st := global.Snapshot()
	if st.Version != v0+1 || st.Pools["web"].Tier != 2 || *st.Pools["web"].Origins["a"].Healthy {
		t.Fatalf("state = %+v", st)
	}
	if string(global.StickyKey()) != "0123456789abcdef" {
		t.Fatalf("sticky key = %q", global.StickyKey())
	}
	if code, _ := post(`{"sticky_key":"c2hvcnQ="}`); code != 400 {
		t.Fatal("short sticky key accepted")
	}
	if code, _ := post(`not json`); code != 400 {
		t.Fatal("bad JSON accepted")
	}

	w := httptest.NewRecorder()
	if err := handleState(w, httptest.NewRequest(http.MethodGet, "/ingressd/state", nil)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.Body.String(), `"draining"`) || strings.Contains(w.Body.String(), "sticky") {
		t.Fatalf("GET = %s", w.Body.String())
	}
}

func TestOverrideActive(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Second), now.Add(time.Minute)
	var nilOv *Override
	for _, tc := range []struct {
		ov   *Override
		want bool
	}{
		{nilOv, false},
		{&Override{}, false},
		{&Override{Tier: 2}, true},
		{&Override{Tier: 2, Until: &future}, true},
		{&Override{Origins: []string{"a"}, Until: &past}, false},
	} {
		if got := tc.ov.Active(now); got != tc.want {
			t.Errorf("%+v.Active = %v, want %v", tc.ov, got, tc.want)
		}
	}
	o := &Override{Tier: 1, Origins: []string{"a"}}
	if !o.Matches("a", 1) || o.Matches("a", 2) || o.Matches("b", 1) {
		t.Fatal("Matches")
	}
}

func TestStickyKeyDefault(t *testing.T) {
	s := &Store{}
	k := s.StickyKey()
	if len(k) != 32 || string(s.StickyKey()) != string(k) {
		t.Fatal("default key not stable")
	}
	s.SetStickyKey([]byte("0123456789abcdef"))
	if string(s.StickyKey()) != "0123456789abcdef" {
		t.Fatal("pushed key not used")
	}
}
