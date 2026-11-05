// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

const testPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

func TestJoinRoundTrip(t *testing.T) {
	for _, j := range []Join{
		{URL: "https://edge.example.com", Token: "abc123"},
		{URL: "https://edge.example.com:8443", Token: "abc123", CA: testPEM},
		{URL: "https://a.example.com", Token: "abc123", Edges: []JoinEdge{{URL: "https://a.example.com"}, {URL: "https://b.example.com", CA: testPEM}}},
		{URL: "https://a.example.com", Edges: []JoinEdge{{URL: "https://a.example.com", T: "ta"}, {URL: "https://b.example.com", T: "tb"}}},
	} {
		s, err := EncodeJoin(j)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(s, "ey") || strings.ContainsAny(s, "+/=") {
			t.Errorf("join string %q is not unpadded base64url JSON", s)
		}
		if !LooksLikeJoin(s) {
			t.Errorf("LooksLikeJoin(%q) = false", s)
		}
		got, err := DecodeJoin("  " + s + "==\n")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, j) {
			t.Errorf("round trip: got %+v, want %+v", got, j)
		}
	}
}

func TestJoinMultiEdge(t *testing.T) {
	s := strings.TrimRight(b64(`{"e":[{"u":"https://a.example.com","ca":"`+strings.ReplaceAll(testPEM, "\n", `\n`)+`"},{"u":"https://b.example.com"}],"t":"tok"}`), "=")
	j, err := DecodeJoin(s)
	if err != nil {
		t.Fatal(err)
	}
	if j.URL != "https://a.example.com" || j.CA != testPEM || j.Token != "tok" {
		t.Errorf("first edge not promoted: %+v", j)
	}
	all := j.All()
	if len(all) != 2 || all[1].URL != "https://b.example.com" {
		t.Errorf("All() = %+v", all)
	}
}

func TestJoinInvalid(t *testing.T) {
	enc := func(js string) string {
		// Build join strings that bypass EncodeJoin's validation.
		return strings.TrimRight(b64(js), "=")
	}
	for name, s := range map[string]string{
		"not base64":  "!!!",
		"not json":    enc("hello"),
		"no token":    enc(`{"u":"https://edge.example.com"}`),
		"no url":      enc(`{"t":"x"}`),
		"http url":    enc(`{"u":"http://edge.example.com","t":"x"}`),
		"bad ca":      enc(`{"u":"https://edge.example.com","t":"x","ca":"nope"}`),
		"bad 2nd url": enc(`{"e":[{"u":"https://a.example.com"},{"u":"ftp://b"}],"t":"x"}`),
		"2nd no token": enc(`{"e":[{"u":"https://a.example.com","t":"x"},{"u":"https://b.example.com"}]}`),
	} {
		if _, err := DecodeJoin(s); err == nil {
			t.Errorf("%s: DecodeJoin(%q) succeeded", name, s)
		}
	}
	if _, err := EncodeJoin(Join{URL: "edge.example.com", Token: "x"}); err == nil {
		t.Error("EncodeJoin accepted a URL without scheme")
	}
	if LooksLikeJoin("https://edge.example.com") {
		t.Error("a URL looks like a join string")
	}
}

func b64(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) }

func TestJoinEdgeTokens(t *testing.T) {
	j, err := DecodeJoin(b64(`{"e":[{"u":"https://a.example.com","t":"ta"},{"u":"https://b.example.com","t":"tb"},{"u":"https://c.example.com"}],"t":"top"}`))
	if err != nil {
		t.Fatal(err)
	}
	all := j.All()
	if len(all) != 3 || all[0].T != "ta" || all[1].T != "tb" || all[2].T != "" || j.Token != "top" {
		t.Errorf("All() = %+v, token %q", all, j.Token)
	}
	if _, err := DecodeJoin(b64(`{"e":[{"u":"https://a.example.com","t":"ta"},{"u":"https://b.example.com","t":"tb"}]}`)); err != nil {
		t.Errorf("per-edge tokens without a top-level token: %v", err)
	}
}
