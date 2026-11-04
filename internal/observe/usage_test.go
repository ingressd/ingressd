// SPDX-License-Identifier: Apache-2.0

package observe

import "testing"

func TestTakeUsage(t *testing.T) {
	o := New(Options{})
	o.Add(Entry{Host: "A.example.com", Status: 200, Bytes: 10, BytesIn: 3})
	o.Add(Entry{Host: "a.example.com", Status: 503, Bytes: 5})
	o.Add(Entry{Host: "b.example.com", Status: 404})
	u := o.TakeUsage()
	a := u["a.example.com"]
	if a.Requests != 2 || a.BytesOut != 15 || a.BytesIn != 3 || a.Status[2] != 1 || a.Status[5] != 1 {
		t.Fatalf("a = %+v", a)
	}
	if u["b.example.com"].Status[4] != 1 {
		t.Fatalf("b = %+v", u["b.example.com"])
	}
	if len(o.TakeUsage()) != 0 {
		t.Fatal("TakeUsage did not reset")
	}
	o.Add(Entry{Host: "a.example.com", Status: 200})
	if got := o.TakeUsage()["a.example.com"].Requests; got != 1 {
		t.Fatalf("after reset: %d", got)
	}
}
