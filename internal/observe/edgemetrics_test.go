// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"testing"
	"time"
)

func TestTakeMetrics(t *testing.T) {
	o := New(Options{})
	o.Add(Entry{Host: "A.example.com", Status: 200, Bytes: 10, BytesIn: 3, Duration: time.Millisecond})
	o.Add(Entry{Host: "a.example.com", Status: 502, Bytes: 5})
	o.Add(Entry{Host: "b.example.com", Status: 404})
	o.Add(Entry{Host: "b.example.com", Status: 500})
	if u := o.TakeUsage(); u["a.example.com"].Requests != 2 {
		t.Fatalf("usage must not be affected: %+v", u)
	}
	w := o.TakeMetrics()
	if w.Requests != 4 || w.Status4xx != 1 || w.Status5xx != 2 || w.OriginErrors != 1 || w.Seen != 4 || len(w.Latencies) != 4 {
		t.Fatalf("window %+v", w)
	}
	if a := w.Hosts["a.example.com"]; a.Requests != 2 || a.BytesOut != 15 || a.BytesIn != 3 {
		t.Fatalf("a = %+v", a)
	}
	if w2 := o.TakeMetrics(); w2.Requests != 0 || w2.Hosts != nil {
		t.Fatalf("not reset: %+v", w2)
	}
	for range maxLatencySamples * 2 {
		o.Add(Entry{Host: "c", Status: 200})
	}
	if w := o.TakeMetrics(); len(w.Latencies) != maxLatencySamples || w.Seen != maxLatencySamples*2 {
		t.Fatalf("reservoir %d of %d", len(w.Latencies), w.Seen)
	}
}
