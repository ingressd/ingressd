// SPDX-License-Identifier: Apache-2.0

package observe

import "strings"

// Usage metering for managed mode (ARCHITECTURE §8): per exact request host,
// counters accumulate until TakeUsage hands them out and resets them, so
// the node agent can send deltas without double counting.

// maxUsageHosts bounds the distinct hosts tracked between two takes (random
// Host headers from scanners must not grow memory without limit).
const maxUsageHosts = 10000

// UsageOtherHost collects requests for hosts beyond maxUsageHosts.
const UsageOtherHost = "_other"

// meter adds e to the usage counters; o.mu is held.
func (o *Observer) meter(e Entry) {
	if o.usage == nil {
		o.usage = map[string]*Totals{}
	}
	h := strings.ToLower(e.Host)
	t := o.usage[h]
	if t == nil {
		if len(o.usage) >= maxUsageHosts {
			h = UsageOtherHost
			t = o.usage[h]
		}
		if t == nil {
			t = &Totals{}
			o.usage[h] = t
		}
	}
	t.add(e)
}

// TakeUsage returns the per-host totals accumulated since the previous call
// and resets them.
func (o *Observer) TakeUsage() map[string]Totals {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make(map[string]Totals, len(o.usage))
	for h, t := range o.usage {
		t.finish()
		out[h] = *t
	}
	o.usage = nil
	return out
}
