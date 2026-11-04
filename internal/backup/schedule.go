// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"fmt"
	"strings"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// Schedule computes backup times.
type Schedule interface {
	// Next returns the first scheduled time strictly after t.
	Next(t time.Time) time.Time
}

// ParseSchedule parses a 5-field cron expression ("m h dom mon dow"),
// @hourly, @daily/@midnight, @weekly or "@every <duration>".
func ParseSchedule(s string) (Schedule, error) {
	if err := config.ValidSchedule(s); err != nil {
		return nil, err
	}
	switch s {
	case "@hourly":
		s = "0 * * * *"
	case "@daily", "@midnight":
		s = "0 0 * * *"
	case "@weekly":
		s = "0 0 * * 0"
	}
	if d, ok := strings.CutPrefix(s, "@every "); ok {
		dur, _ := config.ParsePeriod(strings.TrimSpace(d))
		return every(dur), nil
	}
	f := strings.Fields(s)
	c := &cron{}
	var err error
	sets := []*map[int]bool{&c.min, &c.hour, &c.dom, &c.mon, &c.dow}
	ranges := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	for i := range f {
		if *sets[i], err = config.CronField(f[i], ranges[i][0], ranges[i][1]); err != nil {
			return nil, fmt.Errorf("invalid schedule %q: %v", s, err)
		}
	}
	if c.dow[7] {
		c.dow[0] = true
	}
	c.domAny, c.dowAny = f[2] == "*", f[4] == "*"
	return c, nil
}

type every time.Duration

func (e every) Next(t time.Time) time.Time {
	d := time.Duration(e)
	return t.Truncate(d).Add(d)
}

type cron struct {
	min, hour, dom, mon, dow map[int]bool
	domAny, dowAny           bool
}

func (c *cron) Next(t time.Time) time.Time {
	t = t.Truncate(time.Minute).Add(time.Minute)
	// Bounded search: every valid expression matches within ~4 years
	// (Feb 29); minute steps over 5 years would be slow, so skip whole
	// days/hours that cannot match.
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		if !c.mon[int(t.Month())] || !c.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
			continue
		}
		if !c.hour[t.Hour()] {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
			continue
		}
		if !c.min[t.Minute()] {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

// dayMatches applies cron's rule: if both day-of-month and day-of-week are
// restricted, either may match.
func (c *cron) dayMatches(t time.Time) bool {
	dom, dow := c.dom[t.Day()], c.dow[int(t.Weekday())]
	switch {
	case c.domAny && c.dowAny:
		return true
	case c.domAny:
		return dow
	case c.dowAny:
		return dom
	}
	return dom || dow
}
