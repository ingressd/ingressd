// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/health"
	"github.com/ingressd/ingressd/pkg/config"
)

// newPoolCmd manages pools at runtime. Changes are runtime overrides in
// <state-dir>/pool-overrides.json, not config: `ingressd serve` picks them
// up within a second and pushes them to the edge.
func newPoolCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "pool", Short: "Pool health and runtime overrides (drain, disable, force a tier)"}

	status := &cobra.Command{
		Use:   "status [pool]",
		Short: "Show tiers, origin health and overrides",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			st, err := health.LoadStatus(e.stateDir)
			if err != nil {
				return err
			}
			ov, err := health.LoadOverrides(e.stateDir)
			if err != nil {
				return err
			}
			return printPoolStatus(cmd, cfg, st, ov, args)
		},
	}

	var dur time.Duration
	var reason string
	setState := func(use, short, state string) *cobra.Command {
		c := &cobra.Command{
			Use:   use + " <pool> <origin>",
			Short: short,
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				return e.editOverrides(cmd, func(cfg *config.Config, ov *health.Overrides, now time.Time) (string, error) {
					o, err := findPoolOrigin(cfg, args[0], args[1])
					if err != nil {
						return "", err
					}
					if o.State == config.OriginDisabled {
						return "", fmt.Errorf("origin %s is disabled in config.yaml; change its state there", args[1])
					}
					p := ov.Pool(args[0])
					if p.Origins == nil {
						p.Origins = map[string]health.OriginOverride{}
					}
					if state == config.OriginActive && o.State == config.OriginActive {
						delete(p.Origins, args[1])
						return fmt.Sprintf("Origin %s/%s enabled.", args[0], args[1]), nil
					}
					p.Origins[args[1]] = health.OriginOverride{State: state, Until: until(now, dur), Reason: reason, By: os.Getenv("USER"), At: now}
					return fmt.Sprintf("Origin %s/%s is now %s%s.", args[0], args[1], state, forText(dur)), nil
				})
			},
		}
		if state != config.OriginActive {
			c.Flags().DurationVar(&dur, "for", 0, "expire the override after this long (default: until cleared)")
			c.Flags().StringVar(&reason, "reason", "", "note shown in status")
		}
		return c
	}
	drain := setState("drain", "Stop new sessions to an origin; existing sticky sessions continue", config.OriginDraining)
	disable := setState("disable", "Take an origin out of rotation entirely", config.OriginDisabled)
	enable := setState("enable", "Undo drain/disable: return an origin to rotation", config.OriginActive)

	var tier int
	var origins []string
	override := &cobra.Command{
		Use:   "override <pool> (--tier N | --origin NAME...)",
		Short: "Force a pool's traffic to a tier or to specific origins",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if tier == 0 && len(origins) == 0 {
				return fmt.Errorf("set --tier or --origin")
			}
			return e.editOverrides(cmd, func(cfg *config.Config, ov *health.Overrides, now time.Time) (string, error) {
				pool, ok := cfg.Pools[args[0]]
				if !ok {
					return "", fmt.Errorf("unknown pool %q", args[0])
				}
				if tier != 0 && !slices.ContainsFunc(pool.Origins, func(o config.Origin) bool { return o.Priority == tier }) {
					return "", fmt.Errorf("pool %s has no tier %d", args[0], tier)
				}
				for _, o := range origins {
					if _, err := findPoolOrigin(cfg, args[0], o); err != nil {
						return "", err
					}
				}
				ov.Pool(args[0]).Force = &health.Force{Tier: tier, Origins: origins, Until: until(now, dur), Reason: reason, By: os.Getenv("USER"), At: now}
				what := fmt.Sprintf("tier %d", tier)
				if len(origins) > 0 {
					what = strings.Join(origins, ", ")
					if tier != 0 {
						what += fmt.Sprintf(" (tier %d)", tier)
					}
				}
				return fmt.Sprintf("Pool %s forced to %s%s.", args[0], what, forText(dur)), nil
			})
		},
	}
	override.Flags().IntVar(&tier, "tier", 0, "priority tier to force")
	override.Flags().StringSliceVar(&origins, "origin", nil, "origin(s) to force")
	override.Flags().DurationVar(&dur, "for", 0, "expire the override after this long (default: until cleared)")
	override.Flags().StringVar(&reason, "reason", "", "note shown in status")

	clear := &cobra.Command{
		Use:   "clear-override <pool>",
		Short: "Remove a forced tier/origin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return e.editOverrides(cmd, func(cfg *config.Config, ov *health.Overrides, _ time.Time) (string, error) {
				if _, ok := cfg.Pools[args[0]]; !ok {
					return "", fmt.Errorf("unknown pool %q", args[0])
				}
				ov.Pool(args[0]).Force = nil
				return fmt.Sprintf("Override on pool %s cleared.", args[0]), nil
			})
		},
	}

	failback := &cobra.Command{
		Use:   "failback <pool>",
		Short: "Return a pool to its best healthy tier now (failback: manual, or skip failback_hold)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return e.editOverrides(cmd, func(cfg *config.Config, ov *health.Overrides, now time.Time) (string, error) {
				if _, ok := cfg.Pools[args[0]]; !ok {
					return "", fmt.Errorf("unknown pool %q", args[0])
				}
				ov.Pool(args[0]).FailbackAt = &now
				return fmt.Sprintf("Failback requested for pool %s.", args[0]), nil
			})
		},
	}

	cmd.AddCommand(status, drain, enable, disable, override, clear, failback)
	return cmd
}

// editOverrides loads, changes, prunes and saves the overrides file.
func (e *env) editOverrides(cmd *cobra.Command, fn func(*config.Config, *health.Overrides, time.Time) (string, error)) error {
	cfg, err := e.loadConfig()
	if err != nil {
		return err
	}
	ov, err := health.LoadOverrides(e.stateDir)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	msg, err := fn(cfg, ov, now)
	if err != nil {
		return err
	}
	ov.Prune(cfg, now)
	if err := health.SaveOverrides(e.stateDir, ov); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), msg)
	return nil
}

func findPoolOrigin(cfg *config.Config, pool, origin string) (config.Origin, error) {
	p, ok := cfg.Pools[pool]
	if !ok {
		return config.Origin{}, fmt.Errorf("unknown pool %q", pool)
	}
	for _, o := range p.Origins {
		if o.Name == origin {
			return o, nil
		}
	}
	return config.Origin{}, fmt.Errorf("pool %s has no origin %q", pool, origin)
}

func until(now time.Time, d time.Duration) *time.Time {
	if d <= 0 {
		return nil
	}
	t := now.Add(d)
	return &t
}

func forText(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return " for " + d.String()
}

func printPoolStatus(cmd *cobra.Command, cfg *config.Config, st *health.Status, ov *health.Overrides, only []string) error {
	out := cmd.OutOrStdout()
	now := time.Now()
	if st.Updated.IsZero() {
		fmt.Fprintln(out, "No health data yet (is ingressd serve running?). Showing config and overrides only.")
	} else if age := now.Sub(st.Updated); age > time.Minute {
		fmt.Fprintf(out, "Health data is %s old (is ingressd serve running?).\n", age.Round(time.Second))
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Pools)) {
		if len(only) > 0 && only[0] != name {
			continue
		}
		pool := cfg.Pools[name]
		ps, known := st.Pools[name]
		line := fmt.Sprintf("Pool %s (%s, failback %s)", name, pool.Steering, pool.Failback)
		switch {
		case !known:
			line += ": health unknown"
		case ps.AllDown:
			line += ": ALL ORIGINS DOWN"
		default:
			line += fmt.Sprintf(": active tier %d", ps.ActiveTier)
			if ps.FailbackPending != nil {
				if ps.FailbackManual {
					line += fmt.Sprintf(", tier %d healthy, waiting for manual failback", ps.BestTier)
				} else {
					line += fmt.Sprintf(", failing back to tier %d (hold %s, since %s)", ps.BestTier,
						time.Duration(pool.FailbackHold), ps.FailbackPending.Local().Format(time.TimeOnly))
				}
			}
		}
		fmt.Fprintln(out, line)
		if po := ov.Pools[name]; po != nil && po.Force.Active(now) {
			f := po.Force
			what := []string{}
			if f.Tier != 0 {
				what = append(what, fmt.Sprintf("tier %d", f.Tier))
			}
			what = append(what, f.Origins...)
			msg := "  OVERRIDE: forced to " + strings.Join(what, ", ")
			if f.Until != nil {
				msg += " until " + f.Until.Local().Format(time.DateTime)
			}
			if f.Reason != "" {
				msg += " (" + f.Reason + ")"
			}
			fmt.Fprintln(out, msg)
		}

		byName := map[string]health.OriginStatus{}
		for _, o := range ps.Origins {
			byName[o.Name] = o
		}
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  ORIGIN\tTIER\tWEIGHT\tSTATE\tHEALTH\tSINCE\tDETAIL")
		for _, o := range pool.Origins {
			state := o.State
			if r, ok := ov.OriginState(name, o.Name, now); ok {
				state = r.State + " (runtime)"
				if r.Until != nil {
					state += " until " + r.Until.Local().Format(time.TimeOnly)
				}
			}
			hs, since, detail := "unknown", "", ""
			if s, ok := byName[o.Name]; ok {
				hs = map[bool]string{true: "up", false: "DOWN"}[s.Healthy]
				if !s.Checked && s.Healthy {
					hs = "up (unchecked)"
				}
				if !s.Since.IsZero() {
					since = now.Sub(s.Since).Round(time.Second).String()
				}
				detail = cmp.Or(s.Reason, s.LastError)
				if detail == "" && s.Checked && s.LatencyMS > 0 {
					detail = fmt.Sprintf("%.1fms, %d/%d checks failed in 24h", s.LatencyMS, s.Failures24h, s.Checks24h)
				}
			} else if o.State == config.OriginDisabled {
				hs = "-"
			}
			fmt.Fprintf(w, "  %s\t%d\t%d\t%s\t%s\t%s\t%s\n", o.Name, o.Priority, o.Weight, state, hs, since, detail)
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return nil
}
