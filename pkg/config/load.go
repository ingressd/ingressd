// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Load reads and parses a config file. It does not validate it.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(b)
}

// Parse decodes config YAML, rejecting unknown fields, and fills defaults.
func Parse(b []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("parse config: file is empty")
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) applyDefaults() {
	c.applySecurityDefaults()
	c.applyObserveDefaults()
	if c.Edge.Admin.Exposure == "" {
		c.Edge.Admin.Exposure = ExposurePublic
	}
	if c.Edge.SSHPort == 0 {
		c.Edge.SSHPort = 22
	}
	c.applyTLSDefaults()
	if c.Edge.ACME.CA == "" {
		c.Edge.ACME.CA = "letsencrypt"
	}
	c.applyL4Defaults()
	c.applyAccessDefaults()
	for name, a := range c.Apps {
		for i := range a.Redirects {
			if a.Redirects[i].Code == 0 {
				a.Redirects[i].Code = 301
			}
		}
		c.Apps[name] = a
	}
	for name, t := range c.Tunnels {
		if t.Type == "" {
			t.Type = TunnelWireGuard
		}
		if t.Keepalive == 0 {
			t.Keepalive = 25
		}
		c.Tunnels[name] = t
	}
	for name, p := range c.Pools {
		if p.Steering == "" {
			p.Steering = "round_robin"
		}
		if p.Failback == "" {
			p.Failback = FailbackAuto
		}
		// Weight 0 means "unset"; take an origin out of rotation with state.
		for i := range p.Origins {
			o := &p.Origins[i]
			if o.Weight == 0 {
				o.Weight = 1
			}
			if o.Priority == 0 {
				o.Priority = 1
			}
			if o.State == "" {
				o.State = OriginActive
			}
		}
		if h := p.Health; h != nil {
			if h.Type == "" {
				h.Type = HealthHTTP
			}
			if h.Type == HealthHTTP && h.Path == "" {
				h.Path = "/"
			}
			if h.Type == HealthHTTP && h.Method == "" {
				h.Method = "GET"
			}
			if h.Interval == 0 {
				h.Interval = Duration(10 * time.Second)
			}
			if h.Timeout == 0 {
				h.Timeout = Duration(3 * time.Second)
			}
			if h.Type == HealthHTTP && len(h.ExpectStatus) == 0 {
				h.ExpectStatus = []int{200}
			}
			if h.UnhealthyAfter == 0 {
				h.UnhealthyAfter = 3
			}
			if h.HealthyAfter == 0 {
				h.HealthyAfter = 3
			}
		}
		c.Pools[name] = p
	}
	c.applyCacheDefaults()
	c.applySmartDNSDefaults()
}
