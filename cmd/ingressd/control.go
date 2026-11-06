// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"net/http"

	"github.com/ingressd/ingressd/pkg/config"
)

// controlHandlers maps each control hostname (render.ControlHosts) to the
// handler serving it. It runs after every apply. Features that serve pages
// register here: the access portal (3), login-to-play (4), and the machine
// endpoints under /.ingressd/ (connector enrollment and tunnel fallback, 5)
// on the admin hostname and, in managed mode, on the node's own hostname or
// public IP. There is no local admin UI: standalone nodes are managed with
// the CLI and config.yaml, managed nodes by the hosted panel.
func controlHandlers(cfg *config.Config, e *env) map[string]http.Handler {
	hosts := map[string]http.Handler{}
	if h := cfg.Edge.Admin.Hostname; h != "" {
		hosts[h] = machineHostMux(cfg, e)
	}
	if h := cmp.Or(e.machineHost(), cfg.MachineHostFallback()); h != "" {
		if _, ok := hosts[h]; !ok {
			hosts[h] = machineHostMux(cfg, e)
		}
	}
	l4PortalHandlers(cfg, e, hosts)
	addAccessHandlers(hosts, cfg, e)
	return hosts
}

// machineHostMux serves the edge's own hostname: machine endpoints under
// /.ingressd/ and a plain landing text for everything else.
func machineHostMux(cfg *config.Config, e *env) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ingressd edge node. Manage it with the ingressd CLI or the hosted panel.\n"))
	})
	mountConnector(mux, cfg, e) // /.ingressd/connector/, /.ingressd/tunnel/
	return mux
}
