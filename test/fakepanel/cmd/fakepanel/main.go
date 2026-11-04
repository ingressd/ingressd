// SPDX-License-Identifier: Apache-2.0

// Command fakepanel runs test/fakepanel as a program for the netns
// end-to-end test: the node API (enrol, control channel) plus the /test/
// API the script drives with curl. Never expose it: it has no auth.
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ingressd/ingressd/test/fakepanel"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "listen address")
	tokens := flag.String("tokens", "", "comma-separated enrolment tokens to accept")
	mailLog := flag.String("mail-log", "", "file receiving hosted-Access sign-in codes (email.provider panel)")
	downloads := flag.String("downloads", "", "directory served at /downloads/ (release mirror for remote updates)")
	flag.Parse()
	s := fakepanel.New()
	s.MailLog = *mailLog
	s.Downloads = *downloads
	s.URL = "http://" + *listen
	for _, t := range strings.Split(*tokens, ",") {
		if t != "" {
			s.AddToken(t)
		}
	}
	srv := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("fake panel on http://%s (org key %s)", *listen, s.OrgPublicKey())
	log.Fatal(srv.ListenAndServe())
}
