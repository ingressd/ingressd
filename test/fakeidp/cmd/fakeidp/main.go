// SPDX-License-Identifier: Apache-2.0

// fakeidp serves pkg/access/idp/idptest (fake Discord, Google, Microsoft and
// Steam) for the access-idp netns suite. Users are set with
// PUT /_fake/user/<method> (JSON idptest.User), misbehaviour with
// PUT /_fake/knobs. Nodes reach it through a binary built with
// -tags idptest and INGRESSD_IDP_TEST_BASE.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/ingressd/ingressd/pkg/access/idp/idptest"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9900", "address to listen on")
	clientID := flag.String("client-id", "client-1", "OAuth client ID")
	clientSecret := flag.String("client-secret", "secret-1", "OAuth client secret")
	steamKey := flag.String("steam-key", "steam-key", "Steam Web API key")
	flag.Parse()
	s := idptest.New(*clientID, *clientSecret, *steamKey)
	srv := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("fakeidp listening on %s", *listen)
	log.Fatal(srv.ListenAndServe())
}
