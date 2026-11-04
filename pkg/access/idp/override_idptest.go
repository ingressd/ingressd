// SPDX-License-Identifier: Apache-2.0

//go:build idptest

package idp

import (
	"log"
	"os"
	"strings"
)

// End-to-end test builds only (go build -tags idptest): INGRESSD_IDP_TEST_BASE
// points every provider at a fake (test/fakeidp). Release builds never
// contain this file, so production endpoints cannot be redirected.
func init() {
	base := strings.TrimSuffix(os.Getenv("INGRESSD_IDP_TEST_BASE"), "/")
	if base == "" {
		return
	}
	log.Printf("idp: TEST BUILD: identity providers are faked at %s", base)
	testEndpoints = &Endpoints{
		DiscordAuth:    base + "/discord/oauth2/authorize",
		DiscordAPI:     base + "/discord/api",
		GoogleIssuer:   base + "/google",
		MicrosoftLogin: base + "/ms",
		SteamOpenID:    base + "/steam/openid/login",
		SteamAPI:       base + "/steamapi",
	}
}
