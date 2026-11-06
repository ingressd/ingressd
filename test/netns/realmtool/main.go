// SPDX-License-Identifier: Apache-2.0

// Command realmtool plays a realm's external sign-in portal for the realms
// netns suite: it makes a key pair and seals callback codes with it, as the
// panel's central portal does.
//
//	realmtool keys                 prints "<session key> <jwt key>" (base64)
//	realmtool seal SESSION JWT APP RETURN_URL EMAIL
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/ingressd/ingressd/pkg/access"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "realmtool:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	switch {
	case len(args) == 1 && args[0] == "keys":
		master := make([]byte, 32)
		rand.Read(master)
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(master), base64.StdEncoding.EncodeToString(der))
		return nil
	case len(args) == 6 && args[0] == "seal":
		keys, err := access.ParseKeys(args[1], args[2])
		if err != nil {
			return err
		}
		id := make([]byte, 16)
		rand.Read(id)
		now := time.Now()
		code, err := keys.SealCode(access.SealedCode{ID: hex.EncodeToString(id), SID: "rt-" + hex.EncodeToString(id[:8]),
			Email: args[5], App: args[3], RD: args[4], SessionIssued: now, SessionExpires: now.Add(time.Hour), Expires: now.Add(time.Minute)})
		if err != nil {
			return err
		}
		fmt.Println(code)
		return nil
	}
	return fmt.Errorf("usage: realmtool keys | realmtool seal SESSION JWT APP RETURN_URL EMAIL")
}
