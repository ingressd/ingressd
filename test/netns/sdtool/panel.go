// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// connectorState is the part of the connector's state file the panel
// learns from its reports (public key, age recipient).
type connectorState struct {
	PrivateKey  string `json:"private_key"`
	AgeIdentity string `json:"age_identity"`
}

func readState(path string) connectorState {
	b, err := os.ReadFile(path) //nolint:gosec // G703: test tool reading the file it is given
	if err != nil {
		log.Fatal(err)
	}
	var s connectorState
	if err := json.Unmarshal(b, &s); err != nil {
		log.Fatal(err)
	}
	return s
}

// connkey <connector.json>: prints the connector's WireGuard public key.
func connKey(args []string) {
	k, err := wgtypes.ParseKey(readState(args[0]).PrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(k.PublicKey().String())
}

// seal <connector.json> <file>: encrypts file to the connector's age
// recipient (what the panel's browser does with a VPN config).
func seal(args []string) {
	id, err := age.ParseX25519Identity(readState(args[0]).AgeIdentity)
	if err != nil {
		log.Fatalf("connector has no age identity yet: %v", err)
	}
	in, err := os.ReadFile(args[1]) //nolint:gosec // G703: test tool reading the file it is given
	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, id.Recipient())
	if err != nil {
		log.Fatal(err)
	}
	if _, err := w.Write(in); err != nil {
		log.Fatal(err)
	}
	w.Close()
	aw.Close()
	fmt.Print(buf.String())
}

// sign -seed <hex> -connector <key> -issued <RFC3339> < site.json: prints
// the signed Smart DNS config as one JSON line. The site config is checked
// like the connector checks it.
func sign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	seed := fs.String("seed", "", "64 hex characters: the org key seed")
	connector := fs.String("connector", "", "connector WireGuard public key")
	issued := fs.String("issued", "", "issue time (RFC 3339)")
	_ = fs.Parse(args) // ExitOnError
	sb, err := hex.DecodeString(*seed)
	if err != nil || len(sb) != ed25519.SeedSize {
		log.Fatal("-seed must be 64 hex characters")
	}
	at, err := time.Parse(time.RFC3339, *issued)
	if err != nil {
		log.Fatal(err)
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	var site config.SmartDNSSite
	if err := json.Unmarshal(raw, &site); err != nil {
		log.Fatal(err)
	}
	site.Normalize()
	if err := site.Validate(); err != nil {
		log.Fatal(err)
	}
	cfg, _ := json.Marshal(site)
	env := nodeproto.SignedSmartDNS{Connector: *connector, Issued: at, Config: cfg}
	nodeproto.SignSmartDNS(&env, ed25519.NewKeyFromSeed(sb))
	out, _ := json.Marshal(env)
	fmt.Println(string(out))
}
