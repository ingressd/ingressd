// SPDX-License-Identifier: Apache-2.0

// Command releasetool writes and checks release manifests (release.json,
// see pkg/release). scripts/build-release.sh and the release workflow use
// it; tests use it to sign fake releases with a throwaway key.
//
//	releasetool manifest --dir dist --version v1.2.3 [--min-supported v1.1.0] [--security] [--notes-url URL] [--key minisign.key]
//	releasetool keygen --pub test.pub --key test.key
//	releasetool sign --key minisign.key [--trusted-comment C] FILE...
//	releasetool verify --pub minisign.pub --dir dist
//
// manifest hashes every file in the directory into release.json and
// rewrites SHA256SUMS to cover it as well; with --key it also signs both
// (release.json.minisig, SHA256SUMS.minisig). CI signs with the minisign
// CLI instead, which produces the same files. Keys are unencrypted
// minisign keys (minisign -G -W).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ingressd/ingressd/pkg/release"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "manifest":
		err = manifest(os.Args[2:])
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasetool:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: releasetool manifest|keygen|sign|verify [flags] (see the source for details)")
	os.Exit(2)
}

func loadKey(path string) (*release.SecretKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := release.ParseSecretKey(string(b))
	return &k, err
}

func manifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	dir := fs.String("dir", "dist", "release directory")
	var o release.BuildOptions
	fs.StringVar(&o.Version, "version", "", "release version (vX.Y.Z[-pre])")
	fs.StringVar(&o.Channel, "channel", release.ChannelStable, "release channel")
	fs.StringVar(&o.MinSupported, "min-supported", "", "oldest version still supported")
	fs.BoolVar(&o.Security, "security", false, "the release fixes a security issue")
	fs.StringVar(&o.NotesURL, "notes-url", "", "release notes URL")
	key := fs.String("key", "", "sign with this unencrypted minisign secret key")
	_ = fs.Parse(args)
	m, err := release.BuildManifest(*dir, o)
	if err != nil {
		return err
	}
	var sk *release.SecretKey
	if *key != "" {
		if sk, err = loadKey(*key); err != nil {
			return err
		}
	}
	if err := release.WriteRelease(*dir, m, sk); err != nil {
		return err
	}
	fmt.Printf("wrote %s for %s (%d assets)\n", filepath.Join(*dir, release.ManifestFile), m.Version, len(m.Assets))
	return nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	pubPath := fs.String("pub", "minisign.pub", "public key file")
	keyPath := fs.String("key", "minisign.key", "secret key file (unencrypted)")
	_ = fs.Parse(args)
	pub, sec, err := release.GenerateKey()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*keyPath, []byte(sec), 0o600); err != nil {
		return err
	}
	return os.WriteFile(*pubPath, []byte(pub), 0o644) //nolint:gosec // G306: public key
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "minisign.key", "secret key file")
	tc := fs.String("trusted-comment", "", "trusted comment (default: the file name)")
	_ = fs.Parse(args)
	sk, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("no files to sign")
	}
	for _, f := range fs.Args() {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		c := *tc
		if c == "" {
			c = filepath.Base(f)
		}
		if err := os.WriteFile(f+".minisig", sk.Sign(b, c), 0o644); err != nil { //nolint:gosec // G306: detached signature, published with the release
			return err
		}
	}
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key file (default: the key built into ingressd)")
	dir := fs.String("dir", "dist", "release directory")
	_ = fs.Parse(args)
	pub := release.TrustedPublicKey()
	if *pubPath != "" {
		b, err := os.ReadFile(*pubPath)
		if err != nil {
			return err
		}
		pub = string(b)
	}
	mb, err := os.ReadFile(filepath.Join(*dir, release.ManifestFile))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(*dir, release.ManifestSigFile))
	if err != nil {
		return err
	}
	m, err := release.VerifyManifest(pub, mb, sig)
	if err != nil {
		return err
	}
	got, err := release.BuildManifest(*dir, release.BuildOptions{Version: m.Version})
	if err != nil {
		return err
	}
	for name, want := range m.Assets {
		if got.Assets[name] != want {
			return fmt.Errorf("%s does not match the manifest", name)
		}
	}
	fmt.Printf("release.json OK: %s (%d assets, security=%v, min_supported=%s)\n", m.Version, len(m.Assets), m.Security, m.MinSupported)
	return nil
}
