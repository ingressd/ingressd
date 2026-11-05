// SPDX-License-Identifier: Apache-2.0

// Command sdtool is a test helper for test/netns/connector-smartdns-e2e.sh: a
// DNS query client, a fake CDN resolver that answers by source address, a
// fake CDN HTTPS/HTTP server that reports who connected, a test CA, and
// the panel's part: signing a site config and sealing a VPN config to a
// connector.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: sdtool query|fakedns|cdn|gencert|connkey|seal|sign ...")
	}
	switch os.Args[1] {
	case "query":
		query(os.Args[2:])
	case "fakedns":
		fakeDNS(os.Args[2:])
	case "cdn":
		cdn(os.Args[2:])
	case "gencert":
		gencert(os.Args[2:])
	case "connkey":
		connKey(os.Args[2:])
	case "seal":
		seal(os.Args[2:])
	case "sign":
		sign(os.Args[2:])
	default:
		log.Fatalf("unknown command %s", os.Args[1])
	}
}

// query <server:port> <name> <type> [tcp]: prints "RCODE a1,a2" (A/AAAA
// answers only).
func query(args []string) {
	if len(args) < 3 {
		log.Fatal("query <server:port> <name> <type> [tcp]")
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(args[1]), dns.StringToType[strings.ToUpper(args[2])])
	c := &dns.Client{Timeout: 8 * time.Second}
	if len(args) > 3 && args[3] == "tcp" {
		c.Net = "tcp"
	}
	r, _, err := c.Exchange(q, args[0])
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
	var as []string
	for _, rr := range r.Answer {
		switch v := rr.(type) {
		case *dns.A:
			as = append(as, v.A.String())
		case *dns.AAAA:
			as = append(as, v.AAAA.String())
		}
	}
	fmt.Println(dns.RcodeToString[r.Rcode], strings.Join(as, ","))
}

// fakedns answers A queries with -nl addresses when the query comes from
// -nl-src and with -uk addresses otherwise; AAAA with 2001:db8::1. While
// -fail-file exists, queries from -nl-src get SERVFAIL. Every query is
// logged to stdout as "src name type".
func fakeDNS(args []string) {
	fs := flag.NewFlagSet("fakedns", flag.ExitOnError)
	listen := fs.String("listen", "", "address:port")
	nlSrc := fs.String("nl-src", "", "source address of the NL resolver")
	nl := fs.String("nl", "", "comma-separated NL answers")
	uk := fs.String("uk", "", "comma-separated UK answers")
	ttl := fs.Uint("ttl", 5, "answer TTL")
	bySrc := fs.String("by-src", "", "more per-source answers: src=a1,a2;src=a3")
	failFile := fs.String("fail-file", "", "while this file exists, NL queries get SERVFAIL")
	fs.Parse(args)
	answers := map[string]string{*nlSrc: *nl}
	for _, kv := range strings.Split(*bySrc, ";") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			answers[k] = v
		}
	}
	var mu sync.Mutex
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		src, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		q := r.Question[0]
		mu.Lock()
		fmt.Printf("%s %s %s\n", src, q.Name, dns.TypeToString[q.Qtype])
		mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if src == *nlSrc && *failFile != "" {
			if _, err := os.Stat(*failFile); err == nil {
				m.Rcode = dns.RcodeServerFailure
				w.WriteMsg(m)
				return
			}
		}
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: uint32(*ttl)}
		switch q.Qtype {
		case dns.TypeA:
			list := *uk
			if l, ok := answers[src]; ok {
				list = l
			}
			for _, a := range strings.Split(list, ",") {
				h := hdr
				h.Rrtype = dns.TypeA
				m.Answer = append(m.Answer, &dns.A{Hdr: h, A: net.ParseIP(a)})
			}
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::1")})
		}
		w.WriteMsg(m)
	})
	errc := make(chan error, 2)
	for _, n := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: *listen, Net: n, Handler: h}
		go func() { errc <- srv.ListenAndServe() }()
	}
	log.Fatal(<-errc)
}

// cdn serves HTTPS on :443 and HTTP on :80 of each -addrs address. Every
// response says which edge address was reached and which source connected;
// the /v1/location path answers with the country configured for the edge
// (like a streaming service's location API), and /cdn-cgi/trace answers like Cloudflare's
// trace (ip= the source, loc= the -geo country of the source). Connections
// are logged to stdout.
func cdn(args []string) {
	fs := flag.NewFlagSet("cdn", flag.ExitOnError)
	addrs := fs.String("addrs", "", "comma-separated edge addresses")
	countries := fs.String("countries", "", "edge=CC,... reported by the location API")
	dir := fs.String("certs", "", "directory with cert.pem and key.pem")
	geo := fs.String("geo", "", "src=CC,... countries the trace reports per source address")
	fs.Parse(args)
	cc := map[string]string{}
	for _, kv := range strings.Split(*countries, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			cc[k] = v
		}
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(*dir, "cert.pem"), filepath.Join(*dir, "key.pem"))
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		local := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		edge, _, _ := net.SplitHostPort(local.String())
		src, _, _ := net.SplitHostPort(r.RemoteAddr)
		mu.Lock()
		fmt.Printf("conn edge=%s src=%s host=%s path=%s\n", edge, src, r.Host, r.URL.RequestURI())
		mu.Unlock()
		if r.URL.Path == "/cdn-cgi/trace" {
			loc := "XX"
			for _, kv := range strings.Split(*geo, ",") {
				if k, v, ok := strings.Cut(kv, "="); ok && k == src {
					loc = v
				}
			}
			fmt.Fprintf(w, "h=%s\nip=%s\nloc=%s\n", r.Host, src, loc) //nolint:gosec // G705: plain-text /cdn-cgi/trace stub in the e2e test tool
			return
		}
		if r.URL.Path == "/v1/location" {
			fmt.Fprintf(w, `{"location":{"countryCode":"%s"}}`, cc[edge])
			return
		}
		fmt.Fprintf(w, "edge=%s src=%s host=%s\n", edge, src, r.Host)
	})
	errc := make(chan error, 8)
	for _, a := range strings.Split(*addrs, ",") {
		tlsSrv := &http.Server{Addr: net.JoinHostPort(a, "443"), Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
		go func() { errc <- tlsSrv.ListenAndServeTLS("", "") }()
		plain := &http.Server{Addr: net.JoinHostPort(a, "80"), Handler: handler}
		go func() { errc <- plain.ListenAndServe() }()
	}
	log.Fatal(<-errc)
}

// gencert <dir> <host>...: writes ca.pem, cert.pem and key.pem.
func gencert(args []string) {
	dir, hosts := args[0], args[1:]
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sdtool test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	write := func(name, typ string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0o644); err != nil {
			log.Fatal(err)
		}
	}
	write("ca.pem", "CERTIFICATE", caDER)
	write("cert.pem", "CERTIFICATE", der)
	write("key.pem", "EC PRIVATE KEY", kb)
}
