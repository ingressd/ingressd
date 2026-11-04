// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/version"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// EnrollTokenEnv is the environment variable `ingressd node enroll` reads
// the enrolment token from (keeps it out of argv, which every local user
// can read).
const EnrollTokenEnv = "INGRESSD_ENROLL_TOKEN"

// EnrollOptions are the inputs of `ingressd node enroll`.
type EnrollOptions struct {
	PanelURL string
	Token    string
	Name     string
	// Hostname is the node's public DNS name, if it has one.
	Hostname string
	// PublicIPv4/6 override detection.
	PublicIPv4 string
	PublicIPv6 string
	// SSHPort is where sshd listens (0: unknown, assume 22).
	SSHPort  int
	KeyPath  string
	StateDir string
	// HTTPClient defaults to a client with a 30 s timeout.
	HTTPClient *http.Client
}

// Enroll registers the node with a panel using a one-time token and writes
// node.json. It creates the age identity at KeyPath if missing; its
// recipient is what the panel encrypts secrets to.
func Enroll(ctx context.Context, o EnrollOptions) (*State, error) {
	panel, err := normalizePanelURL(o.PanelURL)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(panel, "http://") {
		warnInsecurePanel(nil, panel)
	}
	if o.Token == "" {
		return nil, errors.New("an enrolment token is required (--token-file, " + EnrollTokenEnv + " or --token)")
	}
	if Managed(o.StateDir) {
		return nil, fmt.Errorf("this node is already enrolled (%s exists); run ingressd node detach first", StatePath(o.StateDir))
	}
	if o.Hostname != "" {
		if _, err := netip.ParseAddr(o.Hostname); err == nil {
			return nil, errors.New("--hostname must be a DNS name; use --public-ip for addresses")
		}
		o.Hostname = strings.ToLower(strings.TrimSuffix(o.Hostname, "."))
	}
	if o.PublicIPv4 != "" {
		if a, err := netip.ParseAddr(o.PublicIPv4); err != nil || !a.Is4() {
			return nil, fmt.Errorf("--public-ip %q is not an IPv4 address", o.PublicIPv4)
		}
	} else {
		o.PublicIPv4 = DetectPublicIPv4(panel)
	}
	recipient, err := EnsureIdentity(o.KeyPath)
	if err != nil {
		return nil, err
	}

	req := nodeproto.EnrollRequest{
		Token: o.Token, Name: o.Name, Hostname: o.Hostname,
		PublicIPv4: o.PublicIPv4, PublicIPv6: o.PublicIPv6,
		AgeRecipient: recipient, Version: version.String(), SSHPort: o.SSHPort,
		OS: runtime.GOOS, Arch: runtime.GOARCH,
	}
	body, _ := json.Marshal(req)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, panel+nodeproto.PathEnroll, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: noDowngradeRedirect}
	}
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("enrol with %s: %w", panel, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("enrol with %s: %s: %s", panel, resp.Status, strings.TrimSpace(string(b)))
	}
	var er nodeproto.EnrollResponse
	if err := json.Unmarshal(b, &er); err != nil {
		return nil, fmt.Errorf("enrol: decode response: %w", err)
	}
	if er.NodeID == "" || er.Credential == "" || er.OrgSigningKey == "" {
		return nil, errors.New("enrol: the panel's response is missing node_id, credential or org_signing_key")
	}
	// Reject an unusable signing key now rather than on the first snapshot.
	if err := nodeproto.Verify(nodeproto.Snapshot{}, er.OrgSigningKey); err != nil && err.Error() == "invalid org signing key" {
		return nil, errors.New("enrol: the panel sent an invalid org signing key")
	}
	st := &State{
		NodeID: er.NodeID, OrgID: er.OrgID, Name: er.Name, Credential: er.Credential,
		OrgSigningKey: er.OrgSigningKey, PanelURL: panel,
		Hostname: o.Hostname, PublicIPv4: o.PublicIPv4, PublicIPv6: o.PublicIPv6, SSHPort: o.SSHPort,
		EnrolledAt: time.Now().UTC(),
	}
	if er.PanelURL != "" {
		// The panel may name its canonical URL (another host is fine), but
		// never a plain-http one.
		u, err := checkEnrolledPanelURL(panel, er.PanelURL)
		if err != nil {
			return nil, err
		}
		st.PanelURL = u
	}
	if err := os.MkdirAll(o.StateDir, 0o750); err != nil {
		return nil, err
	}
	if err := SaveEndpoint(o.StateDir, Endpoint{Hostname: st.Hostname, PublicIPv4: st.PublicIPv4}); err != nil {
		return nil, err
	}
	if err := SaveState(o.StateDir, st); err != nil {
		return nil, err
	}
	return st, nil
}

// EnsureIdentity creates the age identity at path if it does not exist and
// returns its recipient (public key).
func EnsureIdentity(path string) (string, error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		if err := secrets.GenerateIdentity(path); err != nil {
			return "", err
		}
	}
	id, err := secrets.LoadIdentity(path)
	if err != nil {
		return "", err
	}
	return id.Recipient().String(), nil
}

// DetectPublicIPv4 returns the local source address used to reach the panel
// if it is a public (globally routable, non-private) IPv4 address; behind
// NAT it returns "" and the operator passes --public-ip. No packet is sent.
func DetectPublicIPv4(panelURL string) string {
	target := "1.1.1.1:443"
	if u, err := url.Parse(panelURL); err == nil && u.Hostname() != "" {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		target = net.JoinHostPort(u.Hostname(), port)
	}
	c, err := net.Dial("udp4", target)
	if err != nil {
		return ""
	}
	defer c.Close()
	a, ok := netip.AddrFromSlice(c.LocalAddr().(*net.UDPAddr).IP)
	if !ok {
		return ""
	}
	a = a.Unmap()
	if !IsPublic(a) {
		return ""
	}
	return a.String()
}

// IsPublic reports whether a is a globally routable unicast address.
func IsPublic(a netip.Addr) bool {
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}
