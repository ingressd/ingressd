// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// InsecurePanelEnv, set to 1, lets enrolment and the control channel use a
// plain http:// (ws://) panel. It exists for the fake panel in tests only:
// over plain HTTP an on-path attacker reads the enrolment token and the
// node credential and substitutes the org signing key the node pins.
const InsecurePanelEnv = "INGRESSD_INSECURE_PANEL"

func insecurePanelAllowed() bool { return os.Getenv(InsecurePanelEnv) == "1" }

// warnInsecurePanel logs, loudly, that the escape hatch is in use.
func warnInsecurePanel(log *slog.Logger, panelURL string) {
	if log == nil {
		log = slog.Default()
	}
	log.Error("INSECURE: talking to the panel over plain HTTP because "+InsecurePanelEnv+"=1; "+
		"the enrolment token, node credential and org signing key are exposed to the network. Test use only.",
		"panel", panelURL)
}

// normalizePanelURL checks and canonicalises a panel URL. Only https is
// accepted unless InsecurePanelEnv is set.
func normalizePanelURL(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("panel URL %q must be an https:// URL", s)
	}
	if u.User != nil {
		return "", fmt.Errorf("panel URL %q must not contain credentials", s)
	}
	if u.Scheme == "http" && !insecurePanelAllowed() {
		return "", fmt.Errorf("panel URL %q uses plain http; the panel must be reached over https "+
			"(the enrolment token, node credential and org signing key would otherwise be exposed)", s)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

// checkEnrolledPanelURL validates the panel_url an enrol response returns
// (where the node connects from now on): it must be https (http only with
// InsecurePanelEnv and only if enrolment itself used http), so a response
// can never downgrade the control channel.
func checkEnrolledPanelURL(enrolledWith, returned string) (string, error) {
	u, err := normalizePanelURL(returned)
	if err != nil {
		return "", fmt.Errorf("enrol: the panel returned an unusable panel_url: %w", err)
	}
	if strings.HasPrefix(u, "http://") && !strings.HasPrefix(enrolledWith, "http://") {
		return "", fmt.Errorf("enrol: the panel returned panel_url %q, a downgrade from https; refusing", returned)
	}
	return u, nil
}

// noDowngradeRedirect refuses redirects away from https (enrolment client).
func noDowngradeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" && !insecurePanelAllowed() {
		return fmt.Errorf("refusing redirect to non-https URL %s", req.URL.Redacted())
	}
	return nil
}
