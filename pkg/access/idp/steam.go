// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// Steam signs users in with OpenID 2.0 (not OpenID Connect). The callback
// carries a positive assertion that only Steam can vouch for, so Finish:
//
//   - requires openid.return_to to be exactly the URL this flow sent
//     (callback plus the flow's state), and op_endpoint to be Steam's;
//   - requires claimed_id (= identity) to be
//     https://steamcommunity.com/openid/id/<SteamID64>;
//   - requires the signature to cover those fields and the nonce;
//   - asks Steam to check the assertion (mode check_authentication), and
//   - refuses a response nonce it has already accepted.
//
// Steam gives no email: a Steam sign-in's principal is steam:<SteamID64>.
// Group and game facts come from the Steam Web API (key sent in the
// x-webapi-key header, never in a URL) and only exist for profiles whose
// details are public.

const (
	openIDNS         = "http://specs.openid.net/auth/2.0"
	identifierSelect = "http://specs.openid.net/auth/2.0/identifier_select"
)

var claimedIDRe = regexp.MustCompile(`^https://steamcommunity\.com/openid/id/(7656119[0-9]{10})$`)

func steamReturnTo(redirectURI, state string) string {
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	return redirectURI + sep + "state=" + url.QueryEscape(state)
}

func (p *Provider) steamStart(redirectURI string, f Flow) (string, Flow, error) {
	ru, err := url.Parse(redirectURI)
	if err != nil || ru.Host == "" {
		return "", f, fmt.Errorf("steam: invalid callback URL")
	}
	q := url.Values{
		"openid.ns":         {openIDNS},
		"openid.mode":       {"checkid_setup"},
		"openid.return_to":  {steamReturnTo(redirectURI, f.State)},
		"openid.realm":      {ru.Scheme + "://" + ru.Host + "/"},
		"openid.identity":   {identifierSelect},
		"openid.claimed_id": {identifierSelect},
	}
	return p.ep().SteamOpenID + "?" + q.Encode(), f, nil
}

// steamNonces remembers accepted response nonces (replay protection on top
// of the single-use flow cookie).
var steamNonces = struct {
	sync.Mutex
	seen map[string]time.Time
}{seen: map[string]time.Time{}}

func steamNonceFresh(n string) bool {
	steamNonces.Lock()
	defer steamNonces.Unlock()
	now := time.Now()
	for k, t := range steamNonces.seen {
		if now.After(t) {
			delete(steamNonces.seen, k)
		}
	}
	if _, ok := steamNonces.seen[n]; ok {
		return false
	}
	steamNonces.seen[n] = now.Add(2 * FlowTTL)
	return true
}

func (p *Provider) steamFinish(ctx context.Context, redirectURI string, f Flow, q url.Values) (*Identity, error) {
	if q.Get("openid.mode") == "cancel" {
		return nil, userErr("sign-in was cancelled at Steam")
	}
	if q.Get("openid.mode") != "id_res" || q.Get("openid.ns") != openIDNS {
		return nil, userErr("Steam did not return a sign-in assertion")
	}
	if q.Get("openid.return_to") != steamReturnTo(redirectURI, f.State) {
		return nil, ErrState
	}
	if q.Get("openid.op_endpoint") != p.ep().SteamOpenID {
		return nil, fmt.Errorf("steam: assertion from another OpenID provider")
	}
	claimed := q.Get("openid.claimed_id")
	m := claimedIDRe.FindStringSubmatch(claimed)
	if m == nil || q.Get("openid.identity") != claimed {
		return nil, fmt.Errorf("steam: malformed claimed_id")
	}
	signed := strings.Split(q.Get("openid.signed"), ",")
	for _, need := range []string{"op_endpoint", "claimed_id", "identity", "return_to", "response_nonce", "assoc_handle"} {
		if !slices.Contains(signed, need) {
			return nil, fmt.Errorf("steam: assertion does not sign %s", need)
		}
	}
	nonce := q.Get("openid.response_nonce")
	if len(nonce) < 20 || len(nonce) > 256 {
		return nil, fmt.Errorf("steam: missing response nonce")
	}
	if ts, err := time.Parse(time.RFC3339, nonce[:20]); err != nil || time.Since(ts) > FlowTTL || time.Until(ts) > clockSkew {
		return nil, userErr("the Steam sign-in response has expired; start again")
	}
	// Ask Steam whether it issued this assertion.
	form := url.Values{}
	for k, vs := range q {
		if strings.HasPrefix(k, "openid.") && len(vs) == 1 {
			form.Set(k, vs[0])
		}
	}
	form.Set("openid.mode", "check_authentication")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.ep().SteamOpenID, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("steam: check_authentication: %w", unwrapURL(err))
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !keyValueTrue(string(body), "is_valid") {
		return nil, userErr("Steam did not confirm the sign-in")
	}
	if !steamNonceFresh(claimed + "|" + nonce) {
		return nil, userErr("this Steam sign-in response was already used; start again")
	}
	sid := m[1]
	id := &Identity{Method: config.MethodSteam, Subject: sid, Attrs: []string{config.Attr("steam_id", sid)}}
	if f.Wants.SteamGroups || len(f.Wants.SteamApps) > 0 {
		if p.APIKey == "" {
			return nil, fmt.Errorf("steam: group or app selectors need a Steam Web API key")
		}
		if err := p.steamFacts(ctx, sid, f.Wants, id); err != nil {
			return nil, err
		}
	}
	return id, nil
}

// keyValueTrue reads OpenID key-value form ("key:value" lines).
func keyValueTrue(body, key string) bool {
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), ":")
		if ok && k == key {
			return v == "true"
		}
	}
	return false
}

func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func (p *Provider) steamGet(ctx context.Context, path string, q url.Values, v any) error {
	u := strings.TrimSuffix(p.ep().SteamAPI, "/") + path + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-webapi-key", p.APIKey)
	req.Header.Set("Accept", "application/json")
	status, err := p.doJSON(req, v)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusForbidden, http.StatusUnauthorized:
		// Private profiles answer 403 for some methods: no facts.
		return errPrivate
	}
	return fmt.Errorf("steam: Web API %s: HTTP %d", path, status)
}

var errPrivate = errors.New("steam: profile details are private")

func (p *Provider) steamFacts(ctx context.Context, sid string, w Wants, id *Identity) error {
	if w.SteamGroups {
		var r struct {
			Response struct {
				Success bool `json:"success"`
				Groups  []struct {
					GID string `json:"gid"`
				} `json:"groups"`
			} `json:"response"`
		}
		err := p.steamGet(ctx, "/ISteamUser/GetUserGroupList/v1/", url.Values{"steamid": {sid}}, &r)
		if err != nil && !errors.Is(err, errPrivate) {
			return err
		}
		for _, g := range r.Response.Groups {
			if gid, ok := config.NormalizeSteamGroup(g.GID); ok {
				id.Attrs = append(id.Attrs, "steam_group:"+gid)
			}
		}
	}
	if len(w.SteamApps) > 0 {
		q := url.Values{"steamid": {sid}, "include_played_free_games": {"1"}, "include_free_sub": {"1"}}
		for i, a := range w.SteamApps {
			q.Set("appids_filter["+strconv.Itoa(i)+"]", a)
		}
		var r struct {
			Response struct {
				Games []struct {
					AppID int64 `json:"appid"`
				} `json:"games"`
			} `json:"response"`
		}
		err := p.steamGet(ctx, "/IPlayerService/GetOwnedGames/v1/", q, &r)
		if err != nil && !errors.Is(err, errPrivate) {
			return err
		}
		for _, g := range r.Response.Games {
			a := strconv.FormatInt(g.AppID, 10)
			if slices.Contains(w.SteamApps, a) {
				id.Attrs = append(id.Attrs, config.Attr("steam_app", a))
			}
		}
	}
	return nil
}
