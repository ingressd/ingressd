// SPDX-License-Identifier: Apache-2.0

// Package idptest is a fake of every identity provider idp supports, for
// tests without real accounts: Google and Microsoft OpenID Connect
// (discovery, JWKS, authorize, token), Discord OAuth2 and API (users/@me,
// guilds, guild member), Steam OpenID 2.0 (checkid_setup,
// check_authentication) and the Steam Web API (groups, owned games).
//
// The authorize endpoints sign the configured user in at once and redirect
// back, so a test follows the redirects like a browser. Knobs make the
// fake misbehave (bad signatures, wrong audience, ...) for negative tests.
package idptest

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/access/idp"
	"github.com/ingressd/ingressd/pkg/config"
)

// User is the account the fake signs in for a provider.
type User struct {
	Sub           string `json:"sub,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	// Google
	HD string `json:"hd,omitempty"`
	// Microsoft
	TID           string   `json:"tid,omitempty"`
	OID           string   `json:"oid,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	GroupsOverage bool     `json:"groups_overage,omitempty"`
	Edov          bool     `json:"edov,omitempty"` // xms_edov
	// Discord
	Username string              `json:"username,omitempty"`
	Guilds   []string            `json:"guilds,omitempty"`
	Members  map[string][]string `json:"members,omitempty"` // guild ID → role IDs
	// Steam
	SteamID     string   `json:"steam_id,omitempty"`
	SteamGroups []string `json:"steam_groups,omitempty"` // 32-bit gids, as the Web API returns them
	SteamApps   []int64  `json:"steam_apps,omitempty"`
}

// Knobs make the fake misbehave.
type Knobs struct {
	BadSignature  bool `json:"bad_signature,omitempty"`
	WrongAudience bool `json:"wrong_audience,omitempty"`
	WrongIssuer   bool `json:"wrong_issuer,omitempty"`
	WrongNonce    bool `json:"wrong_nonce,omitempty"`
	Expired       bool `json:"expired,omitempty"`
	SteamInvalid  bool `json:"steam_invalid,omitempty"` // check_authentication says is_valid:false
	SteamForeign  bool `json:"steam_foreign,omitempty"` // claimed_id on another host
}

// Server is the fake.
type Server struct {
	ClientID, ClientSecret string
	SteamAPIKey            string
	// URL is the base URL (set by Start, or by the caller with Handler).
	URL string

	key *rsa.PrivateKey
	ts  *httptest.Server

	mu     sync.Mutex
	users  map[string]User
	knobs  Knobs
	codes  map[string]*grant
	tokens map[string]*grant
	steam  map[string]url.Values // response nonce → assertion
	// Requests counts token requests (tests).
	Requests int
}

type grant struct {
	method, redirect, challenge, nonce, scope, tenant string
	used                                              bool
}

// New makes a fake for one OAuth client.
func New(clientID, clientSecret, steamKey string) *Server {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &Server{ClientID: clientID, ClientSecret: clientSecret, SteamAPIKey: steamKey, key: k,
		users: map[string]User{}, codes: map[string]*grant{}, tokens: map[string]*grant{}, steam: map[string]url.Values{}}
}

// Start serves the fake on a local test server.
func (s *Server) Start() *Server {
	s.ts = httptest.NewServer(s.Handler())
	s.URL = s.ts.URL
	return s
}

// Close stops a started fake.
func (s *Server) Close() {
	if s.ts != nil {
		s.ts.Close()
	}
}

// Endpoints points idp at the fake.
func (s *Server) Endpoints() *idp.Endpoints {
	b := s.URL
	return &idp.Endpoints{DiscordAuth: b + "/discord/oauth2/authorize", DiscordAPI: b + "/discord/api", GoogleIssuer: b + "/google",
		MicrosoftLogin: b + "/ms", SteamOpenID: b + "/steam/openid/login", SteamAPI: b + "/steamapi"}
}

// SetUser sets the account signed in for a provider (a login method).
func (s *Server) SetUser(method string, u User) {
	s.mu.Lock()
	s.users[method] = u
	s.mu.Unlock()
}

// SetKnobs replaces the misbehaviour switches.
func (s *Server) SetKnobs(k Knobs) {
	s.mu.Lock()
	s.knobs = k
	s.mu.Unlock()
}

func rnd() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Handler serves every endpoint, plus PUT /_fake/user/<method> and PUT
// /_fake/knobs (JSON) for end-to-end tests.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /_fake/user/{method}", func(w http.ResponseWriter, r *http.Request) {
		var u User
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		s.SetUser(r.PathValue("method"), u)
	})
	mux.HandleFunc("PUT /_fake/knobs", func(w http.ResponseWriter, r *http.Request) {
		var k Knobs
		if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		s.SetKnobs(k)
	})
	// Google
	mux.HandleFunc("GET /google/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		b := s.base(r)
		writeJSON(w, map[string]string{"issuer": b + "/google", "authorization_endpoint": b + "/google/authorize",
			"token_endpoint": b + "/google/token", "jwks_uri": b + "/google/jwks"})
	})
	mux.HandleFunc("GET /google/authorize", func(w http.ResponseWriter, r *http.Request) { s.authorize(w, r, config.MethodGoogle, "") })
	mux.HandleFunc("POST /google/token", func(w http.ResponseWriter, r *http.Request) { s.token(w, r) })
	mux.HandleFunc("GET /google/jwks", s.jwks)
	// Microsoft
	mux.HandleFunc("GET /ms/{tenant}/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		b, t := s.base(r), r.PathValue("tenant")
		iss := b + "/ms/{tenantid}/v2.0"
		switch t {
		case "common", "organizations":
		case "consumers":
			iss = b + "/ms/" + config.MicrosoftConsumersTenant + "/v2.0"
		default:
			iss = b + "/ms/" + t + "/v2.0"
		}
		writeJSON(w, map[string]string{"issuer": iss, "authorization_endpoint": b + "/ms/" + t + "/oauth2/v2.0/authorize",
			"token_endpoint": b + "/ms/" + t + "/oauth2/v2.0/token", "jwks_uri": b + "/ms/discovery/v2.0/keys"})
	})
	mux.HandleFunc("GET /ms/{tenant}/oauth2/v2.0/authorize", func(w http.ResponseWriter, r *http.Request) {
		s.authorize(w, r, config.MethodMicrosoft, r.PathValue("tenant"))
	})
	mux.HandleFunc("POST /ms/{tenant}/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) { s.token(w, r) })
	mux.HandleFunc("GET /ms/discovery/v2.0/keys", s.jwks)
	// Discord
	mux.HandleFunc("GET /discord/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) { s.authorize(w, r, config.MethodDiscord, "") })
	mux.HandleFunc("POST /discord/api/oauth2/token", func(w http.ResponseWriter, r *http.Request) { s.token(w, r) })
	mux.HandleFunc("GET /discord/api/users/@me", func(w http.ResponseWriter, r *http.Request) {
		u, g := s.bearer(w, r, "identify")
		if g == nil {
			return
		}
		out := map[string]any{"id": u.Sub, "username": u.Username, "global_name": u.Name}
		if strings.Contains(" "+g.scope+" ", " email ") {
			out["email"], out["verified"] = u.Email, u.EmailVerified
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("GET /discord/api/users/@me/guilds", func(w http.ResponseWriter, r *http.Request) {
		u, g := s.bearer(w, r, "guilds")
		if g == nil {
			return
		}
		out := []map[string]string{}
		for _, id := range u.Guilds {
			out = append(out, map[string]string{"id": id, "name": "Server " + id})
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("GET /discord/api/users/@me/guilds/{guild}/member", func(w http.ResponseWriter, r *http.Request) {
		u, g := s.bearer(w, r, "guilds.members.read")
		if g == nil {
			return
		}
		roles, ok := u.Members[r.PathValue("guild")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]any{"message": "Unknown Guild", "code": 10004})
			return
		}
		writeJSON(w, map[string]any{"roles": roles})
	})
	// Steam
	mux.HandleFunc("GET /steam/openid/login", s.steamLogin)
	mux.HandleFunc("POST /steam/openid/login", s.steamCheck)
	mux.HandleFunc("GET /steamapi/ISteamUser/GetUserGroupList/v1/", func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.steamAPI(w, r)
		if !ok {
			return
		}
		var gs []map[string]string
		for _, g := range u.SteamGroups {
			gs = append(gs, map[string]string{"gid": g})
		}
		writeJSON(w, map[string]any{"response": map[string]any{"success": true, "groups": gs}})
	})
	mux.HandleFunc("GET /steamapi/IPlayerService/GetOwnedGames/v1/", func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.steamAPI(w, r)
		if !ok {
			return
		}
		var filter []int64
		for k, v := range r.URL.Query() {
			if strings.HasPrefix(k, "appids_filter[") {
				n, _ := strconv.ParseInt(v[0], 10, 64)
				filter = append(filter, n)
			}
		}
		var games []map[string]int64
		for _, a := range u.SteamApps {
			if len(filter) == 0 || slices.Contains(filter, a) {
				games = append(games, map[string]int64{"appid": a})
			}
		}
		writeJSON(w, map[string]any{"response": map[string]any{"game_count": len(games), "games": games}})
	})
	return mux
}

func (s *Server) base(r *http.Request) string {
	if s.URL != "" {
		return s.URL
	}
	return "http://" + r.Host
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, method, tenant string) {
	q := r.URL.Query()
	redirect, state := q.Get("redirect_uri"), q.Get("state")
	if q.Get("client_id") != s.ClientID || redirect == "" || state == "" || q.Get("response_type") != "code" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	if method != config.MethodDiscord && q.Get("nonce") == "" {
		http.Error(w, "nonce required", http.StatusBadRequest)
		return
	}
	code := rnd()
	s.mu.Lock()
	s.codes[code] = &grant{method: method, redirect: redirect, challenge: q.Get("code_challenge"), nonce: q.Get("nonce"),
		scope: q.Get("scope"), tenant: tenant}
	s.mu.Unlock()
	u, _ := url.Parse(redirect)
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", state)
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: a test fake redirects where told
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests++
	fail := func(e string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": e})
	}
	if r.PostForm.Get("client_id") != s.ClientID || r.PostForm.Get("client_secret") != s.ClientSecret {
		fail("invalid_client")
		return
	}
	g := s.codes[r.PostForm.Get("code")]
	if g == nil || g.used || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != g.redirect {
		fail("invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		fail("invalid_grant")
		return
	}
	g.used = true
	at := rnd()
	s.tokens[at] = g
	out := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 3600, "scope": g.scope}
	if g.method != config.MethodDiscord {
		out["id_token"] = s.idToken(r, g)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) idToken(r *http.Request, g *grant) string {
	u := s.users[g.method]
	now := time.Now()
	c := map[string]any{"sub": u.Sub, "aud": s.ClientID, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": g.nonce, "name": u.Name}
	if u.Email != "" {
		c["email"] = u.Email
	}
	b := s.base(r)
	if g.method == config.MethodGoogle {
		c["iss"] = b + "/google"
		c["email_verified"] = u.EmailVerified
		if u.HD != "" {
			c["hd"] = u.HD
		}
	} else {
		c["iss"] = b + "/ms/" + u.TID + "/v2.0"
		c["tid"], c["oid"] = u.TID, u.OID
		if len(u.Groups) > 0 {
			c["groups"] = u.Groups
		}
		if len(u.Roles) > 0 {
			c["roles"] = u.Roles
		}
		if u.GroupsOverage {
			c["_claim_names"] = map[string]string{"groups": "src1"}
		}
		if u.Edov {
			c["xms_edov"] = true
		}
		c["preferred_username"] = u.Email
	}
	k := s.knobs
	if k.WrongAudience {
		c["aud"] = "someone-else"
	}
	if k.WrongIssuer {
		c["iss"] = "https://evil.example/"
	}
	if k.WrongNonce {
		c["nonce"] = "not-the-nonce"
	}
	if k.Expired {
		c["exp"] = now.Add(-time.Hour).Unix()
	}
	return s.sign(c, k.BadSignature)
}

func (s *Server) sign(claims map[string]any, bad bool) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if bad {
		sig[0] ^= 0xff
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := s.key.PublicKey
	writeJSON(w, map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}}})
}

// bearer resolves an access token that was granted scope.
func (s *Server) bearer(w http.ResponseWriter, r *http.Request, scope string) (User, *grant) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	g := s.tokens[tok]
	var u User
	if g != nil {
		u = s.users[g.method]
	}
	s.mu.Unlock()
	if g == nil {
		http.Error(w, `{"message": "401: Unauthorized"}`, http.StatusUnauthorized)
		return u, nil
	}
	if !slices.Contains(strings.Fields(g.scope), scope) {
		http.Error(w, `{"message": "Missing Access"}`, http.StatusForbidden)
		return u, nil
	}
	return u, g
}

func (s *Server) steamLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("openid.mode") != "checkid_setup" || q.Get("openid.claimed_id") != "http://specs.openid.net/auth/2.0/identifier_select" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	u, k := s.users[config.MethodSteam], s.knobs
	s.mu.Unlock()
	ret, err := url.Parse(q.Get("openid.return_to"))
	if err != nil || !strings.HasPrefix(q.Get("openid.return_to"), q.Get("openid.realm")) {
		http.Error(w, "return_to outside realm", http.StatusBadRequest)
		return
	}
	claimed := "https://steamcommunity.com/openid/id/" + u.SteamID
	if k.SteamForeign {
		claimed = "https://evil.example/openid/id/" + u.SteamID
	}
	a := url.Values{
		"openid.ns":             {"http://specs.openid.net/auth/2.0"},
		"openid.mode":           {"id_res"},
		"openid.op_endpoint":    {s.base(r) + "/steam/openid/login"},
		"openid.claimed_id":     {claimed},
		"openid.identity":       {claimed},
		"openid.return_to":      {q.Get("openid.return_to")},
		"openid.response_nonce": {time.Now().UTC().Format(time.RFC3339) + rnd()[:8]},
		"openid.assoc_handle":   {"1234567890"},
		"openid.signed":         {"signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle"},
	}
	m := hmac.New(sha256.New, []byte("fake-steam"))
	m.Write([]byte(a.Encode()))
	a.Set("openid.sig", base64.StdEncoding.EncodeToString(m.Sum(nil)))
	s.mu.Lock()
	s.steam[a.Get("openid.response_nonce")] = a
	s.mu.Unlock()
	rq := ret.Query()
	for k, v := range a {
		rq[k] = v
	}
	ret.RawQuery = rq.Encode()
	http.Redirect(w, r, ret.String(), http.StatusFound) //nolint:gosec // G710: a test fake redirects where told
}

func (s *Server) steamCheck(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	s.mu.Lock()
	a, k := s.steam[r.PostForm.Get("openid.response_nonce")], s.knobs
	s.mu.Unlock()
	valid := a != nil && r.PostForm.Get("openid.mode") == "check_authentication" && !k.SteamInvalid
	if valid {
		for key := range a {
			if key != "openid.mode" && r.PostForm.Get(key) != a.Get(key) {
				valid = false
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ns:http://specs.openid.net/auth/2.0\nis_valid:" + strconv.FormatBool(valid) + "\n"))
}

func (s *Server) steamAPI(w http.ResponseWriter, r *http.Request) (User, bool) {
	if r.Header.Get("x-webapi-key") != s.SteamAPIKey || r.URL.Query().Has("key") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return User{}, false
	}
	s.mu.Lock()
	u := s.users[config.MethodSteam]
	s.mu.Unlock()
	if r.URL.Query().Get("steamid") != u.SteamID {
		writeJSON(w, map[string]any{"response": map[string]any{}})
		return User{}, false
	}
	return u, true
}
