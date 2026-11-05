// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Policy actions (PLAN §7.1).
const (
	ActionAllow       = "allow"
	ActionDeny        = "deny"
	ActionBypass      = "bypass"
	ActionServiceAuth = "service_auth"

	EmailSES  = "ses"
	EmailSMTP = "smtp"
	EmailLog  = "log"
	// EmailPanel (managed nodes only): the hosted panel sends and checks
	// the one-time codes over the node's control channel, so a sign-in
	// works on whichever node of the org the user lands on.
	EmailPanel = "panel"
)

var countryRe = regexp.MustCompile(`^[A-Z]{2}$`)

// Access configures the login portal and its one-time codes.
type Access struct {
	// PortalHost serves the login portal on this node (e.g.
	// auth.example.com). One of PortalHost and PortalURL is required when
	// any app is protected.
	PortalHost string `yaml:"portal_host"`
	// PortalURL is an external sign-in portal (managed nodes: the panel's
	// central portal, e.g. https://auth.ingressd.com/a/<org>). Visitors are
	// sent to <PortalURL>/login?app=&rd= and come back to the app's
	// /.ingressd/callback with a sealed code; the node serves no portal
	// host and login-to-play pages live on the portal too. The node still
	// evaluates the app's policies for the signed-in identity at the
	// callback. Needs org-wide keys (session_key, jwt_key).
	PortalURL string `yaml:"portal_url,omitempty"`
	// Session is how long a portal sign-in lasts (default 24h). App cookies
	// never outlive it.
	Session  Duration `yaml:"session"`
	OTP      OTP      `yaml:"otp"`
	Branding Branding `yaml:"branding"`
	// SessionKey and JWTKey are secret:// references to org-wide keys
	// (managed nodes: delivered encrypted by the panel, identical on every
	// node of the org, so every node accepts every session). Empty: the
	// node generates its own keys (secrets access_session_key and
	// access_jwt_key). Set both or neither.
	SessionKey string `yaml:"session_key,omitempty"`
	JWTKey     string `yaml:"jwt_key,omitempty"`
	// RevokedBefore invalidates sessions issued before a time, per email
	// address or passkey ("passkey:<name>", a removed passkey), or for
	// everyone with the key "*".
	RevokedBefore map[string]Instant `yaml:"revoked_before,omitempty"`
	// RevokedSessions lists revoked session ids (sign-outs on other nodes).
	RevokedSessions []string `yaml:"revoked_sessions,omitempty"`
	// Providers are the third-party sign-in methods this node's portal
	// offers besides the emailed one-time code: discord, google, microsoft
	// and steam. Managed nodes on the panel's central portal configure
	// them on the panel instead. See docs/ACCESS-PROVIDERS.md.
	Providers map[string]IdentityProvider `yaml:"providers,omitempty"`
}

// OTP tunes the emailed one-time codes (PLAN §7.3).
type OTP struct {
	Length         int       `yaml:"length"`          // digits, 4-8 (default 6)
	TTL            Duration  `yaml:"ttl"`             // 1-15m (default 5m)
	Attempts       int       `yaml:"attempts"`        // wrong guesses per code (default 5)
	ResendCooldown Duration  `yaml:"resend_cooldown"` // default 60s
	PerEmail       RateLimit `yaml:"per_email"`       // default 5 codes / 15m
	PerIP          RateLimit `yaml:"per_ip"`          // default 20 codes / 15m
	Lockout        Duration  `yaml:"lockout"`         // default 15m
}

type RateLimit struct {
	Codes  int      `yaml:"codes"`
	Window Duration `yaml:"window"`
}

// Branding is applied to portal pages and emails.
type Branding struct {
	Name    string `yaml:"name"`     // default "ingressd"
	LogoURL string `yaml:"logo_url"` // optional https:// image
	Color   string `yaml:"color"`    // accent colour, #rgb or #rrggbb (default #ff6b2c)
}

// Email configures how one-time codes are delivered.
type Email struct {
	Provider        string `yaml:"provider"` // ses | smtp | log | panel
	From            string `yaml:"from"`
	Region          string `yaml:"region"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	SMTP            *SMTP  `yaml:"smtp"`
	Log             *Log   `yaml:"log"`
}

type SMTP struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"` // default 587
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// TLS is starttls (default), tls (implicit, port 465) or none.
	TLS string `yaml:"tls"`
}

// Log appends every message to a file instead of sending it (tests, dev).
type Log struct {
	Path string `yaml:"path"`
}

// Group is a named set of identities.
type Group struct {
	Emails       []string `yaml:"emails"`
	EmailDomains []string `yaml:"email_domains"`
	// Realm is omitted from JSON when empty so policy versions (which hash
	// the groups a policy uses) stay unchanged for configs without realms.
	Realm string `yaml:"realm,omitempty" json:",omitempty"`
}

// ServiceToken authenticates machines with Edge-Client-Id/Edge-Client-Secret,
// or (a header token) with a secret value in a header of the user's choice.
type ServiceToken struct {
	ClientID     string `yaml:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret"` // secret://name
	Expires      Date   `yaml:"expires"`       // optional
	// Header makes this a header token: a request carrying the secret in
	// this header (e.g. X-Bot-Token) is authenticated as the token, with
	// no client id. edge_auth removes the header before the request
	// reaches the origin. The secret must be at least 16 characters.
	Header string `yaml:"header,omitempty"`
	Realm  string `yaml:"realm,omitempty"`
}

// Policy decides who may reach an app. Policies are listed per app; the
// first matching one wins.
type Policy struct {
	Action  string     `yaml:"action"`
	Include []Selector `yaml:"include"` // any of
	Require []Selector `yaml:"require"` // all of
	Exclude []Selector `yaml:"exclude"` // none of
	// Session is the lifetime of app cookies minted under this policy
	// (default 24h).
	Session Duration `yaml:"session"`
	// Realm is omitted from JSON when empty: Engine.Version hashes the
	// policy's JSON, and configs without realms must keep their versions.
	Realm string `yaml:"realm,omitempty" json:",omitempty"`
}

// Selector matches one property of a request. Exactly one field is set.
// Email selectors match verified email addresses only, whichever login
// method proved them. The identity-provider selectors (login_method and
// discord_*, google_hd, microsoft_*, steam_*) match facts captured when
// the user signed in (docs/ACCESS-PROVIDERS.md).
//
// The fields added with identity providers are omitted when empty, in YAML
// and in JSON: a policy's version (Engine.Version) hashes its JSON, so
// existing policies keep their versions and nobody is signed out.
type Selector struct {
	Everyone     bool       `yaml:"everyone"`
	Email        StringList `yaml:"email"`
	EmailDomain  StringList `yaml:"email_domain"`
	Group        StringList `yaml:"group"`
	IP           StringList `yaml:"ip"`
	Country      StringList `yaml:"country"`
	ServiceToken StringList `yaml:"service_token"`
	// LoginMethod matches how the user signed in: email, discord, google,
	// microsoft, steam or passkey.
	LoginMethod StringList `yaml:"login_method"`

	DiscordUser     StringList `yaml:"discord_user,omitempty" json:",omitempty"`     // user IDs
	DiscordUsername StringList `yaml:"discord_username,omitempty" json:",omitempty"` // usernames (changeable: prefer IDs)
	DiscordGuild    StringList `yaml:"discord_guild,omitempty" json:",omitempty"`    // server (guild) IDs the user is in
	DiscordRole     StringList `yaml:"discord_role,omitempty" json:",omitempty"`     // "<guild ID>/<role ID>"
	GoogleHD        StringList `yaml:"google_hd,omitempty" json:",omitempty"`        // Google Workspace domains (hd claim)
	MicrosoftTenant StringList `yaml:"microsoft_tenant,omitempty" json:",omitempty"` // tenant IDs (tid claim)
	MicrosoftGroup  StringList `yaml:"microsoft_group,omitempty" json:",omitempty"`  // Entra group object IDs (groups claim)
	MicrosoftRole   StringList `yaml:"microsoft_role,omitempty" json:",omitempty"`   // app role values (roles claim)
	SteamID         StringList `yaml:"steam_id,omitempty" json:",omitempty"`         // SteamID64s
	SteamGroup      StringList `yaml:"steam_group,omitempty" json:",omitempty"`      // Steam group IDs (groupID64)
	SteamApp        StringList `yaml:"steam_app,omitempty" json:",omitempty"`        // app IDs the user owns
	// Passkey matches users who signed in with one of the org's passkeys
	// (by name; enrolled on the panel, central portal only).
	Passkey StringList `yaml:"passkey,omitempty" json:",omitempty"`
}

type selectorField struct {
	name string
	v    StringList
}

// fields lists the list-valued selector kinds in a stable order.
func (s Selector) fields() []selectorField {
	return []selectorField{{"email", s.Email}, {"email_domain", s.EmailDomain}, {"group", s.Group}, {"ip", s.IP},
		{"country", s.Country}, {"service_token", s.ServiceToken}, {"login_method", s.LoginMethod},
		{"discord_user", s.DiscordUser}, {"discord_username", s.DiscordUsername}, {"discord_guild", s.DiscordGuild},
		{"discord_role", s.DiscordRole}, {"google_hd", s.GoogleHD}, {"microsoft_tenant", s.MicrosoftTenant},
		{"microsoft_group", s.MicrosoftGroup}, {"microsoft_role", s.MicrosoftRole}, {"steam_id", s.SteamID},
		{"steam_group", s.SteamGroup}, {"steam_app", s.SteamApp}, {"passkey", s.Passkey}}
}

// Kind names the selector's single field ("" if none or several are set).
func (s Selector) Kind() string {
	var kinds []string
	if s.Everyone {
		kinds = append(kinds, "everyone")
	}
	for _, f := range s.fields() {
		if len(f.v) > 0 {
			kinds = append(kinds, f.name)
		}
	}
	if len(kinds) != 1 {
		return ""
	}
	return kinds[0]
}

// Values returns the selector's values (nil for everyone and invalid
// selectors).
func (s Selector) Values() []string {
	k := s.Kind()
	for _, f := range s.fields() {
		if f.name == k {
			return f.v
		}
	}
	return nil
}

// PathRule overrides an app's policies for matching paths. Match is an exact
// path or a prefix ending in "*" (e.g. /api/webhook/*), matched
// case-insensitively against the decoded, dot-segment-resolved request path.
// An app with path rules but no access list of its own leaves every other
// path public (see AccessWarnings): /admin/* does not cover /admin, and an
// origin may serve the same page under other paths.
type PathRule struct {
	Match  string   `yaml:"match"`
	Access []string `yaml:"access"`
}

// Protected reports whether the app has any access policy, which puts the
// edge_auth handler in front of it.
func (a App) Protected() bool {
	if len(a.Access) > 0 {
		return true
	}
	for _, p := range a.Paths {
		if len(p.Access) > 0 {
			return true
		}
	}
	return false
}

// AccessWarnings returns advice about valid but risky access settings, as
// "path: message" lines in a stable order. They do not fail validation.
func (c *Config) AccessWarnings() []string {
	var out []string
	for _, name := range sortedKeys(c.Apps) {
		app := c.Apps[name]
		if len(app.Access) > 0 || !app.Protected() {
			continue
		}
		var protected []string
		for _, r := range app.Paths {
			protected = append(protected, r.Match)
		}
		out = append(out, fmt.Sprintf("apps.%s.access: empty, so only %s %s protected and every other path is public "+
			"(/admin/* does not cover /admin); give the app an access list and open public paths with bypass rules instead",
			name, strings.Join(protected, ", "), map[bool]string{true: "is", false: "are"}[len(protected) == 1]))
	}
	return append(out, c.loginMethodWarnings()...)
}

// StringList accepts either a single string or a list of strings.
type StringList []string

func (l *StringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		*l = StringList{s}
		return nil
	}
	var ss []string
	if err := n.Decode(&ss); err != nil {
		return err
	}
	*l = ss
	return nil
}

// Instant is an RFC 3339 timestamp (2026-11-03T10:00:00Z).
type Instant struct{ time.Time }

func (t *Instant) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("line %d: invalid time %q (use RFC 3339, e.g. 2026-11-03T10:00:00Z)", n.Line, s)
	}
	t.Time = v
	return nil
}

func (t Instant) MarshalYAML() (any, error) {
	if t.IsZero() {
		return nil, nil
	}
	return t.UTC().Format(time.RFC3339), nil
}

// Date is a calendar date (2027-11-01) or an RFC 3339 timestamp.
type Date struct{ time.Time }

func (d *Date) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			d.Time = t
			return nil
		}
	}
	return fmt.Errorf("line %d: invalid date %q (use YYYY-MM-DD)", n.Line, s)
}

func (d Date) MarshalYAML() (any, error) {
	if d.IsZero() {
		return nil, nil
	}
	return d.Format("2006-01-02"), nil
}

func (c *Config) applyAccessDefaults() {
	// With realms the top-level block stays absent (validation refuses it):
	// each realm carries its own.
	if c.Access == nil && len(c.Realms) == 0 {
		c.Access = &Access{}
	}
	if c.Access != nil {
		defaultAccess(c.Access)
	}
	c.applyRealmDefaults()
	if s := c.Email.SMTP; s != nil {
		if s.Port == 0 {
			s.Port = 587
		}
		if s.TLS == "" {
			s.TLS = "starttls"
		}
	}
	for name, p := range c.Policies {
		if p.Session == 0 {
			p.Session = Duration(24 * time.Hour)
		}
		c.Policies[name] = p
	}
}

func defaultAccess(a *Access) {
	setDur := func(d *Duration, def time.Duration) {
		if *d == 0 {
			*d = Duration(def)
		}
	}
	setInt := func(i *int, def int) {
		if *i == 0 {
			*i = def
		}
	}
	setDur(&a.Session, 24*time.Hour)
	setInt(&a.OTP.Length, 6)
	setDur(&a.OTP.TTL, 5*time.Minute)
	setInt(&a.OTP.Attempts, 5)
	setDur(&a.OTP.ResendCooldown, 60*time.Second)
	setInt(&a.OTP.PerEmail.Codes, 5)
	setDur(&a.OTP.PerEmail.Window, 15*time.Minute)
	setInt(&a.OTP.PerIP.Codes, 20)
	setDur(&a.OTP.PerIP.Window, 15*time.Minute)
	setDur(&a.OTP.Lockout, 15*time.Minute)
	if a.Branding.Name == "" {
		a.Branding.Name = "ingressd"
	}
	if a.Branding.Color == "" {
		a.Branding.Color = "#ff6b2c"
	}
}

var colorRe = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

func (c *Config) validateAccess(v *validator) {
	a := c.Access
	if a == nil {
		a = &Access{}
		defaultAccess(a)
	}
	if len(c.Realms) == 0 {
		protected := false
		for _, app := range c.Apps {
			protected = protected || app.Protected()
		}
		c.validateAccessBlock(v, "access", a)
		if a.PortalHost == "" && protected && a.PortalURL == "" {
			v.add("access.portal_host", "is required when an app has access policies")
		}
		// Login-to-play needs email too, but its policy and provider are
		// checked when a player signs in (the page explains what is missing).
		if protected || c.Email.Provider != "" {
			c.validateEmail(v)
		}
	} else if c.Email.Provider != "" {
		c.validateEmail(v)
	}

	for _, name := range sortedKeys(c.Groups) {
		g := c.Groups[name]
		p := "groups." + name
		if !qualifiedNameRe.MatchString(name) {
			v.add(p, "name must match %s", qualifiedNameRe)
		}
		if len(g.Emails) == 0 && len(g.EmailDomains) == 0 {
			v.add(p, "needs emails or email_domains")
		}
		for i, e := range g.Emails {
			validEmail(v, fmt.Sprintf("%s.emails[%d]", p, i), e)
		}
		for i, d := range g.EmailDomains {
			if !validHostname(d, false) {
				v.add(fmt.Sprintf("%s.email_domains[%d]", p, i), "invalid domain %q", d)
			}
		}
	}

	ids := map[string]string{}
	for _, name := range sortedKeys(c.ServiceTokens) {
		t := c.ServiceTokens[name]
		p := "service_tokens." + name
		if !qualifiedNameRe.MatchString(name) {
			v.add(p, "name must match %s", qualifiedNameRe)
		}
		if t.Header != "" {
			validTokenHeader(v, p+".header", t.Header)
			if t.ClientID != "" {
				v.add(p+".client_id", "must be empty for a header token (the header carries the secret alone)")
			}
		} else if len(t.ClientID) < 8 || strings.ContainsAny(t.ClientID, " \t\r\n") {
			v.add(p+".client_id", "must be at least 8 characters without spaces")
		} else if other, dup := ids[t.ClientID]; dup {
			v.add(p+".client_id", "already used by service token %q", other)
		} else {
			ids[t.ClientID] = name
		}
		if !strings.HasPrefix(t.ClientSecret, "secret://") {
			v.add(p+".client_secret", "must be a secret:// reference")
		}
	}

	for _, name := range sortedKeys(c.Policies) {
		c.validatePolicy(v, name, c.Policies[name])
	}

	for _, name := range sortedKeys(c.Apps) {
		app := c.Apps[name]
		p := "apps." + name
		c.validatePolicyList(v, p+".access", app.Access)
		appAccess := a
		if len(c.Realms) > 0 {
			appAccess = c.RealmAccess(app.Realm)
		}
		c.validateLoginMethods(v, appAccess, p+".login_methods", app.LoginMethods)
		for i, r := range app.Paths {
			rp := fmt.Sprintf("%s.paths[%d]", p, i)
			if !strings.HasPrefix(r.Match, "/") || strings.Contains(strings.TrimSuffix(r.Match, "*"), "*") {
				v.add(rp+".match", "must be an exact path or a prefix ending in *, got %q", r.Match)
			} else if strings.ContainsAny(r.Match, "\\;%\x00") {
				// Requests spelled with these are refused by edge_auth; write
				// the plain, decoded path (matching is case-insensitive).
				v.add(rp+".match", "must be a plain path without \\, ; or percent-encoding, got %q", r.Match)
			}
			if len(r.Access) == 0 {
				v.add(rp+".access", "at least one policy is required")
			}
			c.validatePolicyList(v, rp+".access", r.Access)
		}
	}
}

// validateAccessBlock checks one access block (top-level, or a realm's at
// path p).
func (c *Config) validateAccessBlock(v *validator, p string, a *Access) {
	if a.PortalHost != "" {
		if !validHostname(a.PortalHost, false) {
			v.add(p+".portal_host", "invalid hostname %q", a.PortalHost)
		}
		if a.PortalHost == c.Edge.Admin.Hostname {
			v.add(p+".portal_host", "must differ from edge.admin.hostname")
		}
		for _, name := range sortedKeys(c.Apps) {
			if slices.Contains(c.Apps[name].Hosts, a.PortalHost) {
				v.add(p+".portal_host", "%q is already served by app %q", a.PortalHost, name)
			}
		}
	}
	if a.PortalURL != "" {
		u, err := url.Parse(a.PortalURL)
		switch {
		case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "":
			v.add(p+".portal_url", "must be an http(s) URL without query, e.g. https://auth.ingressd.com/a/org")
		case a.PortalHost != "":
			v.add(p+".portal_url", "set portal_host or portal_url, not both")
		case a.SessionKey == "" || a.JWTKey == "":
			v.add(p+".portal_url", "needs org-wide keys (session_key and jwt_key)")
		}
	}
	if a.Session < Duration(time.Minute) {
		v.add(p+".session", "must be at least 1m")
	}
	o := a.OTP
	if o.Length < 4 || o.Length > 8 {
		v.add(p+".otp.length", "must be 4-8, got %d", o.Length)
	}
	if o.TTL < Duration(time.Minute) || o.TTL > Duration(15*time.Minute) {
		v.add(p+".otp.ttl", "must be 1m-15m")
	}
	if o.Attempts < 1 || o.Attempts > 20 {
		v.add(p+".otp.attempts", "must be 1-20, got %d", o.Attempts)
	}
	if o.ResendCooldown < 0 {
		v.add(p+".otp.resend_cooldown", "must not be negative")
	}
	for name, rl := range map[string]RateLimit{"per_email": o.PerEmail, "per_ip": o.PerIP} {
		if rl.Codes < 1 || rl.Window <= 0 {
			v.add(p+".otp."+name, "codes and window must be positive")
		}
	}
	if o.Lockout <= 0 {
		v.add(p+".otp.lockout", "must be positive")
	}
	if u := a.Branding.LogoURL; u != "" && !strings.HasPrefix(u, "https://") {
		v.add(p+".branding.logo_url", "must be an https:// URL")
	}
	if !colorRe.MatchString(a.Branding.Color) {
		v.add(p+".branding.color", "must be #rgb or #rrggbb, got %q", a.Branding.Color)
	}
	if (a.SessionKey == "") != (a.JWTKey == "") {
		v.add(p, "set both session_key and jwt_key, or neither")
	}
	for name, ref := range map[string]string{"session_key": a.SessionKey, "jwt_key": a.JWTKey} {
		if ref != "" && !strings.HasPrefix(ref, "secret://") {
			v.add(p+"."+name, "must be a secret:// reference")
		}
	}
	for _, who := range sortedKeys(a.RevokedBefore) {
		if who != "*" && !validPasskeyPrincipal(who) && (!strings.Contains(who, "@") || who != strings.ToLower(who)) {
			v.add(p+".revoked_before."+who, "key must be a lowercase email address, passkey:<name> or *")
		}
	}
	for i, sid := range a.RevokedSessions {
		if sid == "" || len(sid) > 128 || strings.ContainsFunc(sid, unicode.IsSpace) {
			v.add(fmt.Sprintf("%s.revoked_sessions[%d]", p, i), "invalid session id")
		}
	}
	c.validateProviders(v, p, a)
}

func (c *Config) validateEmail(v *validator) {
	e := c.Email
	switch e.Provider {
	case EmailSES:
		if e.Region == "" {
			v.add("email.region", "is required for ses")
		}
		if (e.AccessKeyID == "") != (e.SecretAccessKey == "") {
			v.add("email", "set both access_key_id and secret_access_key, or neither (to use the instance's AWS credentials)")
		}
	case EmailSMTP:
		if e.SMTP == nil || e.SMTP.Host == "" {
			v.add("email.smtp.host", "is required for smtp")
		} else {
			if e.SMTP.Port < 1 || e.SMTP.Port > 65535 {
				v.add("email.smtp.port", "must be 1-65535")
			}
			if !slices.Contains([]string{"starttls", "tls", "none"}, e.SMTP.TLS) {
				v.add("email.smtp.tls", "must be starttls, tls or none; got %q", e.SMTP.TLS)
			}
		}
	case EmailLog:
		if e.Log == nil || e.Log.Path == "" {
			v.add("email.log.path", "is required for log")
		}
	case EmailPanel:
		// Codes are sent by the hosted panel; nothing else to configure.
		return
	case "":
		v.add("email.provider", "is required when an app has access policies or login-to-play (ses, smtp, log, or panel on managed nodes)")
		return
	default:
		v.add("email.provider", "must be ses, smtp, log or panel; got %q", e.Provider)
		return
	}
	if e.Provider != EmailLog {
		if _, err := mail.ParseAddress(e.From); err != nil {
			v.add("email.from", "invalid address %q", e.From)
		}
	}
}

func validEmail(v *validator, path, e string) {
	if a, err := mail.ParseAddress(e); err != nil || a.Address != e || a.Name != "" || e != strings.ToLower(e) {
		v.add(path, "invalid email %q (use a lowercase bare address)", e)
	}
}

func (c *Config) validatePolicyList(v *validator, path string, names []string) {
	seen := map[string]bool{}
	for i, n := range names {
		if _, ok := c.Policies[n]; !ok {
			v.add(fmt.Sprintf("%s[%d]", path, i), "unknown policy %q", n)
		} else if seen[n] {
			v.add(fmt.Sprintf("%s[%d]", path, i), "policy %q listed twice", n)
		}
		seen[n] = true
	}
}

// edgeSelectors are the selectors edge_auth can evaluate on every request
// without an identity; bypass and service_auth policies may only use these.
var edgeSelectors = []string{"everyone", "ip", "service_token"}

func (c *Config) validatePolicy(v *validator, name string, pol Policy) {
	p := "policies." + name
	if !qualifiedNameRe.MatchString(name) {
		v.add(p, "name must match %s", qualifiedNameRe)
	}
	switch pol.Action {
	case ActionAllow, ActionDeny, ActionBypass, ActionServiceAuth:
	default:
		v.add(p+".action", "must be allow, deny, bypass or service_auth; got %q", pol.Action)
	}
	if len(pol.Include) == 0 {
		v.add(p+".include", "at least one selector is required (use { everyone: true } to match all)")
	}
	if pol.Session < Duration(time.Minute) {
		v.add(p+".session", "must be at least 1m")
	}
	hasToken := false
	for _, part := range []struct {
		name string
		sels []Selector
	}{{"include", pol.Include}, {"require", pol.Require}, {"exclude", pol.Exclude}} {
		for i, s := range part.sels {
			sp := fmt.Sprintf("%s.%s[%d]", p, part.name, i)
			kind := s.Kind()
			if kind == "" {
				v.add(sp, "exactly one of everyone, email, email_domain, group, ip, country, service_token, login_method, discord_*, google_hd, microsoft_* or steam_* must be set")
				continue
			}
			c.validateSelector(v, sp, kind, s)
			if kind == "service_token" {
				hasToken = true
				if pol.Action != ActionServiceAuth {
					v.add(sp, "service_token selectors are only allowed in service_auth policies")
				}
			}
			if (pol.Action == ActionBypass || pol.Action == ActionServiceAuth) && !slices.Contains(edgeSelectors, kind) {
				v.add(sp, "%s policies can only use everyone, ip and service_token selectors (no sign-in happens)", pol.Action)
			}
		}
	}
	if pol.Action == ActionServiceAuth && !hasToken {
		v.add(p+".include", "service_auth policies need a service_token selector")
	}
}

func (c *Config) validateSelector(v *validator, path, kind string, s Selector) {
	switch kind {
	case "email":
		for i, e := range s.Email {
			validEmail(v, fmt.Sprintf("%s.email[%d]", path, i), e)
		}
	case "email_domain":
		for i, d := range s.EmailDomain {
			if !validHostname(d, false) {
				v.add(fmt.Sprintf("%s.email_domain[%d]", path, i), "invalid domain %q", d)
			}
		}
	case "group":
		for i, g := range s.Group {
			if _, ok := c.Groups[g]; !ok {
				v.add(fmt.Sprintf("%s.group[%d]", path, i), "unknown group %q", g)
			}
		}
	case "ip":
		for i, ip := range s.IP {
			if _, err := ParsePrefixOrAddr(ip); err != nil {
				v.add(fmt.Sprintf("%s.ip[%d]", path, i), "invalid IP or CIDR %q", ip)
			}
		}
	case "country":
		for i, cc := range s.Country {
			if !countryRe.MatchString(cc) {
				v.add(fmt.Sprintf("%s.country[%d]", path, i), "must be an ISO 3166 alpha-2 code like GB, got %q", cc)
			}
		}
	case "service_token":
		for i, t := range s.ServiceToken {
			if _, ok := c.ServiceTokens[t]; !ok {
				v.add(fmt.Sprintf("%s.service_token[%d]", path, i), "unknown service token %q", t)
			}
		}
	default:
		c.validateIdentitySelector(v, path, kind, s)
	}
}

// ParsePrefixOrAddr parses a CIDR or a single address (as a /32 or /128).
func ParsePrefixOrAddr(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
