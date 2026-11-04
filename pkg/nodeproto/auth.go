// SPDX-License-Identifier: Apache-2.0

package nodeproto

import "time"

// Hosted Access messages (docs/rev1/NODE-AGENT.md). Managed nodes whose
// config says email.provider: panel ask the panel to send and check
// one-time sign-in codes, so a sign-in works whichever node of the org the
// user lands on. Requests carry an envelope ID; the panel answers with the
// matching *_result type and the same ID.
const (
	// Node → panel requests; panel → node results (same envelope ID).
	TypeAuthOTPStart        = "auth_otp_start"
	TypeAuthOTPStartResult  = "auth_otp_start_result"
	TypeAuthOTPVerify       = "auth_otp_verify"
	TypeAuthOTPVerifyResult = "auth_otp_verify_result"

	// TypeAuthRevoke travels both ways without a reply: a node reports a
	// session it revoked (sign-out), and the panel relays it to the org's
	// other nodes.
	TypeAuthRevoke = "auth_revoke"

	// TypeL4Allow travels both ways without a reply: a node reports an L4
	// allowlist entry it added (login-to-play), and the panel relays it to
	// the org's other nodes that serve the same service.
	TypeL4Allow = "l4_allow"
)

// CapabilityAccessIdentity is listed in Hello.Capabilities by nodes that
// load the Access features added with identity providers and header
// tokens (config.Config.IdentityFeatures): identity-provider and
// login_method selectors, apps.<name>.login_methods, access.providers and
// service_tokens.<name>.header. Older nodes reject a config with those
// fields, so the panel only sends them to nodes that advertise this.
// Such nodes also redeem callback codes carrying sign-in facts and accept
// sessions whose user is not an email address ("steam:<id>").
const CapabilityAccessIdentity = "access-identity"

// CapabilityAccessPasskey is listed by nodes that load passkey sign-in
// (config.Config.PasskeyFeatures): the passkey login method and selector.
// The panel's central portal runs the passkey ceremony; such nodes accept
// its callback codes for "passkey:<name>" users.
const CapabilityAccessPasskey = "access-passkey"

// CapabilitySmartDNSChecks is listed by nodes that load smartdns.checks
// (edge location checks). Older nodes reject a config with that field and
// use the checks built into their binary instead, so the panel only sends
// it to nodes that advertise this.
const CapabilitySmartDNSChecks = "smartdns-checks"

// AuthOTPStart asks the panel to email a one-time code. The node only
// sends it for emails that could satisfy the policy and after its own rate
// limits passed; the panel applies its limits again (per email, per client
// IP, per org per day) because a user may try several nodes.
type AuthOTPStart struct {
	Email string `json:"email"`
	// Policy names what is being signed in to: the app (portal) or the
	// login-to-play policy. Informational (logs, audit).
	Policy string `json:"policy,omitempty"`
	// Label is the human name shown in the email ("web", "Minecraft").
	Label    string `json:"label,omitempty"`
	ClientIP string `json:"client_ip"`
	// Host is the portal (or play) host the user is on, shown in the email.
	Host string `json:"host"`
	// TTL, Length and Attempts mirror the node's access.otp settings; the
	// panel clamps them to its own bounds (defaults 10m, 6, 5).
	TTL      time.Duration `json:"ttl,omitempty"`
	Length   int           `json:"length,omitempty"`
	Attempts int           `json:"attempts,omitempty"`
}

// OTP result codes.
const (
	OTPOK          = "ok"
	OTPRateLimited = "rate_limited" // per email / per IP limit, or lockout
	OTPDailyCap    = "daily_cap"    // the org's daily email cap is reached
	OTPInvalid     = "invalid"      // wrong, expired, used or unknown code
	OTPUnavailable = "unavailable"  // the panel cannot send email right now
)

type AuthOTPStartResult struct {
	OK bool `json:"ok"`
	// Code is one of the OTP* values (OTPOK when OK).
	Code string `json:"code"`
	// TTL is how long the code is valid (for the "it expires in" text).
	TTL     time.Duration `json:"ttl,omitempty"`
	Message string        `json:"message,omitempty"`
}

// AuthOTPVerify checks a code the user typed.
type AuthOTPVerify struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	ClientIP string `json:"client_ip,omitempty"`
}

type AuthOTPVerifyResult struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code"` // OTPOK, OTPInvalid or OTPUnavailable
	Email string `json:"email,omitempty"`
	// Groups the panel knows the identity to belong to (reserved; node
	// config groups are still evaluated by the node).
	Groups []string `json:"groups,omitempty"`
}

// AuthRevoke revokes one portal session (SID) on every node, or every
// session of Email issued before Before.
type AuthRevoke struct {
	SID     string    `json:"sid,omitempty"`
	Email   string    `json:"email,omitempty"`
	Expires time.Time `json:"expires,omitempty"` // when the session would have expired
	Before  time.Time `json:"before,omitzero"`
}

// L4Allow is one runtime allowlist entry for an L4 service.
type L4Allow struct {
	Service string    `json:"service"`
	IP      string    `json:"ip"`
	Email   string    `json:"email,omitempty"`
	Expires time.Time `json:"expires,omitzero"` // zero: no expiry
	// Origin is the node that added the entry (set by the panel on relay).
	Origin string `json:"origin,omitempty"`
}
