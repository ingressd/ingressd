// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"math/big"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ingressd/ingressd/pkg/config"
)

var (
	// ErrRateLimited means too many codes were requested; the caller is
	// locked out for a while. It is returned for any email alike.
	ErrRateLimited = errors.New("too many requests; try again later")
	// ErrInvalidCode covers wrong, expired, used, burned and never-issued
	// codes, and lockouts, so responses reveal nothing.
	ErrInvalidCode = errors.New("invalid or expired code")
)

// OTP issues and verifies emailed one-time codes (PLAN §7.3): argon2id
// hashed, single use, short-lived, attempt-capped and rate-limited.
type OTP struct {
	Store    *Store
	Settings config.OTP
}

func otpHash(code string, salt []byte) []byte {
	// Codes are short and live for minutes; modest parameters keep the
	// portal responsive while making a stolen database useless offline
	// within the code's lifetime.
	return argon2.IDKey([]byte(code), salt, 1, 8*1024, 1, 32)
}

func generateCode(length int) (string, error) {
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b[i] = byte('0' + n.Int64())
	}
	return string(b), nil
}

// guessKeys are the failure counter and lockout for wrong codes. They are
// per client address: a code is capped by its own attempts, and how many
// codes an email can get by the request limits, so failures from one
// address leave the email usable from others.
func guessKeys(email, ip string) (fail, lock string) {
	return "fail:" + ip + ":" + email, "lock:fail:" + ip + ":" + email
}

// Allow applies the per-email and per-IP rate limits and the resend
// cooldown to a code request. It must be called for every request, whether
// or not a code will be sent, so limits behave identically for all emails.
// send=false (with a nil error) means "within cooldown: don't send again".
func (o *OTP) Allow(ctx context.Context, email, ip string) (send bool, err error) {
	s := o.Settings
	_, guessLock := guessKeys(email, ip)
	for _, key := range []string{"lock:email:" + email, "lock:ip:" + ip, guessLock} {
		if locked, err := o.Store.Locked(ctx, key); err != nil {
			return false, err
		} else if locked {
			return false, ErrRateLimited
		}
	}
	last, err := o.Store.LastHit(ctx, "req:email:"+email)
	if err != nil {
		return false, err
	}
	if !last.IsZero() && o.Store.now().Sub(last) < time.Duration(s.ResendCooldown) {
		return false, nil
	}
	n, err := o.Store.Hit(ctx, "req:email:"+email, time.Duration(s.PerEmail.Window))
	if err != nil {
		return false, err
	}
	if n > s.PerEmail.Codes {
		if err := o.Store.Lock(ctx, "lock:email:"+email, time.Duration(s.Lockout)); err != nil {
			return false, err
		}
		return false, ErrRateLimited
	}
	n, err = o.Store.Hit(ctx, "req:ip:"+ip, time.Duration(s.PerIP.Window))
	if err != nil {
		return false, err
	}
	if n > s.PerIP.Codes {
		if err := o.Store.Lock(ctx, "lock:ip:"+ip, time.Duration(s.Lockout)); err != nil {
			return false, err
		}
		return false, ErrRateLimited
	}
	return true, nil
}

// Issue creates a new code for email (invalidating older ones) and returns
// it for delivery. Call Allow first.
func (o *OTP) Issue(ctx context.Context, email, ip string) (string, error) {
	code, err := generateCode(o.Settings.Length)
	if err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if err := o.Store.insertOTP(ctx, email, otpHash(code, salt), salt, ip, time.Duration(o.Settings.TTL)); err != nil {
		return "", err
	}
	return code, nil
}

// Verify checks a code from ip. Wrong guesses count against the code; when
// the attempts run out the code is burned and ip locked out for this email.
// Success consumes the code.
func (o *OTP) Verify(ctx context.Context, email, code, ip string) error {
	failKey, lockKey := guessKeys(email, ip)
	for _, key := range []string{"lock:email:" + email, lockKey} {
		if locked, err := o.Store.Locked(ctx, key); err != nil {
			return err
		} else if locked {
			return ErrInvalidCode
		}
	}
	row, err := o.Store.activeOTP(ctx, email)
	if err != nil {
		return err
	}
	if row == nil {
		// Count guesses against emails without a code too, so they cannot
		// be told apart, and so guessing cannot continue unchecked.
		n, err := o.Store.Hit(ctx, failKey, time.Duration(o.Settings.Lockout))
		if err != nil {
			return err
		}
		if n >= o.Settings.Attempts {
			if err := o.Store.Lock(ctx, lockKey, time.Duration(o.Settings.Lockout)); err != nil {
				return err
			}
		}
		_ = otpHash(code, make([]byte, 16)) // equalise timing
		return ErrInvalidCode
	}
	if len(code) == o.Settings.Length && subtle.ConstantTimeCompare(otpHash(code, row.salt), row.hash) == 1 {
		if ok, err := o.Store.useOTP(ctx, row.id); err != nil || !ok {
			return errors.Join(ErrInvalidCode, err)
		}
		_ = o.Store.ClearHits(ctx, failKey)
		return nil
	}
	burned, err := o.Store.failOTP(ctx, row.id, o.Settings.Attempts)
	if err != nil {
		return err
	}
	if burned {
		if err := o.Store.Lock(ctx, lockKey, time.Duration(o.Settings.Lockout)); err != nil {
			return err
		}
	}
	return ErrInvalidCode
}
