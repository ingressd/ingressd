// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Store is the ephemeral Access state in <state-dir>/access.db: codes,
// sessions, revocations and rate counters. Losing it signs everyone out
// but never loses configuration.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS otp_codes (
	id INTEGER PRIMARY KEY,
	email TEXT NOT NULL,
	code_hash BLOB NOT NULL,
	salt BLOB NOT NULL,
	ip TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	attempts INTEGER NOT NULL DEFAULT 0,
	used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS otp_codes_email ON otp_codes(email);
CREATE TABLE IF NOT EXISTS auth_codes (
	code_hash BLOB PRIMARY KEY,
	sid TEXT NOT NULL,
	app TEXT NOT NULL,
	rd TEXT NOT NULL,
	grants TEXT NOT NULL,
	session_expires INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
	sid TEXT PRIMARY KEY,
	email TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	ip TEXT NOT NULL,
	ua TEXT NOT NULL,
	revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_email ON sessions(email);
CREATE TABLE IF NOT EXISTS rate_events (key TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS rate_events_key ON rate_events(key, at);
CREATE TABLE IF NOT EXISTS lockouts (key TEXT PRIMARY KEY, until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
`

// OpenStore opens (creating if needed) the Access database.
func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init %s: %w", path, err)
	}
	_ = os.Chmod(path, 0o600)
	return &Store{db: db, now: time.Now}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) unix() int64 { return s.now().Unix() }

// --- rate limits and lockouts ---

// Hit records an event under key and returns how many events the key has
// had within window (including this one).
func (s *Store) Hit(ctx context.Context, key string, window time.Duration) (int, error) {
	now := s.unix()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO rate_events(key, at) VALUES (?, ?)`, key, now); err != nil {
		return 0, err
	}
	return s.Count(ctx, key, window)
}

// Count returns the events under key within window.
func (s *Store) Count(ctx context.Context, key string, window time.Duration) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM rate_events WHERE key = ? AND at > ?`,
		key, s.unix()-int64(window/time.Second)).Scan(&n)
	return n, err
}

// LastHit returns the time of the latest event under key (zero if none).
func (s *Store) LastHit(ctx context.Context, key string) (time.Time, error) {
	var at sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT max(at) FROM rate_events WHERE key = ?`, key).Scan(&at)
	if err != nil || !at.Valid {
		return time.Time{}, err
	}
	return time.Unix(at.Int64, 0), nil
}

func (s *Store) ClearHits(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rate_events WHERE key = ?`, key)
	return err
}

func (s *Store) Lock(ctx context.Context, key string, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO lockouts(key, until) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET until = excluded.until`, key, s.now().Add(d).Unix())
	return err
}

// Locked reports whether key is locked out right now.
func (s *Store) Locked(ctx context.Context, key string) (bool, error) {
	var until int64
	err := s.db.QueryRowContext(ctx, `SELECT until FROM lockouts WHERE key = ?`, key).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && until > s.unix(), err
}

// --- one-time codes ---

type otpRow struct {
	id       int64
	hash     []byte
	salt     []byte
	attempts int
}

func (s *Store) insertOTP(ctx context.Context, email string, hash, salt []byte, ip string, ttl time.Duration) error {
	now := s.unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Only the newest code for an email is valid.
	if _, err := tx.ExecContext(ctx, `UPDATE otp_codes SET used = 1 WHERE email = ? AND used = 0`, email); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO otp_codes(email, code_hash, salt, ip, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, email, hash, salt, ip, now, now+int64(ttl/time.Second)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) activeOTP(ctx context.Context, email string) (*otpRow, error) {
	r := &otpRow{}
	err := s.db.QueryRowContext(ctx, `SELECT id, code_hash, salt, attempts FROM otp_codes
		WHERE email = ? AND used = 0 AND expires_at > ? ORDER BY id DESC LIMIT 1`, email, s.unix()).
		Scan(&r.id, &r.hash, &r.salt, &r.attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// failOTP counts a wrong guess, burning the code at maxAttempts. It reports
// whether the code is now burned.
func (s *Store) failOTP(ctx context.Context, id int64, maxAttempts int) (bool, error) {
	var attempts int
	err := s.db.QueryRowContext(ctx, `UPDATE otp_codes SET attempts = attempts + 1,
		used = CASE WHEN attempts + 1 >= ? THEN 1 ELSE used END WHERE id = ? RETURNING attempts`,
		maxAttempts, id).Scan(&attempts)
	return attempts >= maxAttempts, err
}

// useOTP marks a code used; it fails if another request used it first.
func (s *Store) useOTP(ctx context.Context, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE otp_codes SET used = 1 WHERE id = ? AND used = 0`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// --- sessions ---

// Session is a portal sign-in. App cookies carry its sid, so revoking it
// signs the user out everywhere.
type Session struct {
	SID string
	// Email is the principal: an email address, or "<method>:<id>" for a
	// sign-in that proved none (Steam, unverified provider emails).
	Email     string
	Created   time.Time
	Expires   time.Time
	IP        string
	UserAgent string
	Revoked   bool
	// Method and Attrs (not stored: they travel in the signed portal
	// cookie and callback code) are the login method and sign-in facts.
	Method string
	Attrs  []string
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) CreateSession(ctx context.Context, email, ip, ua string, ttl time.Duration) (*Session, error) {
	now := s.now()
	ss := &Session{SID: randomToken(16), Email: email, Created: now, Expires: now.Add(ttl), IP: ip, UserAgent: truncate(ua, 200)}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(sid, email, created_at, expires_at, ip, ua) VALUES (?, ?, ?, ?, ?, ?)`,
		ss.SID, ss.Email, ss.Created.Unix(), ss.Expires.Unix(), ss.IP, ss.UserAgent)
	return ss, err
}

// GetSession returns a live (unexpired, unrevoked) session or nil.
func (s *Store) GetSession(ctx context.Context, sid string) (*Session, error) {
	ss := &Session{SID: sid}
	var created, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT email, created_at, expires_at, ip, ua FROM sessions
		WHERE sid = ? AND revoked_at IS NULL AND expires_at > ?`, sid, s.unix()).
		Scan(&ss.Email, &created, &expires, &ss.IP, &ss.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	ss.Created, ss.Expires = time.Unix(created, 0), time.Unix(expires, 0)
	return ss, err
}

// ListSessions returns unexpired sessions, newest first, optionally for one
// email. Revoked ones are included (and marked).
func (s *Store) ListSessions(ctx context.Context, email string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sid, email, created_at, expires_at, ip, ua, revoked_at IS NOT NULL
		FROM sessions WHERE expires_at > ? AND (? = '' OR email = ?) ORDER BY created_at DESC`, s.unix(), email, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var ss Session
		var created, expires int64
		if err := rows.Scan(&ss.SID, &ss.Email, &created, &expires, &ss.IP, &ss.UserAgent, &ss.Revoked); err != nil {
			return nil, err
		}
		ss.Created, ss.Expires = time.Unix(created, 0), time.Unix(expires, 0)
		out = append(out, ss)
	}
	return out, rows.Err()
}

// Revoke revokes sessions by sid and/or email and returns how many were
// revoked. Each revocation bumps the revision edge_auth polls.
func (s *Store) Revoke(ctx context.Context, sid, email string) (int, error) {
	if sid == "" && email == "" {
		return 0, errors.New("nothing to revoke")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL AND expires_at > ?
		AND (? = '' OR sid = ?) AND (? = '' OR email = ?)`, s.unix(), s.unix(), sid, sid, email, email)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO meta(k, v) VALUES ('revision', 1)
			ON CONFLICT(k) DO UPDATE SET v = v + 1`); err != nil {
			return 0, err
		}
	}
	return int(n), tx.Commit()
}

// Revocations returns the revision counter and the sids of revoked
// sessions that have not expired yet (expired ones fail offline anyway).
func (s *Store) Revocations(ctx context.Context) (int64, []string, error) {
	var rev int64
	err := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'revision'`).Scan(&rev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sid FROM sessions WHERE revoked_at IS NOT NULL AND expires_at > ? ORDER BY sid`, s.unix())
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	sids := []string{}
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			return 0, nil, err
		}
		sids = append(sids, sid)
	}
	return rev, sids, rows.Err()
}

// --- one-time auth (callback) codes ---

// AuthCode is redeemed once by edge_auth at /.ingressd/callback.
type AuthCode struct {
	SID            string
	App            string
	RD             string
	Grants         map[string]string
	SessionExpires time.Time
}

func hashCode(code string) []byte {
	h := sha256.Sum256([]byte(code))
	return h[:]
}

func (s *Store) CreateAuthCode(ctx context.Context, c AuthCode, ttl time.Duration) (string, error) {
	code := randomToken(32)
	g, _ := json.Marshal(c.Grants)
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_codes(code_hash, sid, app, rd, grants, session_expires, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, hashCode(code), c.SID, c.App, c.RD, string(g), c.SessionExpires.Unix(), s.now().Add(ttl).Unix())
	return code, err
}

// RedeemAuthCode marks a code used and returns it, or nil if it is
// unknown, expired, already used or for another app.
func (s *Store) RedeemAuthCode(ctx context.Context, code, app string) (*AuthCode, error) {
	var c AuthCode
	var grants string
	var sexp int64
	err := s.db.QueryRowContext(ctx, `UPDATE auth_codes SET used = 1
		WHERE code_hash = ? AND used = 0 AND expires_at > ? AND app = ?
		RETURNING sid, app, rd, grants, session_expires`, hashCode(code), s.unix(), app).
		Scan(&c.SID, &c.App, &c.RD, &grants, &sexp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.SessionExpires = time.Unix(sexp, 0)
	if err := json.Unmarshal([]byte(grants), &c.Grants); err != nil {
		return nil, err
	}
	return &c, nil
}

// GC deletes rows that can no longer matter.
func (s *Store) GC(ctx context.Context) error {
	now := s.unix()
	for _, q := range []string{
		`DELETE FROM otp_codes WHERE expires_at < ? - 86400`,
		`DELETE FROM auth_codes WHERE expires_at < ? - 3600`,
		`DELETE FROM sessions WHERE expires_at < ? - 86400`,
		`DELETE FROM rate_events WHERE at < ? - 86400`,
		`DELETE FROM lockouts WHERE until < ?`,
	} {
		if _, err := s.db.ExecContext(ctx, q, now); err != nil {
			return err
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
