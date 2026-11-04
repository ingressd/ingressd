// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Sessions created on other nodes of the org. With org-wide keys every
// node accepts every node's cookies; the first time a node sees such a
// session it records it here, so `ingressd sessions` lists it and a local
// sign-out or a relayed revocation applies to it.

// sessionKnown reports whether sid has a row (live, expired or revoked).
func (s *Store) sessionKnown(ctx context.Context, sid string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE sid = ?`, sid).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// importSession records a session created elsewhere (no-op if known) and
// returns the live session, or nil if it is revoked or expired here.
func (s *Store) importSession(ctx context.Context, ss Session) (*Session, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(sid, email, created_at, expires_at, ip, ua) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(sid) DO NOTHING`, ss.SID, ss.Email, ss.Created.Unix(), ss.Expires.Unix(), ss.IP, truncate(ss.UserAgent, 200))
	if err != nil {
		return nil, err
	}
	got, err := s.GetSession(ctx, ss.SID)
	if err != nil || got == nil || got.Email != ss.Email {
		return nil, err
	}
	return got, nil
}

// RevokeRemote applies a revocation relayed from another node: the session
// is recorded as revoked even if this node never saw it, so edge_auth here
// rejects its app cookies too. It reports whether anything changed.
func (s *Store) RevokeRemote(ctx context.Context, sid, email string, expires time.Time) (bool, error) {
	if sid == "" {
		return false, errors.New("missing session id")
	}
	if expires.IsZero() || expires.Before(s.now()) {
		expires = s.now().Add(31 * 24 * time.Hour) // unknown: keep it long enough
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }() // ErrTxDone after Commit
	res, err := tx.ExecContext(ctx, `INSERT INTO sessions(sid, email, created_at, expires_at, ip, ua, revoked_at) VALUES (?, ?, ?, ?, '', 'remote', ?)
		ON CONFLICT(sid) DO UPDATE SET revoked_at = excluded.revoked_at WHERE sessions.revoked_at IS NULL`,
		sid, email, s.unix(), expires.Unix(), s.unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta(k, v) VALUES ('revision', 1) ON CONFLICT(k) DO UPDATE SET v = v + 1`); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// RevokeBefore revokes the sessions of email (every email for "*") created
// before t and returns how many were revoked.
func (s *Store) RevokeBefore(ctx context.Context, email string, t time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }() // ErrTxDone after Commit
	res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL AND expires_at > ?
		AND created_at < ? AND (? = '*' OR email = ?)`, s.unix(), s.unix(), t.Unix(), email, email)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO meta(k, v) VALUES ('revision', 1) ON CONFLICT(k) DO UPDATE SET v = v + 1`); err != nil {
			return 0, err
		}
	}
	return int(n), tx.Commit()
}

// useCode marks a sealed callback code as redeemed on this node. It
// reports false if it was already redeemed here.
func (s *Store) useCode(ctx context.Context, id string, ttl time.Duration) (bool, error) {
	n, err := s.Hit(ctx, "code:"+id, ttl+time.Minute)
	return n == 1, err
}
