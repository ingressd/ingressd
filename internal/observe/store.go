// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver "sqlite"
)

// AggregateRetention is how long per-minute aggregates are kept.
const AggregateRetention = 30 * 24 * time.Hour

// OtherHost is the aggregate bucket for requests whose Host matches no
// configured app (scanners, typos); it bounds metric cardinality.
const OtherHost = "_other"

const schema = `
CREATE TABLE IF NOT EXISTS access_log (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,           -- unix milliseconds
	host TEXT NOT NULL,
	method TEXT NOT NULL,
	path TEXT NOT NULL,
	proto TEXT NOT NULL,
	status INTEGER NOT NULL,
	bytes INTEGER NOT NULL,
	bytes_in INTEGER NOT NULL,
	duration_us INTEGER NOT NULL,
	client_ip TEXT NOT NULL,
	ua TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS access_log_ts ON access_log(ts);
CREATE INDEX IF NOT EXISTS access_log_host_ts ON access_log(host, ts);
CREATE TABLE IF NOT EXISTS access_minutely (
	minute INTEGER NOT NULL,       -- unix seconds, start of the minute
	host TEXT NOT NULL,            -- configured host or _other
	requests INTEGER NOT NULL,
	s1xx INTEGER NOT NULL, s2xx INTEGER NOT NULL, s3xx INTEGER NOT NULL,
	s4xx INTEGER NOT NULL, s5xx INTEGER NOT NULL,
	bytes_out INTEGER NOT NULL,
	bytes_in INTEGER NOT NULL,
	duration_us INTEGER NOT NULL,  -- sum, for averages
	PRIMARY KEY (minute, host)
);
`

// Store is the SQLite log database.
type Store struct {
	db *sql.DB
}

// OpenStore opens (creating if needed) the database at path.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; WAL lets other processes read
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	_ = os.Chmod(path, 0o640)
	return &Store{db: db}, nil
}

// OpenStoreReadOnly opens an existing database for queries (the CLI).
func OpenStoreReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no access logs yet (%s does not exist; is ingressd serve running?)", path)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// batch is one flush: raw entries to store and aggregate deltas.
type batch struct {
	entries []Entry
	aggs    map[aggKey]*Totals
}

type aggKey struct {
	minute int64
	host   string
}

func (b *batch) add(e Entry, aggHost string, keep bool) {
	if keep {
		b.entries = append(b.entries, e)
	}
	if b.aggs == nil {
		b.aggs = map[aggKey]*Totals{}
	}
	k := aggKey{e.Time.Unix() / 60 * 60, aggHost}
	t := b.aggs[k]
	if t == nil {
		t = &Totals{}
		b.aggs[k] = t
	}
	t.add(e)
}

func (s *Store) write(ctx context.Context, b *batch) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(b.entries) > 0 {
		st, err := tx.PrepareContext(ctx, `INSERT INTO access_log
			(ts, host, method, path, proto, status, bytes, bytes_in, duration_us, client_ip, ua)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		for _, e := range b.entries {
			if _, err := st.ExecContext(ctx, e.Time.UnixMilli(), e.Host, e.Method, e.Path, e.Proto,
				e.Status, e.Bytes, e.BytesIn, e.Duration.Microseconds(), e.ClientIP, e.UA); err != nil {
				return err
			}
		}
	}
	for k, t := range b.aggs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO access_minutely
			(minute, host, requests, s1xx, s2xx, s3xx, s4xx, s5xx, bytes_out, bytes_in, duration_us)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(minute, host) DO UPDATE SET
				requests = requests + excluded.requests,
				s1xx = s1xx + excluded.s1xx, s2xx = s2xx + excluded.s2xx, s3xx = s3xx + excluded.s3xx,
				s4xx = s4xx + excluded.s4xx, s5xx = s5xx + excluded.s5xx,
				bytes_out = bytes_out + excluded.bytes_out, bytes_in = bytes_in + excluded.bytes_in,
				duration_us = duration_us + excluded.duration_us`,
			k.minute, k.host, t.Requests, t.Status[1], t.Status[2], t.Status[3], t.Status[4], t.Status[5],
			t.BytesOut, t.BytesIn, t.durationUS); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Prune deletes log entries older than retention and aggregates older than
// AggregateRetention.
func (s *Store) Prune(ctx context.Context, now time.Time, retention time.Duration) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM access_log WHERE ts < ?`, now.Add(-retention).UnixMilli()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM access_minutely WHERE minute < ?`, now.Add(-AggregateRetention).Unix())
	return err
}

// where builds the SQL condition for a filter on access_log.
func (f Filter) where() (string, []any, error) {
	var conds []string
	var args []any
	if f.Host != "" {
		conds, args = append(conds, "host = ?"), append(args, strings.ToLower(f.Host))
	}
	lo, hi, err := f.statusRange()
	if err != nil {
		return "", nil, err
	}
	if lo != 0 {
		conds, args = append(conds, "status BETWEEN ? AND ?"), append(args, lo, hi)
	}
	if !f.Since.IsZero() {
		conds, args = append(conds, "ts >= ?"), append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		conds, args = append(conds, "ts < ?"), append(args, f.Until.UnixMilli())
	}
	if f.Path != "" {
		conds, args = append(conds, "substr(path, 1, ?) = ?"), append(args, len(f.Path), f.Path)
	}
	if f.ClientIP != "" {
		conds, args = append(conds, "client_ip = ?"), append(args, f.ClientIP)
	}
	if f.Method != "" {
		conds, args = append(conds, "method = ?"), append(args, strings.ToUpper(f.Method))
	}
	if len(conds) == 0 {
		return "", nil, nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args, nil
}

// Query returns matching entries, newest first (at most f.Limit, default 100).
func (s *Store) Query(ctx context.Context, f Filter) ([]Entry, error) {
	w, args, err := f.where()
	if err != nil {
		return nil, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ts, host, method, path, proto, status, bytes, bytes_in, duration_us, client_ip, ua
		FROM access_log`+w+` ORDER BY ts DESC, id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts, dur int64
		if err := rows.Scan(&ts, &e.Host, &e.Method, &e.Path, &e.Proto, &e.Status, &e.Bytes, &e.BytesIn, &dur, &e.ClientIP, &e.UA); err != nil {
			return nil, err
		}
		e.Time = time.UnixMilli(ts)
		e.Duration = time.Duration(dur) * time.Microsecond
		out = append(out, e)
	}
	return out, rows.Err()
}

// Totals are request counters over some period.
type Totals struct {
	Requests int64 `json:"requests"`
	// Status[1..5] count 1xx..5xx responses (Status[0] is unused).
	Status     [6]int64      `json:"status"`
	BytesOut   int64         `json:"bytes_out"`
	BytesIn    int64         `json:"bytes_in"`
	AvgLatency time.Duration `json:"avg_latency_ns"`
	durationUS int64
}

func (t *Totals) add(e Entry) {
	t.Requests++
	t.Status[e.StatusClass()]++
	t.BytesOut += e.Bytes
	t.BytesIn += e.BytesIn
	t.durationUS += e.Duration.Microseconds()
}

func (t *Totals) merge(o Totals) {
	t.Requests += o.Requests
	for i := range t.Status {
		t.Status[i] += o.Status[i]
	}
	t.BytesOut += o.BytesOut
	t.BytesIn += o.BytesIn
	t.durationUS += o.durationUS
	t.finish()
}

func (t *Totals) finish() {
	if t.Requests > 0 {
		t.AvgLatency = time.Duration(t.durationUS/t.Requests) * time.Microsecond
	}
}

// StatsQuery selects aggregates. Step is the series resolution (default:
// chosen so the series has at most ~120 points, minimum 1 minute).
type StatsQuery struct {
	Since time.Time
	Until time.Time
	Host  string
	Step  time.Duration
}

type HostStats struct {
	Host string `json:"host"`
	Totals
}

type Point struct {
	Time time.Time `json:"time"`
	Totals
}

// Stats is traffic over a period from the per-minute aggregates.
type Stats struct {
	Since  time.Time   `json:"since"`
	Until  time.Time   `json:"until"`
	Step   Duration    `json:"step"`
	Totals Totals      `json:"totals"`
	Hosts  []HostStats `json:"hosts"` // busiest first
	Series []Point     `json:"series"`
}

// Duration marshals as a Go duration string.
type Duration time.Duration

func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	*d = Duration(v)
	return err
}

// Stats returns totals, per-host totals and a time series.
func (s *Store) Stats(ctx context.Context, q StatsQuery) (*Stats, error) {
	if q.Until.IsZero() {
		q.Until = time.Now()
	}
	if q.Since.IsZero() {
		q.Since = q.Until.Add(-time.Hour)
	}
	step := q.Step
	if step <= 0 {
		step = q.Until.Sub(q.Since) / 120
	}
	step = max(step.Truncate(time.Minute), time.Minute)

	cond := "minute >= ? AND minute < ?"
	args := []any{q.Since.Unix() / 60 * 60, q.Until.Unix()}
	if q.Host != "" {
		cond += " AND host = ?"
		args = append(args, strings.ToLower(q.Host))
	}
	rows, err := s.db.QueryContext(ctx, `SELECT minute, host, requests, s1xx, s2xx, s3xx, s4xx, s5xx, bytes_out, bytes_in, duration_us
		FROM access_minutely WHERE `+cond+` ORDER BY minute`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	st := &Stats{Since: q.Since, Until: q.Until, Step: Duration(step)}
	hosts := map[string]*HostStats{}
	var series []Point
	stepS := int64(step / time.Second)
	for rows.Next() {
		var minute int64
		var host string
		var t Totals
		if err := rows.Scan(&minute, &host, &t.Requests, &t.Status[1], &t.Status[2], &t.Status[3], &t.Status[4], &t.Status[5],
			&t.BytesOut, &t.BytesIn, &t.durationUS); err != nil {
			return nil, err
		}
		st.Totals.merge(t)
		h := hosts[host]
		if h == nil {
			h = &HostStats{Host: host}
			hosts[host] = h
		}
		h.merge(t)
		bucket := time.Unix(minute/stepS*stepS, 0)
		if n := len(series); n == 0 || !series[n-1].Time.Equal(bucket) {
			series = append(series, Point{Time: bucket})
		}
		series[len(series)-1].merge(t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, h := range hosts {
		st.Hosts = append(st.Hosts, *h)
	}
	sortHosts(st.Hosts)
	st.Series = series
	return st, nil
}

// Count is one row of a top-N query.
type Count struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// Top fields.
const (
	TopPath     = "path"
	TopClientIP = "client_ip"
	TopHost     = "host"
	TopStatus   = "status"
	TopUA       = "ua"
)

// Top returns the n most frequent values of field among entries matching f.
func (s *Store) Top(ctx context.Context, f Filter, field string, n int) ([]Count, error) {
	switch field {
	case TopPath, TopClientIP, TopHost, TopStatus, TopUA:
	default:
		return nil, fmt.Errorf("unknown field %q", field)
	}
	w, args, err := f.where()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT CAST(`+field+` AS TEXT), COUNT(*) AS c FROM access_log`+w+
		` GROUP BY 1 ORDER BY c DESC, 1 LIMIT ?`, append(args, n)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Value, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
