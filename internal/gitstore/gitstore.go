// SPDX-License-Identifier: Apache-2.0

// Package gitstore versions the config directory with git: every applied
// change is a commit, so history, diff and rollback come for free.
package gitstore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Repo struct{ Dir string }

type Entry struct {
	Rev     string
	Author  string
	Time    time.Time
	Subject string
}

func (r Repo) git(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", r.Dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// Init creates the repository if needed. It is safe to call repeatedly.
func (r Repo) Init() error {
	if _, err := os.Stat(filepath.Join(r.Dir, ".git")); err == nil {
		return nil
	}
	if err := os.MkdirAll(r.Dir, 0o750); err != nil {
		return err
	}
	if _, err := r.git("init", "-q", "-b", "main"); err != nil {
		return err
	}
	if _, err := r.git("config", "user.name", "ingressd"); err != nil {
		return err
	}
	_, err := r.git("config", "user.email", "ingressd@localhost")
	return err
}

// Commit stages paths and commits them. It returns the new revision, or ""
// if nothing changed. author may be "Name" or "Name <email>".
func (r Repo) Commit(author, msg string, paths ...string) (string, error) {
	if _, err := r.git(append([]string{"add", "--"}, paths...)...); err != nil {
		return "", err
	}
	if _, err := r.git("diff", "--cached", "--quiet"); err == nil {
		return "", nil
	}
	if author == "" {
		author = "ingressd"
	}
	if !strings.Contains(author, "<") {
		author = fmt.Sprintf("%s <%s@ingressd.local>", author, strings.ReplaceAll(strings.ToLower(author), " ", "."))
	}
	if _, err := r.git("commit", "-q", "--author", author, "-m", msg); err != nil {
		return "", err
	}
	return r.Head()
}

func (r Repo) Head() (string, error) {
	out, err := r.git("rev-parse", "HEAD")
	return strings.TrimSpace(out), err
}

// Log returns up to n most recent commits, newest first.
func (r Repo) Log(n int) ([]Entry, error) {
	out, err := r.git("log", fmt.Sprintf("-n%d", n), "--format=%H%x1f%an%x1f%aI%x1f%s")
	if err != nil {
		if strings.Contains(err.Error(), "does not have any commits") {
			return nil, nil
		}
		return nil, err
	}
	var entries []Entry
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\x1f")
		if len(f) != 4 {
			continue
		}
		t, _ := time.Parse(time.RFC3339, f[2])
		entries = append(entries, Entry{Rev: f[0], Author: f[1], Time: t, Subject: f[3]})
	}
	return entries, nil
}

// Show returns the content of path at rev.
func (r Repo) Show(rev, path string) ([]byte, error) {
	if strings.HasPrefix(rev, "-") {
		return nil, errors.New("invalid revision")
	}
	out, err := r.git("show", rev+":"+path)
	return []byte(out), err
}

// Diff returns a unified diff of path between two revisions.
func (r Repo) Diff(from, to, path string) (string, error) {
	if strings.HasPrefix(from, "-") || strings.HasPrefix(to, "-") {
		return "", errors.New("invalid revision")
	}
	return r.git("diff", from, to, "--", path)
}
