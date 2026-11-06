// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/mail"
	"strings"
)

// Admin roles, most to least privileged (PLAN §8.1).
const (
	RoleOwner    = "owner"
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// Roles lists the admin roles from most to least privileged.
var Roles = []string{RoleOwner, RoleAdmin, RoleOperator, RoleViewer}

// RoleRank orders roles: owner 4 … viewer 1; unknown roles are 0.
func RoleRank(role string) int {
	for i, r := range Roles {
		if r == role {
			return len(Roles) - i
		}
	}
	return 0
}

// AdminUser was a user of the local control panel (POC Phase 2). Rev1
// removed the local admin UI/API; the section is still parsed and validated
// so older configs keep loading, but nothing on the node uses it.
// Credentials (password hash, TOTP seed,
// passkeys) live in secrets.age, never in config.yaml.
type AdminUser struct {
	Name  string      `yaml:"name" json:"name"`
	Email string      `yaml:"email" json:"email"`
	Role  string      `yaml:"role" json:"role"`
	Scope *AdminScope `yaml:"scope,omitempty" json:"scope"`
}

// AdminScope limits an admin to named objects. A nil scope means
// everything; within a scope, a kind without a list grants nothing.
type AdminScope struct {
	Apps    []string `yaml:"apps,omitempty" json:"apps"`
	Pools   []string `yaml:"pools,omitempty" json:"pools"`
	Tunnels []string `yaml:"tunnels,omitempty" json:"tunnels"`
	L4      []string `yaml:"l4,omitempty" json:"l4"`
}

// Kinds maps each scoped config section to its allowed names.
func (s *AdminScope) Kinds() map[string][]string {
	return map[string][]string{"apps": s.Apps, "pools": s.Pools, "tunnels": s.Tunnels, "l4": s.L4}
}

// Admin returns the admin with the given email (case-insensitive).
func (c *Config) Admin(email string) (AdminUser, bool) {
	for _, a := range c.Admins {
		if strings.EqualFold(a.Email, email) {
			return a, true
		}
	}
	return AdminUser{}, false
}

// HasOwner reports whether at least one owner is configured.
func (c *Config) HasOwner() bool {
	for _, a := range c.Admins {
		if a.Role == RoleOwner {
			return true
		}
	}
	return false
}

func (c *Config) validateAdmins(v *validator) {
	seen := map[string]bool{}
	owners := 0
	for i, a := range c.Admins {
		p := fmt.Sprintf("admins[%d]", i)
		if strings.TrimSpace(a.Name) == "" {
			v.add(p+".name", "is required")
		}
		if addr, err := mail.ParseAddress(a.Email); err != nil || addr.Address != a.Email || !strings.Contains(a.Email, "@") {
			v.add(p+".email", "invalid email address %q", a.Email)
		} else if k := strings.ToLower(a.Email); seen[k] {
			v.add(p+".email", "duplicate admin %q", a.Email)
		} else {
			seen[k] = true
		}
		if RoleRank(a.Role) == 0 {
			v.add(p+".role", "must be one of owner, admin, operator, viewer; got %q", a.Role)
		}
		if a.Role == RoleOwner {
			owners++
		}
		if s := a.Scope; s != nil {
			if a.Role == RoleOwner {
				v.add(p+".scope", "owners cannot be scoped")
			}
			for kind, names := range s.Kinds() {
				for j, n := range names {
					if !qualifiedNameRe.MatchString(n) {
						v.add(fmt.Sprintf("%s.scope.%s[%d]", p, kind, j), "invalid name %q", n)
					}
				}
			}
		}
	}
	// No admins at all is the bootstrap state (first owner via setup token).
	if len(c.Admins) > 0 && owners == 0 {
		v.add("admins", "at least one owner is required")
	}
}
