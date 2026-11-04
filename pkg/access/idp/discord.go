// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ingressd/ingressd/pkg/config"
)

// Discord is OAuth2 without OpenID Connect: there is no ID token (so no
// nonce); the code is bound to the flow by state and PKCE, and the identity
// comes from the API with the access token.

var snowflake = regexp.MustCompile(`^[0-9]{15,21}$`)

func (p *Provider) discordFinish(ctx context.Context, redirectURI string, f Flow, code string) (*Identity, error) {
	api := strings.TrimSuffix(p.ep().DiscordAPI, "/")
	tr, err := p.exchange(ctx, api+"/oauth2/token", redirectURI, code, f.Verifier)
	if err != nil {
		return nil, err
	}
	var u struct {
		ID         string `json:"id"`
		Username   string `json:"username"`
		GlobalName string `json:"global_name"`
		Email      string `json:"email"`
		Verified   bool   `json:"verified"`
	}
	status, err := p.getJSON(ctx, api+"/users/@me", tr.AccessToken, &u)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || !snowflake.MatchString(u.ID) {
		return nil, fmt.Errorf("discord: users/@me: HTTP %d", status)
	}
	id := &Identity{Method: config.MethodDiscord, Subject: u.ID, Name: u.GlobalName}
	if id.Name == "" {
		id.Name = u.Username
	}
	if e, ok := normEmail(u.Email); ok && u.Verified {
		id.Email = e
	}
	id.Attrs = append(id.Attrs, config.Attr("discord_user", u.ID))
	if u.Username != "" {
		id.Attrs = append(id.Attrs, config.Attr("discord_username", u.Username))
	}
	if f.Wants.DiscordGuilds {
		var guilds []struct {
			ID string `json:"id"`
		}
		status, err := p.getJSON(ctx, api+"/users/@me/guilds", tr.AccessToken, &guilds)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("discord: users/@me/guilds: HTTP %d", status)
		}
		for _, g := range guilds {
			if snowflake.MatchString(g.ID) {
				id.Attrs = append(id.Attrs, config.Attr("discord_guild", g.ID))
			}
		}
	}
	for _, gid := range f.Wants.DiscordRoleGuilds {
		if !snowflake.MatchString(gid) {
			continue
		}
		var m struct {
			Roles []string `json:"roles"`
		}
		status, err := p.getJSON(ctx, api+"/users/@me/guilds/"+url.PathEscape(gid)+"/member", tr.AccessToken, &m)
		if err != nil {
			return nil, err
		}
		switch status {
		case http.StatusOK:
			id.Attrs = append(id.Attrs, config.Attr("discord_guild", gid))
			for _, r := range m.Roles {
				if snowflake.MatchString(r) {
					id.Attrs = append(id.Attrs, config.Attr("discord_role", gid+"/"+r))
				}
			}
		case http.StatusNotFound:
			// Not a member of that server: no roles there.
		default:
			// Includes 429: membership is unknown, so the sign-in fails
			// rather than skipping a role a policy may exclude.
			return nil, fmt.Errorf("discord: guild member: HTTP %d", status)
		}
	}
	return id, nil
}
