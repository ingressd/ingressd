# Access: sign-in providers and header tokens

Besides the emailed one-time code, ingressd Access can sign users in with
**Discord**, **Google**, **Microsoft** (personal accounts and Entra ID) and
**Steam**, let specific people in with **passkeys** (central portal), and
let machines in with **header tokens**. This page explains
how each works, which policy selectors it adds, and exactly how to register
an app with each provider.

- Node config: `access.providers.<name>` (this node's own portal),
  `apps.<app>.login_methods`, the selectors below, and
  `service_tokens.<name>.header`.
- Managed nodes on the panel's central portal: providers are set up per
  organisation in the panel (Access → Sign-in providers), which shows the
  redirect URI to register; policies and header tokens are edited there too.
- Shared code: `pkg/access/idp` (the providers), `pkg/access` (engine and
  tokens), `edge/modules/edgeauth` (per-request checks).

## How a provider sign-in works

1. A visitor without a session opens a protected app; `edge_auth` sends them
   to the portal (`/login?app=&rd=&n=`; `n` binds the sign-in to the browser,
   see DESIGN §7.2).
2. The login page shows a **Continue with …** button for each of the app's
   `login_methods` (default `[email]`), plus the email form when `email` is
   one of them. A button is a same-origin **POST** to `/oauth/start`
   (cross-site posts are rejected, and `rd` is checked against the app's
   hosts exactly as for email).
3. The portal creates a random `state`, a PKCE verifier (S256) and, for
   OpenID Connect, a `nonce`, seals them with the target into a short-lived
   cookie (`__edge_idp`: PASETO v4.local under a key derived from the
   session key, `Path=/oauth/`, `HttpOnly; Secure; SameSite=Lax`, 10 minutes)
   and redirects to the provider. Only the scopes the policies need are
   requested.
4. The provider redirects to `/oauth/<provider>/callback`. The portal
   consumes the cookie (single use) and verifies:
   - `state` matches the cookie (constant-time), the code is redeemed with
     the PKCE verifier and the client secret;
   - Google/Microsoft: the ID token's RS256 signature against the provider's
     JWKS (cached for an hour; an unknown `kid` refetches at most every 30 s),
     `iss` (Microsoft: the issuer of the token's own tenant), `aud` = client
     ID (and `azp`), `exp`/`iat` (2 minutes skew), `nonce`;
   - Steam: see below.
5. The facts the policies refer to (and nothing else) are stored in the
   portal session and the callback code; the app's policies are evaluated
   for them plus the visitor's address, exactly as for an emailed code, and
   the node that redeems the code evaluates them again.
6. `edge_auth` re-checks every policy on every request: network selectors
   (`ip`, `country`) against the request, identity selectors against the
   facts in the (encrypted, authenticated) app cookie, plus the grant for
   the policy's current version.

**Emails** only count when the provider says they are verified. They then
satisfy the existing `email`, `email_domain` and `group` selectors, whichever
method proved them (add `login_method` to a policy to require a particular
one). A sign-in that proves no email (Steam, an unverified Discord or Google
address, an Entra address without a verified domain) has a user ID of the
form `steam:76561198…`, `discord:<id>`, `google:<sub>` or
`microsoft:<tenant>/<object id>`: origins receive it in `X-Edge-User` and as
the JWT `sub`; `X-Edge-User-Email` is only sent for addresses.

### When membership changes take effect

Guild, role, group, tenant and owned-game facts are read **once, at
sign-in**, and kept for the session. A user removed from a Discord role (or
a Steam group, an Entra group…) keeps access until their session ends:

- the portal session lasts `access.session` (default 24h), or less with
  `access.providers.<name>.session`; signing in to another app of the org
  reuses it;
- app cookies last at most the matching policy's `session` (default 24h)
  and never outlive the portal session.

For membership-based policies, set a short `session` on the provider (for
example `session: 4h`) or on the policy. To cut someone off at once, revoke
their sessions (`ingressd sessions revoke`, or the panel). Network selectors
(`ip`, `country`) are never cached: they are checked on every request.

`exclude` rules on provider facts are only as good as what the provider
shows: a Steam profile with private details has no groups or games, so it
is never excluded by `steam_group`/`steam_app`. Prefer `include`/`require`
for those.

## Selectors

| Selector | Matches | Provider data |
|---|---|---|
| `login_method: [email, discord, google, microsoft, steam, passkey]` | how the user signed in | — |
| `email`, `email_domain`, `group` | verified email (any method) | Discord `verified`, Google `email_verified`, Microsoft see below |
| `discord_user: ["<user ID>"]` | Discord user ID | `identify` |
| `discord_username: [name]` | Discord username (lowercase; users can change it, prefer IDs) | `identify` |
| `discord_guild: ["<server ID>"]` | member of the server | `guilds` |
| `discord_role: ["<server ID>/<role ID>"]` | has the role in the server | `guilds.members.read` |
| `google_hd: [example.com]` | Google Workspace account of the domain (`hd` claim) | ID token |
| `microsoft_tenant: ["<tenant ID>"]` | account of the tenant (`tid`) | ID token |
| `microsoft_group: ["<group object ID>"]` | Entra group member (`groups` claim) | ID token, app config |
| `microsoft_role: [Value]` | assigned app role (`roles` claim) | ID token, app config |
| `steam_id: ["7656119…"]` | SteamID64 | OpenID |
| `steam_group: ["<groupID64>"]` | Steam group member (public profiles) | Web API key |
| `steam_app: ["440"]` | owns the app (public game details) | Web API key |
| `passkey: [jacks-iphone]` | signed in with one of these passkeys (see Passkeys) | central portal |

IDs are quoted strings in YAML (they exceed JavaScript's safe integers). In
Discord, enable *Settings → Advanced → Developer Mode*, then right-click a
server, role or user → *Copy ID*. `bypass` and `service_auth` policies cannot
use identity selectors (nobody signs in).

Example:

```yaml
access:
  portal_host: auth.example.com
  providers:
    discord: { client_id: "1300000000000000000", client_secret: secret://discord_client_secret, session: 4h }
    steam: { api_key: secret://steam_api_key }
policies:
  mods:
    action: allow
    include: [{ discord_role: ["1100000000000000000/1200000000000000000"] }]
  gamers:
    action: allow
    include: [{ steam_app: ["440"] }]
    require: [{ login_method: [steam] }, { country: [GB, IE] }]
apps:
  wiki:
    hosts: [wiki.example.com]
    origin: http://192.168.0.21:3000
    access: [mods, gamers]
    login_methods: [discord, steam]
```

`ingressd config validate` warns when an app's policies use a provider's
selectors but the app does not offer that provider.

## Registering the app with each provider

The **redirect URI** is `https://<portal>/oauth/<provider>/callback`, where
`<portal>` is `access.portal_host` (for example
`https://auth.example.com/oauth/discord/callback`). On the panel's central
portal it is `https://<auth URL>/a/<org ID>/oauth/<provider>/callback`; the
panel shows the exact value on the provider's settings card. Store client
secrets and keys as secrets (`ingressd secret set discord_client_secret`),
never in `config.yaml`.

### Discord

1. <https://discord.com/developers/applications> → **New Application**.
2. **OAuth2** → copy the **Client ID**; **Reset Secret** → copy the
   **Client Secret**.
3. **OAuth2 → Redirects** → **Add Redirect**: the redirect URI above.
   Save.
4. Nothing else: no bot and no privileged intents are needed. The portal
   asks for `identify email`, plus `guilds` when a policy uses
   `discord_guild` and `guilds.members.read` when one uses `discord_role`
   (one API call per server named in a `discord_role` selector).
5. Config: `access.providers.discord: { client_id: "<id>", client_secret:
   secret://discord_client_secret }`.

### Google

1. <https://console.cloud.google.com/> → create or pick a project.
2. **APIs & Services → OAuth consent screen** (Google Auth Platform →
   Branding / Audience): user type **External** (or **Internal** to allow
   only your Workspace); add the app name and support email; scopes
   `openid`, `.../auth/userinfo.email`, `.../auth/userinfo.profile` (all
   non-sensitive, no verification needed). While the app is in *Testing*,
   only listed test users can sign in: **Publish** it for everyone.
3. **Credentials → Create credentials → OAuth client ID** → type **Web
   application** → **Authorized redirect URIs**: the redirect URI above.
4. Copy the client ID and secret into `access.providers.google`.

`google_hd` uses the ID token's `hd` claim (present only for Workspace
accounts). **Google Groups are not supported**: listing a user's groups
needs the Admin SDK Directory API (admin credentials or domain-wide
delegation) or the Cloud Identity Groups API with a restricted scope that
needs Google verification and a Workspace Enterprise edition — neither works
with a plain sign-in. Use `google_hd`, `email_domain` or `group` instead.

### Microsoft (personal accounts and Entra ID)

1. <https://entra.microsoft.com/> → **Identity → Applications → App
   registrations → New registration** (a personal Microsoft account can use
   the Azure portal's default directory).
2. **Supported account types**: *Accounts in any organizational directory
   and personal Microsoft accounts* for `tenant: common` (the default);
   *any organizational directory* for `organizations`; *personal accounts
   only* for `consumers`; *this organizational directory only* for a single
   tenant (set `tenant: <Directory (tenant) ID>`).
3. **Redirect URI**: platform **Web**, the redirect URI above.
4. **Certificates & secrets → New client secret** → copy the **Value** (it
   expires: put a reminder in your calendar). The **Application (client) ID**
   is on the Overview page.
5. **API permissions**: the default *Microsoft Graph → User.Read* is enough
   (the portal asks for `openid email profile`; no admin consent needed).
6. Optional, Entra only:
   - Groups: **Token configuration → Add groups claim** → *Security groups*
     (or *Groups assigned to the application*, which avoids the overage
     limit) → ID token: *Group ID*. Use the groups' **Object IDs** in
     `microsoft_group`. If a user is in more than ~200 groups, Entra omits
     the list from the token; the sign-in then fails with an explanation
     when a policy uses `microsoft_group` (it does not silently skip them).
   - App roles: **App roles → Create app role** (allowed member types:
     Users/Groups; *Value* e.g. `Wiki.Editor`), then **Enterprise
     applications → your app → Users and groups → Add assignment**. Use the
     *Value* in `microsoft_role`.
   - Verified email: Entra lets tenant admins set any address as a user's
     email, so an Entra email only counts as verified when Microsoft marks
     the domain as verified by the tenant: **Token configuration → Add
     optional claim → ID → `xms_edov`** (and `email`). Without it Entra users
     have no email for `email`/`email_domain` selectors; use
     `microsoft_tenant`, `microsoft_group` or `microsoft_role`. Personal
     Microsoft accounts' emails are verified by Microsoft.
7. Config: `access.providers.microsoft: { client_id: <id>, client_secret:
   secret://microsoft_client_secret, tenant: common }`.

### Steam

Steam uses **OpenID 2.0**, not OAuth: there is nothing to register and no
client secret. The portal sends the user to `steamcommunity.com`, then
checks that the assertion's `openid.return_to` is exactly this sign-in's
callback (which carries the flow's `state`), that `op_endpoint` is Steam's,
that `claimed_id` is `https://steamcommunity.com/openid/id/<SteamID64>`, that
the signature covers those fields, and asks Steam to confirm it
(`check_authentication`); a response nonce is accepted once.

Steam gives no email: Steam users are `steam:<SteamID64>` and need
`steam_id`, `steam_group`, `steam_app` or `login_method` selectors.

Group and game selectors need a **Steam Web API key**: sign in at
<https://steamcommunity.com/dev/apikey>, enter your portal's domain, accept
the terms and copy the key; store it as a secret and set
`access.providers.steam.api_key`. The key is sent in the `x-webapi-key`
header, never in a URL. Facts come from `ISteamUser/GetUserGroupList` and
`IPlayerService/GetOwnedGames` (only the app IDs named in policies are
checked) and exist only when the user's profile and game details are public
(Steam → Edit Profile → Privacy Settings). Group IDs: use the groupID64
(open `https://steamcommunity.com/groups/<name>/memberslistxml/?xml=1` and
copy `<groupID64>`); the short 32-bit ID is accepted too.

## Passkeys

Passkeys let an organisation allow a fixed list of people (or devices) into
an app, for example Plex for the family, without email codes or a
third-party account. They are offered by the panel's **central portal**
only (`access.portal_url`): it holds the organisation's passkeys and runs
the WebAuthn ceremony; nodes only redeem its callback codes.

1. In the panel, *Access → Sign-in methods → Passkeys → New passkey*, name
   it ("Jack's iPhone"). The panel shows a one-time enrollment link
   (`<auth-url>/a/<org>/passkey/enroll?t=…`, valid 7 days). Whoever opens it
   creates the passkey on their phone, computer, security key or password
   manager. The relying party is the portal's host (e.g.
   `auth.ingressd.com`).
2. Allow it in a policy with a *Passkeys* rule. In node config this is the
   `passkey` selector with the passkey's name (its slug, which never
   changes; renaming in the panel only changes the label):

   ```yaml
   policies:
     family:
       action: allow
       include: [{ passkey: [jacks-iphone, mums-ipad] }]
   apps:
     plex:
       hosts: [plex.example.com]
       access: [family]
       login_methods: [passkey]           # or [email, passkey]
   ```
3. Turn on *Passkey* in the app's sign-in methods. The login page shows
   *Sign in with a passkey*; it is a discoverable sign-in (no name to type).

- The session user is `passkey:<name>` (origins get it in `X-Edge-User`)
  and the session carries the fact `passkey:<name>`; `email` selectors never
  match a passkey sign-in.
- *New link* on an active passkey replaces it (a new device): the old one
  works until the new one is created. Deleting a passkey (only when no
  policy uses it) signs it out everywhere: the panel adds
  `access.revoked_before["passkey:<name>"]`.
- Nodes with their own portal (`portal_host`) reject the `passkey` login
  method and selector.

## Header tokens

A header token lets a bot or script past the login with a secret in a
header of your choice:

```yaml
service_tokens:
  deploy-bot:
    header: X-Deploy-Token
    client_secret: secret://deploy_bot_token   # ingressd secret set deploy_bot_token
    expires: 2027-06-30                        # optional
policies:
  deploy-bot:
    action: service_auth
    include: [{ service_token: deploy-bot }]
    require: [{ ip: [198.51.100.0/24] }]      # optional: AND from this network
apps:
  wiki:
    access: [deploy-bot, staff]                # first match wins
```

```sh
curl -H "X-Deploy-Token: $TOKEN" https://wiki.example.com/api/…
```

- They extend service tokens (`Edge-Client-Id`/`Edge-Client-Secret` pairs
  keep working): same `service_token` selector, `service_auth` action,
  expiry and combination with `ip` (and `country`) in `require`/`exclude`.
- The secret lives in the secrets store (`secrets.age`; on managed nodes it
  is delivered encrypted to each node) and must be at least 16 characters.
  `edge_auth` gets only an HMAC-SHA256 verifier under a key derived from the
  session key and compares in constant time, on every request.
- The header is removed from **every** request before it reaches the
  origin, valid or not. A request with a wrong or expired value gets 401.
  Origins see `X-Edge-Service-Token: <name>` and a JWT with
  `sub = service-token:<name>`.
- Reserved headers cannot be used (`Authorization`-style names are fine;
  `Cookie`, `Host`, `X-Forwarded-*`, `X-Edge-*`, `Edge-*`, `Content-*`,
  `Sec-*`, `Cf-*`, hop-by-hop headers and similar are refused).

## Compatibility

Every field on this page is new; older nodes refuse a config that has any
of them. Nodes that support them advertise the `access-identity` capability
(`pkg/nodeproto`), and the panel refuses to send such a config to a node
without it (the change is rejected with a message naming the node; update
the node first). Configs without the new fields are unchanged, and existing
policies keep their versions (nobody is signed out by the upgrade).

Passkeys (the `passkey` login method and selector, and `passkey:<name>`
keys in `access.revoked_before`) need the `access-passkey` capability; the
panel refuses them for older nodes the same way and leaves passkey
revocations out of their configs.
