# Shared certificate storage (managed nodes)

Applies to managed nodes that share sites across several nodes (multi-PoP).

Several nodes serving the same hostname must not each run ACME: they would hit duplicate-certificate rate limits, and an HTTP-01 challenge for node A can land on node B. Managed nodes therefore keep Caddy's certmagic storage **in the panel**, shared by every node of the org. One node obtains a certificate; every node loads it and can answer the challenge, because certmagic's distributed solving keeps challenge data and locks in the same storage.

Standalone nodes (no `node.json`) are unchanged: Caddy uses `file_system` storage in `<state-dir>/caddy`.

## Pieces

```
Caddy (ingressd-edge)                   ingressd serve                         panel
caddy.storage.ingressd  ──HTTP/unix──▶  storage relay  ──WebSocket──────────▶  nodehub storage handler
  edge/modules/edgestorage              /run/ingressd/storage.sock             cert_storage / cert_locks
  write-through cache_dir               internal/storagerelay                  (Postgres, sealed values)
                                        nodeagent.Storage
                                        storage_request ─▶ ◀─ storage_response
```

- **Render** (`internal/render/storage.go`): with `Options.StorageSocket` set (serve sets it while `node.json` exists) Caddy's top-level storage is
  `{"module":"ingressd","socket":"/run/ingressd/storage.sock","cache_dir":"/var/lib/ingressd/caddy","local_prefixes":["pki"]}`; otherwise `{"module":"file_system","root":"/var/lib/ingressd/caddy"}`. Enrolling while serve runs switches the option before the panel's first snapshot is applied; detaching switches back before `config.yaml` is re-applied.
- **Edge module** `caddy.storage.ingressd` (`edge/modules/edgestorage`): implements `certmagic.Storage` and `certmagic.TryLocker`. Fields: `socket` (required), `cache_dir`, `local_prefixes` (default `["pki"]`).
- **Relay** (`internal/storagerelay`): `POST /v1/storage` on `storage.sock` (mode 0660, group `ingressd`, like the control socket) with a JSON `nodeproto.StorageRequest`; answers `200` with the panel's `nodeproto.StorageResponse`, or `503` when the panel cannot be asked (standalone, agent offline, first-use upload still running, request timeout 20 s).
- **Protocol** (`pkg/nodeproto/storage.go`): `storage_request` (node → panel) `{op, key, value, recursive, name, owner}` with `op` one of `load store delete exists list stat lock unlock`; `storage_response` (panel → node, envelope `id` echoes the request) `{not_exist, error, value, exists, keys, info, acquired}`. Values are bytes (base64 in JSON). List/stat semantics follow certmagic's file storage exactly (`nodeproto.StorageListKeys`): `list` returns full keys strictly below the prefix, direct children (files and "directories") or, recursively, every descendant including intermediate directories; a prefix with nothing below it that is not itself a key is `not_exist`. `delete` removes the key and everything below it.

## Locks

`lock` is a non-blocking try: it takes the lock, or renews it when the same owner already holds it, for `nodeproto.StorageLockTTL` (2 minutes); an expired lease is taken over. The module generates a random owner token per acquisition (the panel prefixes it with the node id, so one node can never renew or release another node's lock), polls once a second while waiting (`Lock`), tries once for `TryLock`, and renews held locks every 30 s until `Unlock`. Held locks are tracked process-wide, so an `Unlock` after a Caddy config reload still finds its token. If a renewal is refused (the lease expired and another node took it) the module logs an error and stops renewing.

## Failure behaviour

| Situation | Reads (`Load`, `Exists`, `List`, `Stat`) | Writes (`Store`, `Delete`) | Locks |
|---|---|---|---|
| Panel reachable | panel; every successful `Load` and `Store` is written through to `cache_dir` | panel, then cache | panel |
| Panel offline, serve down, or first-use upload running (`503` / dial error) | **from `cache_dir`** (warning logged at most once a minute) | **fail** (`ErrUnavailable`) | **fail** |
| Panel answers an error (quota, invalid key) | error | error | error |

So a node keeps serving every certificate it has while the panel is unreachable, but issues and renews nothing: certmagic retries later, and no node ever holds a certificate the others cannot see. Certificates are valid for 90 days and renewed with 30 days left, so outages of days are harmless. A `not_exist` answer does **not** delete the cached copy (a wiped panel database must not make nodes drop their certificates); the stale copy is only ever read during an outage.

`local_prefixes` keys (`pki/…`: Caddy's internal CA, which signs the bare-IP machine certificate and is reported to the panel and pinned by connectors) never leave the node; they are read and written in `cache_dir` only, exactly where `file_system` storage kept them.

## Migration from file_system (first managed start)

`cache_dir` is the old `file_system` root, so everything Caddy stored before stays readable through the cache. On top of that the relay uploads it once:

1. When managed mode starts, the relay gets the agent as its backend and walks `<state-dir>/caddy`, skipping `locks/`, `local_prefixes`, dot files and files over 1 MiB.
2. Every key the panel does not have yet is stored (`exists` then `store`); keys the panel already has are left alone, because another node of the org may have shared a newer certificate for the same name.
3. Until the upload has finished the relay answers `503`, so Caddy reads from the cache: certmagic never sees an empty panel and never re-issues a certificate the node already has. The upload retries every 10 s while the panel is unreachable.
4. Success is recorded in `<state-dir>/caddy-storage-uploaded` (the node id); re-enrolling as another node (another org) uploads again.

Two nodes that both had a certificate for the same name before joining keep serving their own until certmagic next loads from storage, then converge on the panel's copy; both are valid.

On **detach** the node renders `file_system` again with the same directory, which holds every certificate this node loaded or stored while managed (write-through), so it keeps serving without re-issuing.

## Panel side

`cert_storage(org_id, key, value bytea, modified, size)` and `cert_locks(org_id, name, owner, expires_at)` (panel migration `0004_cert_storage.sql`). Values are sealed with AES-256-GCM under a key derived (HKDF-SHA256, purpose `cert-storage`) from the panel master key, with `"<org id>\x00<key>"` as additional data. Every operation is scoped to the org of the node's credential. Limits: 1 MiB per value, 1024-byte keys (clean slash paths), 64 MiB plaintext per org. The fake panel (`test/fakepanel`) answers storage requests from memory (`storagerelay.Memory`, same semantics) and exposes `GET /test/storage`.
