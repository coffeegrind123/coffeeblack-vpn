# Security

- [Threat model](#threat-model)
- [Peer private keys](#peer-private-keys)
- [Secret encryption at rest](#secret-encryption-at-rest)
- [Generated config files](#generated-config-files)
- [Privilege separation](#privilege-separation)
- [Activity history and privacy](#activity-history-and-privacy)
- [Reporting a vulnerability](#reporting-a-vulnerability)

---

## Threat model

**Authentication.** Argon2id password hashes, server-side session table held in memory,
optional RFC 6238 TOTP. Session cookies are `SameSite=Strict`, `HttpOnly`, and `Secure`
unless `INSECURE=true`. Login is rate-limited per username (10/min) *and* per source IP
(50/min), with a separate 5-per-5-minutes limit on TOTP attempts. The username-not-found
path is constant-time, so there is no account enumeration by timing.

**CSRF.** Relies on the `SameSite=Strict` cookie plus JSON-only request bodies. A JSON
content type forces a CORS preflight that a cross-site form submit cannot satisfy.

**CSP.** `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'
'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none';
frame-ancestors 'none'`. The two `'unsafe-inline'` allowances are required by inline
`onclick=` handlers in the embedded SPA.

**Authorization.** Role 0 is a client: it sees only its own peers and cannot edit IPs,
`AllowedIPs`, DNS, MTU, AmneziaWG parameters or the server endpoint of any client. Role 1
is admin. IDOR enforcement is applied at the handler, not the query.

**Command execution.** Every shell-out to `awg`, `awg-quick` and `nft` uses argv-style
`Command::new(…).args(…)`. There is no `bash -c` with tainted arguments anywhere.
nftables transactions are piped to `nft -f -` over stdin — still argv-only — so a peer
name containing quotes, backticks or shell metacharacters can never escape into command
interpretation. Interface names are validated against `[A-Za-z0-9_-]{1,15}` before any
command call.

**Metrics.** Only the SHA-256 of `metricsPassword` is stored, never the cleartext, and
endpoints compare in constant time.

**Two things worth stating rather than burying.** The HTTP server is hand-written and is
the most exposed code in the project; it is strict by construction and covered by
wire-level tests, but it is a hand-written parser on an internet-facing port and should be
read as such — keep a reverse proxy in front of it. And the
[DPI-imitation proxy](TRANSPORTS.md#detection-trade-off) is mimicry, not cryptography;
against an adversary fingerprinting this specific tool it can *increase* detectability.

---

## Peer private keys

Upstream `wg-easy` — and this project, before — generates each peer's keypair server-side
and keeps the **private** key in the database forever so the config and QR can be
re-displayed on demand. That is convenient, and it is the single worst thing a compromise
of this box can yield: whoever reaches the database, or any backup of it, can impersonate
every peer.

The load-bearing fact is that the keys never needed to be there. `generate_server_peer`
uses only `public_key` and `pre_shared_key`: **the server does not need a peer's private
key once the config has been rendered.** Keeping it buys re-display and nothing else.

### Modes

Instance-wide, set in Admin → General:

| Mode | Behaviour |
|---|---|
| **`never`** (default) | The keypair is generated, the config and QR are returned **once** in the create response, and only the public key is stored. `GET /configuration`, `/qrcode.svg` and `generateOneTimeLink` answer **409** afterwards. Recovery from a lost config is rotation, exactly like a lost API key. |
| **`plaintext`** | The private key is stored so the config can be re-rendered on demand. Upstream-equivalent behaviour. The admin console shows a permanent banner naming the exposure. |

It is instance-wide rather than per-peer on purpose: a per-peer toggle makes "does this
server hold key material?" unanswerable without auditing every row, when it should have
exactly one answer for the whole box.

**Switching to `never` purges the keys already stored.** Otherwise the setting would
describe an intention rather than a fact, with every peer created before the switch
keeping its key on disk while the UI claimed otherwise. The admin form names how many
peers are affected and confirms first. Their tunnels keep working; only re-display is lost.

### Bring your own key

Pass `publicKey` when creating a peer — generated on the device with
`wg genkey | wg pubkey` — and the server never sees the private half **at all**, in any
retention mode. There is nothing to leak, nothing to purge, and no window in which key
material exists off the device. The create form accepts it in the *Device public key*
field. This is the strongest option.

### Rotation

`POST /api/client/:id/rotateKey` issues a fresh keypair, returns the new config once, and
invalidates the old public key at the next interface reload. It is both the recovery path
for a lost config and the revocation path for a compromised device, and it drops any
outstanding one-time link, which would otherwise serve a config that can no longer connect.

### What this does not fix

Pre-shared keys, Xray UUIDs and short IDs, MTProxy secrets and the MasterDnsVPN encryption
key are **symmetric or server-verified** — the server needs them on every handshake, so
they cannot be issued and forgotten the way an asymmetric private key can. They remain in
the database and a compromise still yields them. This removes peer private keys from the
blast radius; it does not empty it.

Note also that WireGuard's forward secrecy means static keys never decrypt *previously
recorded* traffic. What a stolen server key does buy an adversary is impersonation, active
MITM, and — because the initiator's static public key in handshake message 1 is encrypted
only to the responder's static key — the ability to identify which peer initiated each
recorded handshake, and when.

---

## Secret encryption at rest

Every credential the service stores is encrypted at rest. They were previously plaintext
columns: peer private and pre-shared keys, the server's own WireGuard key, the Reality
private key, every VLESS UUID and shortId, MTProxy user secrets, the DNS-tunnel key, and
TOTP seeds. Anyone holding the database file — or a backup, or a snapshot — held all of
them.

TOTP was the worst of the set. A second factor is meant to survive a password compromise,
but a stolen database let an attacker mint valid codes forever, and unlike a password the
user gets no signal and no reason to re-enrol.

The full list lives in one place, `db::ENCRYPTED_COLUMNS`, so "what does a stolen database
yield?" has an auditable answer rather than one assembled by grepping. Deliberately
excluded: `users_table.password` and `metrics_password` are already hashes (argon2id and
SHA-256), and encrypting a hash protects nothing the hash does not.

**One-time-link tokens are hashed, not encrypted.** They are looked up *by value*, so
randomised encryption cannot work — but the server only ever needs to *recognise* a token,
never reproduce it, so the lookup column holds a SHA-256 digest. A separate encrypted copy
is kept purely so an active link stays displayable during its five-minute life.

Values are encrypted with **AES-256-GCM** via `ring`, which is already in the dependency
graph through rustls, so this adds no crate. The stored form is `enc$` followed by
base64(12-byte nonce ‖ ciphertext ‖ 16-byte tag).

### Supplying the key

| Source | Use |
|---|---|
| `COFFEEBLACK_SECRET_KEY_PATH` | Path to a file holding the base64 key. Intended for systemd credentials: `LoadCredentialEncrypted=SECRET_KEY:…` decrypts a machine-bound blob into `/run/credentials/coffeeblack-vpn.service/SECRET_KEY` at start, so the key never exists as plaintext on disk. |
| `COFFEEBLACK_SECRET_KEY` | The base64 key itself, 32 bytes. For Docker and development. |

```bash
openssl rand -base64 32
```

With neither set the service still starts and stores plaintext, logging a warning — an
operator upgrading into this feature should not find their VPN down because a new variable
is missing. Which mode an instance is in is visible in the journal without reading the
database.

Encryption is transparent at the storage layer: row mappers decrypt, and `exec_update` —
which every update funnels through, and which already receives the table name — encrypts.
The handful of raw `INSERT`/`UPDATE` statements that bypass it encrypt explicitly. No call
site can introduce a plaintext write by forgetting a step.

**Decryption failure is a hard error, never a fallback.** An earlier revision returned
`None` for an undecryptable TOTP secret, which meant the login path saw no second factor,
skipped the check, and accepted a password alone — a key misconfiguration silently
becoming a 2FA bypass. Failing the row load instead means such an account simply cannot
authenticate until the key is fixed. Handing ciphertext to a config generator would be the
same class of bug: a peer that imports cleanly and never connects.

Values written before a key was configured have no `enc$` prefix and keep working, and a
startup pass upgrades them in place once a key is present — otherwise enabling encryption
would protect only secrets created afterwards while every existing one stayed readable.

### What this is and is not worth

This defends **a stolen database or backup**. The key is delivered out of band and never
written into the database, so the file alone yields nothing.

It does **not** defend a live compromise of the running service. The process must hold the
key to verify a code, so an attacker with code execution as this user can decrypt anything
the process can, often by calling straight into the same module. Encrypting a value the
process can decrypt on demand raises effort; it does not move the boundary.

Where a secret can be **eliminated** rather than encrypted — as peer private keys now are
— that is strictly better, and the two features are deliberately different in kind for
that reason.

---

## Generated config files

Every bundled transport is configured by a file this service renders, and each one carries
credentials: `xray/server.json` holds the Reality private key **and every client's UUID and
shortId**, `mtproxy/config.toml` holds every user's secret, `mdnsvpn/server_config.toml`
holds the tunnel key.

These were written with `tokio::fs::write`, which creates a file at `0666 & ~umask` —
**0644 under the usual 0022**. On a bare-metal install that handed any local account a
working VLESS UUID, meaning free tunnel access as an existing client, plus the Reality
private key. That was a live exposure, not an at-rest one: no stolen disk required, just a
shell on the box.

They now go through `crate::secretfile`, which creates them **0600 at `open(2)`** — not
written-then-chmod'ed, which leaves a window where the file exists at the umask-derived
mode and already holds the secret — inside a `0700` directory, written atomically via a
sibling temp file and a rename. Directories left world-traversable by an older version are
tightened on every write, since `create_dir_all` reports success on an already-loose
directory without touching it.

**These files cannot be encrypted.** The subprocesses parse them, so they must be plaintext
by design, and encrypting the corresponding database column does nothing for them. File
permissions are the only available control, which is exactly why they are worth getting
right.

### Why not keep them in memory instead?

Partly they already are. Under `IN_MEMORY=true` these directories are meant to be tmpfs,
and the startup check verifies **every** secret-bearing directory rather than only the
WireGuard one — it previously reported "RAM-backed" based on a directory that does not
contain most of these files. A tmpfs file is still a file with a mode, though, so `0600`
matters in that mode too.

Going further — rendering the configs into anonymous `memfd` objects, as `memexec.rs`
already does for the bundled *binaries*, so they have no name in any filesystem — is
possible in principle but is not implemented, for a specific reason: **Xray reloads by
re-reading its config path on SIGHUP.** A fresh memfd per render would leave the child
re-reading its original descriptor and silently applying a stale config, which is worse
than a visible failure. Doing it correctly means rewriting one long-lived unsealed memfd in
place, and whether Xray and telemt tolerate a `/proc/self/fd/N` config path at all is
external behaviour that has to be *measured*, not assumed — and the vendored blobs needed
to measure it are CI artifacts, not in the tree.

The `0600` fix closes the actual hole in every mode. Using memfd would additionally remove
the filesystem entry.

---

## Privilege separation

The web UI and the interface manager are the same process, and that process runs as root
because `awg-quick`, `awg` and `nft` need `CAP_NET_ADMIN`. So a remote-code-execution bug
anywhere in the HTTP layer — a handler, a parser, a dependency — is immediately full
control of the host. The privileged work is six operations; the surface carrying that
privilege is an entire web application.

`coffeeblack-vpn --privileged-helper` splits them. It runs as root on a Unix socket, speaks
one line-delimited JSON request per connection, and accepts a **fixed allowlist**:

| Op | Runs |
|---|---|
| `wg_up` / `wg_down` | `awg-quick up\|down <iface>` |
| `wg_sync` | writes `<conf_dir>/<iface>.conf` at 0600, then `awg-quick strip` → `awg syncconf` |
| `wg_show` | `awg show <iface> dump` |
| `nft_apply` | `nft -c -f -` to validate, then `nft -f -` to apply |
| `nft_list` | `nft list table inet coffeeblack` |
| `ping` | liveness |

Everything is executed as an **argument vector**, never a shell string, and `argv[0]`
always comes from a literal in the helper. The interface name and every filesystem path
are fixed when the helper starts and are never read from a request, so `wg_sync` cannot be
turned into an arbitrary-file-write primitive no matter what fields a caller adds.
Operations needing no privilege at all — `genkey`, `pubkey`, `genpsk`, which are pure
crypto — stay in the main process and are not forwardable.

Enable it with `COFFEEBLACK_HELPER_SOCKET`. Unset, the binary behaves exactly as before and
executes the commands itself, so an upgrade changes nothing until you opt in. See
`packaging/coffeeblack-vpn-helper.service` and the commented block in
`packaging/coffeeblack-vpn.service`.

### What it buys, stated honestly

It removes arbitrary code execution as root, arbitrary file read and write, module loading,
and persistence — the things an attacker actually wants out of an RCE.

It does **not** remove control of the VPN. A compromised main process can still ask for a
ruleset to be applied and an interface to be reconfigured, because that is the product's
entire purpose. The helper validates that a ruleset parses; it cannot judge whether the
operator wanted it. The pattern converts *root on the box* into *control of the tunnel* — a
large reduction, not containment.

Still privileged and out of scope: loading the `amneziawg` kernel module, done once via
`ExecStartPre=`, and binding the low ports the optional transports use (Xray on 443,
MasterDnsVPN on 53). Grant `CAP_NET_BIND_SERVICE` or leave those transports off.

---

## Activity history and privacy

`awg show <if> dump` is a snapshot, not a record. Two things follow, and both used to be
visible in the UI:

1. Its byte counters restart at zero whenever the interface is torn down, so a figure
   labelled "lifetime transfer" silently collapsed after every `awg-quick down`/`up`.
2. Nothing answered a question about the past — *was this peer connected last Tuesday?
   which peers went quiet three weeks ago?* — because nothing was ever kept.

A background poller samples the same dump every 30 s and folds each tick into two things
per peer:

- **Monotonic lifetime totals.** Only the non-negative delta between consecutive readings
  is accumulated, so a counter reset contributes 0 instead of driving the total backwards.
  These are what the UI labels "lifetime" and what `wireguard_peer_total_rx_bytes` /
  `_total_tx_bytes` export.
- **One bucket per UTC day**, holding a count of ticks that saw a live handshake plus that
  day's rx/tx deltas. This backs the **Connection activity** heatmap on the clients page:
  peers × days, GitHub-contribution style, shaded by either time connected or traffic
  volume, over a 30/60/90-day window.

### None of it is in the database

Per-peer connection history is the most sensitive thing this service could accumulate: who
connected, when, from where, and how much they moved. Everything in the SQLite schema is
written to a file when `IN_MEMORY=false`, and is copied verbatim into the durable snapshot
when `COFFEEBLACK_PERSIST_DB` is set — so a table, *even one in the `:memory:` database*,
is one operator setting away from becoming a durable record of exactly that.

So the history is not in the schema at all. It lives in a process-memory store
(`RwLock<HashMap<client_id, ClientActivity>>`), which makes the guarantee structural rather
than conditional: **there is no code path from this data to a file, in any mode.** It dies
with the process, which is the intended lifetime. `tests/activity.rs` asserts this against
the live schema — no table may be named for activity, and no `total_*` / `last_seen*` /
`last_sampled_*` column may appear on `clients_table` — so a future change cannot quietly
reintroduce on-disk history.

Two consequences worth stating plainly:

- **A service restart starts the heatmap empty.** That is the trade, not a bug. The peer
  roster, keys and settings persist exactly as before; only connection history does not.
- Because the store is keyed on client id with no foreign key to cascade it, deleting a
  peer drops its record immediately, and every poll tick additionally reconciles the store
  against the live client list — closing the window where a peer deleted mid-tick could
  have its record recreated by the write that follows.

The one thing that *does* persist is the retention **setting**. That is configuration, not
a record of anyone's connections, and it has to survive a restart: an operator who set it
to `0` must not find collection switched back on by the next reboot.

### Why a daily rollup rather than raw samples

Keeping every tick would cost `peers × 2,880` entries per day and grow without bound. The
rollup is `peers × retention_days` no matter how often the poller runs, so retuning the
cadence never changes the memory bill. A per-client hard cap of 366 days backstops the
retention prune, so the store stays bounded even if that prune never runs.

The trade-off is real and permanent: **intra-day resolution does not exist.** A peer that
connected once for ten minutes and one that connected three times for ten minutes look
alike within a day's bucket. Anything needing per-session detail needs its own storage, not
a cleverer query against this one.

`sample_hits` is likewise **a count of poll ticks, not a measured duration** — there are no
connect/disconnect events to work from. The UI presents `hits × 30 s` as an estimate
("connected ~2h 15m") and the API ships `pollIntervalSeconds` so that estimate tracks the
real cadence rather than a hardcoded constant.

### Privacy controls

- **`activityRetentionDays = 0`** stops collection *and* purges everything already held —
  not merely "stop writing more".
- **Erase activity history** (`DELETE /api/activity`, admin only) drops the day buckets,
  the accumulated totals, and the last-seen timestamps and endpoints, then re-anchors the
  sampler so the next tick books nothing rather than crediting the whole pre-purge counter.
- The heatmap follows the same visibility rule as the peer list: a role-0 user sees only
  their own peers, never anyone else's connection pattern.
- **No source addresses.** `awg show dump` reports the endpoint a peer was reached from,
  and it is deliberately dropped rather than accumulated. A peer's real public IP is the
  most identifying field available here, it is exactly what a VPN exists not to retain,
  and unlike a key it cannot be rotated after a compromise. The current endpoint is still
  shown live in the peer list; it simply never enters a history that outlives the
  connection.

Retention defaults to 30 days and is capped at 365. It is deliberately short: the
heatmap's operational value — spotting a peer gone quiet, or one suddenly moving far more
than usual — is served by a few weeks, while the months beyond mostly add retroactive
exposure if the box is ever seized.

---

## Reporting a vulnerability

Open an issue tagged `security`.
