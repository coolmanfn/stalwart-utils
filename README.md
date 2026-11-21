# Stalwart Utils

[English](#english) | [„Q„…„ƒ„ƒ„{„y„z](#„‚„…„ƒ„ƒ„{„y„z)

---

## English

Zero-dependency Python 3 utilities for automating multi-domain administration and mail migration on [Stalwart Mail Server](https://stalw.art/) via JMAP.

### Requirements

- **Python 3.9+** (uses only the Python standard library \ no `pip` packages required)
- **OpenSSL CLI** (optional, used by `provision_domain.py` to inspect SAN/CN fields of DER certificates)
- Administrative API token (Bearer) for Stalwart Mail Server

---

### 1. `provision_domain.py` \ Multi-IP Domain Listeners, MTA Rules & TLS Audit

Automates onboarding a dedicated IP and mail domain on a multi-tenant Stalwart instance, and verifies all mail services and TLS certificates (both with SNI and without SNI).

#### Key Features
- Creates or updates `x:Domain` with automatic DKIM management.
- Creates all 8 `x:NetworkListener` services bound to the domain's dedicated internal/Docker IP (`25`, `587`, `465`, `143`, `993`, `110`, `995`, `4190`) and assigns the matching `x:Certificate` (`defaultCertificateId`) so non-SNI clients receive the right certificate.
- Registers new listener IDs in `x:ServerRole` when `EnableSome` is active.
- Configures inbound `x:MtaStageConnect` (`hostname` and `220` greeting by `local_ip`) and outbound `x:MtaConnectionStrategy` + `x:MtaOutboundStrategy` (`sender_domain` routing + `ehloHostname`).
- Triggers `ReloadSettings` via JMAP.
- **Verification mode (`--check-only`)**: performs a read-only audit via JMAP API (optional) and probes all 8 ports (`STARTTLS` and `Implicit TLS`), checking protocol banners and certificates both **with SNI** and **without SNI**.
- Bilingual interface: `--lang en` / `--lang ru` (or `PROVISION_LANG=en`).

#### Usage

**Provision a new domain and IP:**
```bash
python3 provision_domain.py €
  --lang en €
  --url [https://mail.example.com](https://mail.example.com) €
  --domain example.com €
  --ip 172.28.0.13
```

**Verify ports, banners, and TLS certificates only (no API token required):**
```bash
python3 provision_domain.py €
  --lang en €
  --check-only €
  --domain example.com
```

**Full read-only API configuration audit + live network probe:**
```bash
python3 provision_domain.py €
  --lang en €
  --check-only €
  --url [https://mail.example.com](https://mail.example.com) €
  --domain example.com €
  --ip 172.28.0.13
```

---

### 2. `kerio2stalwart.py` \ Kerio Connect to Stalwart JMAP Migration

Migrates all users, aliases, quotas, mailbox folder hierarchies, message timestamps, and flags of a single domain from Kerio Connect (`users.cfg` + mailstore directory) to Stalwart Mail Server using JMAP.

#### Key Features
- **Fast JMAP Import**: uploads `.eml` blobs in parallel via `uploadUrl` and imports messages in batches using `Email/import`.
- **Automatic JMAP Limit Compliance**: reads `maxSizeUpload`, `maxConcurrentUpload`, `maxObjectsInSet`, and `maxSizeRequest` directly from `/jmap/session`, handles HTTP `429`/`503` `Retry-After` backoff, and skips oversized messages gracefully.
- **Full Mailbox & Metadata Preservation**:
  - Maps Kerio system folders (`Sent Items` -> `Sent`, `Deleted Items` -> `Trash`, `Junk E-mail` -> `Junk`, `Drafts` -> `Drafts`) and nested custom folders.
  - Parses `index.fld` to preserve original `receivedAt` timestamps and message flags (`$seen`, `$answered`, `$flagged`, `$draft`), filtering out non-mail MAPI items (`IPM.Appointment`, `IPM.Contact`, `IPM.Task`).
- **Idempotent Execution**: checks existing `Message-ID` headers in each target mailbox before uploading, allowing safe re-runs without duplicates.
- **Password Handling (`--password-mode`)**:
  - `auto` (default): preserves Stalwart-compatible password hashes (`{ARGON2ID}`, `{SSHA}`, `$2...`, `$6$...`, etc.) and generates strong random passwords for Kerio's proprietary `D3S:` entries.
  - `random`: generates a new random password for every migrated user.
  - `default`: sets a single user-supplied password for all migrated accounts.
  - Exports a credential and forwarding report CSV with `0600` file permissions.
- **Interactive & Non-Interactive Modes**: prompts for any omitted parameter with sensible defaults, or runs unattended with `--yes` (`-y`).

#### Usage

**Preview migration (`--dry-run`, no changes made):**
```bash
python3 kerio2stalwart.py €
  --lang en €
  --users-cfg /opt/kerio/mailserver/users.cfg €
  --domain-dir /store/mail/example.com €
  --url [https://mail.example.com](https://mail.example.com) €
  --dry-run
```

**Run full domain migration (interactive prompts for optional parameters):**
```bash
python3 kerio2stalwart.py €
  --lang en €
  --users-cfg /opt/kerio/mailserver/users.cfg €
  --domain-dir /store/mail/example.com €
  --url [https://mail.example.com](https://mail.example.com)
```

**Migrate accounts and aliases only (skip email import):**
```bash
python3 kerio2stalwart.py €
  --lang en €
  --yes €
  --skip-mail €
  --users-cfg /opt/kerio/mailserver/users.cfg €
  --domain-dir /store/mail/example.com €
  --url [https://mail.example.com](https://mail.example.com)
```

---

## „Q„…„ƒ„ƒ„{„y„z

„T„„„y„|„y„„„ „~„p Python 3 „q„u„x „r„~„u„Š„~„y„‡ „x„p„r„y„ƒ„y„}„€„ƒ„„„u„z „t„|„‘ „p„r„„„€„}„p„„„y„x„p„ˆ„y„y „~„p„ƒ„„„‚„€„z„{„y „t„€„}„u„~„€„r „y „}„y„s„‚„p„ˆ„y„y „„€„‰„„„ „r [Stalwart Mail Server](https://stalw.art/) „‰„u„‚„u„x „„‚„€„„„€„{„€„| JMAP.

### „S„‚„u„q„€„r„p„~„y„‘

- **Python 3.9+** („y„ƒ„„€„|„„x„…„u„„„ƒ„‘ „„„€„|„„{„€ „ƒ„„„p„~„t„p„‚„„„~„p„‘ „q„y„q„|„y„€„„„u„{„p Python \ „…„ƒ„„„p„~„€„r„{„p „„p„{„u„„„€„r „‰„u„‚„u„x `pip` „~„u „„„‚„u„q„…„u„„„ƒ„‘)
- **OpenSSL CLI** („€„„ˆ„y„€„~„p„|„„~„€, „y„ƒ„„€„|„„x„…„u„„„ƒ„‘ „r `provision_domain.py` „t„|„‘ „‰„„„u„~„y„‘ SAN/CN „y„x DER-„ƒ„u„‚„„„y„†„y„{„p„„„€„r)
- „@„t„}„y„~„y„ƒ„„„‚„p„„„y„r„~„„z API-„„„€„{„u„~ (Bearer) „ƒ„u„‚„r„u„‚„p Stalwart

---

### 1. `provision_domain.py` \ „N„p„ƒ„„„‚„€„z„{„p Listeners, „„‚„p„r„y„| MTA „y „„‚„€„r„u„‚„{„p TLS „t„|„‘ „t„€„}„u„~„p

„@„r„„„€„}„p„„„y„x„y„‚„…„u„„ „„€„t„{„|„„‰„u„~„y„u „r„„t„u„|„u„~„~„€„s„€ IP-„p„t„‚„u„ƒ„p „y „„€„‰„„„€„r„€„s„€ „t„€„}„u„~„p „~„p multi-IP „y„~„ƒ„„„p„~„ƒ„u Stalwart, „p „„„p„{„w„u „„‚„€„r„u„‚„‘„u„„ „‚„p„q„€„„„… „r„ƒ„u„‡ „„€„‰„„„€„r„„‡ „ƒ„|„…„w„q „y „r„„t„p„‰„… TLS-„ƒ„u„‚„„„y„†„y„{„p„„„€„r („{„p„{ „ƒ SNI, „„„p„{ „y „q„u„x SNI).

#### „B„€„x„}„€„w„~„€„ƒ„„„y
- „R„€„x„t„p„v„„ „y„|„y „„‚„€„r„u„‚„‘„u„„ `x:Domain` „ƒ „p„r„„„€„}„p„„„y„‰„u„ƒ„{„y„} „…„„‚„p„r„|„u„~„y„u„} DKIM.
- „R„€„x„t„p„v„„ „r„ƒ„u 8 „ƒ„u„„„u„r„„‡ „ƒ„|„…„Š„p„„„u„|„u„z `x:NetworkListener` „~„p „r„~„…„„„‚„u„~„~„u„}/Docker IP „t„€„}„u„~„p (`25`, `587`, `465`, `143`, `993`, `110`, `995`, `4190`) „y „„‚„y„r„‘„x„„r„p„u„„ „ƒ„u„‚„„„y„†„y„{„p„„ `x:Certificate` (`defaultCertificateId`), „‰„„„€„q„ „{„|„y„u„~„„„ „q„u„x SNI „„€„|„…„‰„p„|„y „ƒ„u„‚„„„y„†„y„{„p„„ „~„…„w„~„€„s„€ „t„€„}„u„~„p.
- „P„‚„y „y„ƒ„„€„|„„x„€„r„p„~„y„y „‚„u„w„y„}„p `EnableSome` „r `x:ServerRole` „p„r„„„€„}„p„„„y„‰„u„ƒ„{„y „t„€„q„p„r„|„‘„u„„ „ƒ„€„x„t„p„~„~„„u „ƒ„|„…„Š„p„„„u„|„y „r `listenerIds`.
- „N„p„ƒ„„„‚„p„y„r„p„u„„ „r„‡„€„t„‘„‹„y„u „„‚„p„r„y„|„p `x:MtaStageConnect` (`hostname` „y „q„p„~„~„u„‚ `220` „„€ `local_ip`) „y „y„ƒ„‡„€„t„‘„‹„…„ „}„p„‚„Š„‚„…„„„y„x„p„ˆ„y„ `x:MtaConnectionStrategy` + `x:MtaOutboundStrategy` („„‚„y„r„‘„x„{„p „y„ƒ„‡„€„t„‘„‹„u„s„€ IP „y `ehloHostname` „„€ `sender_domain`).
- „B„„x„„r„p„u„„ „„u„‚„u„x„p„s„‚„…„x„{„… „{„€„~„†„y„s„…„‚„p„ˆ„y„y (`ReloadSettings`) „‰„u„‚„u„x JMAP.
- **„Q„u„w„y„} „„‚„€„r„u„‚„{„y (`--check-only`)**: „r„„„€„|„~„‘„u„„ read-only „p„…„t„y„„ „{„€„~„†„y„s„…„‚„p„ˆ„y„y „‰„u„‚„u„x API („€„„ˆ„y„€„~„p„|„„~„€) „y „„„u„ƒ„„„y„‚„…„u„„ „r„ƒ„u 8 „„€„‚„„„€„r (`STARTTLS` „y `Implicit TLS`), „„‚„€„r„u„‚„‘„‘ „„‚„y„r„u„„„ƒ„„„r„y„‘ „„‚„€„„„€„{„€„|„€„r „y „ƒ„u„‚„„„y„†„y„{„p„„„ **„ƒ SNI** „y **„q„u„x SNI**.
- „B„„q„€„‚ „‘„x„„{„p: `--lang ru` („„€ „…„}„€„|„‰„p„~„y„) „y„|„y `--lang en` („|„y„q„€ „„u„‚„u„}„u„~„~„p„‘ `PROVISION_LANG`).

#### „P„‚„y„}„u„‚„ „x„p„„…„ƒ„{„p

**„N„p„ƒ„„„‚„€„z„{„p „~„€„r„€„s„€ „t„€„}„u„~„p „y IP:**
```bash
python3 provision_domain.py €
  --url [https://mail.example.com](https://mail.example.com) €
  --domain example.com €
  --ip 172.28.0.13
```

**„S„€„|„„{„€ „„‚„€„r„u„‚„{„p „„€„‚„„„€„r, „q„p„~„~„u„‚„€„r „y TLS-„ƒ„u„‚„„„y„†„y„{„p„„„€„r („„„€„{„u„~ API „~„u „„„‚„u„q„…„u„„„ƒ„‘):**
```bash
python3 provision_domain.py €
  --check-only €
  --domain example.com
```

**„P„€„|„~„„z read-only „p„…„t„y„„ „~„p„ƒ„„„‚„€„u„{ „r API Stalwart + „ƒ„u„„„u„r„p„‘ „„‚„€„r„u„‚„{„p „„€„‚„„„€„r:**
```bash
python3 provision_domain.py €
  --check-only €
  --url [https://mail.example.com](https://mail.example.com) €
  --domain example.com €
  --ip 172.28.0.13
```

---

### 2. `kerio2stalwart.py` \ „M„y„s„‚„p„ˆ„y„‘ „t„€„}„u„~„p „y„x Kerio Connect „r Stalwart „‰„u„‚„u„x JMAP

„P„u„‚„u„~„€„ƒ„y„„ „r„ƒ„u„‡ „„€„|„„x„€„r„p„„„u„|„u„z, „p„|„y„p„ƒ„, „{„r„€„„„, „t„u„‚„u„r„€ „„p„„€„{, „t„p„„„ „„€„|„…„‰„u„~„y„‘ „y „†„|„p„s„y „„y„ƒ„u„} „€„t„~„€„s„€ „t„€„}„u„~„p „y„x Kerio Connect (`users.cfg` + „{„p„„„p„|„€„s „t„€„}„u„~„p „~„p „t„y„ƒ„{„u) „r Stalwart Mail Server „‰„u„‚„u„x JMAP.

#### „B„€„x„}„€„w„~„€„ƒ„„„y
- **„A„„ƒ„„„‚„„z „y„}„„€„‚„„ „‰„u„‚„u„x JMAP**: „x„p„s„‚„…„w„p„u„„ `.eml`-„†„p„z„|„ „„p„‚„p„|„|„u„|„„~„€ „‰„u„‚„u„x `uploadUrl` „y „y„}„„€„‚„„„y„‚„…„u„„ „„y„ƒ„„}„p „„p„{„u„„„p„}„y „‰„u„‚„u„x `Email/import`.
- **„R„€„q„|„„t„u„~„y„u „|„y„}„y„„„€„r „ƒ„u„‚„r„u„‚„p**: „p„r„„„€„}„p„„„y„‰„u„ƒ„{„y „ƒ„‰„y„„„„r„p„u„„ `maxSizeUpload`, `maxConcurrentUpload`, `maxObjectsInSet` „y `maxSizeRequest` „y„x `/jmap/session`, „€„q„‚„p„q„p„„„„r„p„u„„ `HTTP 429/503` (`Retry-After`) „y „„‚„€„„…„ƒ„{„p„u„„ „„y„ƒ„„}„p, „„‚„u„r„„Š„p„„‹„y„u „}„p„{„ƒ„y„}„p„|„„~„„z „‚„p„x„}„u„‚ „x„p„s„‚„…„x„{„y.
- **„R„€„‡„‚„p„~„u„~„y„u „ƒ„„„‚„…„{„„„…„‚„ „y „}„u„„„p„t„p„~„~„„‡**:
  - „M„p„„„y„„ „ƒ„y„ƒ„„„u„}„~„„u „„p„„{„y Kerio (`Sent Items` -> `Sent`, `Deleted Items` -> `Trash`, `Junk E-mail` -> `Junk`, `Drafts` -> `Drafts`) „y „r„|„€„w„u„~„~„„u „„€„|„„x„€„r„p„„„u„|„„ƒ„{„y„u „„p„„{„y.
  - „X„y„„„p„u„„ `index.fld` „t„|„‘ „„u„‚„u„~„€„ƒ„p „€„‚„y„s„y„~„p„|„„~„„‡ „t„p„„ (`receivedAt`) „y „†„|„p„s„€„r (`$seen`, `$answered`, `$flagged`, `$draft`), „€„„„†„y„|„„„„‚„€„r„„r„p„‘ „ƒ„|„…„w„u„q„~„„u „„|„u„}„u„~„„„ MAPI (`IPM.Appointment`, `IPM.Contact`, `IPM.Task`).
- **„I„t„u„}„„€„„„u„~„„„~„€„ƒ„„„**: „„‚„€„r„u„‚„‘„u„„ „ƒ„…„‹„u„ƒ„„„r„…„„‹„y„u `Message-ID` „r „ˆ„u„|„u„r„„‡ „„p„„{„p„‡ „„u„‚„u„t „x„p„s„‚„…„x„{„€„z \ „„€„r„„„€„‚„~„„z „x„p„„…„ƒ„{ „~„u „ƒ„€„x„t„p„v„„ „t„…„q„|„y„{„p„„„€„r.
- **„T„„‚„p„r„|„u„~„y„u „„p„‚„€„|„‘„}„y (`--password-mode`)**:
  - `auto` („„€ „…„}„€„|„‰„p„~„y„): „ƒ„€„‡„‚„p„~„‘„u„„ „ƒ„€„r„}„u„ƒ„„„y„}„„u „‡„u„Š„y (`{ARGON2ID}`, `{SSHA}`, `$2...`, `$6$...` „y „t„‚.), „p „t„|„‘ „„‚„€„„‚„y„u„„„p„‚„~„„‡ „x„p„„y„ƒ„u„z Kerio `D3S:` „s„u„~„u„‚„y„‚„…„u„„ „~„p„t„v„w„~„„u „ƒ„|„…„‰„p„z„~„„u „„p„‚„€„|„y.
  - `random`: „s„u„~„u„‚„y„‚„…„u„„ „~„€„r„„u „ƒ„|„…„‰„p„z„~„„u „„p„‚„€„|„y „t„|„‘ „r„ƒ„u„‡ „„€„|„„x„€„r„p„„„u„|„u„z.
  - `default`: „x„p„t„p„v„„ „u„t„y„~„„z „„p„‚„€„|„ „t„|„‘ „r„ƒ„u„‡ „„u„‚„u„~„€„ƒ„y„}„„‡ „p„{„{„p„…„~„„„€„r.
  - „R„€„‡„‚„p„~„‘„u„„ „y„„„€„s„€„r„„z CSV-„€„„„‰„v„„ „ƒ „„p„‚„€„|„‘„}„y „y „„‚„p„r„y„|„p„}„y „„u„‚„u„ƒ„„|„{„y „ƒ „„‚„p„r„p„}„y `0600`.
- **„I„~„„„u„‚„p„{„„„y„r„~„„z „y „p„r„„„€„}„p„„„y„‰„u„ƒ„{„y„z „‚„u„w„y„}„**: „x„p„„‚„p„Š„y„r„p„u„„ „|„„q„€„z „~„u„x„p„t„p„~„~„„z „„p„‚„p„}„u„„„‚ „ƒ „„€„t„ƒ„{„p„x„{„€„z „x„~„p„‰„u„~„y„‘ „„€ „…„}„€„|„‰„p„~„y„, „|„y„q„€ „x„p„„…„ƒ„{„p„u„„„ƒ„‘ „q„u„x „r„€„„‚„€„ƒ„€„r „ƒ „†„|„p„s„€„} `--yes` (`-y`).

#### „P„‚„y„}„u„‚„ „x„p„„…„ƒ„{„p

**„P„‚„u„t„„‚„€„ƒ„}„€„„„‚ „}„y„s„‚„p„ˆ„y„y (`--dry-run`, „q„u„x „r„~„u„ƒ„u„~„y„‘ „y„x„}„u„~„u„~„y„z):**
```bash
python3 kerio2stalwart.py €
  --users-cfg /opt/kerio/mailserver/users.cfg €
  --domain-dir /store/mail/example.com €
  --url [https://mail.example.com](https://mail.example.com) €
  --dry-run
```

**„P„€„|„~„p„‘ „}„y„s„‚„p„ˆ„y„‘ „t„€„}„u„~„p („ƒ „y„~„„„u„‚„p„{„„„y„r„~„„} „„€„t„„„r„u„‚„w„t„u„~„y„u„} „€„„ˆ„y„€„~„p„|„„~„„‡ „„p„‚„p„}„u„„„‚„€„r):**
```bash
python3 kerio2stalwart.py €
  --users-cfg /opt/kerio/mailserver/users.cfg €
  --domain-dir /store/mail/example.com €
  --url [https://mail.example.com](https://mail.example.com)
```

**„M„y„s„‚„p„ˆ„y„‘ „„„€„|„„{„€ „p„{„{„p„…„~„„„€„r „y „p„|„y„p„ƒ„€„r („q„u„x „y„}„„€„‚„„„p „„y„ƒ„u„}):**
```bash
python3 kerio2stalwart.py €
  --yes €
  --skip-mail €
  --users-cfg /opt/kerio/mailserver/users.cfg €
  --domain-dir /store/mail/example.com €
  --url [https://mail.example.com](https://mail.example.com)
```