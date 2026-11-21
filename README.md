# Stalwart Utils

[English](#english) | [Русский](#русский)

---

## English

Zero-dependency Python 3 utilities for automating multi-domain administration and mail migration on [Stalwart Mail Server](https://stalw.art/) via JMAP.

### Requirements

- **Python 3.9+** (uses only the Python standard library — no `pip` packages required)
- **OpenSSL CLI** (optional, used by `provision_domain.py` to inspect SAN/CN fields of DER certificates)
- Administrative API token (Bearer) for Stalwart Mail Server

---

### 1. `provision_domain.py` — Multi-IP Domain Listeners, MTA Rules & TLS Audit

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
python3 provision_domain.py \
  --lang en \
  --url [https://mail.example.com](https://mail.example.com) \
  --domain example.com \
  --ip 172.28.0.13
```

**Verify ports, banners, and TLS certificates only (no API token required):**
```bash
python3 provision_domain.py \
  --lang en \
  --check-only \
  --domain example.com
```

**Full read-only API configuration audit + live network probe:**
```bash
python3 provision_domain.py \
  --lang en \
  --check-only \
  --url [https://mail.example.com](https://mail.example.com) \
  --domain example.com \
  --ip 172.28.0.13
```

---

### 2. `kerio2stalwart.py` — Kerio Connect to Stalwart JMAP Migration

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
python3 kerio2stalwart.py \
  --lang en \
  --users-cfg /opt/kerio/mailserver/users.cfg \
  --domain-dir /store/mail/example.com \
  --url [https://mail.example.com](https://mail.example.com) \
  --dry-run
```

**Run full domain migration (interactive prompts for optional parameters):**
```bash
python3 kerio2stalwart.py \
  --lang en \
  --users-cfg /opt/kerio/mailserver/users.cfg \
  --domain-dir /store/mail/example.com \
  --url [https://mail.example.com](https://mail.example.com)
```

**Migrate accounts and aliases only (skip email import):**
```bash
python3 kerio2stalwart.py \
  --lang en \
  --yes \
  --skip-mail \
  --users-cfg /opt/kerio/mailserver/users.cfg \
  --domain-dir /store/mail/example.com \
  --url [https://mail.example.com](https://mail.example.com)
```

---

## Русский

Утилиты на Python 3 без внешних зависимостей для автоматизации настройки доменов и миграции почты в [Stalwart Mail Server](https://stalw.art/) через протокол JMAP.

### Требования

- **Python 3.9+** (используется только стандартная библиотека Python — установка пакетов через `pip` не требуется)
- **OpenSSL CLI** (опционально, используется в `provision_domain.py` для чтения SAN/CN из DER-сертификатов)
- Административный API-токен (Bearer) сервера Stalwart

---

### 1. `provision_domain.py` — Настройка Listeners, правил MTA и проверка TLS для домена

Автоматизирует подключение выделенного IP-адреса и почтового домена на multi-IP инстансе Stalwart, а также проверяет работу всех почтовых служб и выдачу TLS-сертификатов (как с SNI, так и без SNI).

#### Возможности
- Создаёт или проверяет `x:Domain` с автоматическим управлением DKIM.
- Создаёт все 8 сетевых слушателей `x:NetworkListener` на внутреннем/Docker IP домена (`25`, `587`, `465`, `143`, `993`, `110`, `995`, `4190`) и привязывает сертификат `x:Certificate` (`defaultCertificateId`), чтобы клиенты без SNI получали сертификат нужного домена.
- При использовании режима `EnableSome` в `x:ServerRole` автоматически добавляет созданные слушатели в `listenerIds`.
- Настраивает входящие правила `x:MtaStageConnect` (`hostname` и баннер `220` по `local_ip`) и исходящую маршрутизацию `x:MtaConnectionStrategy` + `x:MtaOutboundStrategy` (привязка исходящего IP и `ehloHostname` по `sender_domain`).
- Вызывает перезагрузку конфигурации (`ReloadSettings`) через JMAP.
- **Режим проверки (`--check-only`)**: выполняет read-only аудит конфигурации через API (опционально) и тестирует все 8 портов (`STARTTLS` и `Implicit TLS`), проверяя приветствия протоколов и сертификаты **с SNI** и **без SNI**.
- Выбор языка: `--lang ru` (по умолчанию) или `--lang en` (либо переменная `PROVISION_LANG`).

#### Примеры запуска

**Настройка нового домена и IP:**
```bash
python3 provision_domain.py \
  --url [https://mail.example.com](https://mail.example.com) \
  --domain example.com \
  --ip 172.28.0.13
```

**Только проверка портов, баннеров и TLS-сертификатов (токен API не требуется):**
```bash
python3 provision_domain.py \
  --check-only \
  --domain example.com
```

**Полный read-only аудит настроек в API Stalwart + сетевая проверка портов:**
```bash
python3 provision_domain.py \
  --check-only \
  --url [https://mail.example.com](https://mail.example.com) \
  --domain example.com \
  --ip 172.28.0.13
```

---

### 2. `kerio2stalwart.py` — Миграция домена из Kerio Connect в Stalwart через JMAP

Переносит всех пользователей, алиасы, квоты, дерево папок, даты получения и флаги писем одного домена из Kerio Connect (`users.cfg` + каталог домена на диске) в Stalwart Mail Server через JMAP.

#### Возможности
- **Быстрый импорт через JMAP**: загружает `.eml`-файлы параллельно через `uploadUrl` и импортирует письма пакетами через `Email/import`.
- **Соблюдение лимитов сервера**: автоматически считывает `maxSizeUpload`, `maxConcurrentUpload`, `maxObjectsInSet` и `maxSizeRequest` из `/jmap/session`, обрабатывает `HTTP 429/503` (`Retry-After`) и пропускает письма, превышающие максимальный размер загрузки.
- **Сохранение структуры и метаданных**:
  - Маппит системные папки Kerio (`Sent Items` -> `Sent`, `Deleted Items` -> `Trash`, `Junk E-mail` -> `Junk`, `Drafts` -> `Drafts`) и вложенные пользовательские папки.
  - Читает `index.fld` для переноса оригинальных дат (`receivedAt`) и флагов (`$seen`, `$answered`, `$flagged`, `$draft`), отфильтровывая служебные элементы MAPI (`IPM.Appointment`, `IPM.Contact`, `IPM.Task`).
- **Идемпотентность**: проверяет существующие `Message-ID` в целевых папках перед загрузкой — повторный запуск не создаёт дубликатов.
- **Управление паролями (`--password-mode`)**:
  - `auto` (по умолчанию): сохраняет совместимые хеши (`{ARGON2ID}`, `{SSHA}`, `$2...`, `$6$...` и др.), а для проприетарных записей Kerio `D3S:` генерирует надёжные случайные пароли.
  - `random`: генерирует новые случайные пароли для всех пользователей.
  - `default`: задаёт единый пароль для всех переносимых аккаунтов.
  - Сохраняет итоговый CSV-отчёт с паролями и правилами пересылки с правами `0600`.
- **Интерактивный и автоматический режимы**: запрашивает любой незаданный параметр с подсказкой значения по умолчанию, либо запускается без вопросов с флагом `--yes` (`-y`).

#### Примеры запуска

**Предпросмотр миграции (`--dry-run`, без внесения изменений):**
```bash
python3 kerio2stalwart.py \
  --users-cfg /opt/kerio/mailserver/users.cfg \
  --domain-dir /store/mail/example.com \
  --url [https://mail.example.com](https://mail.example.com) \
  --dry-run
```

**Полная миграция домена (с интерактивным подтверждением опциональных параметров):**
```bash
python3 kerio2stalwart.py \
  --users-cfg /opt/kerio/mailserver/users.cfg \
  --domain-dir /store/mail/example.com \
  --url [https://mail.example.com](https://mail.example.com)
```

**Миграция только аккаунтов и алиасов (без импорта писем):**
```bash
python3 kerio2stalwart.py \
  --yes \
  --skip-mail \
  --users-cfg /opt/kerio/mailserver/users.cfg \
  --domain-dir /store/mail/example.com \
  --url [https://mail.example.com](https://mail.example.com)
```

