#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import csv
import email
import email.policy
import getpass
import json
import os
import re
import secrets
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


KERIO_SYSTEM_FOLDER_MAP = {
    "inbox": ("INBOX", "inbox"),
    "sent items": ("Sent", "sent"),
    "sent": ("Sent", "sent"),
    "deleted items": ("Trash", "trash"),
    "trash": ("Trash", "trash"),
    "junk e-mail": ("Junk", "junk"),
    "junk email": ("Junk", "junk"),
    "junk": ("Junk", "junk"),
    "spam": ("Junk", "junk"),
    "drafts": ("Drafts", "drafts"),
}

KERIO_SKIP_FOLDERS = {
    "calendar",
    "contacts",
    "tasks",
    "journal",
    "notes",
    "public folders",
    "#msgs",
    "#assoc",
}

MESSAGES: dict[str, dict[str, str]] = {
    "ru": {
        "cli_desc": "Быстрая миграция пользователей, алиасов, квот, папок и писем одного домена из Kerio Connect в Stalwart через JMAP",
        "help_lang": "Язык вывода: ru или en (по умолчанию: ru)",
        "help_users_cfg": "Путь к файлу users.cfg из Kerio Connect (например, /opt/kerio/mailserver/users.cfg)",
        "help_domain_dir": "Путь к каталогу домена в хранилище Kerio (например, /store/mail/example.com)",
        "help_domain": "Имя мигрируемого домена (по умолчанию берётся из имени каталога --domain-dir)",
        "help_url": "URL сервера Stalwart (например, http://127.0.0.1:8080 или https://mail.example.com)",
        "help_pwd_mode": "Режим паролей: auto (сохранять совместимые хеши, для D3S генерировать), random (всем случайные), default (единый пароль)",
        "help_active_only": "Переносить только включённые аккаунты (Account_enabled == 1)",
        "help_skip_mail": "Перенести только аккаунты и алиасы без импорта писем",
        "help_dry_run": "Режим предпросмотра: разобрать Kerio и проверить Stalwart без внесения изменений",
        "help_concurrency": "Максимум параллельных загрузок JMAP blob (ограничивается maxConcurrentUpload сервера)",
        "help_batch_size": "Максимум писем в одном пакете JMAP Email/import (ограничивается maxObjectsInSet сервера)",
        "help_insecure": "Не проверять TLS-сертификаты при подключении к Stalwart",
        "help_out_csv": "Путь для сохранения CSV с мигрированными аккаунтами и паролями",
        "help_yes": "Не запрашивать подтверждение опциональных параметров (использовать значения по умолчанию)",
        "prompt_lang": "Язык интерфейса / Interface language (ru/en) [ru]: ",
        "prompt_users_cfg": "Путь к файлу users.cfg Kerio [/opt/kerio/mailserver/users.cfg]: ",
        "prompt_domain_dir": "Путь к папке домена в Kerio (например, /store/mail/example.com): ",
        "prompt_domain": "Имя мигрируемого домена [{default}]: ",
        "prompt_url": "URL сервера Stalwart [http://127.0.0.1:8080]: ",
        "prompt_pwd_mode": "Режим паролей (auto / random / default) [auto]: ",
        "prompt_active_only": "Переносить только активные аккаунты? (y/N) [N]: ",
        "prompt_skip_mail": "Пропустить импорт писем (только аккаунты и алиасы)? (y/N) [N]: ",
        "prompt_dry_run": "Запустить в режиме предпросмотра (dry-run, без изменений)? (y/N) [N]: ",
        "prompt_concurrency": "Параллельных загрузок JMAP blob [4]: ",
        "prompt_batch_size": "Размер пакета JMAP Email/import [100]: ",
        "prompt_out_csv": "CSV-файл для отчёта и паролей [{default}]: ",
        "prompt_insecure": "Отключить проверку TLS-сертификата HTTPS? (y/N) [N]: ",
        "prompt_token": "API токен Stalwart (ввод скрыт): ",
        "prompt_default_pwd": "Пароль по умолчанию для новых аккаунтов (ввод скрыт): ",
        "err_users_cfg": "Ошибка: файл users.cfg не найден по пути '{path}'.",
        "err_domain_dir": "Ошибка: каталог домена не найден по пути '{path}'.",
        "err_domain": "Ошибка: укажите корректное доменное имя.",
        "err_token": "Ошибка: API токен не может быть пустым.",
        "err_default_pwd": "Ошибка: для режима паролей 'default' необходимо задать непустой пароль.",
        "err_positive_int": "Ошибка: введите целое число больше 0.",
        "parsing_kerio": "\n=== Чтение данных Kerio Connect ===",
        "found_users": "[OK] Найдено пользователей в домене '{domain}': {count} (активных: {active}, отключённых: {disabled})",
        "no_users": "[!] В файле users.cfg не найдено ни одного пользователя для домена '{domain}'.",
        "connecting": "\n=== Подключение к Stalwart ({url}) ===",
        "jmap_limits": "[OK] Лимиты JMAP сервера: maxSizeUpload={upload_mb:.1f} МБ, maxConcurrentUpload={conc}, maxObjectsInSet={objs}, maxSizeRequest={req_mb:.1f} МБ (используем: потоков={eff_conc}, пакет={eff_batch})",
        "domain_exists": "[OK] Домен '{domain}' уже существует в Stalwart (id={id})",
        "domain_created": "[+] Создан домен '{domain}' в Stalwart (id={id})",
        "domain_would_create": "[DRY-RUN] Будет создан домен '{domain}'",
        "user_header": "\n--- Пользователь: {email} (Kerio: {orig_name}, статус: {status}) ---",
        "status_active": "включён",
        "status_disabled": "отключён",
        "user_aliases": "    Алиасы     : {aliases}",
        "user_forward": "    Пересылка  : mode={mode} -> {addr} (требует ручной настройки Sieve в Stalwart)",
        "user_pwd_info": "    Пароль     : {info}",
        "user_mail_scan": "    Почта Kerio: {folders} папок, {msgs} писем ({mb:.2f} МБ) в {path}",
        "user_mail_missing": "    Почта Kerio: каталог ящика на диске не найден",
        "user_created": "    [+] Создан аккаунт '{name}' (id={id})",
        "user_updated": "    [~] Обновлён аккаунт '{name}' (id={id})",
        "user_would_create": "    [DRY-RUN] Будет создан аккаунт '{name}'",
        "user_would_update": "    [DRY-RUN] Будет обновлён аккаунт '{name}'",
        "jmap_importing": "    [>] Импорт писем через JMAP (потоков={conc}, пакет={batch})...",
        "jmap_auth_fallback": "    [i] Переключение JMAP-сессии на прямую авторизацию пользователя {email}",
        "jmap_oversize": "        [!] Пропущено письмо {file} ({mb:.1f} МБ > лимита сервера {limit_mb:.1f} МБ)",
        "jmap_folder": "        Папка '{src}' -> '{dst}': всего={total}, загружено={imported}, пропущено(дубли)={skipped}, ошибок={errors}",
        "jmap_err": "    [!] Ошибка JMAP при импорте для {email}: {err}",
        "csv_saved": "\n[OK] Отчёт и учётные данные сохранены в: {path} (права 0600)",
        "summary_header": "\n=== Итоги миграции ===",
        "summary_line": "Домен: {domain} | Аккаунтов обработано: {users} | Загружено писем: {imported} | Пропущено дублей: {skipped} | Ошибок: {errors}",
        "dry_run_done": "[DRY-RUN] Изменения на сервер не вносились.",
    },
    "en": {
        "cli_desc": "Fast JMAP migration of users, aliases, quotas, folders, and emails for a single domain from Kerio Connect to Stalwart",
        "help_lang": "Output language: ru or en (default: ru)",
        "help_users_cfg": "Path to Kerio Connect users.cfg file (e.g., /opt/kerio/mailserver/users.cfg)",
        "help_domain_dir": "Path to the domain directory in Kerio mailstore (e.g., /store/mail/example.com)",
        "help_domain": "Domain name to migrate (defaults to the basename of --domain-dir)",
        "help_url": "Stalwart server URL (e.g., http://127.0.0.1:8080 or https://mail.example.com)",
        "help_pwd_mode": "Password mode: auto (keep compatible hashes, generate for D3S), random (generate for all), default (shared password)",
        "help_active_only": "Migrate only enabled accounts (Account_enabled == 1)",
        "help_skip_mail": "Migrate accounts and aliases only without email import",
        "help_dry_run": "Preview mode: parse Kerio and inspect Stalwart without making any changes",
        "help_concurrency": "Max parallel JMAP blob uploads (clamped to server maxConcurrentUpload)",
        "help_batch_size": "Max emails per JMAP Email/import batch (clamped to server maxObjectsInSet)",
        "help_insecure": "Disable TLS certificate verification when connecting to Stalwart",
        "help_out_csv": "Output CSV path for migrated accounts and credentials",
        "help_yes": "Do not prompt for optional parameters (accept defaults)",
        "prompt_lang": "Interface language (ru/en) [ru]: ",
        "prompt_users_cfg": "Path to Kerio users.cfg [/opt/kerio/mailserver/users.cfg]: ",
        "prompt_domain_dir": "Path to Kerio domain directory (e.g., /store/mail/example.com): ",
        "prompt_domain": "Domain name to migrate [{default}]: ",
        "prompt_url": "Stalwart server URL [http://127.0.0.1:8080]: ",
        "prompt_pwd_mode": "Password mode (auto / random / default) [auto]: ",
        "prompt_active_only": "Migrate active accounts only? (y/N) [N]: ",
        "prompt_skip_mail": "Skip email import (migrate accounts and aliases only)? (y/N) [N]: ",
        "prompt_dry_run": "Run in preview mode (dry-run, no changes made)? (y/N) [N]: ",
        "prompt_concurrency": "Parallel JMAP blob uploads [4]: ",
        "prompt_batch_size": "JMAP Email/import batch size [100]: ",
        "prompt_out_csv": "Output CSV path for report and credentials [{default}]: ",
        "prompt_insecure": "Disable HTTPS TLS certificate verification? (y/N) [N]: ",
        "prompt_token": "Stalwart API token (input hidden): ",
        "prompt_default_pwd": "Default password for migrated accounts (input hidden): ",
        "err_users_cfg": "Error: users.cfg file not found at '{path}'.",
        "err_domain_dir": "Error: domain directory not found at '{path}'.",
        "err_domain": "Error: please specify a valid domain name.",
        "err_token": "Error: API token cannot be empty.",
        "err_default_pwd": "Error: password mode 'default' requires a non-empty password.",
        "err_positive_int": "Error: please enter an integer greater than 0.",
        "parsing_kerio": "\n=== Reading Kerio Connect Data ===",
        "found_users": "[OK] Found {count} users in domain '{domain}' (enabled: {active}, disabled: {disabled})",
        "no_users": "[!] No users found for domain '{domain}' in users.cfg.",
        "connecting": "\n=== Connecting to Stalwart ({url}) ===",
        "jmap_limits": "[OK] Server JMAP limits: maxSizeUpload={upload_mb:.1f} MB, maxConcurrentUpload={conc}, maxObjectsInSet={objs}, maxSizeRequest={req_mb:.1f} MB (using: workers={eff_conc}, batch={eff_batch})",
        "domain_exists": "[OK] Domain '{domain}' already exists in Stalwart (id={id})",
        "domain_created": "[+] Created domain '{domain}' in Stalwart (id={id})",
        "domain_would_create": "[DRY-RUN] Would create domain '{domain}'",
        "user_header": "\n--- User: {email} (Kerio: {orig_name}, status: {status}) ---",
        "status_active": "enabled",
        "status_disabled": "disabled",
        "user_aliases": "    Aliases    : {aliases}",
        "user_forward": "    Forwarding : mode={mode} -> {addr} (requires manual Sieve rule in Stalwart)",
        "user_pwd_info": "    Password   : {info}",
        "user_mail_scan": "    Kerio Mail : {folders} folders, {msgs} messages ({mb:.2f} MB) at {path}",
        "user_mail_missing": "    Kerio Mail : mailbox directory not found on disk",
        "user_created": "    [+] Created account '{name}' (id={id})",
        "user_updated": "    [~] Updated account '{name}' (id={id})",
        "user_would_create": "    [DRY-RUN] Would create account '{name}'",
        "user_would_update": "    [DRY-RUN] Would update account '{name}'",
        "jmap_importing": "    [>] Importing messages via JMAP (workers={conc}, batch={batch})...",
        "jmap_auth_fallback": "    [i] Switching JMAP session to direct user authentication for {email}",
        "jmap_oversize": "        [!] Skipped {file} ({mb:.1f} MB exceeds server limit {limit_mb:.1f} MB)",
        "jmap_folder": "        Folder '{src}' -> '{dst}': total={total}, imported={imported}, skipped(dups)={skipped}, errors={errors}",
        "jmap_err": "    [!] JMAP error while importing for {email}: {err}",
        "csv_saved": "\n[OK] Migration report and credentials saved to: {path} (mode 0600)",
        "summary_header": "\n=== Migration Summary ===",
        "summary_line": "Domain: {domain} | Accounts processed: {users} | Messages imported: {imported} | Duplicates skipped: {skipped} | Errors: {errors}",
        "dry_run_done": "[DRY-RUN] No changes were written to the server.",
    },
}

CURRENT_LANG = "ru"


def t(key: str, **kwargs: object) -> str:
    lang_map = MESSAGES.get(CURRENT_LANG, MESSAGES["ru"])
    template = lang_map.get(key, MESSAGES["ru"][key])
    return template.format(**kwargs) if kwargs else template


@dataclass
class KerioUser:
    orig_name: str
    username: str
    domain: str
    enabled: bool
    raw_password: str
    is_admin: bool
    fullname: str
    description: str
    quota_kb: int
    aliases: list[str] = field(default_factory=list)
    forward_mode: str = "0"
    forward_address: str = ""


@dataclass
class KerioMessageMeta:
    uid_hex: str
    eml_path: Path
    keywords: dict[str, bool]
    timestamp: int | None


class StalwartJmapClient:
    def __init__(
        self,
        base_url: str,
        auth_header: str,
        verify_tls: bool = True,
        max_retries: int = 4,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header
        self.max_retries = max_retries
        self.ssl_ctx = None
        if not verify_tls:
            self.ssl_ctx = ssl.create_default_context()
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

        self.api_url = f"{self.base_url}/jmap"
        self.upload_url_template = f"{self.base_url}/jmap/upload/{{accountId}}/"
        self.account_id = "a"
        self.admin_using = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]
        self.mail_using = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]

        self.max_size_upload = 50 * 1024 * 1024
        self.max_concurrent_upload = 4
        self.max_size_request = 10 * 1024 * 1024
        self.max_calls_in_request = 16
        self.max_objects_in_get = 500
        self.max_objects_in_set = 500

        self._init_session()

    def _raw_http(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        content_type: str | None = None,
        timeout: float = 60.0,
    ) -> dict:
        headers = {
            "Authorization": self.auth_header,
            "Accept": "application/json",
        }
        if content_type:
            headers["Content-Type"] = content_type

        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=self.ssl_ctx) as resp:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="replace")
                if e.code in (429, 502, 503, 504) and attempt < self.max_retries:
                    retry_after = e.headers.get("Retry-After")
                    delay = float(retry_after) if (retry_after and retry_after.isdigit()) else (1.5 * (2**attempt))
                    time.sleep(min(delay, 30.0))
                    continue
                raise RuntimeError(f"HTTP {e.code} {e.reason} at {url}: {err_body}") from e
            except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
                if attempt < self.max_retries:
                    time.sleep(1.5 * (2**attempt))
                    continue
                reason = getattr(e, "reason", str(e))
                raise RuntimeError(f"Connection error to {url}: {reason}") from e

        raise RuntimeError(f"Exhausted retries for {url}")

    def _init_session(self) -> None:
        session = self._raw_http("GET", f"{self.base_url}/jmap/session", timeout=20.0)
        api_url = session.get("apiUrl")
        if api_url:
            self.api_url = urllib.parse.urljoin(self.base_url + "/", api_url)

        upload_url = session.get("uploadUrl")
        if upload_url:
            self.upload_url_template = urllib.parse.urljoin(self.base_url + "/", upload_url)

        primary = session.get("primaryAccounts") or {}
        if "urn:ietf:params:jmap:core" in primary:
            self.account_id = primary["urn:ietf:params:jmap:core"]
        elif primary:
            self.account_id = next(iter(primary.values()))

        caps = session.get("capabilities") or {}
        core_caps = caps.get("urn:ietf:params:jmap:core") or {}
        if isinstance(core_caps, dict):
            self.max_size_upload = int(core_caps.get("maxSizeUpload") or self.max_size_upload)
            self.max_concurrent_upload = int(core_caps.get("maxConcurrentUpload") or self.max_concurrent_upload)
            self.max_size_request = int(core_caps.get("maxSizeRequest") or self.max_size_request)
            self.max_calls_in_request = int(core_caps.get("maxCallsInRequest") or self.max_calls_in_request)
            self.max_objects_in_get = int(core_caps.get("maxObjectsInGet") or self.max_objects_in_get)
            self.max_objects_in_set = int(core_caps.get("maxObjectsInSet") or self.max_objects_in_set)

        stalwart_caps = [c for c in caps if "stalwart" in c]
        if stalwart_caps:
            self.admin_using = ["urn:ietf:params:jmap:core"] + stalwart_caps

    def call(
        self,
        method_name: str,
        args: dict,
        account_id: str | None = None,
        using: list[str] | None = None,
    ) -> dict:
        target_acc = account_id if account_id is not None else self.account_id
        full_args = {"accountId": target_acc, **args}
        payload = json.dumps(
            {
                "using": using or self.admin_using,
                "methodCalls": [[method_name, full_args, "c0"]],
            }
        ).encode("utf-8")

        resp = self._raw_http("POST", self.api_url, body=payload, content_type="application/json")
        responses = resp.get("methodResponses") or []
        if not responses:
            raise RuntimeError(f"Empty JMAP response for {method_name}: {resp}")
        resp_name, resp_data, _ = responses[0]
        if resp_name == "error":
            raise RuntimeError(f"JMAP error in {method_name}: {json.dumps(resp_data, ensure_ascii=False)}")
        return resp_data

    def upload_blob(self, target_account_id: str, raw_bytes: bytes) -> str:
        encoded_acc = urllib.parse.quote(target_account_id, safe="")
        url = self.upload_url_template.replace("{accountId}", encoded_acc)
        resp = self._raw_http(
            "POST",
            url,
            body=raw_bytes,
            content_type="message/rfc822",
            timeout=120.0,
        )
        blob_id = resp.get("blobId")
        if not blob_id:
            raise RuntimeError(f"No blobId returned from upload endpoint: {resp}")
        return blob_id

    def get_all(self, object_type: str) -> list[dict]:
        res = self.call(f"{object_type}/get", {"ids": None})
        return res.get("list") or []

    def create(self, object_type: str, obj: dict) -> str:
        res = self.call(f"{object_type}/set", {"create": {"item": obj}})
        created = res.get("created") or {}
        if "item" in created:
            return created["item"]["id"]
        not_created = res.get("notCreated") or {}
        raise RuntimeError(
            f"Failed to create {object_type}: {json.dumps(not_created, ensure_ascii=False)}"
        )

    def update(self, object_type: str, obj_id: str, patch: dict) -> None:
        res = self.call(f"{object_type}/set", {"update": {obj_id: patch}})
        not_updated = res.get("notUpdated") or {}
        if obj_id in not_updated:
            raise RuntimeError(
                f"Failed to update {object_type} ({obj_id}): "
                f"{json.dumps(not_updated[obj_id], ensure_ascii=False)}"
            )


def parse_kerio_users(users_cfg_path: Path, target_domain: str) -> list[KerioUser]:
    raw_xml = users_cfg_path.read_text(encoding="utf-8", errors="replace")
    root = ET.fromstring(raw_xml)

    extra_aliases_by_target: dict[str, list[str]] = {}
    for alias_list in root.findall(".//list[@name='Alias']"):
        for item in alias_list.findall("listitem"):
            vars_map: dict[str, list[str]] = {}
            for var in item.findall("variable"):
                vname = var.attrib.get("name", "")
                vars_map.setdefault(vname, []).append((var.text or "").strip())
            alias_name = (vars_map.get("Name") or [""])[0].lower()
            alias_dom = (vars_map.get("Domain") or [target_domain])[0].lower()
            target_addr = (vars_map.get("MailAddress") or vars_map.get("Target") or [""])[0].lower()
            if alias_name and alias_dom == target_domain and target_addr:
                target_local = target_addr.split("@", 1)[0]
                extra_aliases_by_target.setdefault(target_local, []).append(alias_name)

    users: list[KerioUser] = []
    for user_list in root.findall(".//list[@name='User']"):
        for item in user_list.findall("listitem"):
            vars_map: dict[str, list[str]] = {}
            for var in item.findall("variable"):
                vname = var.attrib.get("name", "")
                vars_map.setdefault(vname, []).append((var.text or "").strip())

            dom = (vars_map.get("Domain") or [""])[0].lower()
            if dom != target_domain:
                continue

            orig_name = (vars_map.get("Name") or [""])[0]
            if not orig_name:
                continue
            username = orig_name.lower()

            enabled = (vars_map.get("Account_enabled") or ["1"])[0] == "1"
            raw_password = (vars_map.get("Password") or [""])[0]
            rights_str = (vars_map.get("Rights") or ["0"])[0]
            try:
                is_admin = int(rights_str) >= 2
            except ValueError:
                is_admin = False

            fullname = (vars_map.get("Fullname") or [""])[0]
            desc = (vars_map.get("Description") or [""])[0]
            qstorage_str = (vars_map.get("Qstorage") or ["0"])[0]
            try:
                quota_kb = int(qstorage_str)
            except ValueError:
                quota_kb = 0

            forward_mode = (vars_map.get("ForwardMode") or ["0"])[0]
            forward_addr = (vars_map.get("ForwardAddress") or [""])[0]

            aliases: list[str] = []
            for addr in vars_map.get("MailAddress", []):
                addr_clean = addr.strip().lower()
                if not addr_clean:
                    continue
                if "@" in addr_clean:
                    local_part, addr_dom = addr_clean.split("@", 1)
                    if addr_dom == target_domain and local_part != username:
                        aliases.append(local_part)
                elif addr_clean != username:
                    aliases.append(addr_clean)

            for extra in extra_aliases_by_target.get(username, []):
                if extra != username:
                    aliases.append(extra)

            aliases = list(dict.fromkeys(aliases))

            users.append(
                KerioUser(
                    orig_name=orig_name,
                    username=username,
                    domain=target_domain,
                    enabled=enabled,
                    raw_password=raw_password,
                    is_admin=is_admin,
                    fullname=fullname,
                    description=desc,
                    quota_kb=quota_kb,
                    aliases=aliases,
                    forward_mode=forward_mode,
                    forward_address=forward_addr,
                )
            )

    return users


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
        ):
            return pwd


def is_stalwart_compatible_secret(raw: str) -> bool:
    if not raw:
        return False
    if raw.startswith(("D3S:", "DES:", "AES:")):
        return False
    if raw.startswith("$"):
        return True
    if raw.startswith("{") and "}" in raw:
        algo = raw[1 : raw.index("}")].upper()
        return algo in {
            "ARGON2",
            "ARGON2I",
            "ARGON2ID",
            "PBKDF2",
            "SHA",
            "SSHA",
            "SHA256",
            "SSHA256",
            "SHA512",
            "SSHA512",
            "MD5",
            "CRYPT",
            "PLAIN",
            "CLEAR",
        }
    return True


def resolve_user_password(
    user: KerioUser,
    mode: str,
    default_pwd: str | None,
) -> tuple[str, str | None, str]:
    if mode == "default":
        assert default_pwd
        return default_pwd, default_pwd, "default password"

    if mode == "random":
        pwd = generate_password()
        return pwd, pwd, "generated random password"

    raw = user.raw_password
    if is_stalwart_compatible_secret(raw):
        if raw.startswith(("{", "$")):
            prefix = raw.split("}", 1)[0] + "}" if raw.startswith("{") else raw[:6] + "..."
            return raw, None, f"preserved hash ({prefix})"
        if raw.upper().startswith(("{PLAIN}", "{CLEAR}")):
            plain = raw.split("}", 1)[1]
            return plain, plain, "preserved plaintext password"
        return raw, raw, "preserved plaintext password"

    if default_pwd:
        return default_pwd, default_pwd, "D3S encrypted in Kerio -> set default password"

    pwd = generate_password()
    return pwd, pwd, "D3S encrypted in Kerio -> generated new password"


def build_description(user: KerioUser) -> str | None:
    parts = []
    if user.fullname:
        parts.append(user.fullname)
    if user.description and user.description != user.fullname:
        parts.append(user.description)
    if not user.enabled:
        parts.append("[Disabled in Kerio]")
    return " - ".join(parts) if parts else None


def ensure_domain(client: StalwartJmapClient, domain: str, dry_run: bool) -> str | None:
    for d in client.get_all("x:Domain"):
        if (d.get("name") or "").lower() == domain.lower():
            print(t("domain_exists", domain=domain, id=d["id"]))
            return d["id"]

    if dry_run:
        print(t("domain_would_create", domain=domain))
        return None

    dom_id = client.create(
        "x:Domain",
        {
            "name": domain,
            "enable": True,
            "dkimManagement": {"@type": "Automatic"},
            "reportAddressUri": "mailto:postmaster",
        },
    )
    print(t("domain_created", domain=domain, id=dom_id))
    return dom_id


def build_account_payload(
    user: KerioUser,
    domain_id: str,
    secret_value: str,
) -> dict:
    payload: dict = {
        "@type": "User",
        "name": user.username,
        "domainId": domain_id,
        "roles": {"@type": "Admin" if user.is_admin else "User"},
        "credentials": {
            "0": {
                "@type": "Password",
                "secret": secret_value,
            }
        },
    }
    desc = build_description(user)
    if desc:
        payload["description"] = desc

    if user.quota_kb > 0:
        payload["quotas"] = {"message": user.quota_kb * 1024}

    if user.aliases:
        payload["aliases"] = {
            str(i): {
                "enable": True,
                "name": alias_local,
                "domainId": domain_id,
            }
            for i, alias_local in enumerate(user.aliases)
        }

    return payload


def upsert_stalwart_account(
    client: StalwartJmapClient,
    existing_accounts: dict[str, dict],
    user: KerioUser,
    domain_id: str,
    secret_value: str,
) -> tuple[str, bool]:
    payload = build_account_payload(user, domain_id, secret_value)
    cur = existing_accounts.get(user.username)
    if cur:
        patch = {
            "roles": payload["roles"],
            "credentials": payload["credentials"],
            "aliases": payload.get("aliases", {}),
        }
        if "description" in payload:
            patch["description"] = payload["description"]
        if "quotas" in payload:
            patch["quotas"] = payload["quotas"]
        client.update("x:Account", cur["id"], patch)
        return cur["id"], False

    acc_id = client.create("x:Account", payload)
    return acc_id, True


def set_account_secret(client: StalwartJmapClient, account_id: str, secret_val: str) -> None:
    client.update(
        "x:Account",
        account_id,
        {
            "credentials": {
                "0": {
                    "@type": "Password",
                    "secret": secret_val,
                }
            }
        },
    )


def map_kerio_folder_parts(rel_parts: tuple[str, ...]) -> tuple[list[str], str | None]:
    mapped: list[str] = []
    role: str | None = None
    for idx, part in enumerate(rel_parts):
        if idx == 0 and part.lower() in KERIO_SYSTEM_FOLDER_MAP:
            norm_name, mapped_role = KERIO_SYSTEM_FOLDER_MAP[part.lower()]
            mapped.append(norm_name)
            if len(rel_parts) == 1:
                role = mapped_role
        else:
            mapped.append(part)
    return mapped, role


def parse_kerio_index_fld(folder_dir: Path) -> list[KerioMessageMeta]:
    msgs_dir = folder_dir / "#msgs"
    if not msgs_dir.is_dir():
        return []

    index_file = folder_dir / "index.fld"
    metas: list[KerioMessageMeta] = []
    seen_files: set[str] = set()

    if index_file.is_file():
        content = index_file.read_text(encoding="utf-8", errors="replace")
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line.startswith("U"):
                continue

            tokens = line.split()
            uid_hex = ""
            flags_int = 0
            ts_int: int | None = None
            msg_class = "IPM.Note"

            for tok in tokens:
                if tok.startswith("U") and len(tok) > 1:
                    uid_hex = tok[1:]
                elif tok.startswith("F") and len(tok) > 1:
                    try:
                        flags_int = int(tok[1:], 16)
                    except ValueError:
                        flags_int = 0
                elif tok.startswith("D") and len(tok) > 1:
                    try:
                        ts_int = int(tok[1:], 16)
                    except ValueError:
                        ts_int = None
                elif tok.startswith("C") and len(tok) > 1:
                    msg_class = tok[1:]

            if not msg_class.lower().startswith("ipm.note"):
                continue

            if not uid_hex:
                continue

            eml_name = f"{uid_hex.lower()}.eml"
            eml_path = msgs_dir / eml_name
            if not eml_path.is_file():
                eml_path = msgs_dir / f"{uid_hex.upper()}.eml"
            if not eml_path.is_file():
                continue

            seen_files.add(eml_path.name.lower())

            keywords: dict[str, bool] = {}
            if flags_int & 0x01:
                keywords["$seen"] = True
            if flags_int & 0x02:
                keywords["$answered"] = True
            if flags_int & 0x04:
                keywords["$flagged"] = True
            if flags_int & 0x10:
                keywords["$draft"] = True

            metas.append(
                KerioMessageMeta(
                    uid_hex=uid_hex,
                    eml_path=eml_path,
                    keywords=keywords,
                    timestamp=ts_int,
                )
            )

    for eml_path in sorted(msgs_dir.glob("*.eml")):
        if eml_path.name.lower() not in seen_files:
            mtime = int(eml_path.stat().st_mtime)
            metas.append(
                KerioMessageMeta(
                    uid_hex=eml_path.stem,
                    eml_path=eml_path,
                    keywords={},
                    timestamp=mtime,
                )
            )

    return metas


def scan_user_mailbox(user_dir: Path) -> list[tuple[str, list[str], str | None, list[KerioMessageMeta]]]:
    if not user_dir.is_dir():
        return []

    results: list[tuple[str, list[str], str | None, list[KerioMessageMeta]]] = []
    for root, dirs, _files in os.walk(user_dir):
        root_path = Path(root)
        rel = root_path.relative_to(user_dir)

        dirs[:] = [
            d
            for d in sorted(dirs)
            if not d.startswith(("__", "."))
            and not d.startswith("#")
            and d.lower() not in KERIO_SKIP_FOLDERS
        ]

        if rel == Path("."):
            continue

        top_name = rel.parts[0].lower()
        if top_name.startswith(("__", ".")) or top_name in KERIO_SKIP_FOLDERS:
            continue

        msgs_dir = root_path / "#msgs"
        if msgs_dir.is_dir():
            src_name = "/".join(rel.parts)
            mapped_parts, role = map_kerio_folder_parts(rel.parts)
            metas = parse_kerio_index_fld(root_path)
            results.append((src_name, mapped_parts, role, metas))

    results.sort(key=lambda x: (0 if x[2] == "inbox" else 1, len(x[1]), "/".join(x[1]).lower()))
    return results


def normalize_message_id(mid: str | None) -> str | None:
    if not mid:
        return None
    cleaned = mid.strip().strip("<>").strip()
    return cleaned.lower() if cleaned else None


def extract_message_id_from_file(eml_path: Path) -> str | None:
    try:
        with eml_path.open("rb") as f:
            head = f.read(65536)
        msg = email.message_from_bytes(head, policy=email.policy.compat32)
        return normalize_message_id(msg.get("Message-ID"))
    except Exception:
        return None


def ensure_jmap_mailbox_tree(
    mail_client: StalwartJmapClient,
    target_account_id: str,
    folders: list[tuple[str, list[str], str | None, list[KerioMessageMeta]]],
) -> dict[tuple[str, ...], str]:
    res = mail_client.call(
        "Mailbox/get",
        {"ids": None},
        account_id=target_account_id,
        using=mail_client.mail_using,
    )
    existing_list = res.get("list") or []

    by_role: dict[str, str] = {}
    by_parent_and_name: dict[tuple[str | None, str], str] = {}
    for mb in existing_list:
        mb_id = mb["id"]
        role = mb.get("role")
        if role:
            by_role[role.lower()] = mb_id
        parent_id = mb.get("parentId")
        name_key = (mb.get("name") or "").lower()
        by_parent_and_name[(parent_id, name_key)] = mb_id

    resolved: dict[tuple[str, ...], str] = {}

    needed_prefixes: list[tuple[tuple[str, ...], str | None]] = []
    seen_prefixes: set[tuple[str, ...]] = set()
    for _src, parts, role, _metas in folders:
        for depth in range(1, len(parts) + 1):
            prefix = tuple(parts[:depth])
            if prefix not in seen_prefixes:
                seen_prefixes.add(prefix)
                prefix_role = role if depth == len(parts) else None
                if depth == 1 and prefix[0].lower() in KERIO_SYSTEM_FOLDER_MAP:
                    prefix_role = KERIO_SYSTEM_FOLDER_MAP[prefix[0].lower()][1]
                needed_prefixes.append((prefix, prefix_role))

    needed_prefixes.sort(key=lambda x: len(x[0]))

    max_depth = max((len(p) for p, _ in needed_prefixes), default=0)
    for depth in range(1, max_depth + 1):
        to_create: dict[str, dict] = {}
        key_to_prefix: dict[str, tuple[str, ...]] = {}

        for idx, (prefix, prefix_role) in enumerate(needed_prefixes):
            if len(prefix) != depth or prefix in resolved:
                continue

            if depth == 1 and prefix_role and prefix_role in by_role:
                resolved[prefix] = by_role[prefix_role]
                continue

            parent_id = resolved.get(prefix[:-1]) if depth > 1 else None
            name = prefix[-1]
            lookup = (parent_id, name.lower())
            if lookup in by_parent_and_name:
                resolved[prefix] = by_parent_and_name[lookup]
                continue

            cid = f"mb_{depth}_{idx}"
            obj: dict = {
                "name": name,
                "parentId": parent_id,
            }
            if prefix_role and prefix_role not in by_role:
                obj["role"] = prefix_role
            to_create[cid] = obj
            key_to_prefix[cid] = prefix

        if to_create:
            batch_limit = max(1, min(mail_client.max_objects_in_set, 100))
            cids = list(to_create.keys())
            for start in range(0, len(cids), batch_limit):
                sub = {k: to_create[k] for k in cids[start : start + batch_limit]}
                set_res = mail_client.call(
                    "Mailbox/set",
                    {"create": sub},
                    account_id=target_account_id,
                    using=mail_client.mail_using,
                )
                created = set_res.get("created") or {}
                for cid, info in created.items():
                    prefix = key_to_prefix[cid]
                    mb_id = info["id"]
                    resolved[prefix] = mb_id
                    parent_id = resolved.get(prefix[:-1]) if len(prefix) > 1 else None
                    by_parent_and_name[(parent_id, prefix[-1].lower())] = mb_id
                    if "role" in sub[cid]:
                        by_role[sub[cid]["role"]] = mb_id

    return resolved


def fetch_existing_jmap_message_ids(
    mail_client: StalwartJmapClient,
    target_account_id: str,
    mailbox_id: str,
) -> set[str]:
    existing: set[str] = set()
    page_limit = max(50, min(mail_client.max_objects_in_get, 500))
    position = 0

    while True:
        q_res = mail_client.call(
            "Email/query",
            {
                "filter": {"inMailbox": mailbox_id},
                "position": position,
                "limit": page_limit,
            },
            account_id=target_account_id,
            using=mail_client.mail_using,
        )
        ids = q_res.get("ids") or []
        if not ids:
            break

        g_res = mail_client.call(
            "Email/get",
            {
                "ids": ids,
                "properties": ["messageId"],
            },
            account_id=target_account_id,
            using=mail_client.mail_using,
        )
        for item in g_res.get("list") or []:
            mids = item.get("messageId") or []
            if isinstance(mids, str):
                mids = [mids]
            for m in mids:
                norm = normalize_message_id(m)
                if norm:
                    existing.add(norm)

        if len(ids) < page_limit:
            break
        position += len(ids)

    return existing


def format_rfc3339_utc(ts: int | None) -> str | None:
    if ts is None or ts <= 0 or ts > 4102444800:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def import_mailbox_via_jmap(
    mail_client: StalwartJmapClient,
    target_account_id: str,
    folders: list[tuple[str, list[str], str | None, list[KerioMessageMeta]]],
    concurrency: int,
    batch_size: int,
) -> tuple[int, int, int]:
    eff_workers = max(1, min(concurrency, mail_client.max_concurrent_upload))
    eff_batch = max(1, min(batch_size, mail_client.max_objects_in_set))
    max_req_bytes = int(mail_client.max_size_request * 0.75)

    mailbox_map = ensure_jmap_mailbox_tree(mail_client, target_account_id, folders)

    total_imported = 0
    total_skipped = 0
    total_errors = 0

    for src_folder, mapped_parts, _role, metas in folders:
        dst_label = "/".join(mapped_parts)
        mailbox_id = mailbox_map.get(tuple(mapped_parts))
        if not mailbox_id:
            total_errors += len(metas)
            print(
                t(
                    "jmap_folder",
                    src=src_folder,
                    dst=dst_label,
                    total=len(metas),
                    imported=0,
                    skipped=0,
                    errors=len(metas),
                )
            )
            continue

        existing_mids = fetch_existing_jmap_message_ids(mail_client, target_account_id, mailbox_id)

        f_imported = 0
        f_skipped = 0
        f_errors = 0

        to_upload: list[tuple[KerioMessageMeta, str | None]] = []
        for meta in metas:
            try:
                fsize = meta.eml_path.stat().st_size
            except OSError:
                f_errors += 1
                continue

            if fsize > mail_client.max_size_upload:
                f_errors += 1
                print(
                    t(
                        "jmap_oversize",
                        file=meta.eml_path.name,
                        mb=fsize / (1024 * 1024),
                        limit_mb=mail_client.max_size_upload / (1024 * 1024),
                    )
                )
                continue

            mid = extract_message_id_from_file(meta.eml_path)
            if mid and mid in existing_mids:
                f_skipped += 1
                continue

            to_upload.append((meta, mid))

        wave_size = max(eff_batch, eff_workers * 4)
        for wave_start in range(0, len(to_upload), wave_size):
            wave = to_upload[wave_start : wave_start + wave_size]

            def _upload_one(item: tuple[KerioMessageMeta, str | None]) -> tuple[KerioMessageMeta, str | None, str | None]:
                m_meta, m_mid = item
                try:
                    raw = m_meta.eml_path.read_bytes()
                    crlf_bytes = re.sub(rb"\r?\n", b"\r\n", raw)
                    b_id = mail_client.upload_blob(target_account_id, crlf_bytes)
                    return m_meta, m_mid, b_id
                except Exception:
                    return m_meta, m_mid, None

            uploaded_items: list[tuple[KerioMessageMeta, str | None, str]] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=eff_workers) as pool:
                for m_meta, m_mid, blob_id in pool.map(_upload_one, wave):
                    if blob_id:
                        uploaded_items.append((m_meta, m_mid, blob_id))
                    else:
                        f_errors += 1

            current_emails: dict[str, dict] = {}
            current_mids: dict[str, str | None] = {}
            approx_json_bytes = 256

            def _flush_import_batch() -> None:
                nonlocal f_imported, f_errors, current_emails, current_mids, approx_json_bytes
                if not current_emails:
                    return
                try:
                    imp_res = mail_client.call(
                        "Email/import",
                        {"emails": current_emails},
                        account_id=target_account_id,
                        using=mail_client.mail_using,
                    )
                    created = imp_res.get("created") or {}
                    not_created = imp_res.get("notCreated") or {}
                    for k in created:
                        f_imported += 1
                        mid_val = current_mids.get(k)
                        if mid_val:
                            existing_mids.add(mid_val)
                    f_errors += len(not_created)
                except Exception:
                    f_errors += len(current_emails)
                finally:
                    current_emails = {}
                    current_mids = {}
                    approx_json_bytes = 256

            for idx, (m_meta, m_mid, blob_id) in enumerate(uploaded_items):
                key = f"m{idx}"
                entry: dict = {
                    "blobId": blob_id,
                    "mailboxIds": {mailbox_id: True},
                    "keywords": m_meta.keywords,
                }
                rec_at = format_rfc3339_utc(m_meta.timestamp)
                if rec_at:
                    entry["receivedAt"] = rec_at

                entry_size = len(json.dumps(entry)) + 16
                if len(current_emails) >= eff_batch or (approx_json_bytes + entry_size > max_req_bytes):
                    _flush_import_batch()

                current_emails[key] = entry
                current_mids[key] = m_mid
                approx_json_bytes += entry_size

            _flush_import_batch()

        total_imported += f_imported
        total_skipped += f_skipped
        total_errors += f_errors

        print(
            t(
                "jmap_folder",
                src=src_folder,
                dst=dst_label,
                total=len(metas),
                imported=f_imported,
                skipped=f_skipped,
                errors=f_errors,
            )
        )

    return total_imported, total_skipped, total_errors


def build_case_insensitive_dir_map(domain_dir: Path) -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    if not domain_dir.is_dir():
        return mapping
    for entry in domain_dir.iterdir():
        if entry.is_dir() and not entry.name.startswith(("#", ".")):
            mapping[entry.name.lower()] = entry
    return mapping


def prompt_bool(prompt_text: str, default: bool = False) -> bool:
    raw = input(prompt_text).strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes", "д", "да", "1", "true")


def prompt_positive_int(prompt_text: str, default: int) -> int:
    while True:
        raw = input(prompt_text).strip()
        if not raw:
            return default
        try:
            val = int(raw)
            if val > 0:
                return val
        except ValueError:
            pass
        print(t("err_positive_int"), file=sys.stderr)


def main() -> int:
    global CURRENT_LANG

    env_lang = os.environ.get("MIGRATION_LANG", os.environ.get("PROVISION_LANG", "")).strip().lower()

    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--lang", choices=["ru", "en"], default=None)
    pre_args, _ = pre_parser.parse_known_args()

    if pre_args.lang in MESSAGES:
        CURRENT_LANG = pre_args.lang
    elif env_lang in MESSAGES:
        CURRENT_LANG = env_lang
    else:
        CURRENT_LANG = "ru"

    parser = argparse.ArgumentParser(description=t("cli_desc"))
    parser.add_argument("--lang", choices=["ru", "en"], default=None, help=t("help_lang"))
    parser.add_argument("--users-cfg", default=None, help=t("help_users_cfg"))
    parser.add_argument("--domain-dir", default=None, help=t("help_domain_dir"))
    parser.add_argument("--domain", default=None, help=t("help_domain"))
    parser.add_argument("--url", default=None, help=t("help_url"))
    parser.add_argument(
        "--password-mode",
        choices=["auto", "random", "default"],
        default=None,
        help=t("help_pwd_mode"),
    )
    parser.add_argument("--active-only", action=argparse.BooleanOptionalAction, default=None, help=t("help_active_only"))
    parser.add_argument("--skip-mail", action=argparse.BooleanOptionalAction, default=None, help=t("help_skip_mail"))
    parser.add_argument("--dry-run", action=argparse.BooleanOptionalAction, default=None, help=t("help_dry_run"))
    parser.add_argument("--concurrency", type=int, default=None, help=t("help_concurrency"))
    parser.add_argument("--batch-size", type=int, default=None, help=t("help_batch_size"))
    parser.add_argument("--insecure", action=argparse.BooleanOptionalAction, default=None, help=t("help_insecure"))
    parser.add_argument("--out-csv", default=None, help=t("help_out_csv"))
    parser.add_argument("-y", "--yes", action="store_true", help=t("help_yes"))
    args = parser.parse_args()

    if args.lang in MESSAGES:
        CURRENT_LANG = args.lang
    elif env_lang in MESSAGES:
        CURRENT_LANG = env_lang
    elif not args.yes:
        chosen_lang = input(t("prompt_lang")).strip().lower()
        if chosen_lang in MESSAGES:
            CURRENT_LANG = chosen_lang

    if args.users_cfg is not None:
        users_cfg_input = args.users_cfg
    elif args.yes:
        users_cfg_input = "/opt/kerio/mailserver/users.cfg"
    else:
        users_cfg_input = input(t("prompt_users_cfg")).strip() or "/opt/kerio/mailserver/users.cfg"

    users_cfg_path = Path(users_cfg_input).expanduser()
    if not users_cfg_path.is_file():
        print(t("err_users_cfg", path=users_cfg_path), file=sys.stderr)
        return 1

    if args.domain_dir is not None:
        domain_dir_input = args.domain_dir
    else:
        domain_dir_input = input(t("prompt_domain_dir")).strip()

    domain_dir_path = Path(domain_dir_input).expanduser()
    if not domain_dir_input or not domain_dir_path.is_dir():
        print(t("err_domain_dir", path=domain_dir_path), file=sys.stderr)
        return 1

    inferred_domain = domain_dir_path.name.lower().rstrip(".")
    if args.domain is not None:
        domain = args.domain.lower().rstrip(".")
    elif args.yes:
        domain = inferred_domain
    else:
        domain = (input(t("prompt_domain", default=inferred_domain)).strip() or inferred_domain).lower().rstrip(".")

    if not domain or "." not in domain:
        print(t("err_domain"), file=sys.stderr)
        return 1

    if args.url is not None:
        stalwart_url = args.url
    elif args.yes:
        stalwart_url = "http://127.0.0.1:8080"
    else:
        stalwart_url = input(t("prompt_url")).strip() or "http://127.0.0.1:8080"

    if args.insecure is not None:
        insecure = args.insecure
    elif args.yes or not stalwart_url.lower().startswith("https://"):
        insecure = False
    else:
        insecure = prompt_bool(t("prompt_insecure"), default=False)

    if args.password_mode is not None:
        password_mode = args.password_mode
    elif args.yes:
        password_mode = "auto"
    else:
        raw_pm = input(t("prompt_pwd_mode")).strip().lower() or "auto"
        password_mode = raw_pm if raw_pm in ("auto", "random", "default") else "auto"

    if args.active_only is not None:
        active_only = args.active_only
    elif args.yes:
        active_only = False
    else:
        active_only = prompt_bool(t("prompt_active_only"), default=False)

    if args.skip_mail is not None:
        skip_mail = args.skip_mail
    elif args.yes:
        skip_mail = False
    else:
        skip_mail = prompt_bool(t("prompt_skip_mail"), default=False)

    if args.dry_run is not None:
        dry_run = args.dry_run
    elif args.yes:
        dry_run = False
    else:
        dry_run = prompt_bool(t("prompt_dry_run"), default=False)

    if args.concurrency is not None:
        concurrency = max(1, args.concurrency)
    elif args.yes or skip_mail or dry_run:
        concurrency = 4
    else:
        concurrency = prompt_positive_int(t("prompt_concurrency"), default=4)

    if args.batch_size is not None:
        batch_size = max(1, args.batch_size)
    elif args.yes or skip_mail or dry_run:
        batch_size = 100
    else:
        batch_size = prompt_positive_int(t("prompt_batch_size"), default=100)

    default_csv = f"migrated_accounts_{domain}.csv"
    if args.out_csv is not None:
        out_csv_str = args.out_csv
    elif args.yes or dry_run:
        out_csv_str = default_csv
    else:
        out_csv_str = input(t("prompt_out_csv", default=default_csv)).strip() or default_csv

    default_pwd: str | None = None
    if password_mode == "default" and not dry_run:
        default_pwd = getpass.getpass(t("prompt_default_pwd")).strip()
        if not default_pwd:
            print(t("err_default_pwd"), file=sys.stderr)
            return 1

    token = getpass.getpass(t("prompt_token")).strip()
    if not token:
        print(t("err_token"), file=sys.stderr)
        return 1

    print(t("parsing_kerio"))
    all_users = parse_kerio_users(users_cfg_path, domain)
    active_count = sum(1 for u in all_users if u.enabled)
    disabled_count = len(all_users) - active_count
    print(t("found_users", domain=domain, count=len(all_users), active=active_count, disabled=disabled_count))

    users = [u for u in all_users if (u.enabled or not active_only)]
    if not users:
        print(t("no_users", domain=domain))
        return 0

    dir_map = build_case_insensitive_dir_map(domain_dir_path)

    print(t("connecting", url=stalwart_url))
    client = StalwartJmapClient(stalwart_url, f"Bearer {token}", verify_tls=not insecure)
    eff_workers = max(1, min(concurrency, client.max_concurrent_upload))
    eff_batch = max(1, min(batch_size, client.max_objects_in_set))
    print(
        t(
            "jmap_limits",
            upload_mb=client.max_size_upload / (1024 * 1024),
            conc=client.max_concurrent_upload,
            objs=client.max_objects_in_set,
            req_mb=client.max_size_request / (1024 * 1024),
            eff_conc=eff_workers,
            eff_batch=eff_batch,
        )
    )

    domain_id = ensure_domain(client, domain, dry_run=dry_run)

    existing_accounts: dict[str, dict] = {}
    for acc in client.get_all("x:Account"):
        if acc.get("@type") == "User" and acc.get("domainId") == domain_id:
            uname = (acc.get("name") or "").lower()
            if uname:
                existing_accounts[uname] = acc

    csv_rows: list[dict[str, str]] = []
    total_imported = 0
    total_skipped = 0
    total_errors = 0

    for user in users:
        email_addr = f"{user.username}@{domain}"
        status_str = t("status_active") if user.enabled else t("status_disabled")
        print(t("user_header", email=email_addr, orig_name=user.orig_name, status=status_str))

        if user.aliases:
            print(t("user_aliases", aliases=", ".join(f"{a}@{domain}" for a in user.aliases)))

        if user.forward_mode != "0" and user.forward_address:
            print(t("user_forward", mode=user.forward_mode, addr=user.forward_address))

        final_secret, plain_pwd, pwd_info = resolve_user_password(user, password_mode, default_pwd)
        print(t("user_pwd_info", info=pwd_info))

        mbox_dir = dir_map.get(user.username) or dir_map.get(user.orig_name.lower())
        folders: list[tuple[str, list[str], str | None, list[KerioMessageMeta]]] = []
        if mbox_dir and mbox_dir.is_dir():
            folders = scan_user_mailbox(mbox_dir)
            msg_count = sum(len(m) for _, _, _, m in folders)
            total_bytes = sum(
                meta.eml_path.stat().st_size
                for _, _, _, metas in folders
                for meta in metas
            )
            print(
                t(
                    "user_mail_scan",
                    folders=len(folders),
                    msgs=msg_count,
                    mb=total_bytes / (1024 * 1024),
                    path=mbox_dir,
                )
            )
        else:
            print(t("user_mail_missing"))

        csv_rows.append(
            {
                "email": email_addr,
                "kerio_name": user.orig_name,
                "enabled": "1" if user.enabled else "0",
                "role": "Admin" if user.is_admin else "User",
                "aliases": ";".join(f"{a}@{domain}" for a in user.aliases),
                "password": plain_pwd or "(hash preserved)",
                "forward_mode": user.forward_mode,
                "forward_address": user.forward_address,
            }
        )

        if dry_run:
            if user.username in existing_accounts:
                print(t("user_would_update", name=user.username))
            else:
                print(t("user_would_create", name=user.username))
            continue

        assert domain_id is not None
        acc_id, created = upsert_stalwart_account(
            client,
            existing_accounts,
            user,
            domain_id,
            final_secret,
        )
        if created:
            print(t("user_created", name=user.username, id=acc_id))
        else:
            print(t("user_updated", name=user.username, id=acc_id))

        if not skip_mail and folders:
            print(t("jmap_importing", conc=eff_workers, batch=eff_batch))
            temp_pwd_set = False
            try:
                try:
                    imp, skp, err = import_mailbox_via_jmap(
                        mail_client=client,
                        target_account_id=acc_id,
                        folders=folders,
                        concurrency=eff_workers,
                        batch_size=eff_batch,
                    )
                except RuntimeError as admin_jmap_err:
                    if not any(code in str(admin_jmap_err) for code in ("403", "forbidden", "accountNotFound")):
                        raise
                    print(t("jmap_auth_fallback", email=email_addr))
                    login_pwd = plain_pwd
                    if not login_pwd:
                        login_pwd = generate_password(24)
                        set_account_secret(client, acc_id, login_pwd)
                        temp_pwd_set = True

                    basic_tok = base64.b64encode(f"{email_addr}:{login_pwd}".encode("utf-8")).decode("ascii")
                    user_client = StalwartJmapClient(
                        stalwart_url,
                        f"Basic {basic_tok}",
                        verify_tls=not insecure,
                    )
                    imp, skp, err = import_mailbox_via_jmap(
                        mail_client=user_client,
                        target_account_id=acc_id,
                        folders=folders,
                        concurrency=eff_workers,
                        batch_size=eff_batch,
                    )

                total_imported += imp
                total_skipped += skp
                total_errors += err
            except Exception as e:
                total_errors += 1
                print(t("jmap_err", email=email_addr, err=e))
            finally:
                if temp_pwd_set:
                    set_account_secret(client, acc_id, final_secret)

    print(t("summary_header"))
    print(
        t(
            "summary_line",
            domain=domain,
            users=len(users),
            imported=total_imported,
            skipped=total_skipped,
            errors=total_errors,
        )
    )

    if dry_run:
        print(t("dry_run_done"))
        return 0

    out_csv = Path(out_csv_str)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "email",
                "kerio_name",
                "enabled",
                "role",
                "aliases",
                "password",
                "forward_mode",
                "forward_address",
            ],
        )
        writer.writeheader()
        writer.writerows(csv_rows)
    os.chmod(out_csv, 0o600)
    print(t("csv_saved", path=out_csv.resolve()))

    return 0 if total_errors == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
