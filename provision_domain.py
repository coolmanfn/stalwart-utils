#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


LISTENERS_SPEC = [
    ("smtp", 25, "smtp", False),
    ("submission", 587, "smtp", False),
    ("submissions", 465, "smtp", True),
    ("imap", 143, "imap", False),
    ("imaps", 993, "imap", True),
    ("pop3", 110, "pop3", False),
    ("pop3s", 995, "pop3", True),
    ("sieve", 4190, "manageSieve", False),
    ("https", 443, "http", True),
]

MESSAGES: dict[str, dict[str, str]] = {
    "ru": {
        "cli_desc": "Настройка и/или проверка Listeners, правил MTA и TLS-сертификатов в Stalwart",
        "help_lang": "Язык вывода интерфейса: ru или en (по умолчанию: ru)",
        "help_check": "Только проверка без создания/изменения настроек в Stalwart",
        "help_url": "URL сервера Stalwart (например, https://mail.kvit.tv)",
        "help_domain": "Почтовый домен (например, born2fly.space)",
        "help_ip": "Локальный IP-адрес в Docker для домена (например, 172.28.0.13)",
        "help_hostname": "Почтовый хостнейм для EHLO/баннера (по умолчанию mail.<domain>)",
        "help_probe": "Хост/публичный IP для проверки портов (по умолчанию auto)",
        "help_cert": "Явный ID сертификата",
        "help_insecure": "Не проверять TLS-сертификат самого API Stalwart",
        "domain_exists": "[OK] Домен '{domain}' уже существует ({id})",
        "domain_created": "[+] Создан домен '{domain}' ({id})",
        "listener_updated": "[~] Обновлён listener '{name}' ({bind}, cert={cert})",
        "listener_ok": "[OK] Listener '{name}' уже настроен ({bind})",
        "listener_created": "[+] Создан listener '{name}' -> {bind} ({lid}, cert={cert})",
        "listener_bind_conflict": "[!] Внимание: адрес {bind} уже занят другим listener '{other}' ({oid}), создание '{name}' пропущено",
        "role_updated": "[~] Обновлён список listeners в x:ServerRole ({id})",
        "role_warn": "[!] Предупреждение при проверке x:ServerRole: {err}",
        "mta_inbound": "[+] Настроено входящее MTA приветствие для {ip} -> {host}",
        "mta_strategy_updated": "[~] Обновлена исходящая стратегия '{name}' (IP={ip}, EHLO={host})",
        "mta_strategy_created": "[+] Создана исходящая стратегия '{name}' ({sid}, IP={ip}, EHLO={host})",
        "mta_outbound": "[+] Настроена исходящая маршрутизация MTA: {cond} -> '{name}'",
        "reload_ok": "[OK] Конфигурация Stalwart перезагружена (ReloadSettings)",
        "reload_warn": "[!] Не удалось вызвать ReloadSettings через API ({err}). Перезагрузите конфигурацию в WebUI.",
        "audit_header": "\n=== Аудит конфигурации в Stalwart API (read-only) ===",
        "audit_domain_pass": "[PASS] x:Domain '{domain}' найден (id={id}, enable={enable})",
        "audit_domain_fail": "[FAIL] x:Domain '{domain}' не найден",
        "audit_cert_pass": "[PASS] x:Certificate для {host}/{domain} найден (id={id})",
        "audit_cert_fail": "[FAIL] x:Certificate для {host}/{domain} не найден",
        "audit_listener_missing": "[FAIL] Listener '{name}' отсутствует",
        "issue_bind": "bind={binds} (ожидался {expected})",
        "issue_proto": "protocol={actual} (ожидался {expected})",
        "issue_tls": "implicitTls={actual} (ожидался {expected})",
        "issue_cert": "defaultCertificateId={actual} (ожидался {expected})",
        "audit_listener_fail": "[FAIL] Listener '{name}' ({id}): {issues}",
        "audit_listener_pass": "[PASS] Listener '{name}' ({id}) -> binds={binds}, cert={cert}",
        "audit_connect_pass": "[PASS] x:MtaStageConnect содержит правило для {host}",
        "audit_connect_fail": "[FAIL] x:MtaStageConnect не содержит правило для {host} / {ip}",
        "audit_strategy_pass": "[PASS] x:MtaConnectionStrategy '{name}' найдена",
        "audit_strategy_fail": "[FAIL] x:MtaConnectionStrategy '{name}' отсутствует",
        "audit_outbound_pass": "[PASS] x:MtaOutboundStrategy направляет '{domain}' в '{name}'",
        "audit_outbound_fail": "[FAIL] x:MtaOutboundStrategy не привязывает '{domain}' к '{name}'",
        "probe_fallback": "[i] Локальный Docker IP {ip} недоступен с этой машины — проверяем через {host}",
        "verify_header": "\n=== Проверка всех сервисов и TLS-сертификатов на {target} (с SNI и без SNI) ===",
        "verify_banner_warn": "       [!] Ожидался хостнейм '{host}' в SMTP-баннере",
        "verify_cert_warn": "       [!] Сертификат не совпадает с доменом '{domain}' / '{host}'",
        "verify_err": "[FAIL] {name:<26} {target}:{port:<5} -> Ошибка: {err}",
        "prompt_domain": "Почтовый домен (например, born2fly.space): ",
        "err_domain": "Ошибка: укажите корректное доменное имя.",
        "prompt_hostname": "Почтовый хостнейм для баннера/EHLO [{default}]: ",
        "err_ip": "Ошибка: некорректный IP-адрес '{ip}'.",
        "prompt_token_ro": "API токен Stalwart для read-only аудита (Enter — пропустить): ",
        "connecting_ro": "\nПодключение к {url} (режим только чтения)...",
        "check_summary_label": "\nИтог проверки:",
        "check_pass": "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ",
        "check_fail": "ЕСТЬ ЗАМЕЧАНИЯ (см. вывод выше)",
        "prompt_url": "URL сервера Stalwart [http://127.0.0.1:8080]: ",
        "prompt_ip": "Локальный IP-адрес в Docker (например, 172.28.0.13): ",
        "prompt_token": "API токен Stalwart (ввод скрыт): ",
        "err_token": "Ошибка: API токен не может быть пустым.",
        "connecting": "\nПодключение к {url}...",
        "cert_found": "[OK] Найден сертификат для {host}/{domain}: {id}",
        "cert_missing": (
            "[!] Сертификат для {host} или *.{domain} пока не найден в x:Certificate.\n"
            "    Listeners будут созданы с глобальным сертификатом по умолчанию."
        ),
        "run_summary_label": "\nИтог:",
        "run_pass": "ВСЕ СЕРВИСЫ ПРОШЛИ ПРОВЕРКУ",
        "run_fail": "ЕСТЬ ЗАМЕЧАНИЯ (см. вывод выше)",
    },
    "en": {
        "cli_desc": "Provision and/or verify Stalwart NetworkListeners, MTA routing rules, and TLS certificates",
        "help_lang": "Output language: ru or en (default: ru)",
        "help_check": "Run verification/audit only without creating or modifying settings in Stalwart",
        "help_url": "Stalwart server URL (e.g., https://mail.example.com)",
        "help_domain": "Mail domain (e.g., example.com)",
        "help_ip": "Local Docker IP address bound to this domain (e.g., 172.28.0.13)",
        "help_hostname": "Mail hostname for EHLO/banner (default: mail.<domain>)",
        "help_probe": "Target host or public IP for port/TLS probing (default: auto)",
        "help_cert": "Explicit certificate object ID",
        "help_insecure": "Disable TLS certificate verification for the Stalwart API endpoint",
        "domain_exists": "[OK] Domain '{domain}' already exists ({id})",
        "domain_created": "[+] Created domain '{domain}' ({id})",
        "listener_updated": "[~] Updated listener '{name}' ({bind}, cert={cert})",
        "listener_ok": "[OK] Listener '{name}' is already configured ({bind})",
        "listener_created": "[+] Created listener '{name}' -> {bind} ({lid}, cert={cert})",
        "listener_bind_conflict": "[!] Warning: {bind} is already bound by another listener '{other}' ({oid}), skipping '{name}'",
        "role_updated": "[~] Updated listeners list in x:ServerRole ({id})",
        "role_warn": "[!] Warning while checking x:ServerRole: {err}",
        "mta_inbound": "[+] Configured inbound MTA greeting for {ip} -> {host}",
        "mta_strategy_updated": "[~] Updated outbound strategy '{name}' (IP={ip}, EHLO={host})",
        "mta_strategy_created": "[+] Created outbound strategy '{name}' ({sid}, IP={ip}, EHLO={host})",
        "mta_outbound": "[+] Configured outbound MTA routing: {cond} -> '{name}'",
        "reload_ok": "[OK] Stalwart configuration reloaded (ReloadSettings)",
        "reload_warn": "[!] Failed to trigger ReloadSettings via API ({err}). Please reload configuration in WebUI.",
        "audit_header": "\n=== Auditing configuration in Stalwart API (read-only) ===",
        "audit_domain_pass": "[PASS] x:Domain '{domain}' found (id={id}, enable={enable})",
        "audit_domain_fail": "[FAIL] x:Domain '{domain}' not found",
        "audit_cert_pass": "[PASS] x:Certificate for {host}/{domain} found (id={id})",
        "audit_cert_fail": "[FAIL] x:Certificate for {host}/{domain} not found",
        "audit_listener_missing": "[FAIL] Listener '{name}' is missing",
        "issue_bind": "bind={binds} (expected {expected})",
        "issue_proto": "protocol={actual} (expected {expected})",
        "issue_tls": "implicitTls={actual} (expected {expected})",
        "issue_cert": "defaultCertificateId={actual} (expected {expected})",
        "audit_listener_fail": "[FAIL] Listener '{name}' ({id}): {issues}",
        "audit_listener_pass": "[PASS] Listener '{name}' ({id}) -> binds={binds}, cert={cert}",
        "audit_connect_pass": "[PASS] x:MtaStageConnect contains rule for {host}",
        "audit_connect_fail": "[FAIL] x:MtaStageConnect does not contain rule for {host} / {ip}",
        "audit_strategy_pass": "[PASS] x:MtaConnectionStrategy '{name}' found",
        "audit_strategy_fail": "[FAIL] x:MtaConnectionStrategy '{name}' is missing",
        "audit_outbound_pass": "[PASS] x:MtaOutboundStrategy routes '{domain}' to '{name}'",
        "audit_outbound_fail": "[FAIL] x:MtaOutboundStrategy does not bind '{domain}' to '{name}'",
        "probe_fallback": "[i] Local Docker IP {ip} is unreachable from this host — probing via {host}",
        "verify_header": "\n=== Verifying all services and TLS certificates on {target} (with SNI and without SNI) ===",
        "verify_banner_warn": "       [!] Expected hostname '{host}' in SMTP banner",
        "verify_cert_warn": "       [!] Certificate does not match domain '{domain}' / '{host}'",
        "verify_err": "[FAIL] {name:<26} {target}:{port:<5} -> Error: {err}",
        "prompt_domain": "Mail domain (e.g., example.com): ",
        "err_domain": "Error: please provide a valid domain name.",
        "prompt_hostname": "Mail hostname for banner/EHLO [{default}]: ",
        "err_ip": "Error: invalid IP address '{ip}'.",
        "prompt_token_ro": "Stalwart API token for read-only audit (Enter to skip): ",
        "connecting_ro": "\nConnecting to {url} (read-only mode)...",
        "check_summary_label": "\nVerification summary:",
        "check_pass": "ALL CHECKS PASSED",
        "check_fail": "ISSUES FOUND (see output above)",
        "prompt_url": "Stalwart server URL [http://127.0.0.1:8080]: ",
        "prompt_ip": "Local Docker IP address for the domain (e.g., 172.28.0.13): ",
        "prompt_token": "Stalwart API token (input hidden): ",
        "err_token": "Error: API token cannot be empty.",
        "connecting": "\nConnecting to {url}...",
        "cert_found": "[OK] Found certificate for {host}/{domain}: {id}",
        "cert_missing": (
            "[!] Certificate for {host} or *.{domain} was not found in x:Certificate yet.\n"
            "    Listeners will be created with the global default certificate."
        ),
        "run_summary_label": "\nResult:",
        "run_pass": "ALL SERVICES PASSED VERIFICATION",
        "run_fail": "ISSUES FOUND (see output above)",
    },
}

CURRENT_LANG = "ru"


def t(key: str, **kwargs: object) -> str:
    lang_map = MESSAGES.get(CURRENT_LANG, MESSAGES["ru"])
    template = lang_map.get(key, MESSAGES["ru"][key])
    return template.format(**kwargs) if kwargs else template


class StalwartJmapClient:
    def __init__(self, base_url: str, token: str, verify_tls: bool = True):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.ssl_ctx = None
        if not verify_tls:
            self.ssl_ctx = ssl.create_default_context()
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

        self.api_url = f"{self.base_url}/jmap"
        self.account_id = "a"
        self.using = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]
        self._init_session()

    def _request(self, method: str, url: str, payload: dict | None = None) -> dict:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20, context=self.ssl_ctx) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code} {e.reason} at {url}: {body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Connection error to {url}: {e.reason}") from e

    def _init_session(self) -> None:
        session = self._request("GET", f"{self.base_url}/jmap/session")
        api_url = session.get("apiUrl")
        if api_url:
            self.api_url = urllib.parse.urljoin(self.base_url + "/", api_url)

        primary = session.get("primaryAccounts") or {}
        if "urn:ietf:params:jmap:core" in primary:
            self.account_id = primary["urn:ietf:params:jmap:core"]
        elif primary:
            self.account_id = next(iter(primary.values()))

        caps = session.get("capabilities") or {}
        if caps:
            stalwart_caps = [c for c in caps if "stalwart" in c or c == "urn:ietf:params:jmap:core"]
            if stalwart_caps:
                self.using = stalwart_caps

    def call(self, method_name: str, args: dict) -> dict:
        full_args = {"accountId": self.account_id, **args}
        resp = self._request(
            "POST",
            self.api_url,
            {
                "using": self.using,
                "methodCalls": [[method_name, full_args, "c0"]],
            },
        )
        responses = resp.get("methodResponses") or []
        if not responses:
            raise RuntimeError(f"Empty JMAP response for {method_name}: {resp}")
        resp_name, resp_data, _ = responses[0]
        if resp_name == "error":
            raise RuntimeError(f"JMAP error in {method_name}: {json.dumps(resp_data, ensure_ascii=False)}")
        return resp_data

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


def sanitize_domain_suffix(domain: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", domain)


def san_matches(sans: list[str], hostname: str, domain: str) -> bool:
    targets = {hostname.lower(), domain.lower()}
    for san in sans:
        s = san.lower().strip()
        if s in targets:
            return True
        if s.startswith("*."):
            base = s[2:]
            if hostname.lower().endswith("." + base) and hostname.lower().count(".") == base.count(".") + 1:
                return True
            if domain.lower() == base:
                return True
    return False


def find_certificate_id(client: StalwartJmapClient, hostname: str, domain: str) -> str | None:
    certs = client.get_all("x:Certificate")
    best_id = None
    for cert in certs:
        sans = cert.get("subjectAlternativeNames") or []
        if hostname.lower() in [s.lower() for s in sans]:
            return cert["id"]
        if san_matches(sans, hostname, domain) and best_id is None:
            best_id = cert["id"]
    return best_id


def ensure_domain_exists(client: StalwartJmapClient, domain: str) -> str:
    domains = client.get_all("x:Domain")
    for d in domains:
        if (d.get("name") or "").lower() == domain.lower():
            print(t("domain_exists", domain=domain, id=d["id"]))
            return d["id"]

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


def extract_bind_set(bind_val) -> set[str]:
    if isinstance(bind_val, dict):
        return {k for k, v in bind_val.items() if v}
    if isinstance(bind_val, list):
        return set(bind_val)
    return set()


def build_listener_plan(domain: str) -> list[tuple[str, str, int, str, bool]]:
    suffix = sanitize_domain_suffix(domain)
    return [
        (f"{svc}_{suffix}", svc, port, proto, implicit_tls)
        for svc, port, proto, implicit_tls in LISTENERS_SPEC
    ]


def ensure_listeners(
    client: StalwartJmapClient,
    domain: str,
    local_ip: str,
    cert_id: str | None,
) -> list[tuple[str, str, int, str, bool]]:
    all_listeners = client.get_all("x:NetworkListener")
    existing = {item.get("name"): item for item in all_listeners}
    bind_to_listener: dict[str, dict] = {}
    for item in all_listeners:
        for b in extract_bind_set(item.get("bind")):
            bind_to_listener[b] = item

    domain_listener_ids: list[str] = []
    plan = build_listener_plan(domain)

    ip_formatted = f"[{local_ip}]" if ":" in local_ip else local_ip

    for name, svc, port, proto, implicit_tls in plan:
        bind_addr = f"{ip_formatted}:{port}"

        if name in existing:
            cur = existing[name]
            domain_listener_ids.append(cur["id"])
            patch = {}
            cur_binds = extract_bind_set(cur.get("bind"))
            if cur_binds != {bind_addr}:
                patch["bind"] = {bind_addr: True}
            if cur.get("protocol") != proto:
                patch["protocol"] = proto
            if cur.get("useTls") is not True:
                patch["useTls"] = True
            if bool(cur.get("implicitTls")) != implicit_tls:
                patch["implicitTls"] = implicit_tls
            if cert_id and cur.get("defaultCertificateId") != cert_id:
                patch["defaultCertificateId"] = cert_id

            if patch:
                client.update("x:NetworkListener", cur["id"], patch)
                print(t("listener_updated", name=name, bind=bind_addr, cert=cert_id or "global"))
            else:
                print(t("listener_ok", name=name, bind=bind_addr))
        else:
            conflict = bind_to_listener.get(bind_addr)
            if conflict and conflict.get("name") != name:
                print(
                    t(
                        "listener_bind_conflict",
                        bind=bind_addr,
                        other=conflict.get("name"),
                        oid=conflict.get("id"),
                        name=name,
                    )
                )
                continue

            payload = {
                "name": name,
                "protocol": proto,
                "bind": {bind_addr: True},
                "useTls": True,
                "implicitTls": implicit_tls,
            }
            if cert_id:
                payload["defaultCertificateId"] = cert_id
            lid = client.create("x:NetworkListener", payload)
            domain_listener_ids.append(lid)
            print(t("listener_created", name=name, bind=bind_addr, lid=lid, cert=cert_id or "global"))

    if domain_listener_ids:
        try:
            roles = client.get_all("x:ServerRole")
            for role in roles:
                listeners_cfg = role.get("listeners") or {}
                if listeners_cfg.get("@type") == "EnableSome":
                    raw_ids = listeners_cfg.get("listenerIds") or {}
                    if isinstance(raw_ids, dict):
                        merged_map = {k: True for k, v in raw_ids.items() if v}
                        for lid in domain_listener_ids:
                            merged_map[lid] = True
                        if merged_map != raw_ids:
                            client.update(
                                "x:ServerRole",
                                role["id"],
                                {"listeners/listenerIds": merged_map},
                            )
                            print(t("role_updated", id=role["id"]))
                    elif isinstance(raw_ids, list):
                        merged_list = list(dict.fromkeys(raw_ids + domain_listener_ids))
                        if merged_list != raw_ids:
                            client.update(
                                "x:ServerRole",
                                role["id"],
                                {"listeners/listenerIds": {lid: True for lid in merged_list}},
                            )
                            print(t("role_updated", id=role["id"]))
        except Exception as e:
            print(t("role_warn", err=e))

    return plan


def append_expression_rule(expr_obj: dict | None, cond: str, then_val: str) -> dict:
    expr = dict(expr_obj or {})
    raw_match = expr.get("match") or {}
    if isinstance(raw_match, list):
        items = list(raw_match)
    elif isinstance(raw_match, dict):
        items = [raw_match[k] for k in sorted(raw_match.keys(), key=lambda x: int(x) if str(x).isdigit() else 0)]
    else:
        items = []

    updated = False
    for item in items:
        if (item.get("if") or "").strip() == cond.strip():
            item["then"] = then_val
            updated = True
            break
    if not updated:
        items.append({"if": cond, "then": then_val})

    expr["match"] = {str(i): item for i, item in enumerate(items)}
    if "else" not in expr:
        expr["else"] = "false"
    return expr


def configure_mta_rules(
    client: StalwartJmapClient,
    domain: str,
    local_ip: str,
    mail_hostname: str,
) -> None:
    connect_list = client.get_all("x:MtaStageConnect")
    connect_cfg = connect_list[0] if connect_list else {}
    connect_id = connect_cfg.get("id", "singleton")

    cond_ip = f"local_ip == '{local_ip}'"
    new_hostname_expr = append_expression_rule(
        connect_cfg.get("hostname"),
        cond_ip,
        f"'{mail_hostname}'",
    )
    new_greeting_expr = append_expression_rule(
        connect_cfg.get("smtpGreeting"),
        cond_ip,
        f"'{mail_hostname} Stalwart ESMTP at your service'",
    )
    client.update(
        "x:MtaStageConnect",
        connect_id,
        {
            "hostname": new_hostname_expr,
            "smtpGreeting": new_greeting_expr,
        },
    )
    print(t("mta_inbound", ip=local_ip, host=mail_hostname))

    strategy_name = f"conn_{sanitize_domain_suffix(domain)}"
    strategies = {s.get("name"): s for s in client.get_all("x:MtaConnectionStrategy")}
    strategy_payload = {
        "name": strategy_name,
        "description": f"Dedicated outbound IP and EHLO for {domain}",
        "ehloHostname": mail_hostname,
        "localIps": {
            "0": {
                "localIp": local_ip,
                "ehloHostname": mail_hostname,
            }
        },
    }
    if strategy_name in strategies:
        client.update(
            "x:MtaConnectionStrategy",
            strategies[strategy_name]["id"],
            {
                "ehloHostname": mail_hostname,
                "localIps": strategy_payload["localIps"],
            },
        )
        print(t("mta_strategy_updated", name=strategy_name, ip=local_ip, host=mail_hostname))
    else:
        sid = client.create("x:MtaConnectionStrategy", strategy_payload)
        print(t("mta_strategy_created", name=strategy_name, sid=sid, ip=local_ip, host=mail_hostname))

    outbound_list = client.get_all("x:MtaOutboundStrategy")
    outbound_cfg = outbound_list[0] if outbound_list else {}
    outbound_id = outbound_cfg.get("id", "singleton")

    cond_sender = f"sender_domain == '{domain}'"
    new_conn_expr = append_expression_rule(
        outbound_cfg.get("connection"),
        cond_sender,
        f"'{strategy_name}'",
    )
    client.update(
        "x:MtaOutboundStrategy",
        outbound_id,
        {"connection": new_conn_expr},
    )
    print(t("mta_outbound", cond=cond_sender, name=strategy_name))


def reload_stalwart(client: StalwartJmapClient) -> None:
    try:
        client.create("x:Action", {"@type": "ReloadSettings"})
        print(t("reload_ok"))
    except Exception as e:
        print(t("reload_warn", err=e))


def audit_api_config(
    client: StalwartJmapClient,
    domain: str,
    local_ip: str | None,
    mail_hostname: str,
) -> bool:
    print(t("audit_header"))
    audit_ok = True

    domains = client.get_all("x:Domain")
    dom_obj = next((d for d in domains if (d.get("name") or "").lower() == domain.lower()), None)
    if dom_obj:
        print(t("audit_domain_pass", domain=domain, id=dom_obj["id"], enable=dom_obj.get("enable")))
    else:
        print(t("audit_domain_fail", domain=domain))
        audit_ok = False

    cert_id = find_certificate_id(client, mail_hostname, domain)
    if cert_id:
        print(t("audit_cert_pass", host=mail_hostname, domain=domain, id=cert_id))
    else:
        print(t("audit_cert_fail", host=mail_hostname, domain=domain))
        audit_ok = False

    existing_listeners = {item.get("name"): item for item in client.get_all("x:NetworkListener")}
    ip_formatted = f"[{local_ip}]" if (local_ip and ":" in local_ip) else local_ip

    for name, svc, port, proto, implicit_tls in build_listener_plan(domain):
        cur = existing_listeners.get(name)
        if not cur:
            print(t("audit_listener_missing", name=name))
            audit_ok = False
            continue

        binds = extract_bind_set(cur.get("bind"))
        cur_cert = cur.get("defaultCertificateId")
        issues = []
        if ip_formatted and f"{ip_formatted}:{port}" not in binds:
            issues.append(t("issue_bind", binds=sorted(binds), expected=f"{ip_formatted}:{port}"))
        if cur.get("protocol") != proto:
            issues.append(t("issue_proto", actual=cur.get("protocol"), expected=proto))
        if bool(cur.get("implicitTls")) != implicit_tls:
            issues.append(t("issue_tls", actual=cur.get("implicitTls"), expected=implicit_tls))
        if cert_id and cur_cert != cert_id:
            issues.append(t("issue_cert", actual=cur_cert, expected=cert_id))

        if issues:
            print(t("audit_listener_fail", name=name, id=cur["id"], issues="; ".join(issues)))
            audit_ok = False
        else:
            print(t("audit_listener_pass", name=name, id=cur["id"], binds=sorted(binds), cert=cur_cert))

    connect_list = client.get_all("x:MtaStageConnect")
    connect_raw = json.dumps(connect_list, ensure_ascii=False)
    if mail_hostname in connect_raw and (not local_ip or local_ip in connect_raw):
        print(t("audit_connect_pass", host=mail_hostname))
    else:
        print(t("audit_connect_fail", host=mail_hostname, ip=local_ip or "*"))
        audit_ok = False

    strategy_name = f"conn_{sanitize_domain_suffix(domain)}"
    strategies = {s.get("name"): s for s in client.get_all("x:MtaConnectionStrategy")}
    if strategy_name in strategies:
        print(t("audit_strategy_pass", name=strategy_name))
    else:
        print(t("audit_strategy_fail", name=strategy_name))
        audit_ok = False

    outbound_raw = json.dumps(client.get_all("x:MtaOutboundStrategy"), ensure_ascii=False)
    if domain in outbound_raw and strategy_name in outbound_raw:
        print(t("audit_outbound_pass", domain=domain, name=strategy_name))
    else:
        print(t("audit_outbound_fail", domain=domain, name=strategy_name))
        audit_ok = False

    return audit_ok


def extract_cert_names_from_der(der_bytes: bytes) -> list[str]:
    with tempfile.NamedTemporaryFile(suffix=".der") as f:
        f.write(der_bytes)
        f.flush()
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", f.name, "-noout", "-subject", "-ext", "subjectAltName"],
            capture_output=True,
            text=True,
        )
        out = proc.stdout + "\n" + proc.stderr
        names = []
        for m in re.finditer(r"DNS:([^\s,]+)", out):
            names.append(m.group(1))
        cn = re.search(r"CN\s*=\s*([^\n,/]+)", out)
        if cn:
            names.append(cn.group(1).strip())
        return list(dict.fromkeys(names))


def recv_line(sock: socket.socket) -> str:
    buf = bytearray()
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        buf.extend(chunk)
    return buf.decode("utf-8", errors="replace").strip()


def read_smtp_multilines(sock: socket.socket) -> list[str]:
    lines = []
    while True:
        line = recv_line(sock)
        if not line:
            break
        lines.append(line)
        if len(line) >= 4 and line[3] == " ":
            break
    return lines


def read_sieve_banner(sock: socket.socket) -> str:
    lines = []
    while True:
        line = recv_line(sock)
        if not line:
            break
        lines.append(line)
        if line.startswith("OK") or line.startswith("NO"):
            break
    return " | ".join(lines)


def probe_service(
    target_host: str,
    port: int,
    proto: str,
    implicit_tls: bool,
    sni_hostname: str | None,
    ehlo_name: str,
    timeout: float = 6.0,
) -> tuple[bool, str, list[str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw_sock = socket.create_connection((target_host, port), timeout=timeout)
    raw_sock.settimeout(timeout)

    try:
        if implicit_tls:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=sni_hostname)
            der = tls_sock.getpeercert(binary_form=True)
            names = extract_cert_names_from_der(der) if der else []
            if proto == "smtp":
                banner = " | ".join(read_smtp_multilines(tls_sock))
                tls_sock.sendall(b"QUIT\r\n")
            elif proto == "imap":
                banner = recv_line(tls_sock)
                tls_sock.sendall(b"a001 LOGOUT\r\n")
            elif proto == "pop3":
                banner = recv_line(tls_sock)
                tls_sock.sendall(b"QUIT\r\n")
            elif proto == "http":
                host_hdr = sni_hostname or ehlo_name
                req = f"HEAD / HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n".encode("ascii")
                tls_sock.sendall(req)
                banner = recv_line(tls_sock)
            else:
                banner = recv_line(tls_sock)
            tls_sock.close()
            return True, banner, names

        if proto == "http":
            host_hdr = sni_hostname or ehlo_name
            req = f"HEAD / HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n".encode("ascii")
            raw_sock.sendall(req)
            banner = recv_line(raw_sock)
            raw_sock.close()
            return True, banner, []

        if proto == "smtp":
            banner_lines = read_smtp_multilines(raw_sock)
            banner = " | ".join(banner_lines)
            raw_sock.sendall(f"EHLO {ehlo_name}\r\n".encode("ascii"))
            ehlo_resp = read_smtp_multilines(raw_sock)
            if not any("STARTTLS" in l.upper() for l in ehlo_resp):
                return False, f"No STARTTLS in EHLO: {ehlo_resp}", []
            raw_sock.sendall(b"STARTTLS\r\n")
            stls = recv_line(raw_sock)
            if not stls.startswith("220"):
                return False, f"STARTTLS rejected: {stls}", []
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=sni_hostname)
            der = tls_sock.getpeercert(binary_form=True)
            names = extract_cert_names_from_der(der) if der else []
            tls_sock.sendall(b"QUIT\r\n")
            tls_sock.close()
            return True, banner, names

        if proto == "imap":
            banner = recv_line(raw_sock)
            raw_sock.sendall(b"a001 STARTTLS\r\n")
            stls = recv_line(raw_sock)
            if not stls.upper().startswith("A001 OK"):
                return False, f"IMAP STARTTLS rejected: {stls}", []
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=sni_hostname)
            der = tls_sock.getpeercert(binary_form=True)
            names = extract_cert_names_from_der(der) if der else []
            tls_sock.sendall(b"a002 LOGOUT\r\n")
            tls_sock.close()
            return True, banner, names

        if proto == "pop3":
            banner = recv_line(raw_sock)
            raw_sock.sendall(b"STLS\r\n")
            stls = recv_line(raw_sock)
            if not stls.upper().startswith("+OK"):
                return False, f"POP3 STLS rejected: {stls}", []
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=sni_hostname)
            der = tls_sock.getpeercert(binary_form=True)
            names = extract_cert_names_from_der(der) if der else []
            tls_sock.sendall(b"QUIT\r\n")
            tls_sock.close()
            return True, banner, names

        if proto == "manageSieve":
            banner = read_sieve_banner(raw_sock)
            raw_sock.sendall(b"STARTTLS\r\n")
            stls = recv_line(raw_sock)
            if not stls.upper().startswith("OK"):
                return False, f"Sieve STARTTLS rejected: {stls}", []
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=sni_hostname)
            der = tls_sock.getpeercert(binary_form=True)
            names = extract_cert_names_from_der(der) if der else []
            tls_sock.sendall(b"LOGOUT\r\n")
            tls_sock.close()
            return True, banner, names

        return False, f"Unsupported protocol: {proto}", []
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass


def resolve_probe_target(local_ip: str | None, mail_hostname: str, explicit_probe_host: str | None) -> str:
    if explicit_probe_host:
        return explicit_probe_host
    if not local_ip:
        return mail_hostname
    try:
        ip_obj = ipaddress.ip_address(local_ip)
        if ip_obj.is_private:
            with socket.create_connection((local_ip, 25), timeout=1.5):
                return local_ip
    except OSError:
        print(t("probe_fallback", ip=local_ip, host=mail_hostname))
        return mail_hostname
    except ValueError:
        pass
    return local_ip


def run_verification(
    plan: list[tuple[str, str, int, str, bool]],
    local_ip: str | None,
    probe_host: str | None,
    domain: str,
    mail_hostname: str,
    expect_domain_cert: bool,
    wait_seconds: float = 0.0,
) -> bool:
    if wait_seconds > 0:
        time.sleep(wait_seconds)
    target = resolve_probe_target(local_ip, mail_hostname, probe_host)
    print(t("verify_header", target=target))
    all_ok = True

    for name, svc, port, proto, implicit_tls in plan:
        try:
            ok_sni, banner, certs_sni = probe_service(
                target, port, proto, implicit_tls, mail_hostname, mail_hostname
            )
            ok_nosni, _, certs_nosni = probe_service(
                target, port, proto, implicit_tls, None, mail_hostname
            )

            banner_ok = True
            if proto == "smtp" and mail_hostname.lower() not in banner.lower():
                banner_ok = False

            cert_ok = True
            if expect_domain_cert:
                cert_ok = san_matches(certs_sni, mail_hostname, domain) and san_matches(
                    certs_nosni, mail_hostname, domain
                )

            step_ok = ok_sni and ok_nosni and banner_ok and cert_ok
            if not step_ok:
                all_ok = False

            status = "PASS" if step_ok else "FAIL"
            mode = "ImplicitTLS" if implicit_tls else "STARTTLS"
            print(f"[{status}] {name:<26} {target}:{port:<5} ({mode})")
            print(f"       Banner : {banner[:100]}")
            print(f"       SNI    : {', '.join(certs_sni) or 'none'}")
            print(f"       No-SNI : {', '.join(certs_nosni) or 'none'}")
            if not banner_ok:
                print(t("verify_banner_warn", host=mail_hostname))
            if expect_domain_cert and not cert_ok:
                print(t("verify_cert_warn", domain=domain, host=mail_hostname))
        except Exception as e:
            all_ok = False
            print(t("verify_err", name=name, target=target, port=port, err=e))

    return all_ok


def main() -> int:
    global CURRENT_LANG

    env_lang = os.environ.get("PROVISION_LANG", "ru").strip().lower()
    default_lang = env_lang if env_lang in MESSAGES else "ru"

    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--lang", choices=["ru", "en"], default=default_lang)
    pre_args, _ = pre_parser.parse_known_args()
    CURRENT_LANG = pre_args.lang

    parser = argparse.ArgumentParser(description=t("cli_desc"))
    parser.add_argument("--lang", choices=["ru", "en"], default=CURRENT_LANG, help=t("help_lang"))
    parser.add_argument(
        "--check-only",
        "--verify-only",
        action="store_true",
        dest="check_only",
        help=t("help_check"),
    )
    parser.add_argument("--url", help=t("help_url"))
    parser.add_argument("--domain", help=t("help_domain"))
    parser.add_argument("--ip", help=t("help_ip"))
    parser.add_argument("--hostname", help=t("help_hostname"))
    parser.add_argument("--probe-host", help=t("help_probe"))
    parser.add_argument("--cert-id", help=t("help_cert"))
    parser.add_argument("--insecure", action="store_true", help=t("help_insecure"))
    args = parser.parse_args()
    CURRENT_LANG = args.lang

    domain = (args.domain or input(t("prompt_domain")).strip()).lower().rstrip(".")
    if not domain or "." not in domain:
        print(t("err_domain"), file=sys.stderr)
        return 1

    default_host = f"mail.{domain}"
    if args.hostname:
        mail_hostname = args.hostname.lower().rstrip(".")
    elif args.check_only and args.domain:
        mail_hostname = default_host
    else:
        mail_hostname = (
            input(t("prompt_hostname", default=default_host)).strip()
            or default_host
        ).lower().rstrip(".")

    if args.check_only:
        local_ip: str | None = None
        if args.ip:
            try:
                local_ip = str(ipaddress.ip_address(args.ip.strip()))
            except ValueError:
                print(t("err_ip", ip=args.ip), file=sys.stderr)
                return 1

        api_ok = True
        if args.url:
            token = getpass.getpass(t("prompt_token_ro")).strip()
            if token:
                print(t("connecting_ro", url=args.url))
                client = StalwartJmapClient(args.url, token, verify_tls=not args.insecure)
                api_ok = audit_api_config(client, domain, local_ip, mail_hostname)

        plan = build_listener_plan(domain)
        net_ok = run_verification(
            plan,
            local_ip,
            args.probe_host,
            domain,
            mail_hostname,
            expect_domain_cert=True,
            wait_seconds=0.0,
        )
        ok = api_ok and net_ok
        print(t("check_summary_label"), t("check_pass") if ok else t("check_fail"))
        return 0 if ok else 2

    stalwart_url = (
        args.url
        or input(t("prompt_url")).strip()
        or "http://127.0.0.1:8080"
    )

    raw_ip = args.ip or input(t("prompt_ip")).strip()
    try:
        local_ip = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        print(t("err_ip", ip=raw_ip), file=sys.stderr)
        return 1

    token = getpass.getpass(t("prompt_token")).strip()
    if not token:
        print(t("err_token"), file=sys.stderr)
        return 1

    print(t("connecting", url=stalwart_url))
    client = StalwartJmapClient(stalwart_url, token, verify_tls=not args.insecure)

    ensure_domain_exists(client, domain)

    cert_id = args.cert_id or find_certificate_id(client, mail_hostname, domain)
    if cert_id:
        print(t("cert_found", host=mail_hostname, domain=domain, id=cert_id))
    else:
        print(t("cert_missing", host=mail_hostname, domain=domain))

    plan = ensure_listeners(client, domain, local_ip, cert_id)
    configure_mta_rules(client, domain, local_ip, mail_hostname)
    reload_stalwart(client)

    ok = run_verification(
        plan,
        local_ip,
        args.probe_host,
        domain,
        mail_hostname,
        expect_domain_cert=bool(cert_id),
        wait_seconds=1.5,
    )
    print(t("run_summary_label"), t("run_pass") if ok else t("run_fail"))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())