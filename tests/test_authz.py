"""authz katmanı testleri — rol kontrolü, 401/403, dev bypass güvenliği."""
import base64
import json

import pytest

import authz


def _principal_header(*roles):
    payload = {"claims": [{"typ": "roles", "val": r} for r in roles]}
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _headers(*roles):
    return {"x-ms-client-principal": _principal_header(*roles)}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    # Testler deterministik olsun: bypass ve azure runtime kapalı; auth yapılandırılmış.
    monkeypatch.delenv("AISPM_AUTH_DEV_BYPASS", raising=False)
    monkeypatch.delenv("WEBSITE_INSTANCE_ID", raising=False)
    monkeypatch.setenv("AISPM_AUTH_ENFORCED", "true")


def test_unconfigured_denies_all(monkeypatch):
    # Easy Auth kurulmadan (enforce bayrağı yok) hiçbir header'a güvenilmez → 401
    monkeypatch.delenv("AISPM_AUTH_ENFORCED", raising=False)
    res = authz.authorize(_headers(authz.ROLE_ADMIN), {authz.ROLE_READER})
    assert res is not None and res[0] == 401


# --- Kabul kriterleri --------------------------------------------------------

def test_anonymous_cannot_access_report():
    res = authz.authorize({}, {authz.ROLE_READER})
    assert res is not None and res[0] == 401


def test_report_reader_cannot_start_scan():
    res = authz.authorize(_headers(authz.ROLE_READER), {authz.ROLE_ASSESSMENT})
    assert res is not None and res[0] == 403


def test_assessment_operator_can_start_scan():
    res = authz.authorize(_headers(authz.ROLE_ASSESSMENT), {authz.ROLE_ASSESSMENT})
    assert res is None


def test_notification_operator_can_digest():
    assert authz.authorize(_headers(authz.ROLE_NOTIFICATION), {authz.ROLE_NOTIFICATION}) is None


def test_reader_can_read_report():
    assert authz.authorize(_headers(authz.ROLE_READER), {authz.ROLE_READER}) is None


def test_admin_can_do_everything():
    h = _headers(authz.ROLE_ADMIN)
    assert authz.authorize(h, {authz.ROLE_READER}) is None
    assert authz.authorize(h, {authz.ROLE_ASSESSMENT}) is None
    assert authz.authorize(h, {authz.ROLE_NOTIFICATION}) is None


def test_authenticated_without_role_is_403():
    # Geçerli kimlik ama hiç AI-SPM rolü yok
    res = authz.authorize(_headers("SomeOther.Role"), {authz.ROLE_READER})
    assert res is not None and res[0] == 403


# --- Dev bypass güvenliği ----------------------------------------------------

def test_dev_bypass_local(monkeypatch):
    monkeypatch.setenv("AISPM_AUTH_DEV_BYPASS", "true")
    # WEBSITE_INSTANCE_ID yok → local kabul edilir
    assert authz.dev_bypass_enabled() is True
    assert authz.authorize({}, {authz.ROLE_READER}) is None  # header yok ama bypass


def test_dev_bypass_rejected_in_production(monkeypatch):
    monkeypatch.setenv("AISPM_AUTH_DEV_BYPASS", "true")
    monkeypatch.setenv("WEBSITE_INSTANCE_ID", "prod-instance-123")
    assert authz.dev_bypass_enabled() is False
    # Production'da bypass yok → header'sız istek 401
    res = authz.authorize({}, {authz.ROLE_READER})
    assert res is not None and res[0] == 401


def test_dev_bypass_off_by_default():
    assert authz.dev_bypass_enabled() is False


# --- Principal ayrıştırma ----------------------------------------------------

def test_parse_principal_extracts_roles():
    p = authz.parse_principal(_principal_header(authz.ROLE_ADMIN, authz.ROLE_READER))
    assert authz.ROLE_ADMIN in p["roles"] and authz.ROLE_READER in p["roles"]


def test_parse_principal_bad_input_returns_none():
    assert authz.parse_principal("not-base64-!!!") is None
    assert authz.parse_principal("") is None
    assert authz.parse_principal(None) is None
