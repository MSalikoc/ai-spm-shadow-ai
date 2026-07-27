"""notify testleri — send_email_digest'in tüm gövde-kurulum yolunu (network mock'lu) çalıştırır.
Bu test, _report_url gibi bir yardımcının silinmesi/regresyonunu yakalar."""
import notify


class _Resp:
    status_code = 202
    text = ""


def test_send_email_digest_builds_and_posts(monkeypatch):
    monkeypatch.setenv("AISPM_MAIL_SENDER", "sender@contoso.com")
    monkeypatch.setenv("AISPM_MAIL_TO", "team@contoso.com")
    monkeypatch.setenv("WEBSITE_HOSTNAME", "aispm.azurewebsites.net")
    monkeypatch.setattr(notify.auth, "get_token_managed_identity", lambda: "tok")
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return _Resp()

    monkeypatch.setattr(notify.requests, "post", fake_post)

    apps = [{"display_name": "ChatGPT", "vendor": "OpenAI", "first_party_microsoft": False,
             "risk_score": 81, "risk_level": "Kritik", "reasons": ["files.read.all"],
             "scopes": ["files.read.all"]}]
    changes = [{"change_type": "NEW_APPLICATION", "asset_name": "Claude",
                "old_value": None, "new_value": "v"}]
    out = notify.send_email_digest(apps, "tenant-1", changes)

    assert out["sent"] is True
    body = captured["json"]["message"]["body"]["content"]
    assert "ChatGPT" in body and "Bu hafta" in body        # digest + changes bloğu
    # temiz report URL (key yok) butonu
    assert "https://aispm.azurewebsites.net/api/report" in body
    assert "?code=" not in body
    # HTML eki mevcut
    assert captured["json"]["message"]["attachments"]


def test_report_url_uses_explicit_as_is(monkeypatch):
    # function-key dünyasında ?code= korunmalı (link çalışsın diye)
    monkeypatch.setenv("AISPM_REPORT_URL", "https://x/api/report?code=SECRET")
    assert notify._report_url() == "https://x/api/report?code=SECRET"


def test_report_url_falls_back_to_hostname(monkeypatch):
    monkeypatch.delenv("AISPM_REPORT_URL", raising=False)
    monkeypatch.setenv("WEBSITE_HOSTNAME", "func.azurewebsites.net")
    assert notify._report_url() == "https://func.azurewebsites.net/api/report"


def test_send_email_digest_no_config_returns_reason(monkeypatch):
    monkeypatch.delenv("AISPM_MAIL_SENDER", raising=False)
    monkeypatch.delenv("AISPM_MAIL_TO", raising=False)
    out = notify.send_email_digest([], "t", None)
    assert out["sent"] is False and "AISPM_MAIL_SENDER" in out["reason"]
