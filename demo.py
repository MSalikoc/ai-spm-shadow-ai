"""
Tenant gerektirmeyen demo: sentetik keşif verisini scoring + rapor hattından
geçirir. Kod boru hattının doğru çalıştığını kanıtlamak ve hackathon sunumunda
canlı tenant olmadan göstermek için.

  python demo.py   →  out/shadow_ai.html + out/shadow_ai.json
"""
import os
import report
import scoring

SAMPLE = [
    {  # Kritik: doğrulanmamış transcription botu, admin onaylı, geniş izin
        "sp_id": "1", "app_id": "aaa", "display_name": "MeetingNotes AI Bot",
        "publisher": "notecorp-io", "verified_publisher": False, "owner_tenant": "ext-1",
        "third_party": True, "vendor": "Otter.ai", "confidence": "high",
        "scopes": ["mail.read", "files.readwrite.all", "chat.read", "offline_access", "user.read"],
        "consent_type": "AllPrincipals", "user_count": 340,
    },
    {  # Yüksek: kişisel ChatGPT bağlayıcısı, kullanıcı onayı, dosya erişimi
        "sp_id": "2", "app_id": "bbb", "display_name": "ChatGPT connector",
        "publisher": "OpenAI", "verified_publisher": True, "owner_tenant": "ext-2",
        "third_party": True, "vendor": "OpenAI (ChatGPT)", "confidence": "high",
        "scopes": ["files.read.all", "offline_access", "user.read", "openid"],
        "consent_type": "Principal", "user_count": 12,
    },
    {  # Orta: Grammarly, sınırlı izin
        "sp_id": "3", "app_id": "ccc", "display_name": "Grammarly for Office",
        "publisher": "Grammarly Inc", "verified_publisher": True, "owner_tenant": "ext-3",
        "third_party": True, "vendor": "Grammarly", "confidence": "high",
        "scopes": ["user.read", "openid", "profile"],
        "consent_type": "Principal", "user_count": 5,
    },
    {  # Düşük güven: jenerik AI eşleşmesi
        "sp_id": "4", "app_id": "ddd", "display_name": "Acme GPT Helper",
        "publisher": "—", "verified_publisher": False, "owner_tenant": "ext-4",
        "third_party": True, "vendor": "Bilinmeyen AI (jenerik eşleşme)", "confidence": "low",
        "scopes": ["user.read", "calendars.read"],
        "consent_type": "Principal", "user_count": 2,
    },
]


def main() -> None:
    scored = scoring.score_all([dict(s) for s in SAMPLE])
    os.makedirs("out", exist_ok=True)
    report.write_json(scored, "out/shadow_ai.json")
    report.write_html(scored, "out/shadow_ai.html", "DEMO-TENANT-0000")
    print("Demo bulguları (risk sırasıyla):")
    for a in scored:
        print(f"  [{a['risk_score']:>3} · {a['risk_level']:<6}] {a['display_name']} — {a['vendor']}")
    print("\nHTML: out/shadow_ai.html")


if __name__ == "__main__":
    main()
