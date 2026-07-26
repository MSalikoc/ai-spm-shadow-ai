"""
AI-SPM configuration: sınıflandırma sözlükleri + hassas Graph scope ağırlıkları.

AI vendor kataloğu KOD DIŞINDA `catalog.json` dosyasındadır (kriter 2); buradan
yüklenir. Scope ağırlıkları ve governance sözlükleri politikadır, burada durur.
"""
import json
import os

# --- AI vendor kataloğu (catalog.json'dan) ---------------------------------
with open(os.path.join(os.path.dirname(__file__), "catalog.json"), encoding="utf-8") as _f:
    _CATALOG = json.load(_f)
AI_VENDORS = _CATALOG["vendors"]          # her biri: {name, app_ids, patterns, domains}
GENERIC_AI_HINTS = _CATALOG["generic_hints"]

# --- Sınıflandırma sözlükleri ----------------------------------------------
AI_CATEGORIES = [
    "Microsoft First-Party AI", "Approved Enterprise AI", "Unapproved Enterprise AI",
    "Third-Party Shadow AI", "Internal Custom AI", "Personal AI Usage",
    "Unknown AI", "Retired AI",
]
OWNERSHIP_CLASSES = ["Internal", "External", "Unknown"]

# --- Hassas delegated (kullanıcı adına) Graph scope ağırlıkları -------------
# 0-10 arası. Yüksek = veri sızıntısı açısından daha tehlikeli.
SENSITIVE_SCOPES = {
    "mail.read": 9, "mail.readwrite": 10, "mail.send": 9,
    "files.read.all": 9, "files.readwrite.all": 10,
    "sites.read.all": 8, "sites.readwrite.all": 9, "sites.fullcontrol.all": 10,
    "chat.read": 7, "chat.readwrite": 8, "chatmessage.read": 7,
    "calendars.read": 5, "calendars.readwrite": 6,
    "contacts.read": 5,
    "user.read.all": 7, "directory.read.all": 8, "group.read.all": 6,
    "mailboxsettings.readwrite": 6,
    # Yüksek-ayrıcalıklı application (app-only) permission'lar
    "directory.readwrite.all": 10, "application.readwrite.all": 10,
    "rolemanagement.readwrite.directory": 10, "group.readwrite.all": 8,
    "user.readwrite.all": 9,
    "notes.read.all": 6,
    "offline_access": 4,  # kalıcı erişim (refresh token) → blast radius büyütür
    "openid": 0, "profile": 0, "email": 0, "user.read": 1,
}

# Scope adında bu parçalar geçiyorsa ve tabloda yoksa, orta ağırlık ata.
SCOPE_HEURISTICS = [("readwrite", 7), ("read.all", 6), (".all", 5), ("read", 3)]

# --- Business / lifecycle governance sözlükleri ----------------------------
LIFECYCLE_STATUSES = ["Discovered", "Under Review", "Pilot", "Approved",
                      "Restricted", "Blocked", "Retired", "Unknown"]
CRITICALITY = ["", "Low", "Medium", "High", "Critical", "Unknown"]
ENVIRONMENTS = ["", "Production", "Non-production", "Development", "Unknown"]

# Microsoft'un kendi first-party uygulamalarının sahip olduğu tenant ID'leri.
# Bunlar "3. parti Shadow AI" sayılmaz.
MICROSOFT_OWNER_TENANTS = {
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",  # Microsoft Services
    "72f988bf-86f1-41af-91ab-2d7cd011db47",  # Microsoft corp
}
