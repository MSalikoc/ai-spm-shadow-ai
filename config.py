"""
AI-SPM configuration: AI vendor catalog + sensitive Graph scope weights.

Bu dosya "neyi Shadow AI sayıyoruz" ve "hangi izin ne kadar riskli"
kararlarının tek kaynağıdır. Yeni vendor / scope eklemek için burayı düzenle.
"""

# --- Bilinen AI SaaS sağlayıcıları -----------------------------------------
# `patterns`: servicePrincipal.displayName / publisherName / homepage içinde
#             (küçük harf) aranan alt-dizeler.
# `appIds`  : kesin eşleşme için bilinen Entra multi-tenant App ID'leri (varsa).
AI_VENDORS = [
    {"name": "OpenAI (ChatGPT)", "patterns": ["openai", "chatgpt", "chat.openai"], "appIds": []},
    {"name": "Anthropic (Claude)", "patterns": ["anthropic", "claude.ai"], "appIds": []},
    {"name": "Google Gemini", "patterns": ["gemini", "bard", "generativeai", "aistudio"], "appIds": []},
    {"name": "Perplexity", "patterns": ["perplexity"], "appIds": []},
    {"name": "Cohere", "patterns": ["cohere"], "appIds": []},
    {"name": "Mistral", "patterns": ["mistral"], "appIds": []},
    {"name": "Hugging Face", "patterns": ["huggingface", "hugging face"], "appIds": []},
    {"name": "Glean", "patterns": ["glean"], "appIds": []},
    {"name": "Grammarly", "patterns": ["grammarly"], "appIds": []},
    {"name": "Notion AI", "patterns": ["notion"], "appIds": []},
    {"name": "Jasper", "patterns": ["jasper.ai", "jasper ai"], "appIds": []},
    {"name": "Writer", "patterns": ["writer.com"], "appIds": []},
    {"name": "Otter.ai", "patterns": ["otter.ai"], "appIds": []},
    {"name": "Fireflies", "patterns": ["fireflies"], "appIds": []},
    {"name": "ElevenLabs", "patterns": ["elevenlabs"], "appIds": []},
    {"name": "Character.AI", "patterns": ["character.ai", "character ai"], "appIds": []},
    {"name": "Poe (Quora)", "patterns": ["poe.com"], "appIds": []},
    {"name": "Copy.ai", "patterns": ["copy.ai"], "appIds": []},
    {"name": "Gamma", "patterns": ["gamma.app"], "appIds": []},
    {"name": "Read AI", "patterns": ["read.ai"], "appIds": []},
    {"name": "Tactiq", "patterns": ["tactiq"], "appIds": []},
]

# Vendor listesinde olmasa bile bu genel AI anahtar kelimeleri "AI olabilir"
# şüphesi doğurur (envantere düşük güvenle eklenir).
GENERIC_AI_HINTS = [
    "ai assistant", " ai ", "gpt", "llm", "copilot", "genai",
    "generative", "machine learning", "chatbot", "transcription", "meeting notes",
]

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
    "notes.read.all": 6,
    "offline_access": 4,  # kalıcı erişim (refresh token) → blast radius büyütür
    "openid": 0, "profile": 0, "email": 0, "user.read": 1,
}

# Scope adında bu parçalar geçiyorsa ve tabloda yoksa, orta ağırlık ata.
SCOPE_HEURISTICS = [("readwrite", 7), ("read.all", 6), (".all", 5), ("read", 3)]

# Microsoft'un kendi first-party uygulamalarının sahip olduğu tenant ID'leri.
# Bunlar "3. parti Shadow AI" sayılmaz.
MICROSOFT_OWNER_TENANTS = {
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",  # Microsoft Services
    "72f988bf-86f1-41af-91ab-2d7cd011db47",  # Microsoft corp
}
