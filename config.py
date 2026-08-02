"""
AI-SPM configuration: classification dictionaries + sensitive Graph scope weights.

The AI vendor catalog lives OUT OF CODE in `catalog.json` (criterion 2); loaded from
there. Scope weights and governance dictionaries are policy, so they stay here.
"""
import json
import logging
import os

# --- AI vendor catalog (from catalog.json) ---------------------------------
DEFAULT_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "catalog.json")


def load_catalog(path: str | None = None) -> dict:
    """
    Loads the AI vendor catalog, preferring `AISPM_CATALOG_PATH` when it is set.

    Tenants disagree about what counts as an AI application — an override lets a team
    add their own vendors, or replace the list wholesale, without forking the repo or
    redeploying. A bad path falls back to the shipped catalog rather than silently
    scanning with an empty one, which would look exactly like "no AI found".
    """
    chosen = path or os.environ.get("AISPM_CATALOG_PATH") or DEFAULT_CATALOG_PATH
    try:
        with open(chosen, encoding="utf-8") as f:
            catalog = json.load(f)
        if not catalog.get("vendors"):
            raise ValueError("catalog has no vendors")
        return catalog
    except (OSError, ValueError) as e:
        if chosen != DEFAULT_CATALOG_PATH:
            logging.warning("AISPM_CATALOG_PATH %s unusable (%s); using the shipped catalog.",
                            chosen, e)
            with open(DEFAULT_CATALOG_PATH, encoding="utf-8") as f:
                return json.load(f)
        raise


_CATALOG = load_catalog()
AI_VENDORS = _CATALOG["vendors"]          # each: {name, app_ids, patterns, domains}
GENERIC_AI_HINTS = _CATALOG["generic_hints"]

# --- Classification dictionaries --------------------------------------------
AI_CATEGORIES = [
    "Microsoft First-Party AI", "Approved Enterprise AI", "Unapproved Enterprise AI",
    "Third-Party Shadow AI", "Internal Custom AI", "Personal AI Usage",
    "Unknown AI", "Retired AI",
]
OWNERSHIP_CLASSES = ["Internal", "External", "Unknown"]
FINDING_STATUSES = ["Open", "Assigned", "In Progress", "Pending Review",
                    "Resolved", "Accepted", "False Positive", "Reopened"]

# --- Sensitive delegated (on-behalf-of-user) Graph scope weights -----------
# 0-10. Higher = more dangerous in terms of data leakage.
SENSITIVE_SCOPES = {
    "mail.read": 9, "mail.readwrite": 10, "mail.send": 9,
    "files.read.all": 9, "files.readwrite.all": 10,
    "sites.read.all": 8, "sites.readwrite.all": 9, "sites.fullcontrol.all": 10,
    "chat.read": 7, "chat.readwrite": 8, "chatmessage.read": 7,
    "calendars.read": 5, "calendars.readwrite": 6,
    "contacts.read": 5,
    "user.read.all": 7, "directory.read.all": 8, "group.read.all": 6,
    "mailboxsettings.readwrite": 6,
    # High-privilege application (app-only) permissions
    "directory.readwrite.all": 10, "application.readwrite.all": 10,
    "rolemanagement.readwrite.directory": 10, "group.readwrite.all": 8,
    "user.readwrite.all": 9,
    "notes.read.all": 6,
    "offline_access": 4,  # persistent access (refresh token) → grows the blast radius
    "openid": 0, "profile": 0, "email": 0, "user.read": 1,
}

# If a scope name contains one of these fragments and isn't in the table, assign a medium weight.
SCOPE_HEURISTICS = [("readwrite", 7), ("read.all", 6), (".all", 5), ("read", 3)]

# --- Business / lifecycle governance dictionaries ---------------------------
LIFECYCLE_STATUSES = ["Discovered", "Under Review", "Pilot", "Approved",
                      "Restricted", "Blocked", "Retired", "Unknown"]
CRITICALITY = ["", "Low", "Medium", "High", "Critical", "Unknown"]
ENVIRONMENTS = ["", "Production", "Non-production", "Development", "Unknown"]

# Tenant IDs owned by Microsoft's own first-party applications.
# These are never counted as "third-party Shadow AI".
MICROSOFT_OWNER_TENANTS = {
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",  # Microsoft Services
    "72f988bf-86f1-41af-91ab-2d7cd011db47",  # Microsoft corp
}
