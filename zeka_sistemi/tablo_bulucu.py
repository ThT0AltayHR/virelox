"""
VIRELOX Tablo Bulucu v4.1 — Sniper Mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Brute-force tablo bulucu — information_schema başarısız olduğunda kullanılır.
v4.1 yenilikleri:
  • CMS-spesifik tablo listeleri (WordPress, Joomla, Drupal, Laravel, vb.)
  • Öncelikli kategoriler: kritik tablolar (users, passwords) önce denenir
  • cms_tablo_listesi(cms_adi) ve tablo_listesi_al(cms, limit) yardımcıları
  • Otomatik CMS tespiti için cms_tespit_ipuclari sözlüğü
Mozilla Public License 2.0 — AltayHR Developers
"""
from typing import List, Optional, Dict


# ─────────────────────────────────────────────────────────────────────────────
# KATEGORİLENDİRİLMİŞ TABLO LİSTESİ  (öncelik sırasıyla)
# ─────────────────────────────────────────────────────────────────────────────

# Önce bu kritik tablolar denenir — kimlik bilgisi içerme olasılığı en yüksek
_KRITIK = [
    "users", "user", "admins", "admin", "administrators",
    "passwords", "password", "credentials", "credential",
    "logins", "login", "accounts", "account",
    "members", "member", "staff",
    "auth", "authentication",
    "sessions", "session",
    "tokens", "token", "api_keys", "api_key",
]

_KULLANICI = [
    "customers", "customer", "clients", "client",
    "profiles", "profile", "persons", "person",
    "employees", "employee", "operators", "operator",
    "moderators", "moderator", "managers", "manager",
    "subscribers", "subscriber", "vendors", "vendor",
    "agents", "agent", "partners", "partner",
    "users_info", "user_info", "user_data", "user_details",
    "account_info", "account_details",
]

_OTURUM_GUVENLIK = [
    "auth_tokens", "access_tokens", "refresh_tokens",
    "oauth_tokens", "jwt_tokens",
    "password_resets", "password_reset",
    "remember_tokens", "two_factor_tokens",
    "login_attempts", "failed_logins",
    "audit_log", "audit_logs", "audit",
    "security_logs", "security_events",
    "ip_blacklist", "ip_whitelist",
]

_GENEL_ICERIK = [
    "settings", "setting", "config", "configuration", "configs",
    "options", "option",
    "emails", "email", "contacts", "contact",
    "posts", "post", "articles", "article", "pages", "page",
    "comments", "comment", "messages", "message",
    "files", "file", "uploads", "upload", "media", "attachments",
    "logs", "log",
    "roles", "role", "permissions", "permission",
    "groups", "group", "teams", "team",
    "news", "blogs", "blog",
    "categories", "category", "tags", "tag",
    "items", "item", "products", "product",
    "orders", "order", "invoices", "invoice",
    "notifications", "notification",
    "events", "event",
    "data", "info",
]

_ODEME_FINANS = [
    "transactions", "transaction", "payments", "payment",
    "subscriptions", "subscription",
    "invoices", "invoice",
    "billing", "billing_info",
    "credit_cards", "card_numbers", "bank_accounts",
    "accounts_balance", "transactions_history",
    "coupons", "coupon", "discounts", "discount",
    "carts", "cart", "wishlist", "favorites",
    "shipping", "shipping_addresses",
    "refunds", "refund",
]

_CRM_SATIS = [
    "leads", "lead", "opportunities", "deals",
    "companies", "company", "organizations", "organization",
    "contacts_crm", "prospects", "pipeline",
    "tickets", "ticket", "support_tickets",
    "feedback", "surveys", "survey",
]

_FRAMEWORK = [
    # Laravel / PHP
    "migrations", "jobs", "failed_jobs",
    "personal_access_tokens", "oauth_access_tokens",
    "oauth_clients", "oauth_auth_codes",
    "model_has_roles", "role_has_permissions",
    "password_resets",
    # Django
    "django_session", "django_migrations",
    "auth_user", "auth_group", "auth_permission",
    "django_content_type", "django_admin_log",
    # Ruby on Rails
    "ar_internal_metadata", "schema_migrations",
    "active_storage_blobs", "active_storage_attachments",
    # Node/Sequelize
    "sequelize_meta",
    # SQLite özel
    "sqlite_sequence",
]

# ─────────────────────────────────────────────────────────────────────────────
# CMS-SPESİFİK TABLOLAR
# ─────────────────────────────────────────────────────────────────────────────

_CMS_TABLOLAR: Dict[str, List[str]] = {
    "wordpress": [
        "wp_users", "wp_usermeta", "wp_options", "wp_posts", "wp_postmeta",
        "wp_terms", "wp_term_taxonomy", "wp_term_relationships",
        "wp_comments", "wp_commentmeta", "wp_links",
        # Yaygın WP plugin tabloları
        "wp_woocommerce_orders", "wp_woocommerce_order_items",
        "wp_woocommerce_sessions",
        "wp_wfblockediplog", "wp_wflogins",   # Wordfence
        "wp_actionscheduler_actions",
        "wp_smush_dir_images",
        "wp_seopress_analysis",
        "wp_rank_math_redirections",
    ],
    "joomla": [
        "jos_users", "jos_categories", "jos_content", "jos_session",
        "jos_groups", "jos_assets", "jos_extensions",
        "jos_menu", "jos_modules", "jos_components",
        "jos_user_usergroup_map", "jos_usergroups",
        "jos_user_profiles",
    ],
    "drupal": [
        "users", "users_field_data", "sessions",
        "node", "node_field_data", "node_body",
        "taxonomy_term_data", "taxonomy_vocabulary",
        "field_config", "field_storage_config",
        "system", "key_value", "config",
        "watchdog",
    ],
    "magento": [
        "admin_user", "customer_entity", "customer_entity_varchar",
        "sales_order", "sales_order_address", "sales_order_item",
        "quote", "quote_address", "quote_item",
        "catalog_product_entity", "catalog_product_entity_varchar",
        "catalog_category_entity",
        "eav_attribute", "eav_entity_type",
        "store", "store_website",
        "core_config_data",
    ],
    "prestashop": [
        "ps_employee", "ps_customer", "ps_customer_group",
        "ps_orders", "ps_order_detail", "ps_order_payment",
        "ps_product", "ps_product_lang", "ps_category",
        "ps_cart", "ps_cart_product",
        "ps_configuration", "ps_shop", "ps_currency",
        "ps_address", "ps_country",
        "ps_connections", "ps_guest",
    ],
    "opencart": [
        "oc_user", "oc_customer", "oc_customer_group",
        "oc_order", "oc_order_product", "oc_order_history",
        "oc_product", "oc_product_description", "oc_category",
        "oc_setting", "oc_session",
    ],
    "phpbb": [
        "phpbb_users", "phpbb_groups", "phpbb_user_group",
        "phpbb_sessions", "phpbb_config",
        "phpbb_topics", "phpbb_posts", "phpbb_forums",
        "phpbb_bots", "phpbb_banlist",
    ],
    "vbulletin": [
        "user", "usergroup", "session",
        "thread", "post", "forum",
        "setting", "settinggroup",
        "datastore", "cache",
    ],
    "mybb": [
        "mybb_users", "mybb_usergroups", "mybb_sessions",
        "mybb_threads", "mybb_posts", "mybb_forums",
        "mybb_settings", "mybb_settinggroups",
    ],
    "oscommerce": [
        "customers", "customers_info", "customers_basket",
        "orders", "orders_products", "orders_status",
        "products", "products_description", "categories",
        "administrators", "configuration",
    ],
    "xenforo": [
        "xf_user", "xf_user_authenticate", "xf_session",
        "xf_user_group", "xf_permission_combination",
        "xf_thread", "xf_post", "xf_forum",
        "xf_option", "xf_template",
    ],
}

# CMS tespiti için URL/başlık ipuçları
CMS_TESPIT_IPUCLARI: Dict[str, List[str]] = {
    "wordpress": ["wp-content", "wp-includes", "wp-login", "wordpress"],
    "joomla":    ["joomla", "jos_", "/administrator/", "com_content"],
    "drupal":    ["drupal", "sites/default", "node/", "?q=node"],
    "magento":   ["magento", "mage", "/checkout/cart", "skin/frontend"],
    "prestashop":["prestashop", "ps_", "PrestaShop"],
    "opencart":  ["opencart", "oc_", "route=common"],
    "phpbb":     ["phpbb", "viewtopic", "viewforum", "memberlist"],
    "vbulletin": ["vbulletin", "vb_", "showthread", "forumdisplay"],
    "xenforo":   ["xenforo", "xf_", "threads/", "members/"],
}

# ─────────────────────────────────────────────────────────────────────────────
# ANA BRUTE-FORCE LİSTESİ — tüm kategorilerin birleşimi (öncelik sırasıyla)
# ─────────────────────────────────────────────────────────────────────────────
def _listele_uniq(*listeler: List[str]) -> List[str]:
    """Verilen listeleri birleştirip tekrarları kaldırır (sıra korunur)."""
    goruldu = set()
    sonuc = []
    for lst in listeler:
        for item in lst:
            if item not in goruldu:
                goruldu.add(item)
                sonuc.append(item)
    return sonuc


BRUTE_TABLO_LISTESI: List[str] = _listele_uniq(
    _KRITIK,
    _KULLANICI,
    _OTURUM_GUVENLIK,
    _GENEL_ICERIK,
    _ODEME_FINANS,
    _CRM_SATIS,
    _FRAMEWORK,
    # Tüm CMS tablolarını da ekle
    *list(_CMS_TABLOLAR.values()),
)

# ─────────────────────────────────────────────────────────────────────────────
# YARDIMCI FONKSİYONLAR
# ─────────────────────────────────────────────────────────────────────────────

def cms_tespit_et(url: str = "", basliklar: str = "") -> Optional[str]:
    """
    URL ve sayfa içeriğinden CMS adını tahmin eder.
    Döner: cms adı str veya None.
    """
    birlesik = (url + basliklar).lower()
    for cms, ipuclari in CMS_TESPIT_IPUCLARI.items():
        if any(ip in birlesik for ip in ipuclari):
            return cms
    return None


def cms_tablo_listesi(cms_adi: str) -> List[str]:
    """
    Belirli bir CMS için özel tablo listesini döner.
    CMS bilinmiyorsa boş liste döner.

    Örnek:
        tablolar = cms_tablo_listesi("wordpress")
        # → ["wp_users", "wp_usermeta", ...]
    """
    return list(_CMS_TABLOLAR.get(cms_adi.lower(), []))


def tablo_listesi_al(cms: Optional[str] = None,
                     limit: Optional[int] = None,
                     kritik_once: bool = True) -> List[str]:
    """
    Brute-force için optimize edilmiş tablo listesi döner.

    Parametreler:
        cms         : Tespit edilen CMS adı (örn. "wordpress") — varsa CMS
                      tabloları listeye eklenir ve öne çıkarılır.
        limit       : Maksimum tablo sayısı (None = tümü).
        kritik_once : True → kritik tablolar (users, passwords) her zaman önce.

    Kullanım:
        from zeka_sistemi.tablo_bulucu import tablo_listesi_al, cms_tespit_et
        cms = cms_tespit_et(url, sayfa_icerigi)
        tablolar = tablo_listesi_al(cms=cms, limit=100)
    """
    if cms:
        cms_tablolar = cms_tablo_listesi(cms)
        temel = _listele_uniq(
            _KRITIK if kritik_once else [],
            cms_tablolar,
            BRUTE_TABLO_LISTESI,
        )
    else:
        temel = _listele_uniq(
            _KRITIK if kritik_once else [],
            BRUTE_TABLO_LISTESI,
        )

    return temel[:limit] if limit else temel


def kritik_tablo_listesi() -> List[str]:
    """Sadece kritik tabloları döner (hızlı tarama için)."""
    return list(_KRITIK)
