"""
VIRELOX Agresif Parametre Bulucu v4.0
200+ parametre wordlist ile gizli parametre keşfi
Mozilla Public License 2.0 — AltayHR Developers
"""

import re
import urllib.parse
from typing import Dict, Callable, Optional, List


# 200+ yaygın parametre listesi
PARAMETRE_LISTESI = [
    # Kimlik / ID
    "id", "user_id", "userid", "uid", "account_id", "accountid",
    "member_id", "memberid", "customer_id", "customerid", "client_id",
    "profile_id", "post_id", "article_id", "item_id", "product_id",
    "category_id", "cat_id", "page_id", "order_id", "transaction_id",
    "session_id", "token_id", "key_id", "ref_id", "pid", "cid",
    "nid", "aid", "bid", "tid", "eid", "fid", "gid",
    # Kullanıcı
    "user", "username", "login", "email", "phone", "mobile",
    "name", "firstname", "lastname", "fullname",
    "password", "passwd", "pass", "pwd", "secret",
    # Sayfa / navigasyon
    "page", "p", "pg", "paged", "pagination", "offset", "limit",
    "start", "end", "from", "to", "per_page",
    "view", "mode", "tab", "section", "step", "stage",
    # İçerik
    "q", "query", "search", "s", "keyword", "keywords", "term",
    "text", "content", "message", "comment", "body", "title",
    "subject", "description", "note", "tag", "tags", "label",
    # Dosya / kaynak
    "file", "filename", "filepath", "path", "dir", "folder",
    "url", "link", "href", "src", "ref", "redirect", "return",
    "next", "back", "goto", "continue", "target", "dest", "destination",
    "img", "image", "photo", "picture", "avatar", "thumb",
    # Sıralama / filtreleme
    "sort", "order", "orderby", "order_by", "sortby", "sort_by",
    "filter", "type", "category", "cat", "tag", "status", "state",
    "format", "lang", "language", "locale", "country", "region",
    # Güvenlik / token
    "token", "csrf", "nonce", "hash", "signature", "key", "api_key",
    "apikey", "access_token", "auth_token", "session", "cookie",
    # Dönem / zaman
    "date", "time", "datetime", "timestamp", "year", "month", "day",
    "start_date", "end_date", "from_date", "to_date",
    # Para / miktar
    "amount", "price", "total", "quantity", "qty", "count",
    "currency", "discount", "tax",
    # Çeşitli
    "action", "cmd", "command", "do", "op", "operation", "method",
    "callback", "format", "output", "return_url", "success_url",
    "error_url", "cancel_url",
    "debug", "test", "dev", "preview", "draft",
    "include", "exclude", "show", "hide", "display",
    "data", "value", "val", "input", "param", "arg", "args",
    "code", "number", "num", "no", "index", "idx",
]


class AgresifParametreBulucu:
    def __init__(self, http_istemci=None, log_func: Optional[Callable] = None):
        self.http = http_istemci
        self.log  = log_func or (lambda m: None)

    def tara(self, url: str) -> Dict:
        """Her parametreyi URL'ye ekleyerek yansıma kontrolü yapar."""
        bulunanlar = []
        parsed     = urllib.parse.urlparse(url)
        base_url   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        self.log(f"[PARAM] {len(PARAMETRE_LISTESI)} parametre test ediliyor...")

        # Referans yanıt
        try:
            ref_r = self.http.get(url)
            ref_body = getattr(ref_r, 'text', '') if ref_r else ''
        except Exception:
            ref_body = ''

        ISARETCI = "VLXPROBEMARKER7x9z"

        for param in PARAMETRE_LISTESI:
            test_url = f"{base_url}?{param}={ISARETCI}"
            try:
                r = self.http.get(test_url)
                if not r:
                    continue
                durum = getattr(r, 'status_code', 0)
                body  = getattr(r, 'text', '')

                # 200 yanıtı VE içerik farklı olmalı
                if durum == 200 and body != ref_body:
                    yansima = ISARETCI in body
                    bulunanlar.append({
                        "parametre": param,
                        "url":       test_url,
                        "yansima":   yansima,
                        "durum":     durum,
                    })
                    self.log(f"[PARAM] ✔ ?{param}{'  [YANSIMA]' if yansima else ''}")
            except Exception:
                continue

        return {
            "bulunanlar":  bulunanlar,
            "toplam":      len(PARAMETRE_LISTESI),
            "bulunan_say": len(bulunanlar),
        }
