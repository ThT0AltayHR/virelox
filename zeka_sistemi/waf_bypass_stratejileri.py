"""
VIRELOX WAF Bypass Stratejileri
Mozilla Public License 2.0 — AltayHR Developers
"""
from .pyload_havuzu.tamper_teknikleri import (
    TamperMotoru, TAMPER_HARITASI, tamper_zinciri_uygula,
    waf_icin_tamper_sec, tum_tamperler
)


class WafBypassStrateji:
    """Tek WAF bypass stratejisi"""

    def __init__(self, isim: str, tamper_zinciri: list, aciklama: str = ""):
        self.isim           = isim
        self.tamper_zinciri = tamper_zinciri
        self.aciklama       = aciklama

    def uygula(self, payload: str) -> str:
        return tamper_zinciri_uygula(payload, self.tamper_zinciri)


class WAFBypassGrubu:
    """WAF tespitine göre otomatik bypass stratejisi seçer"""

    STRATEJILER = {
        "Cloudflare": WafBypassStrateji(
            "Cloudflare", ["space2comment", "randomcase", "versionedkeywords"],
            "Cloudflare için comment+randomcase"),
        "ModSecurity": WafBypassStrateji(
            "ModSecurity", ["space2comment", "modsecurityversioned", "randomcase"],
            "ModSecurity için versioned comment"),
        "F5 BIG-IP": WafBypassStrateji(
            "F5 BIG-IP", ["space2comment", "randomcase", "charencode"],
            "F5 için comment+encode"),
        "AWS WAF": WafBypassStrateji(
            "AWS WAF", ["space2comment", "randomcase", "apostrophemask"],
            "AWS WAF için mask"),
        "Imperva": WafBypassStrateji(
            "Imperva", ["space2comment", "multiplespaces", "randomcase"],
            "Imperva için çoklu boşluk"),
        "Barracuda": WafBypassStrateji(
            "Barracuda", ["space2plus", "randomcase", "versionedmorekeywords"],
            "Barracuda için plus+versioned"),
        "Sucuri": WafBypassStrateji(
            "Sucuri", ["space2comment", "randomcase", "htmlencode"],
            "Sucuri için html encode"),
        "Akamai": WafBypassStrateji(
            "Akamai", ["space2comment", "charencode", "randomcase"],
            "Akamai için char encode"),
        "Generic": WafBypassStrateji(
            "Generic", ["space2comment", "randomcase"],
            "Genel bypass"),

        # ── v4.0: +200 Yeni WAF Bypass Stratejisi ─────────────────────────────
        # Cloudflare varyantları
        "Cloudflare-v1": WafBypassStrateji(
            "Cloudflare-v1", ["space2comment","randomcase","versionedkeywords"],
            "Cloudflare temel"),
        "Cloudflare-v2": WafBypassStrateji(
            "Cloudflare-v2", ["space2comment","percentage","randomcase"],
            "Cloudflare percentage"),
        "Cloudflare-v3": WafBypassStrateji(
            "Cloudflare-v3", ["space2randomblank","randomcase","charencode"],
            "Cloudflare randomblank"),
        "Cloudflare-v4": WafBypassStrateji(
            "Cloudflare-v4", ["space2comment","randomcase","versionedmorekeywords"],
            "Cloudflare morekeywords"),
        "Cloudflare-v5": WafBypassStrateji(
            "Cloudflare-v5", ["unicodespace","randomcase","versionedkeywords"],
            "Cloudflare unicode boşluk"),
        "Cloudflare-v6": WafBypassStrateji(
            "Cloudflare-v6", ["space2tab","randomcase","versionedkeywords"],
            "Cloudflare tab"),
        "Cloudflare-v7": WafBypassStrateji(
            "Cloudflare-v7", ["nullbytebetween","randomcase","versionedkeywords"],
            "Cloudflare nullbyte"),
        "Cloudflare-v8": WafBypassStrateji(
            "Cloudflare-v8", ["space2comment","randomcase","mysqlversion"],
            "Cloudflare MySQL version comment"),
        "Cloudflare-v9": WafBypassStrateji(
            "Cloudflare-v9", ["space2comment","randomcase","fromhex"],
            "Cloudflare hex encode"),
        "Cloudflare-v10": WafBypassStrateji(
            "Cloudflare-v10", ["space2comment","randomcase","hex2charconcat"],
            "Cloudflare CHAR() encode"),

        # ModSecurity varyantları
        "ModSecurity-v1": WafBypassStrateji(
            "ModSecurity-v1", ["space2comment","modsecurityversioned","randomcase"],
            "ModSecurity versioned"),
        "ModSecurity-v2": WafBypassStrateji(
            "ModSecurity-v2", ["space2comment","modsecurityzeroversioned","randomcase"],
            "ModSecurity zero versioned"),
        "ModSecurity-v3": WafBypassStrateji(
            "ModSecurity-v3", ["space2hash","randomcase","modsecurityversioned"],
            "ModSecurity hash"),
        "ModSecurity-v4": WafBypassStrateji(
            "ModSecurity-v4", ["space2randomblank","randomcase","modsecurityversioned"],
            "ModSecurity random blank"),
        "ModSecurity-v5": WafBypassStrateji(
            "ModSecurity-v5", ["space2comment","randomcase","equaltolike"],
            "ModSecurity equaltolike"),
        "ModSecurity-v6": WafBypassStrateji(
            "ModSecurity-v6", ["space2comment","randomcase","inlinecomment"],
            "ModSecurity inline comment"),
        "ModSecurity-v7": WafBypassStrateji(
            "ModSecurity-v7", ["space2comment","randomcase","fromhex"],
            "ModSecurity hex"),
        "ModSecurity-v8": WafBypassStrateji(
            "ModSecurity-v8", ["unicodespace","modsecurityversioned","randomcase"],
            "ModSecurity unicode+versioned"),
        "ModSecurity-v9": WafBypassStrateji(
            "ModSecurity-v9", ["space2mssqlblank","randomcase","modsecurityversioned"],
            "ModSecurity mssql blank"),
        "ModSecurity-v10": WafBypassStrateji(
            "ModSecurity-v10", ["carriagereturn","randomcase","modsecurityversioned"],
            "ModSecurity carriage return"),

        # AWS WAF varyantları
        "AWS-v1": WafBypassStrateji(
            "AWS-v1", ["space2comment","randomcase","apostrophemask"],
            "AWS mask"),
        "AWS-v2": WafBypassStrateji(
            "AWS-v2", ["space2comment","randomcase","htmlencode"],
            "AWS html encode"),
        "AWS-v3": WafBypassStrateji(
            "AWS-v3", ["space2comment","randomcase","chardoubleencode"],
            "AWS double encode"),
        "AWS-v4": WafBypassStrateji(
            "AWS-v4", ["space2comment","randomcase","charunicodeencode"],
            "AWS unicode encode"),
        "AWS-v5": WafBypassStrateji(
            "AWS-v5", ["space2randomblank","randomcase","apostrophemask"],
            "AWS random blank"),
        "AWS-v6": WafBypassStrateji(
            "AWS-v6", ["space2comment","randomcase","overlongutf8"],
            "AWS overlong utf8"),
        "AWS-v7": WafBypassStrateji(
            "AWS-v7", ["space2comment","randomcase","fromhex"],
            "AWS hex"),
        "AWS-v8": WafBypassStrateji(
            "AWS-v8", ["unicodespace","randomcase","apostrophemask"],
            "AWS unicode+mask"),
        "AWS-v9": WafBypassStrateji(
            "AWS-v9", ["space2comment","randomcase","percentage"],
            "AWS percentage"),
        "AWS-v10": WafBypassStrateji(
            "AWS-v10", ["space2comment","uppercase","apostrophemask"],
            "AWS uppercase"),

        # Akamai varyantları
        "Akamai-v1": WafBypassStrateji(
            "Akamai-v1", ["space2comment","charencode","randomcase"],
            "Akamai char encode"),
        "Akamai-v2": WafBypassStrateji(
            "Akamai-v2", ["space2comment","chardoubleencode","randomcase"],
            "Akamai double encode"),
        "Akamai-v3": WafBypassStrateji(
            "Akamai-v3", ["space2comment","overlongutf8","randomcase"],
            "Akamai overlong utf8"),
        "Akamai-v4": WafBypassStrateji(
            "Akamai-v4", ["space2randomblank","charencode","randomcase"],
            "Akamai random blank"),
        "Akamai-v5": WafBypassStrateji(
            "Akamai-v5", ["unicodespace","charencode","randomcase"],
            "Akamai unicode space"),
        "Akamai-v6": WafBypassStrateji(
            "Akamai-v6", ["space2comment","charunicodeencode","randomcase"],
            "Akamai unicode encode"),
        "Akamai-v7": WafBypassStrateji(
            "Akamai-v7", ["space2comment","charencode","versionedkeywords"],
            "Akamai char+versioned"),
        "Akamai-v8": WafBypassStrateji(
            "Akamai-v8", ["space2comment","fromhex","randomcase"],
            "Akamai hex"),
        "Akamai-v9": WafBypassStrateji(
            "Akamai-v9", ["nullbytebetween","charencode","randomcase"],
            "Akamai null byte"),
        "Akamai-v10": WafBypassStrateji(
            "Akamai-v10", ["space2comment","hex2charconcat","randomcase"],
            "Akamai CHAR() encode"),

        # Imperva varyantları
        "Imperva-v1": WafBypassStrateji(
            "Imperva-v1", ["space2comment","multiplespaces","randomcase"],
            "Imperva multiple spaces"),
        "Imperva-v2": WafBypassStrateji(
            "Imperva-v2", ["space2randomblank","multiplespaces","randomcase"],
            "Imperva random+multi"),
        "Imperva-v3": WafBypassStrateji(
            "Imperva-v3", ["space2comment","randomcase","charencode"],
            "Imperva char encode"),
        "Imperva-v4": WafBypassStrateji(
            "Imperva-v4", ["space2comment","randomcase","equaltolike"],
            "Imperva like"),
        "Imperva-v5": WafBypassStrateji(
            "Imperva-v5", ["unicodespace","multiplespaces","randomcase"],
            "Imperva unicode+multi"),
        "Imperva-v6": WafBypassStrateji(
            "Imperva-v6", ["space2comment","randomcase","inlinecomment"],
            "Imperva inline comment"),
        "Imperva-v7": WafBypassStrateji(
            "Imperva-v7", ["space2comment","randomcase","overlongutf8"],
            "Imperva overlong utf8"),
        "Imperva-v8": WafBypassStrateji(
            "Imperva-v8", ["space2comment","randomcase","apostrophemask"],
            "Imperva apostrophe mask"),
        "Imperva-v9": WafBypassStrateji(
            "Imperva-v9", ["space2hash","randomcase","multiplespaces"],
            "Imperva hash+multi"),
        "Imperva-v10": WafBypassStrateji(
            "Imperva-v10", ["space2comment","randomcase","fromhex"],
            "Imperva hex"),

        # F5 BIG-IP varyantları
        "F5-v1": WafBypassStrateji(
            "F5-v1", ["space2comment","randomcase","charencode"],
            "F5 char encode"),
        "F5-v2": WafBypassStrateji(
            "F5-v2", ["space2comment","randomcase","modsecurityversioned"],
            "F5 modsec versioned"),
        "F5-v3": WafBypassStrateji(
            "F5-v3", ["space2randomblank","randomcase","charencode"],
            "F5 random blank"),
        "F5-v4": WafBypassStrateji(
            "F5-v4", ["space2comment","uppercase","charencode"],
            "F5 uppercase"),
        "F5-v5": WafBypassStrateji(
            "F5-v5", ["unicodespace","randomcase","charencode"],
            "F5 unicode"),
        "F5-v6": WafBypassStrateji(
            "F5-v6", ["space2comment","randomcase","htmlencode"],
            "F5 html encode"),
        "F5-v7": WafBypassStrateji(
            "F5-v7", ["space2comment","randomcase","overlongutf8"],
            "F5 overlong utf8"),
        "F5-v8": WafBypassStrateji(
            "F5-v8", ["space2comment","randomcase","fromhex"],
            "F5 hex"),
        "F5-v9": WafBypassStrateji(
            "F5-v9", ["nullbytebetween","randomcase","charencode"],
            "F5 nullbyte"),
        "F5-v10": WafBypassStrateji(
            "F5-v10", ["space2comment","randomcase","hex2charconcat"],
            "F5 CHAR()"),

        # Barracuda varyantları
        "Barracuda-v1": WafBypassStrateji(
            "Barracuda-v1", ["space2plus","randomcase","versionedmorekeywords"],
            "Barracuda plus+more"),
        "Barracuda-v2": WafBypassStrateji(
            "Barracuda-v2", ["space2comment","randomcase","versionedmorekeywords"],
            "Barracuda comment+more"),
        "Barracuda-v3": WafBypassStrateji(
            "Barracuda-v3", ["space2plus","randomcase","charencode"],
            "Barracuda plus+char"),
        "Barracuda-v4": WafBypassStrateji(
            "Barracuda-v4", ["space2plus","uppercase","versionedmorekeywords"],
            "Barracuda uppercase+more"),
        "Barracuda-v5": WafBypassStrateji(
            "Barracuda-v5", ["unicodespace","randomcase","versionedmorekeywords"],
            "Barracuda unicode"),

        # Sucuri varyantları
        "Sucuri-v1": WafBypassStrateji(
            "Sucuri-v1", ["space2comment","randomcase","htmlencode"],
            "Sucuri html"),
        "Sucuri-v2": WafBypassStrateji(
            "Sucuri-v2", ["space2comment","randomcase","charencode"],
            "Sucuri char encode"),
        "Sucuri-v3": WafBypassStrateji(
            "Sucuri-v3", ["space2comment","randomcase","overlongutf8"],
            "Sucuri overlong"),
        "Sucuri-v4": WafBypassStrateji(
            "Sucuri-v4", ["space2randomblank","randomcase","htmlencode"],
            "Sucuri random+html"),
        "Sucuri-v5": WafBypassStrateji(
            "Sucuri-v5", ["space2comment","uppercase","htmlencode"],
            "Sucuri uppercase+html"),

        # Fortinet varyantları
        "Fortinet-v1": WafBypassStrateji(
            "Fortinet-v1", ["space2comment","randomcase","versionedmorekeywords"],
            "Fortinet more keywords"),
        "Fortinet-v2": WafBypassStrateji(
            "Fortinet-v2", ["space2comment","randomcase","charencode"],
            "Fortinet char encode"),
        "Fortinet-v3": WafBypassStrateji(
            "Fortinet-v3", ["unicodespace","randomcase","versionedmorekeywords"],
            "Fortinet unicode"),
        "Fortinet-v4": WafBypassStrateji(
            "Fortinet-v4", ["space2comment","randomcase","fromhex"],
            "Fortinet hex"),
        "Fortinet-v5": WafBypassStrateji(
            "Fortinet-v5", ["space2randomblank","randomcase","versionedmorekeywords"],
            "Fortinet random"),

        # Citrix varyantları
        "Citrix-v1": WafBypassStrateji(
            "Citrix-v1", ["space2comment","randomcase","charunicodeencode"],
            "Citrix unicode encode"),
        "Citrix-v2": WafBypassStrateji(
            "Citrix-v2", ["space2comment","randomcase","charencode"],
            "Citrix char encode"),
        "Citrix-v3": WafBypassStrateji(
            "Citrix-v3", ["unicodespace","randomcase","charunicodeencode"],
            "Citrix unicode"),
        "Citrix-v4": WafBypassStrateji(
            "Citrix-v4", ["space2comment","randomcase","overlongutf8"],
            "Citrix overlong"),
        "Citrix-v5": WafBypassStrateji(
            "Citrix-v5", ["space2randomblank","randomcase","charunicodeencode"],
            "Citrix random"),

        # Azure varyantları
        "Azure-v1": WafBypassStrateji(
            "Azure-v1", ["space2comment","randomcase","charencode"],
            "Azure char"),
        "Azure-v2": WafBypassStrateji(
            "Azure-v2", ["space2comment","randomcase","chardoubleencode"],
            "Azure double"),
        "Azure-v3": WafBypassStrateji(
            "Azure-v3", ["space2comment","randomcase","overlongutf8"],
            "Azure overlong"),
        "Azure-v4": WafBypassStrateji(
            "Azure-v4", ["unicodespace","randomcase","charencode"],
            "Azure unicode"),
        "Azure-v5": WafBypassStrateji(
            "Azure-v5", ["space2randomblank","randomcase","charencode"],
            "Azure random blank"),

        # PerimeterX varyantları
        "PerimeterX-v1": WafBypassStrateji(
            "PerimeterX-v1", ["space2comment","randomcase","charencode"],
            "PerimeterX char"),
        "PerimeterX-v2": WafBypassStrateji(
            "PerimeterX-v2", ["space2comment","randomcase","overlongutf8"],
            "PerimeterX overlong"),
        "PerimeterX-v3": WafBypassStrateji(
            "PerimeterX-v3", ["unicodespace","randomcase","charencode"],
            "PerimeterX unicode"),

        # DataDome
        "DataDome-v1": WafBypassStrateji(
            "DataDome-v1", ["space2comment","randomcase","charencode"],
            "DataDome char"),
        "DataDome-v2": WafBypassStrateji(
            "DataDome-v2", ["space2comment","randomcase","chardoubleencode"],
            "DataDome double encode"),
        "DataDome-v3": WafBypassStrateji(
            "DataDome-v3", ["unicodespace","randomcase","charencode"],
            "DataDome unicode"),

        # Zscaler
        "Zscaler-v1": WafBypassStrateji(
            "Zscaler-v1", ["space2comment","randomcase","charencode"],
            "Zscaler char"),
        "Zscaler-v2": WafBypassStrateji(
            "Zscaler-v2", ["space2comment","randomcase","overlongutf8"],
            "Zscaler overlong"),
        "Zscaler-v3": WafBypassStrateji(
            "Zscaler-v3", ["space2randomblank","randomcase","charencode"],
            "Zscaler random"),

        # Wordfence
        "Wordfence-v1": WafBypassStrateji(
            "Wordfence-v1", ["space2comment","randomcase","versionedkeywords"],
            "Wordfence versioned"),
        "Wordfence-v2": WafBypassStrateji(
            "Wordfence-v2", ["space2comment","randomcase","charencode"],
            "Wordfence char"),
        "Wordfence-v3": WafBypassStrateji(
            "Wordfence-v3", ["unicodespace","randomcase","versionedkeywords"],
            "Wordfence unicode"),

        # Imunify360
        "Imunify360-v1": WafBypassStrateji(
            "Imunify360-v1", ["space2comment","modsecurityversioned","randomcase"],
            "Imunify versioned"),
        "Imunify360-v2": WafBypassStrateji(
            "Imunify360-v2", ["space2comment","randomcase","charencode"],
            "Imunify char"),
        "Imunify360-v3": WafBypassStrateji(
            "Imunify360-v3", ["space2randomblank","modsecurityversioned","randomcase"],
            "Imunify random"),

        # DDoS-Guard
        "DDoSGuard-v1": WafBypassStrateji(
            "DDoSGuard-v1", ["space2comment","randomcase"],
            "DDoS-Guard temel"),
        "DDoSGuard-v2": WafBypassStrateji(
            "DDoSGuard-v2", ["space2comment","randomcase","charencode"],
            "DDoS-Guard char"),

        # Naxsi
        "Naxsi-v1": WafBypassStrateji(
            "Naxsi-v1", ["space2comment","randomcase","charencode"],
            "Naxsi char"),
        "Naxsi-v2": WafBypassStrateji(
            "Naxsi-v2", ["space2comment","randomcase","overlongutf8"],
            "Naxsi overlong"),
        "Naxsi-v3": WafBypassStrateji(
            "Naxsi-v3", ["unicodespace","randomcase","charencode"],
            "Naxsi unicode"),

        # Radware
        "Radware-v1": WafBypassStrateji(
            "Radware-v1", ["space2comment","randomcase","apostrophemask"],
            "Radware mask"),
        "Radware-v2": WafBypassStrateji(
            "Radware-v2", ["space2comment","randomcase","charencode"],
            "Radware char"),
        "Radware-v3": WafBypassStrateji(
            "Radware-v3", ["unicodespace","randomcase","apostrophemask"],
            "Radware unicode"),

        # SonicWall
        "SonicWall-v1": WafBypassStrateji(
            "SonicWall-v1", ["space2comment","randomcase","apostrophemask"],
            "SonicWall mask"),
        "SonicWall-v2": WafBypassStrateji(
            "SonicWall-v2", ["space2comment","randomcase","charencode"],
            "SonicWall char"),

        # Palo Alto
        "PaloAlto-v1": WafBypassStrateji(
            "PaloAlto-v1", ["space2comment","randomcase","charencode"],
            "Palo Alto char"),
        "PaloAlto-v2": WafBypassStrateji(
            "PaloAlto-v2", ["space2comment","randomcase","base64encode"],
            "Palo Alto base64"),
        "PaloAlto-v3": WafBypassStrateji(
            "PaloAlto-v3", ["space2comment","randomcase","overlongutf8"],
            "Palo Alto overlong"),

        # Genel ileri teknikler
        "Generic-v2": WafBypassStrateji(
            "Generic-v2", ["space2randomblank","randomcase"],
            "Genel v2 random blank"),
        "Generic-v3": WafBypassStrateji(
            "Generic-v3", ["unicodespace","randomcase"],
            "Genel v3 unicode"),
        "Generic-v4": WafBypassStrateji(
            "Generic-v4", ["space2comment","randomcase","charencode"],
            "Genel v4 char encode"),
        "Generic-v5": WafBypassStrateji(
            "Generic-v5", ["space2comment","randomcase","overlongutf8"],
            "Genel v5 overlong"),
        "Generic-v6": WafBypassStrateji(
            "Generic-v6", ["space2comment","randomcase","htmlencode"],
            "Genel v6 html"),
        "Generic-v7": WafBypassStrateji(
            "Generic-v7", ["space2comment","randomcase","apostrophemask"],
            "Genel v7 apostrophe"),
        "Generic-v8": WafBypassStrateji(
            "Generic-v8", ["space2comment","randomcase","fromhex"],
            "Genel v8 hex"),
        "Generic-v9": WafBypassStrateji(
            "Generic-v9", ["space2comment","randomcase","versionedkeywords"],
            "Genel v9 versioned"),
        "Generic-v10": WafBypassStrateji(
            "Generic-v10", ["space2comment","randomcase","inlinecomment"],
            "Genel v10 inline"),
        "Generic-v11": WafBypassStrateji(
            "Generic-v11", ["space2tab","randomcase"],
            "Genel v11 tab"),
        "Generic-v12": WafBypassStrateji(
            "Generic-v12", ["space2vtab","randomcase"],
            "Genel v12 vtab"),
        "Generic-v13": WafBypassStrateji(
            "Generic-v13", ["carriagereturn","randomcase"],
            "Genel v13 CR"),
        "Generic-v14": WafBypassStrateji(
            "Generic-v14", ["space2comment","randomcase","hex2charconcat"],
            "Genel v14 CHAR()"),
        "Generic-v15": WafBypassStrateji(
            "Generic-v15", ["space2comment","randomcase","mysqlversion"],
            "Genel v15 MySQL ver"),
        "Generic-v16": WafBypassStrateji(
            "Generic-v16", ["nullbytebetween","randomcase"],
            "Genel v16 nullbyte"),
        "Generic-v17": WafBypassStrateji(
            "Generic-v17", ["space2mssqlblank","randomcase"],
            "Genel v17 MSSQL blank"),
        "Generic-v18": WafBypassStrateji(
            "Generic-v18", ["space2mysqlblank","randomcase"],
            "Genel v18 MySQL blank"),
        "Generic-v19": WafBypassStrateji(
            "Generic-v19", ["space2morehash","randomcase"],
            "Genel v19 more hash"),
        "Generic-v20": WafBypassStrateji(
            "Generic-v20", ["space2morecomment","randomcase"],
            "Genel v20 more comment"),

        # Çift ve üçlü tamper kombinasyonları
        "Combo-Encode-1": WafBypassStrateji(
            "Combo-Encode-1", ["charencode","chardoubleencode"],
            "Çift URL encode"),
        "Combo-Encode-2": WafBypassStrateji(
            "Combo-Encode-2", ["space2comment","charencode","chardoubleencode","randomcase"],
            "Triple encode combo"),
        "Combo-Space-1": WafBypassStrateji(
            "Combo-Space-1", ["space2comment","multiplespaces","doublespace"],
            "Boşluk karmaşası"),
        "Combo-Space-2": WafBypassStrateji(
            "Combo-Space-2", ["unicodespace","multiplespaces","space2randomblank"],
            "Unicode+multi boşluk"),
        "Combo-Case-1": WafBypassStrateji(
            "Combo-Case-1", ["space2comment","randomcase","randomcomments"],
            "Random case+comment"),
        "Combo-Case-2": WafBypassStrateji(
            "Combo-Case-2", ["space2comment","uppercase","charencode"],
            "Uppercase+encode"),
        "Combo-Keyword-1": WafBypassStrateji(
            "Combo-Keyword-1", ["space2comment","versionedkeywords","randomcase","charencode"],
            "Versioned+char"),
        "Combo-Keyword-2": WafBypassStrateji(
            "Combo-Keyword-2", ["space2comment","versionedmorekeywords","randomcase","overlongutf8"],
            "Versioned more+overlong"),
        "Combo-Heavy-1": WafBypassStrateji(
            "Combo-Heavy-1", ["space2comment","randomcase","versionedkeywords","charencode","apostrophemask"],
            "5-katmanlı combo"),
        "Combo-Heavy-2": WafBypassStrateji(
            "Combo-Heavy-2", ["unicodespace","randomcase","versionedmorekeywords","overlongutf8"],
            "Unicode+versioned+overlong"),
        "Combo-Heavy-3": WafBypassStrateji(
            "Combo-Heavy-3", ["space2randomblank","randomcase","modsecurityversioned","charencode"],
            "Random+modsec+char"),
        "Combo-Heavy-4": WafBypassStrateji(
            "Combo-Heavy-4", ["nullbytebetween","randomcase","versionedkeywords","charencode"],
            "Nullbyte+versioned+char"),
        "Combo-Heavy-5": WafBypassStrateji(
            "Combo-Heavy-5", ["space2comment","inlinecomment","randomcase","fromhex"],
            "Inline+hex"),
        "Combo-Heavy-6": WafBypassStrateji(
            "Combo-Heavy-6", ["space2comment","randomcase","hex2charconcat","mysqlversion"],
            "CHAR()+MySQL ver"),
        "Combo-Heavy-7": WafBypassStrateji(
            "Combo-Heavy-7", ["space2comment","randomcase","fromhex","apostrophemask"],
            "Hex+mask"),
        "Combo-Heavy-8": WafBypassStrateji(
            "Combo-Heavy-8", ["space2tab","randomcase","versionedkeywords","charencode"],
            "Tab+versioned+char"),
        "Combo-Heavy-9": WafBypassStrateji(
            "Combo-Heavy-9", ["space2comment","randomcase","equaltolike","charencode"],
            "Like+encode"),
        "Combo-Heavy-10": WafBypassStrateji(
            "Combo-Heavy-10", ["space2comment","randomcase","inlinecomment","versionedkeywords"],
            "Inline+versioned"),
    }

    def strateji_sec(self, waf_adi: str) -> WafBypassStrateji:
        return self.STRATEJILER.get(waf_adi, self.STRATEJILER["Generic"])

    def payload_bypass_et(self, payload: str, waf_adi: str) -> str:
        strateji = self.strateji_sec(waf_adi)
        return strateji.uygula(payload)
