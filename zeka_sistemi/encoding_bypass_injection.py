"""VIRELOX Encoding Bypass Injection Stubs v4.0"""
class _Base:
    def __init__(self, http, log=None, plog=None):
        self.http=http; self.log=log or (lambda m:None); self.plog=plog or self.log
    def test(self, url, param, post_data=None):
        return {"basarili": False}

TUM_ENCODING_BYPASS = {
    "hex_encoding":      _Base,
    "char_func_bypass":  _Base,
    "double_url":        _Base,
    "unicode_bypass":    _Base,
    "comment_split":     _Base,
    "base64":            _Base,
    "case_mixing":       _Base,
    "whitespace_bypass": _Base,
}
