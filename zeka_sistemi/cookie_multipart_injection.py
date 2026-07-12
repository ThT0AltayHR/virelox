"""VIRELOX Cookie/Multipart/HPP Injection Stubs v4.0"""
class _Base:
    def __init__(self, http, log=None, plog=None):
        self.http=http; self.log=log or (lambda m:None); self.plog=plog or self.log
    def test(self, url, param, post_data=None):
        return {"basarili": False}

class CookieInjection(_Base): pass
class MultipartInjection(_Base): pass
class HTTPParameterPollution(_Base): pass
