"""
VIRELOX Genişletilmiş SQL Injection Tipleri v4.0
Stub implementasyonlar — injection_motor tarafından lazy-load edilir
Mozilla Public License 2.0 — AltayHR Developers
"""

from typing import Callable, Optional


class _BaseInjection:
    def __init__(self, http, log=None, plog=None):
        self.http = http
        self.log  = log  or (lambda m: None)
        self.plog = plog or log or (lambda m: None)

    def test(self, url, param, post_data=None):
        return {"basarili": False, "tip": self.__class__.__name__}


class InlineQueryInjection(_BaseInjection): pass
class ConditionalErrorInjection(_BaseInjection): pass
class HeavyQueryInjection(_BaseInjection): pass
class XMLExtractInjection(_BaseInjection): pass
class JSONExtractInjection(_BaseInjection): pass
class PiggybackInjection(_BaseInjection): pass
class NestedSelectInjection(_BaseInjection): pass
class CaseWhenInjection(_BaseInjection): pass
class CharFuncInjection(_BaseInjection): pass
class FileReadInjection(_BaseInjection): pass
class FileWriteInjection(_BaseInjection): pass
class ProcedureInjection(_BaseInjection): pass
class BenchmarkBlindInjection(_BaseInjection): pass
class DecimalInjection(_BaseInjection): pass
class RowIDInjection(_BaseInjection): pass


TUM_SQL_INJECTION_TIPLERI = {
    "inline_query":       InlineQueryInjection,
    "conditional_error":  ConditionalErrorInjection,
    "heavy_query":        HeavyQueryInjection,
    "xml_extract":        XMLExtractInjection,
    "json_extract":       JSONExtractInjection,
    "piggyback":          PiggybackInjection,
    "nested_select":      NestedSelectInjection,
    "case_when":          CaseWhenInjection,
    "char_func":          CharFuncInjection,
    "file_read":          FileReadInjection,
    "file_write":         FileWriteInjection,
    "procedure":          ProcedureInjection,
    "benchmark_blind":    BenchmarkBlindInjection,
    "decimal":            DecimalInjection,
    "rowid":              RowIDInjection,
}
