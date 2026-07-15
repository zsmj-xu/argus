"""Static injection vulnerability analyzer."""

from argus.analyzers.shannon import ShannonAnalyzerBase


class InjectionAnalyzer(ShannonAnalyzerBase):
    name = "injection"
    vuln_class = "injection"


ANALYZER = InjectionAnalyzer()
