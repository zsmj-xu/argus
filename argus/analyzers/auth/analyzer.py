"""Static authentication vulnerability analyzer."""

from argus.analyzers.shannon import ShannonAnalyzerBase


class AuthAnalyzer(ShannonAnalyzerBase):
    name = "auth"
    vuln_class = "auth"


ANALYZER = AuthAnalyzer()
