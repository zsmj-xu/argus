"""Static server-side request forgery analyzer."""

from argus.analyzers.shannon import ShannonAnalyzerBase


class SsrfAnalyzer(ShannonAnalyzerBase):
    name = "ssrf"
    vuln_class = "ssrf"


ANALYZER = SsrfAnalyzer()
