"""Static cross-site scripting analyzer."""

from argus.analyzers.shannon import ShannonAnalyzerBase


class XssAnalyzer(ShannonAnalyzerBase):
    name = "xss"
    vuln_class = "xss"


ANALYZER = XssAnalyzer()
