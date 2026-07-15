import argus.contracts as c


def test_exports_present():
    for name in ["Phase","Severity","Confidence","SourceMode","CodeLocation","Finding",
                 "GraphHandle","SourceAccess","LLMClient","AnalysisContext",
                 "AnalyzerResult","Analyzer","ArgusState"]:
        assert hasattr(c, name), f"缺少 {name}"


def test_phase_values():
    assert c.Phase.ENRICHMENT.value == "enrichment"
    assert c.Phase.VULN_ANALYSIS.value == "vuln_analysis"


def test_analyzer_is_runtime_checkable():
    class Dummy:
        name = "d"; phase = c.Phase.VULN_ANALYSIS; requires = []
        def run(self, ctx): return {"analyzer":"d","findings":[],"enrichment":{}}
    assert isinstance(Dummy(), c.Analyzer)
