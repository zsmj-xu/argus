import json

from argus.llm import AuditedLLM


class _FakeContentBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _FakeMessage:
    def __init__(self, text: str) -> None:
        self.content = [_FakeContentBlock(text)]


class _FakeMessages:
    def __init__(self, text: str) -> None:
        self._text = text
        self.calls: list[dict] = []

    def create(self, **kwargs) -> _FakeMessage:
        self.calls.append(kwargs)
        return _FakeMessage(self._text)


class _FakeAnthropic:
    """Stand-in for anthropic.Anthropic — records calls, returns canned text."""

    def __init__(self, text: str) -> None:
        self.messages = _FakeMessages(text)


def test_complete_returns_text_and_writes_audit(tmp_path):
    fake = _FakeAnthropic("hello from claude")
    llm = AuditedLLM(api_key="test-key", workspace="smoke", client=fake, runs_root=str(tmp_path))

    result = llm.complete(system="you are a scanner", prompt="find bugs")

    assert result == "hello from claude"

    # SDK was actually invoked with our system/prompt
    assert len(fake.messages.calls) == 1

    audit_path = tmp_path / "smoke" / "audit" / "llm.jsonl"
    assert audit_path.exists()

    lines = audit_path.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["system"] == "you are a scanner"
    assert record["prompt"] == "find bugs"
    assert record["response"] == "hello from claude"
    assert record["model"]
    assert record["timestamp"]
