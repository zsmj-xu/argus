import json
import os

import pytest

from argus.llm import AuditedLLM, LLMOutputTruncatedError
from argus.llm.client import load_llm_environment


class _FakeResponse:
    def __init__(self, text: str, finish_reason: str = "stop") -> None:
        self._text = text
        self._finish_reason = finish_reason
        self.raise_calls = 0

    def raise_for_status(self) -> None:
        self.raise_calls += 1

    def json(self) -> dict:
        return {
            "choices": [{"message": {"content": self._text}, "finish_reason": self._finish_reason}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        }


class _FakeClient:
    def __init__(self, text: str, finish_reason: str = "stop") -> None:
        self.response = _FakeResponse(text, finish_reason)
        self.calls: list[tuple[str, dict]] = []

    def post(self, url: str, *, json: dict) -> _FakeResponse:
        self.calls.append((url, json))
        return self.response


def test_complete_returns_text_and_writes_audit(tmp_path):
    fake = _FakeClient("hello from compatible model")
    llm = AuditedLLM(
        api_key="test-key",
        base_url="https://llm.example.test/v1",
        model="example-model",
        workspace="smoke",
        client=fake,
        runs_root=str(tmp_path),
    )

    result = llm.complete(system="you are a scanner", prompt="find bugs")

    assert result == "hello from compatible model"

    assert fake.calls == [
        (
            "https://llm.example.test/v1/chat/completions",
            {
                "model": "example-model",
                "max_tokens": 8192,
                "messages": [
                    {"role": "system", "content": "you are a scanner"},
                    {"role": "user", "content": "find bugs"},
                ],
            },
        )
    ]
    assert fake.response.raise_calls == 1

    audit_path = tmp_path / "smoke" / "audit" / "llm.jsonl"
    assert audit_path.exists()

    lines = audit_path.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["system"] == "you are a scanner"
    assert record["prompt"] == "find bugs"
    assert record["response"] == "hello from compatible model"
    assert record["model"] == "example-model"
    assert record["base_url"] == "https://llm.example.test/v1"
    assert record["finish_reason"] == "stop"
    assert record["usage"] == {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    assert record["timestamp"]
    assert "test-key" not in json.dumps(record)


def test_truncated_response_is_audited_then_rejected(tmp_path):
    fake = _FakeClient('{"findings": [', finish_reason="length")
    llm = AuditedLLM(
        api_key="test-key",
        base_url="https://llm.example.test/v1",
        model="example-model",
        workspace="truncated",
        client=fake,
        runs_root=str(tmp_path),
    )

    with pytest.raises(LLMOutputTruncatedError, match="max_tokens=8192"):
        llm.complete(system="system", prompt="prompt")

    record = json.loads((tmp_path / "truncated" / "audit" / "llm.jsonl").read_text().strip())
    assert record["finish_reason"] == "length"
    assert record["response"] == '{"findings": ['


def test_disable_thinking_adds_provider_extension(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LLM_DISABLE_THINKING", "true")
    fake = _FakeClient("ok")
    llm = AuditedLLM(
        api_key="test-key",
        base_url="https://llm.example.test/v1",
        model="example-model",
        workspace="no-thinking",
        client=fake,
        runs_root=str(tmp_path),
    )

    assert llm.complete(system="system", prompt="prompt") == "ok"
    assert fake.calls[0][1]["thinking"] == {"type": "disabled"}


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        ("https://llm.example.test", "https://llm.example.test/v1/chat/completions"),
        ("https://llm.example.test/v1/", "https://llm.example.test/v1/chat/completions"),
        (
            "https://llm.example.test/v1/chat/completions",
            "https://llm.example.test/v1/chat/completions",
        ),
    ],
)
def test_base_url_variants(base_url, expected, tmp_path):
    fake = _FakeClient("ok")
    llm = AuditedLLM(
        api_key="key",
        base_url=base_url,
        model="model",
        workspace="urls",
        client=fake,
        runs_root=str(tmp_path),
    )

    assert llm.complete(system="system", prompt="prompt") == "ok"
    assert fake.calls[0][0] == expected


def test_dotenv_overrides_environment_and_is_found_from_child_directory(tmp_path, monkeypatch):
    child = tmp_path / "nested" / "work"
    child.mkdir(parents=True)
    (tmp_path / ".env").write_text(
        "ARGUS_LLM_BASE_URL=https://dotenv.example.test/v1\n"
        "ARGUS_LLM_API_KEY=dotenv-key\n"
        "ARGUS_LLM_MODEL=dotenv-model\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(child)
    monkeypatch.setenv("ARGUS_LLM_BASE_URL", "https://environment.example.test")
    monkeypatch.setenv("ARGUS_LLM_API_KEY", "environment-key")
    monkeypatch.setenv("ARGUS_LLM_MODEL", "environment-model")

    loaded = load_llm_environment()

    assert loaded == str(tmp_path / ".env")
    assert os.environ["ARGUS_LLM_BASE_URL"] == "https://dotenv.example.test/v1"
    assert os.environ["ARGUS_LLM_API_KEY"] == "dotenv-key"
    assert os.environ["ARGUS_LLM_MODEL"] == "dotenv-model"
