import json
import os

import pytest

from argus.llm import AuditLevel, AuditedLLM, LLMOutputTruncatedError
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


class _SequenceClient:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def post(self, url: str, *, json: dict) -> _FakeResponse:
        self.calls.append((url, json))
        return self.responses[len(self.calls) - 1]


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
                "max_tokens": 32768,
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
    assert "system" not in record
    assert "prompt" not in record
    assert "response" not in record
    assert record["audit_level"] == "redacted"
    assert record["content"]["system"]["chars"] == len("you are a scanner")
    assert record["content"]["prompt"]["chars"] == len("find bugs")
    assert record["content"]["response"]["chars"] == len("hello from compatible model")
    assert len(record["content"]["prompt"]["sha256"]) == 64
    assert record["model"] == "example-model"
    assert record["base_url"] == "https://llm.example.test"
    assert record["finish_reason"] == "stop"
    assert record["usage"] == {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    assert record["timestamp"]
    assert "test-key" not in json.dumps(record)
    progress = [
        json.loads(line) for line in (tmp_path / "smoke" / "progress.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [event["event"] for event in progress] == [
        "llm_request_started",
        "llm_request_completed",
    ]
    assert progress[0]["details"]["prompt_chars"] == len("find bugs")
    assert "test-key" not in json.dumps(progress)


def test_truncated_response_is_audited_then_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LLM_MAX_OUTPUT_TOKENS", "32768")
    fake = _FakeClient('{"findings": [', finish_reason="length")
    llm = AuditedLLM(
        api_key="test-key",
        base_url="https://llm.example.test/v1",
        model="example-model",
        workspace="truncated",
        client=fake,
        runs_root=str(tmp_path),
    )

    with pytest.raises(LLMOutputTruncatedError, match="max_tokens=32768"):
        llm.complete(system="system", prompt="prompt")

    record = json.loads((tmp_path / "truncated" / "audit" / "llm.jsonl").read_text().strip())
    assert record["finish_reason"] == "length"
    assert record["content"]["response"]["chars"] == len('{"findings": [')
    assert record["attempt"] == 1
    assert record["max_tokens"] == 32768


def test_full_audit_requires_explicit_level(tmp_path):
    fake = _FakeClient("full response")
    llm = AuditedLLM(
        api_key="test-key",
        base_url="https://user:password@llm.example.test/v1?token=secret",
        model="example-model",
        workspace="full",
        client=fake,
        runs_root=str(tmp_path),
        audit_level=AuditLevel.FULL,
    )

    llm.complete(system="full system", prompt="full prompt")

    record = json.loads((tmp_path / "full" / "audit" / "llm.jsonl").read_text())
    assert record["audit_level"] == "full"
    assert record["system"] == "full system"
    assert record["prompt"] == "full prompt"
    assert record["response"] == "full response"
    assert record["base_url"] == "https://llm.example.test"
    assert "password" not in json.dumps(record)
    assert "token=secret" not in json.dumps(record)


def test_truncated_response_retries_with_larger_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LLM_MAX_OUTPUT_TOKENS", "131072")
    fake = _SequenceClient(
        [
            _FakeResponse('{"findings": [', finish_reason="length"),
            _FakeResponse('{"findings": []}', finish_reason="stop"),
        ]
    )
    llm = AuditedLLM(
        api_key="test-key",
        base_url="https://llm.example.test/v1",
        model="example-model",
        workspace="retry",
        client=fake,
        runs_root=str(tmp_path),
    )

    result = llm.complete(system="system", prompt="prompt")

    assert result == '{"findings": []}'
    assert [call[1]["max_tokens"] for call in fake.calls] == [32768, 65536]
    records = [json.loads(line) for line in (tmp_path / "retry" / "audit" / "llm.jsonl").read_text().splitlines()]
    assert [record["attempt"] for record in records] == [1, 2]
    assert [record["finish_reason"] for record in records] == ["length", "stop"]
    progress = [
        json.loads(line) for line in (tmp_path / "retry" / "progress.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [event["event"] for event in progress] == [
        "llm_request_started",
        "llm_request_completed",
        "llm_retry_scheduled",
        "llm_request_started",
        "llm_request_completed",
    ]


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
