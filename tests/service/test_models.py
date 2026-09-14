import pytest

from argus.service.models import ScanCreateRequest


def test_request_normalizes_git_url_and_patterns() -> None:
    request = ScanCreateRequest(
        repository_url=" https://github.com/example/project.git ",
        ref="feature/auth",
        include=["src", "src"],
        exclude=["**/generated/*"],
        background="Review access control.",
    )
    assert request.repository_url == "https://github.com/example/project.git"
    assert request.include == ["src"]


@pytest.mark.parametrize(
    "payload",
    [
        {"repository_url": "https://user:secret@example.com/repo.git"},
        {"repository_url": "https://example.com/repo.git?token=secret"},
        {"repository_url": "file:///tmp/repo"},
        {"repository_url": "https://example.com/repo.git", "ref": "--upload-pack=evil"},
        {"repository_url": "https://example.com/repo.git", "include": ["../secret"]},
        {"repository_url": "https://example.com/repo.git", "exclude": ["/etc"]},
    ],
)
def test_request_rejects_unsafe_repository_inputs(payload) -> None:
    with pytest.raises(ValueError):
        ScanCreateRequest.model_validate(payload)
