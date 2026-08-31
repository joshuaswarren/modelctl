from pathlib import Path

from scripts.privacy_scan import scan_paths


def test_privacy_scan_accepts_public_fixture(tmp_path: Path) -> None:
    path = tmp_path / "clean.txt"
    path.write_text("host=engine-a.example.test\n", encoding="utf-8")

    assert scan_paths([tmp_path]) == []


def test_privacy_scan_rejects_private_values(tmp_path: Path) -> None:
    path = tmp_path / "private.txt"
    hostname = "mac" + "studio"
    address = ".".join(("10", "42", "0", "5"))  # noqa: FLY002 - keep private address out of source
    path.write_text(f"host={hostname}\naddress={address}\n", encoding="utf-8")

    errors = scan_paths([tmp_path])

    assert any("private hostname" in error for error in errors)
    assert any("RFC1918" in error for error in errors)


def test_privacy_scan_rejects_secrets_private_links_prompts_and_eval_data(tmp_path: Path) -> None:
    path = tmp_path / ("private" + "-eval.txt")
    secret = "sk-" + "test-secret-value"
    repository = "https://github.com/acme/" + "private-repo"
    instruction = "prompt=" + "You are a " + "private system " + "prompt"
    evaluation_flag = "private" + "Eval=true"
    actor_identity = "user" + "name=alice"
    customer_identity = "client" + "Name=Example Client"
    path.write_text(
        f"api_key={secret}\n"
        f"repo={repository}\n"
        f"{instruction}\n"
        f"{evaluation_flag}\n"
        f"{actor_identity}\n"
        f"{customer_identity}\n",
        encoding="utf-8",
    )

    errors = scan_paths([tmp_path])

    assert any("secret" in error for error in errors)
    assert any("private repository" in error for error in errors)
    assert any("prompt" in error for error in errors)
    assert any("private eval" in error for error in errors)
    assert any("username" in error for error in errors)
    assert any("client name" in error for error in errors)


def test_privacy_scan_distinguishes_source_identifiers_from_literal_secrets(tmp_path: Path) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text(
        "token = document.getElementById\nsecret = load_secret_value\n",
        encoding="utf-8",
    )
    unsafe = tmp_path / "unsafe.py"
    unsafe.write_text('token = "' + "abcdefgh" + "ijklmnop" + '"\n', encoding="utf-8")

    errors = scan_paths([tmp_path])

    assert not any(str(clean) in error for error in errors)
    assert any(str(unsafe) in error and "secret" in error for error in errors)


def test_privacy_scan_does_not_trust_placeholder_words_inside_secrets(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe.py"
    unsafe.write_text(
        'token = "' + "real-" + "example-" + "production-secret" + '"\n',
        encoding="utf-8",
    )

    errors = scan_paths([tmp_path])

    assert any(str(unsafe) in error and "secret" in error for error in errors)


def test_privacy_scan_excludes_generated_environments(tmp_path: Path) -> None:
    generated = tmp_path / ".venv" / "lib"
    generated.mkdir(parents=True)
    address = ".".join(("192", "168", "1", "20"))  # noqa: FLY002 - generated exclusion control
    (generated / "generated.py").write_text(f"host={'jar' + 'vis'}\naddress={address}\n", encoding="utf-8")

    assert scan_paths([tmp_path]) == []
