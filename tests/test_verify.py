from tdca.cli import main


def _run(args, monkeypatch, tmp_path):
    monkeypatch.setenv("TDCA_CA_PASSWORD", "test-passphrase")
    return main(["--ca-dir", str(tmp_path), *args])


def test_verify_valid_and_revoked(monkeypatch, tmp_path):
    _run(["init-root", "--cn", "Demo Root", "--org", "Home Lab", "--valid-days", "3650"], monkeypatch, tmp_path)
    _run(["init-intermediate", "--cn", "Demo Intermediate", "--org", "Home Lab", "--valid-days", "1825"], monkeypatch, tmp_path)
    _run([
        "issue",
        "--ca", "intermediate",
        "--cn", "example.com",
        "--san", "DNS:example.com,DNS:www.example.com,IP:192.168.1.10",
        "--valid-days", "365",
        "--out", str(tmp_path / "issued"),
    ], monkeypatch, tmp_path)

    assert _run(["verify", "--cert", str(tmp_path / "issued" / "cert.pem")], monkeypatch, tmp_path) == 0
    assert _run(["revoke", "--cn", "example.com", "--reason", "keyCompromise"], monkeypatch, tmp_path) == 0
    assert _run(["verify", "--cert", str(tmp_path / "issued" / "cert.pem")], monkeypatch, tmp_path) == 1


def test_password_error_is_business_error_and_redacted(monkeypatch, tmp_path, capsys):
    _run(["init-root", "--cn", "Demo Root", "--org", "Home Lab", "--valid-days", "365"], monkeypatch, tmp_path)
    monkeypatch.setenv("TDCA_CA_PASSWORD", "wrong-pass")
    assert main([
        "--ca-dir", str(tmp_path),
        "init-intermediate", "--cn", "Demo Intermediate", "--org", "Home Lab", "--valid-days", "30",
    ]) == 1
    captured = capsys.readouterr()
    assert "wrong-pass" not in captured.out
    assert "wrong-pass" not in captured.err
