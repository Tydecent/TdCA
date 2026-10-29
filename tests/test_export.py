from tdca.cli import main


def _run(args, monkeypatch, tmp_path):
    monkeypatch.setenv("TDCA_CA_PASSWORD", "test-passphrase")
    return main(["--ca-dir", str(tmp_path), *args])


def test_export_outputs_bundle_files(monkeypatch, tmp_path):
    _run(["init-root", "--cn", "Demo Root", "--org", "Home Lab", "--valid-days", "3650"], monkeypatch, tmp_path)
    _run(["init-intermediate", "--cn", "Demo Intermediate", "--org", "Home Lab", "--valid-days", "1825"], monkeypatch, tmp_path)
    monkeypatch.setenv("TDCA_KEY_PASSWORD", "server-key-passphrase")
    _run([
        "issue",
        "--ca", "intermediate",
        "--cn", "example.com",
        "--san", "DNS:example.com,DNS:www.example.com,IP:192.168.1.10",
        "--valid-days", "365",
        "--encrypt-key",
        "--out", str(tmp_path / "issued"),
    ], monkeypatch, tmp_path)

    assert _run(["export", "--cn", "example.com", "--out", str(tmp_path / "exported")], monkeypatch, tmp_path) == 0
    exported = tmp_path / "exported"
    for name in ["cert.pem", "chain.pem", "fullchain.pem", "key.pem"]:
        assert (exported / name).exists(), name
    assert (exported / "key.pem").read_bytes() == (tmp_path / "issued" / "key.pem").read_bytes()
    assert b"ENCRYPTED" in (exported / "key.pem").read_bytes().splitlines()[0]
    assert oct((exported / "key.pem").stat().st_mode & 0o777) == "0o600"
