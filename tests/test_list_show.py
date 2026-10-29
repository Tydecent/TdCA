from tdca.cli import main


def _run(args, monkeypatch, tmp_path):
    monkeypatch.setenv("TDCA_CA_PASSWORD", "test-passphrase")
    return main(["--ca-dir", str(tmp_path), *args])


def test_list_and_show_return_expected_entries(monkeypatch, tmp_path):
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

    assert _run(["list"], monkeypatch, tmp_path) == 0
    assert main(["list", "--ca-dir", str(tmp_path), "--json"]) == 0
    assert _run(["show", "--cn", "example.com"], monkeypatch, tmp_path) == 0
    assert _run(["show", "--cn", "example.com", "--json"], monkeypatch, tmp_path) == 0
