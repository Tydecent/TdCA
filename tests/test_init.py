import os

from tdca.cli import main


def _run(args, monkeypatch, tmp_path):
    monkeypatch.setenv("TDCA_CA_PASSWORD", "test-passphrase")
    return main(["--ca-dir", str(tmp_path), *args])


def test_init_root_creates_ca_and_rejects_repeat(monkeypatch, tmp_path):
    assert _run(["init-root", "--cn", "Demo Root", "--org", "Home Lab", "--valid-days", "3650"], monkeypatch, tmp_path) == 0
    assert _run(["init-root", "--cn", "Demo Root", "--org", "Home Lab", "--valid-days", "3650"], monkeypatch, tmp_path) == 1

    root_dir = tmp_path / "ca" / "root"
    assert (root_dir / "cert.pem").exists()
    assert (root_dir / "key.pem").exists()
    assert oct((root_dir / "key.pem").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path).stat().st_mode & 0o777) == "0o700"
    assert oct((tmp_path / "ca").stat().st_mode & 0o777) == "0o700"


def test_init_intermediate_creates_ca(monkeypatch, tmp_path):
    assert _run(["init-root", "--cn", "Demo Root", "--org", "Home Lab", "--valid-days", "3650"], monkeypatch, tmp_path) == 0
    assert _run(["init-intermediate", "--cn", "Demo Intermediate", "--org", "Home Lab", "--valid-days", "1825"], monkeypatch, tmp_path) == 0
    assert (tmp_path / "ca" / "intermediate" / "cert.pem").exists()
    assert (tmp_path / "ca" / "intermediate" / "key.pem").exists()
