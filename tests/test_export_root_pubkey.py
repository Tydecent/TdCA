from cryptography.hazmat.primitives import serialization

from tdca.cli import main


def _run(args, monkeypatch, tmp_path):
    monkeypatch.setenv("TDCA_CA_PASSWORD", "test-passphrase")
    return main(["--ca-dir", str(tmp_path), *args])


def test_export_root_pubkey_pem_and_der(monkeypatch, tmp_path):
    assert _run(["init-root", "--cn", "Demo Root", "--org", "Home Lab", "--valid-days", "3650"], monkeypatch, tmp_path) == 0
    out_pem = tmp_path / "root_pubkey.pem"
    assert _run(["export-root-pubkey", "--out", str(out_pem)], monkeypatch, tmp_path) == 0
    pem_key = serialization.load_pem_public_key(out_pem.read_bytes())

    out_der = tmp_path / "root_pubkey.der"
    assert _run(["export-root-pubkey", "--out", str(out_der), "--format", "der"], monkeypatch, tmp_path) == 0
    der_key = serialization.load_der_public_key(out_der.read_bytes())
    assert pem_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == der_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    existing_data = out_pem.read_bytes()
    assert _run(["export-root-pubkey", "--out", str(out_pem)], monkeypatch, tmp_path) == 1
    assert out_pem.read_bytes() == existing_data
