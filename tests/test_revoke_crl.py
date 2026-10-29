from tdca.cli import main
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding


def _run(args, monkeypatch, tmp_path):
    monkeypatch.setenv("TDCA_CA_PASSWORD", "test-passphrase")
    return main(["--ca-dir", str(tmp_path), *args])


def test_revoke_and_crl(monkeypatch, tmp_path):
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

    assert _run(["revoke", "--cn", "example.com", "--reason", "keyCompromise"], monkeypatch, tmp_path) == 0
    original = _get_revocation(tmp_path)
    assert _run(["revoke", "--cn", "example.com", "--reason", "superseded"], monkeypatch, tmp_path) == 0
    assert _get_revocation(tmp_path) == original
    assert _run(["crl", "--ca", "intermediate", "--out", str(tmp_path / "crl-out")], monkeypatch, tmp_path) == 0
    assert (tmp_path / "crl-out" / "crl.pem").exists()
    generated_crl = x509.load_pem_x509_crl((tmp_path / "crl-out" / "crl.pem").read_bytes())
    assert len(generated_crl) == 1
    assert generated_crl[0].serial_number == int(_serial_from_meta(tmp_path), 16)
    reason = generated_crl[0].extensions.get_extension_for_class(x509.CRLReason).value.reason
    assert reason == x509.ReasonFlags.key_compromise
    issuer = x509.load_pem_x509_certificate((tmp_path / "ca" / "intermediate" / "cert.pem").read_bytes())
    issuer.public_key().verify(
        generated_crl.signature,
        generated_crl.tbs_certlist_bytes,
        padding.PKCS1v15(),
        generated_crl.signature_hash_algorithm,
    )
    assert generated_crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 1
    assert _run(["crl", "--ca", "intermediate", "--out", str(tmp_path / "crl-out")], monkeypatch, tmp_path) == 0
    second_crl = x509.load_pem_x509_crl((tmp_path / "crl-out" / "crl.pem").read_bytes())
    assert second_crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 2


def _serial_from_meta(tmp_path):
    import sqlite3

    with sqlite3.connect(tmp_path / "db.sqlite") as connection:
        return connection.execute("SELECT serial FROM certificates").fetchone()[0]


def _get_revocation(tmp_path):
    import sqlite3

    with sqlite3.connect(tmp_path / "db.sqlite") as connection:
        return connection.execute("SELECT revoked_at, revoke_reason FROM certificates").fetchone()
