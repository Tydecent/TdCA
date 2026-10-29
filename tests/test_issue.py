from cryptography import x509

from tdca.cli import main


def _run(args, monkeypatch, tmp_path):
    monkeypatch.setenv("TDCA_CA_PASSWORD", "test-passphrase")
    return main(["--ca-dir", str(tmp_path), *args])


def test_issue_generates_server_cert_with_sans(monkeypatch, tmp_path):
    _run(["init-root", "--cn", "Demo Root", "--org", "Home Lab", "--valid-days", "3650"], monkeypatch, tmp_path)
    _run(["init-intermediate", "--cn", "Demo Intermediate", "--org", "Home Lab", "--valid-days", "1825"], monkeypatch, tmp_path)
    code = _run([
        "issue",
        "--ca", "intermediate",
        "--cn", "example.com",
        "--san", "DNS:example.com,DNS:www.example.com,IP:192.168.1.10",
        "--valid-days", "365",
        "--out", str(tmp_path / "issued"),
    ], monkeypatch, tmp_path)
    assert code == 0
    issued = tmp_path / "issued"
    assert (issued / "cert.pem").exists()
    assert (issued / "key.pem").exists()
    assert oct((issued / "key.pem").stat().st_mode & 0o777) == "0o600"
    assert (issued / "chain.pem").exists()
    assert (issued / "fullchain.pem").exists()
    cert = x509.load_pem_x509_certificate((issued / "cert.pem").read_bytes())
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(sans.get_values_for_type(x509.DNSName)) == {"example.com", "www.example.com"}
    assert "192.168.1.10" in {str(value) for value in sans.get_values_for_type(x509.IPAddress)}
    assert (issued / "chain.pem").read_bytes().count(b"BEGIN CERTIFICATE") == 2
    assert (issued / "fullchain.pem").read_bytes().count(b"BEGIN CERTIFICATE") == 2


def test_issue_from_csr(monkeypatch, tmp_path):
    _run(["init-root", "--cn", "Demo Root", "--org", "Home Lab", "--valid-days", "3650"], monkeypatch, tmp_path)
    _run(["init-intermediate", "--cn", "Demo Intermediate", "--org", "Home Lab", "--valid-days", "1825"], monkeypatch, tmp_path)

    csr = tmp_path / "request.csr"
    key = tmp_path / "request.key"
    # Create simple CSR via Python stdlib and cryptography in test
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key.write_bytes(
        key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    csr_obj = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "example.org"),
        ]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.org"), x509.DNSName("www.example.org")]), critical=False)
        .sign(key_obj, hashes.SHA256())
    )
    csr.write_bytes(csr_obj.public_bytes(serialization.Encoding.PEM))

    code = _run(["issue", "--ca", "intermediate", "--csr", str(csr), "--valid-days", "365", "--out", str(tmp_path / "issued-csr")], monkeypatch, tmp_path)
    assert code == 0
    assert (tmp_path / "issued-csr" / "cert.pem").exists()
    assert not (tmp_path / "issued-csr" / "key.pem").exists()
    cert = x509.load_pem_x509_certificate((tmp_path / "issued-csr" / "cert.pem").read_bytes())
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(sans.get_values_for_type(x509.DNSName)) == {"example.org", "www.example.org"}
