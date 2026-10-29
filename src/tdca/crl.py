from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .ca import load_ca_certificate, load_ca_key
from .store import all_certificates, increment_crl_number
from .utils import atomic_write, now_utc, private_directory


REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "CACompromise": x509.ReasonFlags.ca_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "certificateHold": x509.ReasonFlags.certificate_hold,
    "privilegeWithdrawn": x509.ReasonFlags.privilege_withdrawn,
}


def build_crl(ca_dir: Path, ca_name: str, next_update_days: int = 7) -> x509.CertificateRevocationList:
    issuer = load_ca_certificate(ca_dir, ca_name)
    signing_key = load_ca_key(ca_dir, ca_name)
    current = now_utc()
    number = increment_crl_number(ca_dir, ca_name)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.subject)
        .last_update(current)
        .next_update(current + timedelta(days=next_update_days))
        .add_extension(x509.CRLNumber(number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()), critical=False
        )
    )
    for row in all_certificates(ca_dir):
        if row["issuer_ca"] != ca_name or row["status"] != "revoked":
            continue
        certificate = x509.load_pem_x509_certificate(Path(row["cert_path"]).read_bytes())
        if certificate.not_valid_after_utc < current:
            continue
        revoked_at = datetime.fromisoformat(row["revoked_at"])
        reason = REASONS.get(row["revoke_reason"], x509.ReasonFlags.unspecified)
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(certificate.serial_number)
            .revocation_date(revoked_at)
            .add_extension(x509.CRLReason(reason), critical=False)
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    return builder.sign(private_key=signing_key, algorithm=hashes.SHA256())


def write_crl(ca_dir: Path, ca_name: str, output_dir: Path, next_update_days: int = 7) -> Path:
    crl = build_crl(ca_dir, ca_name, next_update_days)
    data = crl.public_bytes(serialization.Encoding.PEM)
    stored_path = ca_dir / "crl" / ca_name / "crl.pem"
    output_path = output_dir / "crl.pem"
    private_directory(stored_path.parent)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    atomic_write(stored_path, data, 0o644)
    if output_path.resolve() != stored_path.resolve():
        atomic_write(output_path, data, 0o644)
    return output_path