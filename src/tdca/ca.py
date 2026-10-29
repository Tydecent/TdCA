from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .crypto import build_ca_certificate, certificate_pem, encrypted_private_key, generate_private_key, load_private_key, subject, verify_signature
from .errors import TdcaError
from .utils import atomic_write, now_utc, password_from_env_or_prompt, private_directory


def ca_path(ca_dir: Path, name: str) -> Path:
    return ca_dir / "ca" / name


def load_ca_certificate(ca_dir: Path, name: str) -> x509.Certificate:
    path = ca_path(ca_dir, name) / "cert.pem"
    if not path.is_file():
        raise TdcaError(f"{name} CA 不存在：{path}；请先初始化或显式选择现有 CA")
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except ValueError as exc:
        raise TdcaError(f"CA 证书无法解析：{path}") from exc


def load_ca_key(ca_dir: Path, name: str, password: bytes | None = None) -> Any:
    path = ca_path(ca_dir, name) / "key.pem"
    if not path.is_file():
        raise TdcaError(f"{name} CA 私钥不存在：{path}")
    return load_private_key(str(path), password or password_from_env_or_prompt("TDCA_CA_PASSWORD"))


def initialize_root(
    ca_dir: Path, common_name: str, organization: str | None, valid_days: int, key_type: str, key_size: int | None
) -> x509.Certificate:
    target = ca_path(ca_dir, "root")
    if target.exists():
        raise TdcaError(f"root CA 路径已存在，未覆盖：{target}")
    if valid_days < 1:
        raise TdcaError("有效天数必须大于 0")
    password = password_from_env_or_prompt("TDCA_CA_PASSWORD", confirm=True)
    key = generate_private_key(key_type, key_size)
    certificate = build_ca_certificate(
        name=subject(common_name, organization),
        issuer=subject(common_name, organization),
        public_key=key.public_key(),
        signing_key=key,
        valid_days=valid_days,
        path_length=1,
    )
    private_directory(ca_dir)
    private_directory(target.parent)
    private_directory(target)
    try:
        atomic_write(target / "key.pem", encrypted_private_key(key, password), 0o600, replace=False)
        atomic_write(target / "cert.pem", certificate_pem(certificate), 0o644, replace=False)
    except Exception:
        (target / "key.pem").unlink(missing_ok=True)
        (target / "cert.pem").unlink(missing_ok=True)
        target.rmdir()
        raise
    return certificate


def initialize_intermediate(
    ca_dir: Path, common_name: str, organization: str | None, valid_days: int, key_type: str, key_size: int | None
) -> x509.Certificate:
    target = ca_path(ca_dir, "intermediate")
    if target.exists():
        raise TdcaError(f"intermediate CA 路径已存在，未覆盖：{target}")
    if valid_days < 1:
        raise TdcaError("有效天数必须大于 0")
    root_cert = load_ca_certificate(ca_dir, "root")
    root_key = load_ca_key(ca_dir, "root")
    current = now_utc()
    if current + __import__("datetime").timedelta(days=valid_days) > root_cert.not_valid_after_utc:
        raise TdcaError("中间 CA 有效期超过根 CA 剩余有效期")
    key = generate_private_key(key_type, key_size)
    certificate = build_ca_certificate(
        name=subject(common_name, organization),
        issuer=root_cert.subject,
        public_key=key.public_key(),
        signing_key=root_key,
        valid_days=valid_days,
        path_length=0,
        authority_cert=root_cert,
    )
    verify_signature(certificate, root_cert)
    private_directory(target.parent)
    private_directory(target)
    try:
        password = password_from_env_or_prompt("TDCA_CA_PASSWORD")
        atomic_write(target / "key.pem", encrypted_private_key(key, password), 0o600, replace=False)
        atomic_write(target / "cert.pem", certificate_pem(certificate), 0o644, replace=False)
    except Exception:
        (target / "key.pem").unlink(missing_ok=True)
        (target / "cert.pem").unlink(missing_ok=True)
        target.rmdir()
        raise
    return certificate


def issuer_chain(ca_dir: Path, name: str) -> list[x509.Certificate]:
    certificate = load_ca_certificate(ca_dir, name)
    if name == "root":
        verify_signature(certificate, certificate)
        return [certificate]
    root = load_ca_certificate(ca_dir, "root")
    verify_signature(certificate, root)
    verify_signature(root, root)
    return [certificate, root]