from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .errors import TdcaError
from .utils import now_utc


def generate_private_key(key_type: str, key_size: int | None = None) -> Any:
    if key_type == "rsa":
        size = 4096 if key_size is None else key_size
        if size not in {2048, 4096}:
            raise TdcaError("RSA 密钥长度仅支持 2048 或 4096")
        return rsa.generate_private_key(public_exponent=65537, key_size=size)
    if key_type == "ec":
        if key_size not in {None, 256}:
            raise TdcaError("EC 密钥仅支持 P-256（--key-size 256）")
        return ec.generate_private_key(ec.SECP256R1())
    raise TdcaError("密钥类型仅支持 rsa 或 ec")


def encrypted_private_key(key: Any, password: bytes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )


def private_key_pem(key: Any, password: bytes | None = None) -> bytes:
    encryption = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )


def load_private_key(path: str | Path, password: bytes) -> Any:
    try:
        return serialization.load_pem_private_key(Path(path).read_bytes(), password=password)
    except (ValueError, TypeError) as exc:
        raise TdcaError("无法解密 CA 私钥，请检查 TDCA_CA_PASSWORD") from exc


def subject(common_name: str, organization: str | None) -> x509.Name:
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        attributes.insert(0, x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    return x509.Name(attributes)


def build_ca_certificate(
    *,
    name: x509.Name,
    issuer: x509.Name,
    public_key: Any,
    signing_key: Any,
    valid_days: int,
    path_length: int,
    authority_cert: x509.Certificate | None = None,
) -> x509.Certificate:
    if valid_days < 1:
        raise TdcaError("有效天数必须大于 0")
    current = now_utc()
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=5))
        .not_valid_after(current + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )
    if authority_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_cert.public_key()), critical=False
        )
    return builder.sign(private_key=signing_key, algorithm=hashes.SHA256())


def build_server_certificate(
    *,
    csr: x509.CertificateSigningRequest | None,
    common_name: str,
    sans: list[x509.GeneralName],
    issuer_cert: x509.Certificate,
    signing_key: Any,
    valid_days: int,
) -> x509.Certificate:
    if valid_days < 1:
        raise TdcaError("有效天数必须大于 0")
    current = now_utc()
    not_after = current + timedelta(days=valid_days)
    if not_after > issuer_cert.not_valid_after_utc:
        raise TdcaError("请求的有效期超过签发 CA 的剩余有效期")
    public_key = csr.public_key() if csr is not None else None
    if public_key is None:
        raise TdcaError("签发服务器证书时缺少公钥")
    is_rsa = isinstance(public_key, rsa.RSAPublicKey)
    is_ec = isinstance(public_key, ec.EllipticCurvePublicKey)
    if not (is_rsa or is_ec):
        raise TdcaError("CSR 公钥类型仅支持 RSA 或 EC")
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=is_rsa,
                data_encipherment=False,
                key_agreement=is_ec,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False
        )
    )
    return builder.sign(private_key=signing_key, algorithm=hashes.SHA256())


def verify_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    key = issuer.public_key()
    signature = cert.signature
    data = cert.tbs_certificate_bytes
    algorithm = cert.signature_hash_algorithm
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, cert.signature_algorithm_parameters, algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, cert.signature_algorithm_parameters)
        else:
            key.verify(signature, data)
    except Exception as exc:
        raise TdcaError("证书签名验证失败") from exc


def certificate_pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)