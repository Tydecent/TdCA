from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from . import __version__
from . import ca, crl, store
from .audit import record as audit_record
from .crypto import (
    build_server_certificate,
    certificate_pem,
    generate_private_key,
    private_key_pem,
    verify_signature,
)
from .errors import TdcaError
from .utils import (
    atomic_write,
    certificate_sans,
    common_name,
    isoformat,
    now_utc,
    parse_sans,
    private_directory,
    san_text,
    serial_hex,
)


def _base_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tdca", description="个人网站 CA 管理工具")
    parser.add_argument("--ca-dir", default="~/.tdca", help="CA 工作目录（默认：~/.tdca）")
    parser.add_argument("--verbose", action="store_true", help="显示脱敏后的调试信息")
    commands = parser.add_subparsers(dest="command", required=True)

    def common(subparser: argparse.ArgumentParser, *, json_output: bool = True) -> None:
        subparser.add_argument("--ca-dir", default=argparse.SUPPRESS, help="CA 工作目录")
        if json_output:
            subparser.add_argument("--json", action="store_true", help="输出 JSON")

    root = commands.add_parser("init-root", help="初始化自签名根 CA")
    common(root)
    root.add_argument("--cn", required=True, help="根 CA 通用名称")
    root.add_argument("--org", help="组织名称")
    root.add_argument("--valid-days", type=int, default=3650)
    root.add_argument("--key-type", choices=("rsa", "ec"), default="rsa")
    root.add_argument("--key-size", type=int)

    intermediate = commands.add_parser("init-intermediate", help="初始化中间 CA")
    common(intermediate)
    intermediate.add_argument("--cn", required=True)
    intermediate.add_argument("--org")
    intermediate.add_argument("--valid-days", type=int, default=1825)
    intermediate.add_argument("--key-type", choices=("rsa", "ec"), default="rsa")
    intermediate.add_argument("--key-size", type=int)

    issue = commands.add_parser("issue", help="签发服务器证书")
    common(issue)
    issue.add_argument("--ca", choices=("root", "intermediate"), default="intermediate")
    identity = issue.add_mutually_exclusive_group(required=True)
    identity.add_argument("--cn")
    identity.add_argument("--csr", type=Path)
    issue.add_argument("--san", help="逗号分隔的 DNS:名称 或 IP:地址")
    issue.add_argument("--valid-days", type=int, default=365)
    issue.add_argument("--key-type", choices=("rsa", "ec"), default="rsa")
    issue.add_argument("--key-size", type=int)
    issue.add_argument("--encrypt-key", action="store_true", help="使用 TDCA_KEY_PASSWORD 加密服务器私钥")
    issue.add_argument("--out", type=Path, required=True)

    listing = commands.add_parser("list", help="列出已签发证书")
    common(listing)

    show = commands.add_parser("show", help="显示证书详情")
    common(show)
    selector = show.add_mutually_exclusive_group(required=True)
    selector.add_argument("--serial")
    selector.add_argument("--cn")

    export = commands.add_parser("export", help="导出证书文件")
    common(export)
    selector = export.add_mutually_exclusive_group(required=True)
    selector.add_argument("--serial")
    selector.add_argument("--cn")
    export.add_argument("--out", type=Path, required=True)

    revoke = commands.add_parser("revoke", help="吊销证书")
    common(revoke)
    selector = revoke.add_mutually_exclusive_group(required=True)
    selector.add_argument("--serial")
    selector.add_argument("--cn")
    revoke.add_argument("--reason", choices=tuple(crl.REASONS), default="unspecified")

    make_crl = commands.add_parser("crl", help="生成并签名 CRL")
    common(make_crl)
    make_crl.add_argument("--ca", choices=("root", "intermediate"), default="intermediate")
    make_crl.add_argument("--out", type=Path, required=True)
    make_crl.add_argument("--next-update-days", type=int, default=7)

    verify = commands.add_parser("verify", help="验证证书签名链、有效期和吊销状态")
    common(verify)
    verify.add_argument("--cert", type=Path, required=True)

    audit = commands.add_parser("audit", help="查看审计日志")
    common(audit)
    audit.add_argument("--limit", type=int, default=50)

    version = commands.add_parser("version", help="显示版本")
    common(version)
    return parser


def _ca_dir(args: argparse.Namespace) -> Path:
    return Path(args.ca_dir).expanduser().resolve()


def _emit(value: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2, default=str))
    elif isinstance(value, str):
        print(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, list):
                print(f"{key}: {', '.join(str(value) for value in item)}")
            elif isinstance(item, dict):
                print(f"{key}:")
                for nested_key, nested_value in item.items():
                    print(f"  {nested_key}: {nested_value}")
            else:
                print(f"{key}: {item}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                print("- " + ", ".join(f"{key}={value}" for key, value in item.items()))
            else:
                print(item)
    else:
        print(value)


def _ca_summary(certificate: x509.Certificate, path: Path) -> dict[str, Any]:
    return {
        "certificate": str(path),
        "subject": certificate.subject.rfc4514_string(),
        "not_before": isoformat(certificate.not_valid_before_utc),
        "not_after": isoformat(certificate.not_valid_after_utc),
        "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex().upper(),
    }


def _write_new_bundle(output: Path, files: dict[str, tuple[bytes, int]]) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True, mode=0o755)
    written: list[Path] = []
    try:
        for name, (content, mode) in files.items():
            path = output / name
            atomic_write(path, content, mode, replace=False)
            written.append(path)
    except Exception:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    return written


def _load_csr(path: Path) -> x509.CertificateSigningRequest:
    try:
        data = path.read_bytes()
        try:
            csr = x509.load_pem_x509_csr(data)
        except ValueError:
            csr = x509.load_der_x509_csr(data)
    except (OSError, ValueError) as exc:
        raise TdcaError(f"无法读取或解析 CSR：{path}") from exc
    if not csr.is_signature_valid:
        raise TdcaError("CSR 签名无效")
    return csr


def _csr_sans(csr: x509.CertificateSigningRequest) -> list[x509.GeneralName]:
    try:
        extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        cn_values = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_values:
            raise TdcaError("CSR 缺少 SAN 扩展和 CN，无法安全确定证书名称")
        return [x509.DNSName(cn_values[-1].value)]
    names = list(extension.value)
    if not names:
        raise TdcaError("CSR 的 SAN 扩展为空")
    return names


def _issue(args: argparse.Namespace, ca_dir: Path) -> dict[str, Any]:
    issuer_cert = ca.load_ca_certificate(ca_dir, args.ca)
    current = now_utc()
    if current < issuer_cert.not_valid_before_utc or current > issuer_cert.not_valid_after_utc:
        raise TdcaError("签发 CA 当前不在有效期内")
    issuer_key = ca.load_ca_key(ca_dir, args.ca)
    if args.csr:
        csr = _load_csr(args.csr.expanduser())
        names = _csr_sans(csr)
        subject_name = csr.subject
        cn_values = subject_name.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn_values[-1].value if cn_values else ""
        if args.san:
            raise TdcaError("使用 --csr 时 SAN 必须来自 CSR，不能再传入 --san")
        key = None
    else:
        cn = args.cn
        names = parse_sans(args.san, cn)
        subject_name = ca.subject(cn, None)
        leaf_key_size = args.key_size if args.key_size is not None else (2048 if args.key_type == "rsa" else None)
        key = generate_private_key(args.key_type, leaf_key_size)
        from cryptography.hazmat.primitives import hashes as crypto_hashes

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject_name)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(key, crypto_hashes.SHA256())
        )
    certificate = build_server_certificate(
        csr=csr,
        common_name=cn,
        sans=names,
        issuer_cert=issuer_cert,
        signing_key=issuer_key,
        valid_days=args.valid_days,
    )
    verify_signature(certificate, issuer_cert)
    serial = serial_hex(certificate.serial_number)
    san_values = certificate_sans(certificate)
    chain_certs = ca.issuer_chain(ca_dir, args.ca)
    from cryptography.hazmat.primitives import serialization

    chain_bytes = b"".join(item.public_bytes(serialization.Encoding.PEM) for item in chain_certs)
    fullchain_bytes = certificate_pem(certificate) + b"".join(
        item.public_bytes(serialization.Encoding.PEM) for item in chain_certs[:-1]
    )
    key_path: Path | None = None
    key_bytes: bytes | None = None
    if key is not None:
        key_password = None
        if args.encrypt_key:
            from .utils import password_from_env_or_prompt

            key_password = password_from_env_or_prompt("TDCA_KEY_PASSWORD")
        key_bytes = private_key_pem(key, key_password)
        key_path = ca_dir / "certs" / serial / "key.pem"
    files = {
        "cert.pem": (certificate_pem(certificate), 0o644),
        "chain.pem": (chain_bytes, 0o644),
        "fullchain.pem": (fullchain_bytes, 0o644),
    }
    if key_bytes is not None:
        files["key.pem"] = (key_bytes, 0o600)
    output_paths = _write_new_bundle(args.out.expanduser(), files)
    internal_dir = ca_dir / "certs" / serial
    private_directory(internal_dir)
    internal_files = {
        "cert.pem": (certificate_pem(certificate), 0o644),
        "chain.pem": (chain_bytes, 0o644),
        "fullchain.pem": (fullchain_bytes, 0o644),
    }
    if key_bytes is not None:
        internal_files["key.pem"] = (key_bytes, 0o600)
    internal_paths: list[Path] = []
    try:
        for name, (content, mode) in internal_files.items():
            path = internal_dir / name
            atomic_write(path, content, mode, replace=False)
            internal_paths.append(path)
        store.insert_certificate(
            ca_dir,
            {
                "serial": serial,
                "common_name": cn,
                "san": san_text(san_values),
                "issuer_ca": args.ca,
                "not_before": isoformat(certificate.not_valid_before_utc),
                "not_after": isoformat(certificate.not_valid_after_utc),
                "status": "valid",
                "cert_path": str(internal_dir / "cert.pem"),
                "key_path": str(key_path) if key_path else None,
                "chain_path": str(internal_dir / "chain.pem"),
                "fullchain_path": str(internal_dir / "fullchain.pem"),
                "created_at": isoformat(now_utc()),
            },
        )
    except Exception:
        for path in [*internal_paths, *output_paths]:
            path.unlink(missing_ok=True)
        raise
    audit_record(ca_dir, "issue", serial)
    return {
        "serial": serial,
        "subject": certificate.subject.rfc4514_string(),
        "san": san_values,
        "issuer_ca": args.ca,
        "not_before": isoformat(certificate.not_valid_before_utc),
        "not_after": isoformat(certificate.not_valid_after_utc),
        "files": {path.name: str(path) for path in output_paths},
    }


def _status(row: sqlite3.Row, certificate: x509.Certificate) -> tuple[str, int]:
    remaining = (certificate.not_valid_after_utc - now_utc()).days
    if row["status"] == "revoked":
        return "revoked", remaining
    if certificate.not_valid_after_utc <= now_utc():
        return "expired", remaining
    return "valid", remaining


def _certificate_detail(row: sqlite3.Row) -> dict[str, Any]:
    certificate = x509.load_pem_x509_certificate(Path(row["cert_path"]).read_bytes())
    status, remaining = _status(row, certificate)
    return {
        "serial": row["serial"],
        "common_name": row["common_name"],
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "san": certificate_sans(certificate),
        "issuer_ca": row["issuer_ca"],
        "not_before": row["not_before"],
        "not_after": row["not_after"],
        "remaining_days": remaining,
        "status": status,
        "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex().upper(),
        "certificate_path": row["cert_path"],
        "revoked_at": row["revoked_at"],
        "revoke_reason": row["revoke_reason"],
    }


def _list_certificates(ca_dir: Path) -> list[dict[str, Any]]:
    return [_certificate_detail(row) for row in store.all_certificates(ca_dir)]


def _format_table(rows: list[dict[str, Any]]) -> str:
    headers = ("SERIAL", "CN", "SAN", "CA", "NOT BEFORE", "NOT AFTER", "DAYS", "STATUS")
    values = [
        (
            row["serial"],
            row["common_name"],
            ",".join(row["san"]),
            row["issuer_ca"],
            row["not_before"][:10],
            row["not_after"][:10],
            str(row["remaining_days"]),
            row["status"],
        )
        for row in rows
    ]
    widths = [min(max(len(headers[index]), *(len(item[index]) for item in values)) if values else len(headers[index]), 36) for index in range(len(headers))]
    line = "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    separator = "  ".join("-" * width for width in widths)
    lines = [line, separator]
    for row in values:
        lines.append("  ".join(row[index][:widths[index]].ljust(widths[index]) for index in range(len(headers))))
    return "\n".join(lines)


def _verify(args: argparse.Namespace, ca_dir: Path) -> dict[str, Any]:
    try:
        certificate = x509.load_pem_x509_certificate(args.cert.expanduser().read_bytes())
    except (OSError, ValueError) as exc:
        raise TdcaError(f"无法读取或解析证书：{args.cert}") from exc
    candidates: list[tuple[str, x509.Certificate]] = []
    for name in ("intermediate", "root"):
        path = ca.ca_path(ca_dir, name) / "cert.pem"
        if path.is_file():
            issuer = x509.load_pem_x509_certificate(path.read_bytes())
            if issuer.subject == certificate.issuer:
                candidates.append((name, issuer))
    if not candidates:
        raise TdcaError("找不到可验证该证书的本地签发 CA")
    issuer_name, issuer_cert = candidates[0]
    verify_signature(certificate, issuer_cert)
    current = now_utc()
    if current < issuer_cert.not_valid_before_utc or current > issuer_cert.not_valid_after_utc:
        raise TdcaError("签发 CA 当前不在有效期内")
    if issuer_name == "intermediate":
        root_cert = ca.load_ca_certificate(ca_dir, "root")
        verify_signature(issuer_cert, root_cert)
        if current < root_cert.not_valid_before_utc or current > root_cert.not_valid_after_utc:
            raise TdcaError("根 CA 当前不在有效期内")
        verify_signature(root_cert, root_cert)
    else:
        verify_signature(issuer_cert, issuer_cert)
    if current < certificate.not_valid_before_utc or current > certificate.not_valid_after_utc:
        raise TdcaError("证书当前不在有效期内")
    serial = serial_hex(certificate.serial_number)
    if not store.database_path(ca_dir).is_file():
        raise TdcaError("CA 元数据数据库不存在，无法检查本地吊销状态")
    try:
        row = store.find_certificate(ca_dir, serial=serial)
    except TdcaError:
        row = None
    if row is not None and row["status"] == "revoked":
        raise TdcaError(f"证书已吊销：{serial}（{row['revoke_reason']}，{row['revoked_at']}）")
    return {
        "valid": True,
        "serial": serial,
        "issuer_ca": issuer_name,
        "subject": certificate.subject.rfc4514_string(),
        "not_before": isoformat(certificate.not_valid_before_utc),
        "not_after": isoformat(certificate.not_valid_after_utc),
        "revoked": False,
    }


def _run(args: argparse.Namespace) -> int:
    ca_dir = _ca_dir(args)
    as_json = bool(getattr(args, "json", False))
    if args.command == "version":
        _emit({"version": __version__}, as_json)
        return 0
    if args.command == "init-root":
        certificate = ca.initialize_root(ca_dir, args.cn, args.org, args.valid_days, args.key_type, args.key_size)
        store.initialize(ca_dir)
        result = _ca_summary(certificate, ca.ca_path(ca_dir, "root") / "cert.pem")
        audit_record(ca_dir, "init-root", "root")
        _emit(result, as_json)
    elif args.command == "init-intermediate":
        certificate = ca.initialize_intermediate(ca_dir, args.cn, args.org, args.valid_days, args.key_type, args.key_size)
        result = _ca_summary(certificate, ca.ca_path(ca_dir, "intermediate") / "cert.pem")
        audit_record(ca_dir, "init-intermediate", "intermediate")
        _emit(result, as_json)
    elif args.command == "issue":
        _emit(_issue(args, ca_dir), as_json)
    elif args.command == "list":
        rows = _list_certificates(ca_dir)
        _emit(rows, True) if as_json else print(_format_table(rows))
    elif args.command == "show":
        serial = serial_hex(args.serial) if args.serial else None
        row = store.find_certificate(ca_dir, serial=serial, cn=args.cn)
        _emit(_certificate_detail(row), as_json)
    elif args.command == "export":
        serial = serial_hex(args.serial) if args.serial else None
        row = store.find_certificate(ca_dir, serial=serial, cn=args.cn)
        cert_data = Path(row["cert_path"]).read_bytes()
        chain_data = Path(row["chain_path"]).read_bytes()
        fullchain_data = Path(row["fullchain_path"]).read_bytes()
        files = {
            "cert.pem": (cert_data, 0o644),
            "chain.pem": (chain_data, 0o644),
            "fullchain.pem": (fullchain_data, 0o644),
        }
        if row["key_path"] and Path(row["key_path"]).is_file():
            files["key.pem"] = (Path(row["key_path"]).read_bytes(), 0o600)
        paths = _write_new_bundle(args.out.expanduser(), files)
        result = {"serial": row["serial"], "files": {path.name: str(path) for path in paths}}
        audit_record(ca_dir, "export", row["serial"])
        _emit(result, as_json)
    elif args.command == "revoke":
        serial = serial_hex(args.serial) if args.serial else None
        row = store.find_certificate(ca_dir, serial=serial, cn=args.cn)
        if row["status"] == "revoked":
            result = {"serial": row["serial"], "status": "revoked", "revoked_at": row["revoked_at"], "reason": row["revoke_reason"], "already_revoked": True}
            audit_record(ca_dir, "revoke", row["serial"], "already-revoked")
        else:
            revoked_at = isoformat(now_utc())
            store.update_certificate_status(ca_dir, row["serial"], revoked_at, args.reason)
            result = {"serial": row["serial"], "status": "revoked", "revoked_at": revoked_at, "reason": args.reason, "already_revoked": False}
            audit_record(ca_dir, "revoke", row["serial"])
        _emit(result, as_json)
    elif args.command == "crl":
        if args.next_update_days < 1:
            raise TdcaError("CRL next-update 天数必须大于 0")
        path = crl.write_crl(ca_dir, args.ca, args.out.expanduser(), args.next_update_days)
        audit_record(ca_dir, "crl", args.ca)
        _emit({"ca": args.ca, "crl": str(path)}, as_json)
    elif args.command == "verify":
        _emit(_verify(args, ca_dir), as_json)
    elif args.command == "audit":
        if args.limit < 1:
            raise TdcaError("--limit 必须大于 0")
        path = ca_dir / "audit.log"
        try:
            entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except FileNotFoundError:
            entries = []
        entries = entries[-args.limit :]
        _emit(entries, as_json)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _base_parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except TdcaError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"错误：操作失败：{exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc(file=sys.stderr)
        return 1
    except Exception:
        print("错误：内部操作失败；未输出敏感内容", file=sys.stderr)
        if args.verbose:
            traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())