from __future__ import annotations

import getpass
import ipaddress
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.x509.oid import NameOID

from .errors import TdcaError


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def serial_hex(serial: int | str) -> str:
    if isinstance(serial, int):
        value = format(serial, "X")
    else:
        value = serial.strip().replace(":", "").removeprefix("0x").removeprefix("0X")
        if not value:
            raise TdcaError("证书序列号不能为空")
        try:
            value = format(int(value, 16), "X")
        except ValueError as exc:
            raise TdcaError("序列号必须是十六进制") from exc
    return value.upper()


def common_name(cert: x509.Certificate) -> str:
    values = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[-1].value if values else ""


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def atomic_write(path: Path, content: bytes, mode: int = 0o644, *, replace: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise TdcaError(f"目标文件已存在，未覆盖：{path}") from exc
            temporary.unlink()
        path.chmod(mode)
    finally:
        temporary.unlink(missing_ok=True)


def password_from_env_or_prompt(env_name: str, *, confirm: bool = False) -> bytes:
    value = os.environ.get(env_name)
    if value is None:
        value = getpass.getpass(f"请输入 {env_name} 密码：")
        if confirm:
            repeated = getpass.getpass("请再次输入密码：")
            if value != repeated:
                raise TdcaError("两次输入的密码不一致")
    if not value:
        raise TdcaError(f"密码不能为空（环境变量 {env_name}）")
    return value.encode("utf-8")


def certificate_sans(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    names: list[str] = []
    for name in extension.value:
        if isinstance(name, x509.DNSName):
            names.append(f"DNS:{name.value}")
        elif isinstance(name, x509.IPAddress):
            names.append(f"IP:{name.value}")
    return names


def parse_sans(value: str | None, cn: str) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    seen: set[tuple[str, str]] = set()
    if value:
        for item in value.split(","):
            item = item.strip()
            kind, separator, raw = item.partition(":")
            if not separator or not raw.strip():
                raise TdcaError(f"SAN 格式错误：{item!r}；请使用 DNS:example.com 或 IP:192.0.2.1")
            raw = raw.strip()
            if kind.upper() == "DNS":
                if any(character.isspace() for character in raw):
                    raise TdcaError(f"SAN DNS 名称无效：{raw}")
                name: x509.GeneralName = x509.DNSName(raw)
                key = ("DNS", raw.lower())
            elif kind.upper() == "IP":
                try:
                    address = ipaddress.ip_address(raw)
                except ValueError as exc:
                    raise TdcaError(f"SAN IP 地址无效：{raw}") from exc
                name = x509.IPAddress(address)
                key = ("IP", str(address))
            else:
                raise TdcaError(f"不支持的 SAN 类型：{kind}；仅支持 DNS 和 IP")
            if key not in seen:
                names.append(name)
                seen.add(key)
    if cn and ("DNS", cn.lower()) not in seen:
        names.append(x509.DNSName(cn))
    if not names:
        raise TdcaError("必须至少提供一个 SAN 或通用名称")
    return names


def san_text(names: Iterable[str]) -> str:
    return ",".join(names)