from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .errors import TdcaError
from .utils import private_directory


SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    serial TEXT PRIMARY KEY,
    common_name TEXT NOT NULL,
    san TEXT NOT NULL,
    issuer_ca TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'valid',
    revoked_at TEXT,
    revoke_reason TEXT,
    cert_path TEXT NOT NULL,
    key_path TEXT,
    chain_path TEXT NOT NULL,
    fullchain_path TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS crl_numbers (
    ca_name TEXT PRIMARY KEY,
    number INTEGER NOT NULL
);
"""


def database_path(ca_dir: Path) -> Path:
    return ca_dir / "db.sqlite"


def initialize(ca_dir: Path) -> None:
    private_directory(ca_dir)
    connection = sqlite3.connect(database_path(ca_dir))
    try:
        connection.executescript(SCHEMA)
        connection.commit()
    finally:
        connection.close()
    database_path(ca_dir).chmod(0o600)


def update_certificate_status(ca_dir: Path, serial: str, revoked_at: str, reason: str) -> None:
    with transaction(ca_dir) as connection:
        connection.execute(
            "UPDATE certificates SET status = 'revoked', revoked_at = ?, revoke_reason = ? WHERE serial = ?",
            (revoked_at, reason, serial),
        )


def connect(ca_dir: Path) -> sqlite3.Connection:
    path = database_path(ca_dir)
    if not path.exists():
        raise TdcaError(f"CA 尚未初始化：找不到数据库 {path}，请先运行 init-root")
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def transaction(ca_dir: Path) -> Iterator[sqlite3.Connection]:
    connection = connect(ca_dir)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def insert_certificate(ca_dir: Path, record: dict[str, Any]) -> None:
    initialize(ca_dir)
    columns = ",".join(record.keys())
    placeholders = ",".join("?" for _ in record)
    with transaction(ca_dir) as connection:
        connection.execute(
            f"INSERT INTO certificates ({columns}) VALUES ({placeholders})",
            tuple(record.values()),
        )


def all_certificates(ca_dir: Path) -> list[sqlite3.Row]:
    with transaction(ca_dir) as connection:
        return list(connection.execute("SELECT * FROM certificates ORDER BY created_at DESC"))


def find_certificate(ca_dir: Path, *, serial: str | None = None, cn: str | None = None) -> sqlite3.Row:
    with transaction(ca_dir) as connection:
        if serial is not None:
            row = connection.execute("SELECT * FROM certificates WHERE serial = ?", (serial,)).fetchone()
            if row is None:
                raise TdcaError(f"证书不存在：序列号 {serial}")
            return row
        rows = list(connection.execute("SELECT * FROM certificates WHERE common_name = ? ORDER BY created_at DESC", (cn,)))
    if not rows:
        raise TdcaError(f"证书不存在：CN {cn}")
    if len(rows) > 1:
        choices = ", ".join(row["serial"] for row in rows)
        raise TdcaError(f"CN {cn} 命中多个证书，请使用 --serial。候选序列号：{choices}")
    return rows[0]


def increment_crl_number(ca_dir: Path, ca_name: str) -> int:
    initialize(ca_dir)
    with transaction(ca_dir) as connection:
        row = connection.execute("SELECT number FROM crl_numbers WHERE ca_name = ?", (ca_name,)).fetchone()
        number = (row["number"] if row else 0) + 1
        connection.execute(
            "INSERT INTO crl_numbers (ca_name, number) VALUES (?, ?) "
            "ON CONFLICT(ca_name) DO UPDATE SET number = excluded.number",
            (ca_name, number),
        )
        return number