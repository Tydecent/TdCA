from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def record(ca_dir: Path, command: str, object_id: str, result: str = "success") -> None:
    ca_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = ca_dir / "audit.log"
    entry: dict[str, Any] = {
        "time": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "object": object_id,
        "result": result,
    }
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)