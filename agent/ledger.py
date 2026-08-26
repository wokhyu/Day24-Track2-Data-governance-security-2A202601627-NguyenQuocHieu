"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash)

    verify(path: pathlib.Path) -> bool
        True nếu mọi dòng có `reason` non-empty, chuỗi prev_hash liền mạch,
        và hash lưu trong mỗi dòng khớp khi tính lại.

--- Ghi chú thiết kế ---

**Vì sao hash chain chứ không chỉ append.** Một file log thường chứng minh
được "có chuyện này xảy ra" nhưng không chứng minh được "không có chuyện nào
bị gỡ đi". Mỗi dòng nhét hash của dòng trước vào phần được hash của chính nó,
nên sửa/xoá/chèn một dòng ở giữa sẽ làm lệch mọi dòng phía sau — người sửa
phải tính lại toàn bộ đuôi file mới che được, và điều đó nhìn thấy được nếu
hash cuối được chốt ở nơi khác.

Đây là thứ mở ra khi regulator hỏi "chứng minh dữ liệu khách hàng chưa từng
ra khỏi hệ thống": không phải sink.log (do bên nhận ghi), mà là ledger này
cộng với `verify()` trả về True.

**`reason` rỗng làm verify() fail, không chỉ là cảnh báo.** Rubric.md coi
một dòng thiếu reason là điều kiện trượt, nên tính toàn vẹn ở đây gồm cả
tính đầy đủ của nội dung, không riêng tính nguyên vẹn của chuỗi hash. Một
ledger đầy đủ hash mà dòng nào cũng "decision=deny, reason=" thì vô dụng
với người đi kiểm tra.

**Field `hash` bị loại khỏi chính phép tính hash** — không thì tự tham chiếu.
`json.dumps(..., sort_keys=True)` để thứ tự field lúc ghi không ảnh hưởng
kết quả.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS_HASH = "0" * 64

# Field bắt buộc theo Guide.md §3d. Thiếu field nào cũng làm dòng đó vô dụng
# cho việc truy nguyên, nên chặn ngay lúc ghi thay vì phát hiện lúc verify.
REQUIRED_FIELDS = (
    "ts",
    "agent_id",
    "run_id",
    "tool",
    "args_hash",
    "classification",
    "decision",
    "reason",
)


def _digest(payload: dict) -> str:
    """sha256 của entry, KHÔNG tính field `hash` (tránh tự tham chiếu)."""
    body = {k: v for k, v in payload.items() if k != "hash"}
    encoded = json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def _last_hash(path: Path) -> str:
    entries = _read_entries(path)
    return entries[-1].get("hash", GENESIS_HASH) if entries else GENESIS_HASH


def append(entry: dict, path: Path) -> dict:
    """Nối một dòng vào ledger, tự gắn prev_hash và hash. Trả về dòng đã ghi."""
    path = Path(path)
    missing = [f for f in REQUIRED_FIELDS if f not in entry]
    if missing:
        raise ValueError(f"ledger entry thiếu field bắt buộc: {missing}")

    record = dict(entry)
    record["prev_hash"] = _last_hash(path)
    record["hash"] = _digest(record)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def verify(path: Path) -> bool:
    """True nếu ledger vừa nguyên vẹn vừa đầy đủ.

    Ba điều kiện, hỏng bất kỳ điều nào cũng trả về False:
      1. mọi dòng có `reason` non-empty
      2. prev_hash của dòng n khớp hash đã lưu của dòng n-1
      3. hash lưu ở dòng n khớp khi tính lại từ nội dung dòng đó
    """
    path = Path(path)
    try:
        entries = _read_entries(path)
    except (OSError, json.JSONDecodeError):
        return False

    expected_prev = GENESIS_HASH
    for record in entries:
        if not str(record.get("reason") or "").strip():
            return False
        if record.get("prev_hash") != expected_prev:
            return False
        stored = record.get("hash")
        if not stored or stored != _digest(record):
            return False
        expected_prev = stored
    return True
