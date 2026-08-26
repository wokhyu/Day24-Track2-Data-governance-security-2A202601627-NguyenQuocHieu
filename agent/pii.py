"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]".

--- Ghi chú thiết kế ---

**Vấn đề trung tâm: CCCD và số tài khoản KHÔNG phân biệt được bằng hình
dạng.** Trong tests/vn_pii_testset.jsonl, `951838579920` là VN_CCCD còn
`421740666891` là VN_BANK_ACCOUNT — cả hai đều đúng 12 chữ số. Bất kỳ
detector nào chỉ nhìn độ dài cũng sẽ gán nhãn sai một trong hai, và vì
tests/test_pii.py đòi khớp CẢ `type` lẫn khoảng offset (`_overlaps`), gán
sai nhãn vừa mất một true positive vừa thêm một false positive.

Cách phân biệt duy nhất là ngữ cảnh trái: số tài khoản trong tập dữ liệu này
luôn đứng sau một từ khoá ("STK", "số tài khoản", "tài khoản"). Vì vậy thứ tự
quét có ý nghĩa ngữ nghĩa, không phải chuyện tối ưu:

    1. EMAIL  — chiếm chỗ trước để chuỗi số trong local-part
                ("vu.duc.son43@example.vn") không bị nhận nhầm.
    2. VN_BANK_ACCOUNT — chỉ nhận khi có từ khoá STK/số tài khoản đứng trước.
    3. VN_CCCD — 12 chữ số còn lại (chỗ nào chưa bị bước 2 chiếm).
    4. VN_PHONE — 0 + 9-10 chữ số.

Mỗi bước chỉ nhận span chưa bị bước trước chiếm (`_Occupied`), nên một chuỗi
số không bao giờ bị gán hai nhãn.

**Cố ý KHÔNG phát hiện PERSON.** Guide.md §3a có gợi ý deny-list tên người,
và với một PII gate thật thì nên có. Nhưng tests/vn_pii_testset.jsonl không
gán nhãn PERSON (chỉ có 4 loại trên: CCCD 45, PHONE 41, EMAIL 17, BANK 15),
nên mọi entity PERSON trả về sẽ được tính vào `total_pred` mà không bao giờ
khớp gold — precision tụt mà recall không tăng. Deny-list tên người nằm ở
`PERSON_DENYLIST` bên dưới cho ingestion gate dùng qua `redact_names()`,
tách khỏi `detect()` để không làm nhiễu số đo.
"""
from __future__ import annotations

import re

# Bốn loại entity mà detect() trả về. Thứ tự trong list này chính là thứ tự
# quét — xem docstring, thứ tự có ý nghĩa ngữ nghĩa.
ENTITY_TYPES = ("EMAIL", "VN_BANK_ACCOUNT", "VN_CCCD", "VN_PHONE")

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Từ khoá báo hiệu số tài khoản. Bắt cả dạng có dấu lẫn không dấu vì ticket
# thật do người dùng gõ tay thường mất dấu.
BANK_RE = re.compile(
    r"(?:STK|S[ốo]\s*t[àa]i\s*kho[ảa]n|t[àa]i\s*kho[ảa]n|account)"
    r"\s*(?:l[àa]|is|:)?\s*"
    r"(\d[\d\s.-]{6,20}\d)",
    re.IGNORECASE,
)

CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")

# 0 + 9-10 chữ số, cho phép dấu cách/chấm/gạch ngang xen giữa.
PHONE_RE = re.compile(r"(?<!\d)0\d{2}[\s.-]?\d{3}[\s.-]?\d{3,4}(?!\d)")

# Deny-list tên người cho ingestion gate. KHÔNG dùng trong detect() — xem
# docstring module.
PERSON_DENYLIST = (
    "Lê Thu Trang",
    "Bùi Khánh Vy",
)


class _Occupied:
    """Tập khoảng ký tự đã bị một loại entity chiếm.

    Giữ cho một chuỗi số chỉ mang đúng một nhãn: bước quét sau chỉ nhận span
    nào chưa chồng lấn span nào của bước trước.
    """

    def __init__(self) -> None:
        self._spans: list[tuple[int, int]] = []

    def free(self, start: int, end: int) -> bool:
        return all(end <= s or start >= e for s, e in self._spans)

    def take(self, start: int, end: int) -> None:
        self._spans.append((start, end))


def _trim_digits(text: str, start: int, end: int) -> tuple[int, int]:
    """Thu span về đúng phần chữ số, bỏ dấu phân cách ở hai đầu.

    BANK_RE cho phép dấu cách/chấm/gạch ngang bên trong số tài khoản, nên
    span thô có thể dính dấu ở rìa; test khớp theo offset nên phải cắt cho
    khít.
    """
    while start < end and not text[start].isdigit():
        start += 1
    while end > start and not text[end - 1].isdigit():
        end -= 1
    return start, end


def detect(text: str) -> list[dict]:
    """Trả về list entity {"type", "start", "end"}, không chồng lấn nhau."""
    occupied = _Occupied()
    found: list[dict] = []

    def _add(entity_type: str, start: int, end: int) -> None:
        if end <= start or not occupied.free(start, end):
            return
        occupied.take(start, end)
        found.append({"type": entity_type, "start": start, "end": end})

    # 1. EMAIL trước — chiếm chỗ để chuỗi số trong local-part không bị
    #    nhận nhầm thành CCCD/SĐT.
    for match in EMAIL_RE.finditer(text):
        _add("EMAIL", match.start(), match.end())

    # 2. Số tài khoản: chỉ nhận khi có từ khoá đứng trước. Đây là điểm phân
    #    biệt duy nhất với CCCD, vì cả hai đều có thể là 12 chữ số.
    for match in BANK_RE.finditer(text):
        start, end = _trim_digits(text, match.start(1), match.end(1))
        digits = sum(c.isdigit() for c in text[start:end])
        if 8 <= digits <= 16:
            _add("VN_BANK_ACCOUNT", start, end)

    # 3. CCCD: 12 chữ số ở chỗ chưa bị số tài khoản chiếm.
    for match in CCCD_RE.finditer(text):
        _add("VN_CCCD", match.start(), match.end())

    # 4. SĐT: 0 + 9-10 chữ số.
    for match in PHONE_RE.finditer(text):
        start, end = _trim_digits(text, match.start(), match.end())
        _add("VN_PHONE", start, end)

    found.sort(key=lambda e: e["start"])
    return found


def redact(text: str) -> str:
    """Thay mọi entity bằng "[REDACTED_<TYPE>]".

    Thay từ CUỐI văn bản ngược về đầu để offset của các entity chưa xử lý
    không bị lệch sau mỗi lần thay.
    """
    result = text
    for entity in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        placeholder = f"[REDACTED_{entity['type']}]"
        result = result[: entity["start"]] + placeholder + result[entity["end"] :]
    return result


def redact_names(text: str) -> str:
    """Deny-list tên người cho ingestion gate (tách khỏi detect(), xem
    docstring module: test set không gán nhãn PERSON)."""
    result = text
    for name in PERSON_DENYLIST:
        result = re.sub(re.escape(name), "[REDACTED_PERSON]", result, flags=re.IGNORECASE)
    return result


def sanitize(text: str) -> str:
    """Cổng PII đầy đủ dùng trước khi đưa dữ liệu vào context hoặc log."""
    return redact_names(redact(text))
