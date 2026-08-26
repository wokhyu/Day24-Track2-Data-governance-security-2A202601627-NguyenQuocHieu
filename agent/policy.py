"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input đúng slide §3.3 (đã định nghĩa sẵn, đừng đổi field):

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

--- Ghi chú thiết kế ---

**Vì sao mọi nhánh đều trả về `reason` mô tả được, kể cả nhánh allow.** Một
dòng ledger `decision=allow` không kèm lý do thì về sau không phân biệt được
"đã cân nhắc rồi cho phép" với "chưa ai từng hỏi". Với người đi kiểm tra thì
hai thứ đó khác hẳn nhau. Đây cũng là điều kiện trượt trong Rubric.md, nên
`reason` được ghép từ chính các field của context chứ không phải chuỗi cố
định — đọc lại ledger là dựng lại được nguyên đầu vào của quyết định.

**Fail closed.** Classification lạ, purpose rỗng hay owner rỗng đều bị deny.
Một PEP mặc định cho qua khi không hiểu đầu vào thì không phải PEP.

Thứ tự rule đi từ hẹp tới rộng; rule tối thiểu của đề bài là RULE 3.
"""
from __future__ import annotations

from dataclasses import dataclass

KNOWN_CLASSIFICATIONS = ("public", "internal", "restricted")

# Chuỗi uỷ quyền càng dài thì càng khó truy nguyên ai thật sự yêu cầu. Kiến
# trúc ở agent/runner.py chỉ cần depth 1 (Run A -> Run B), nên 2 đã là rộng
# rãi; sâu hơn nữa là dấu hiệu vòng lặp agent gọi agent ngoài dự tính.
MAX_DELEGATION_DEPTH = 2


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    """Quyết định cho phép hay chặn một tool call. Luôn kèm lý do."""
    classification = (context.data_classification or "").strip().lower()
    purpose = (context.request_purpose or "").strip()
    owner = (context.agent_owner or "").strip()

    # RULE 1 — fail closed: không hiểu nhãn phân loại thì không cho chạy.
    if classification not in KNOWN_CLASSIFICATIONS:
        return False, (
            f"deny: data_classification={context.data_classification!r} không thuộc "
            f"{KNOWN_CLASSIFICATIONS}; fail closed vì không xác định được mức nhạy cảm"
        )

    # RULE 2 — fail closed: không có mục đích hoặc không có chủ thể thì không
    # ghi được audit có nghĩa, nên cũng không cho chạy.
    if not purpose:
        return False, "deny: request_purpose rỗng; mọi truy cập dữ liệu phải nêu mục đích"
    if not owner:
        return False, "deny: agent_owner rỗng; không truy nguyên được run nào yêu cầu"

    # RULE 3 — RULE TỐI THIỂU của đề bài: đây là chỗ mạch trifecta bị cắt.
    # Một run vừa cầm dữ liệu restricted vừa có quyền ra mạng chính là điều
    # kiện đủ để exfil, bất kể nội dung yêu cầu là gì.
    if classification == "restricted" and context.egress_enabled:
        return False, (
            f"deny: dữ liệu restricted + egress_enabled=True cho "
            f"{owner!r} (purpose={purpose!r}) — cắt mạch lethal trifecta, "
            f"không run nào được vừa giữ private data vừa gọi network"
        )

    # RULE 4 — chuỗi uỷ quyền quá sâu thì không còn truy nguyên được.
    if context.delegation_depth > MAX_DELEGATION_DEPTH:
        return False, (
            f"deny: delegation_depth={context.delegation_depth} vượt ngưỡng "
            f"{MAX_DELEGATION_DEPTH}; chuỗi uỷ quyền quá sâu để truy nguyên trách nhiệm"
        )

    # RULE 5 — cho phép, và nói rõ đã cho phép cái gì dựa trên đâu.
    return True, (
        f"allow: {owner!r} đọc dữ liệu {classification} cho mục đích {purpose!r} "
        f"(delegation_depth={context.delegation_depth}, egress_enabled={context.egress_enabled})"
    )
