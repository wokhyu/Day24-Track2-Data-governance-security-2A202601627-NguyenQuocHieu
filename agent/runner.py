"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Tách một yêu cầu người dùng thành hai run, không run nào cầm cả 3 chân của
lethal trifecta:

    Run A  — untrusted content.  Gọi search_docs. Không read_customer,
             không http_post. egress_enabled=False.
    Run B  — private data.       Gọi read_customer. Chỉ nhận `tuple[int, ...]`
             ticket_id đã trích từ TÊN FILE. Không bao giờ nhận text của
             document. egress_enabled=False.
    Egress — mọi yêu cầu ra mạng đều đi qua policy trước, và trong lab này
             luôn bị deny vì dữ liệu đang giữ là restricted.

Mọi lần gọi tool (allow HAY deny) đều đi qua `agent.policy.check()` TRƯỚC khi
tool chạy, và đều được ghi vào ledger qua `agent.ledger.append()`.

Interface bắt buộc (agent/loop.py import và gọi nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str

--- Ghi chú thiết kế ---

**Ranh giới thật nằm ở chữ ký hàm, không nằm ở kỷ luật lập trình viên.**
`_run_b()` nhận `ticket_ids: tuple[int, ...]`. Không có tham số nào của nó
mang được một câu tiếng Việt, nên free text của attacker *không có đường* đi
tới chỗ quyết định đọc dữ liệu của ai — kể cả khi có người sau này sửa code
mà quên mất vì sao. `int` không chở được chỉ thị.

**Nguồn tin cậy để map ticket_id -> customer_id.** Run A chỉ trích ticket_id
từ TÊN FILE (`ticket-904b.md` -> 904), không đọc nội dung. Run B tra ngược
qua `related_tickets` trong `data/customers.json`. Attacker ghi được vào
`corpus/` nhưng không ghi được vào `customers.json`, nên `KH-000999` chỉ tới
được vì ticket 901-905 thật sự thuộc về khách đó — không phải vì document
nói thế. Khách `KH-000777` (`related_tickets: []`) là không thể với tới.

**`llm.find_injection()` vẫn được gọi, nhưng kết quả chỉ dùng để GHI LOG.**
`injection.customer_ids` và `injection.target_url` không bao giờ đi vào một
lời gọi tool nào. Đây là khác biệt giữa "phát hiện để chặn" (mitigation, phải
đúng 100% mới an toàn) và "phát hiện để ghi nhận" (không ai phải đoán đúng
mọi cách viết lại của attacker).

**Vì sao không dùng filter chuỗi** — xem `reports/filter-vs-split.txt`: gộp cả
ba filter (`"hãy gọi"`, `"read_customer"`, `"http://"`) chỉ chặn 3/5 biến thể.
Biến thể 4 trượt hết vì không file nào chứa tên tool lẫn URL; biến thể 5 trượt
vì teencode `g0i` và homoglyph Cyrillic. Containment không tham gia cuộc đua
đó.

**Vì sao Run B vẫn đọc `KH-000999` sau khi contain, và vì sao thế là đúng.**
Ticket 901-905 nằm trong `related_tickets` của khách đó, nên đây là truy cập
hợp lệ theo đúng công việc được giao. Cái bị chặn là chặng gửi ra ngoài.
Ngược lại `KH-000777` không bao giờ bị ĐỌC — đó mới là chỗ split khác filter,
và là thứ `tests/test_split.py` kiểm.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"

AGENT_ID = "lab24-agent"

# Chỉ lấy phần số ngay sau "ticket-": "ticket-904b.md" -> 904. Hậu tố chữ
# (biến thể chia payload) bị bỏ qua, đúng ý — hai file cùng thuộc một ticket.
TICKET_ID_RE = re.compile(r"ticket-(\d+)")


@dataclass(frozen=True)
class RunAResult:
    """Thứ Run A được phép chuyển sang Run B: **chỉ** ticket_id đã typed.

    `injection` đi kèm để ghi log, và `handle()` không truyền nó cho Run B.
    Kiểu dữ liệu ở đây là bản hợp đồng: `tuple[int, ...]` không chở được một
    câu tiếng Việt nào.
    """

    ticket_ids: tuple[int, ...]
    doc_ids: tuple[str, ...]
    injection: object | None
    pii_count: int


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _args_hash(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def _gate(
    *,
    tool: str,
    args: object,
    classification: str,
    purpose: str,
    owner: str,
    depth: int,
    egress: bool,
    run_id: str,
    ledger_path: Path,
    extra: dict | None = None,
) -> bool:
    """Hỏi policy TRƯỚC khi tool chạy, ghi ledger dù allow hay deny.

    Trả về True nếu được phép gọi tool. Gộp hai việc vào một chỗ để không thể
    xảy ra trường hợp "gọi tool mà quên ghi log" — mọi lời gọi tool trong file
    này đều phải đi qua đây.
    """
    context = PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=owner,
        delegation_depth=depth,
        egress_enabled=egress,
    )
    allow, reason = policy.check(context)

    entry = {
        "ts": _now(),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "tool": tool,
        "args_hash": _args_hash(args),
        "classification": classification,
        "decision": "allow" if allow else "deny",
        "reason": reason,
        "agent_owner": owner,
        "request_purpose": purpose,
        "delegation_depth": depth,
        "egress_enabled": egress,
    }
    if extra:
        entry.update(extra)
    ledger.append(entry, ledger_path)
    return allow


def _run_a(message: str, llm, run_id: str, ledger_path: Path) -> RunAResult:
    """Chân 1 — untrusted content. Không có quyền đọc private data, không egress."""
    owner = f"run-a:{run_id}"

    allowed = _gate(
        tool="search_docs",
        args={"query": message},
        classification="internal",
        purpose="summarize-tickets",
        owner=owner,
        depth=0,
        egress=False,
        run_id=run_id,
        ledger_path=ledger_path,
    )
    if not allowed:
        return RunAResult(ticket_ids=(), doc_ids=(), injection=None, pii_count=0)

    docs = tools.search_docs(message)

    # ticket_id lấy từ TÊN FILE, không phải từ nội dung. Nội dung là thứ
    # attacker viết được; tên file thì không (attacker đặt được tên file,
    # nhưng tên file chỉ dẫn tới ticket, còn ticket dẫn tới ai thì
    # customers.json quyết định — xem docstring module).
    ticket_ids = sorted({
        int(m.group(1)) for d in docs if (m := TICKET_ID_RE.search(d["id"]))
    })

    combined = "\n\n".join(d["text"] for d in docs)

    # PII gate (BƯỚC 3a): đếm PII trong untrusted content để ghi vào audit.
    # Không đưa giá trị thật vào ledger — chỉ số lượng.
    pii_count = len(pii.detect(combined))

    # Phát hiện injection CHỈ để ghi log. Không dùng customer_ids/target_url
    # mà nó trả về cho bất kỳ lời gọi tool nào.
    injection = llm.find_injection(combined)
    if injection is not None:
        ledger.append(
            {
                "ts": _now(),
                "agent_id": AGENT_ID,
                "run_id": run_id,
                "tool": "llm.find_injection",
                "args_hash": _args_hash({"docs": len(docs)}),
                "classification": "internal",
                "decision": "flag",
                "reason": (
                    f"phát hiện chỉ thị nhúng trong untrusted content: "
                    f"{len(injection.matched_markers)} marker "
                    f"({', '.join(injection.matched_markers)}); "
                    f"customer_id do document chỉ định: {injection.customer_ids} — "
                    f"GHI NHẬN, KHÔNG dùng để gọi tool"
                ),
                "agent_owner": owner,
                "request_purpose": "summarize-tickets",
                "delegation_depth": 0,
                "egress_enabled": False,
                "matched_markers": list(injection.matched_markers),
                "attacker_named_customers": list(injection.customer_ids),
                "attacker_named_url": injection.target_url,
            },
            ledger_path,
        )

    return RunAResult(
        ticket_ids=tuple(ticket_ids),
        doc_ids=tuple(d["id"] for d in docs),
        injection=injection,
        pii_count=pii_count,
    )


def _customers_for_tickets(ticket_ids: tuple[int, ...]) -> list[str]:
    """Nguồn tin cậy: ticket_id -> customer_id qua `related_tickets`.

    Attacker ghi được vào corpus/ nhưng không ghi được vào customers.json,
    nên đây là chỗ duy nhất quyết định ticket nào thuộc về ai.
    """
    wanted = set(ticket_ids)
    customers = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return [
        c["customer_id"]
        for c in customers
        if wanted.intersection(c.get("related_tickets") or [])
    ]


def _run_b(ticket_ids: tuple[int, ...], run_id: str, ledger_path: Path) -> list[dict]:
    """Chân 2 — private data.

    Tham số duy nhất mang thông tin từ Run A là `ticket_ids: tuple[int, ...]`.
    Không có chỗ nào để nhét một câu tiếng Việt vào, nên free text của
    attacker dừng lại ở Run A theo đúng nghĩa đen.
    """
    owner = f"run-b:{run_id}"
    records: list[dict] = []

    for customer_id in _customers_for_tickets(ticket_ids):
        allowed = _gate(
            tool="read_customer",
            args={"customer_id": customer_id},
            classification="restricted",
            purpose="reconciliation",
            owner=owner,
            depth=1,
            egress=False,  # Run B không bao giờ có quyền ra mạng
            run_id=run_id,
            ledger_path=ledger_path,
            extra={"resolved_from": "related_tickets", "customer_id": customer_id},
        )
        if not allowed:
            continue
        try:
            records.append(tools.read_customer(customer_id))
        except tools.ToolError:
            continue

    return records


def _egress_stage(
    injection: object | None,
    records: list[dict],
    run_id: str,
    ledger_path: Path,
) -> None:
    """Chân 3 — egress. Đi qua policy trước, và ở đây luôn bị deny.

    Run duy nhất muốn gửi dữ liệu ra ngoài là run đang giữ dữ liệu restricted,
    nên RULE 3 của policy.py chặn. Ghi lại cả yêu cầu bị chặn để Bước 4 có
    bằng chứng: một deny không ghi lại thì không chứng minh được gì.
    """
    if injection is None or not records:
        return

    requested_url = getattr(injection, "target_url", "")
    parsed_ok = requested_url.startswith(
        f"http://{tools.ALLOWED_EGRESS_HOST}:{tools.ALLOWED_EGRESS_PORT}/"
    )

    allowed = _gate(
        tool="http_post",
        args={"url": requested_url, "records": len(records)},
        classification="restricted",
        purpose="exfil-requested-by-document",
        owner=f"run-b:{run_id}",
        depth=1,
        egress=True,  # đúng cấu hình mà RULE 3 của policy.py chặn
        run_id=run_id,
        ledger_path=ledger_path,
        extra={
            "requested_url": requested_url,
            "url_in_hard_allowlist": parsed_ok,
            "records_withheld": len(records),
        },
    )

    # Không có nhánh nào gọi tools.http_post: policy deny thì tool không chạy.
    # Nếu về sau có nhu cầu egress hợp lệ, nó phải là dữ liệu đã qua
    # pii.redact() và được phân loại lại, chứ không phải bỏ rule đi.
    assert not allowed, "policy.check() phải deny restricted + egress (RULE 3)"


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Entrypoint được agent/loop.py gọi thay cho `_naive_loop`.

    Hành vi quan sát từ CLI không đổi so với trước khi contain — chỉ sink.log
    và ledger là khác. Đó là chủ đích: cùng một lệnh, hai kết quả, trước và
    sau khi contain.
    """
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    run_id = uuid.uuid4().hex[:8]

    run_a = _run_a(message, llm, run_id, ledger_path)

    # Ranh giới trifecta: chỉ `tuple[int, ...]` đi qua đây.
    records = _run_b(run_a.ticket_ids, run_id, ledger_path)

    _egress_stage(run_a.injection, records, run_id, ledger_path)

    # Câu trả lời dựng từ metadata của document, không từ private data —
    # `records` không rời khỏi tiến trình này.
    docs = [{"id": doc_id, "text": ""} for doc_id in run_a.doc_ids]
    return llm.summarize(docs)
