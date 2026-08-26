# Compliance mapping

Evidence là đường dẫn file/dòng thật trong repo này. Mọi số đo lấy từ lần
chạy Bước 4: `pytest` 14/14 pass, `reports/sink.log` 0 byte,
`reports/ledger.jsonl` 144 dòng, `ledger.verify()` = True.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | **Chưa implement delete cascade** (xem Stretch goal #3 trong `Guide.md`). Đã có một nửa nền: ledger cố ý không lưu giá trị PII nào — chỉ `args_hash` (sha256 rút gọn) và `customer_id` giả danh — nên xoá một subject khỏi `data/customers.json` không đòi hỏi viết lại ledger, tức là không phá hash chain | `agent/runner.py:135` (`args_hash`, không phải giá trị thật), `agent/ledger.py:66` (`_digest`), `reports/ledger.jsonl` — grep `811753472374` không ra dòng nào |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho mọi đích dữ liệu có thể tới, gồm cả LLM API call khi chạy `--model` | `reports/dpia-lite.md` §3 |
| ASI03 — privilege abuse | Per-run identity + PEP tại mọi tool call. Mọi lời gọi tool đi qua một cổng duy nhất `_gate()`, không có đường vòng | `agent/policy.py:83` (RULE 3 tối thiểu), `agent/runner.py:102` (`_gate`), `agent/runner.py:322` (`run_id` per-run), ledger field `agent_owner` / `run_id` / `delegation_depth` |
| ASI01 — goal hijack | Trifecta split: Run B nhận `tuple[int, ...]` nên free text của attacker không tới được chỗ quyết định đọc dữ liệu của ai | `agent/runner.py:238` (`_run_b`), `reports/attack-after.log` (5/5 sink rỗng), `tests/test_split.py` PASSED |
| ISO 42001 Clause 5-6 | Policy-as-code, mỗi control một commit có lý do thay đổi ghi rõ | `git log --oneline -- agent/policy.py` → `d16a44c`; 4 commit cho 4 control: `8621e49` (pii), `d16a44c` (policy), `5d1c479` (ledger), `bdd0397` (runner) |

---

## Ghi chú cho người chấm

**Về dòng 1 (quyền xoá).** Không claim là đã làm. Delete cascade chưa
implement. Phần ghi ở cột Control là tính chất *đã có sẵn* của thiết kế
ledger, không phải control cho quyền xoá: vì ledger chỉ lưu hash và mã khách
giả danh, việc xoá dữ liệu gốc sau này sẽ không xung đột với yêu cầu
tamper-evident. Đó là điều kiện cần, chưa phải điều kiện đủ.

`Guide.md` Bước 4 ghi "xem stretch #4" cho mục này, nhưng theo danh sách
Stretch goals trong chính `Guide.md` thì delete cascade là mục **#3** (#4 là
agent memory poisoning). Ghi theo số thứ tự thật của danh sách.

**Về dòng 3 (ASI03).** `Guide.md` gợi ý "per-agent identity + TTL trong
ledger". Identity thì có: mỗi lần chạy sinh `run_id` riêng
(`agent/runner.py:322`), và mỗi dòng ledger mang `agent_owner` phân biệt
`run-a:<id>` với `run-b:<id>`. **TTL thì chưa có** — ledger có `ts` nhưng
không có trường hết hạn và không có cơ chế thu hồi quyền theo thời gian.
Ghi rõ để không bị hiểu là đã làm.

**Về dòng 5 (ISO 42001).** Bốn control nằm ở bốn commit riêng, mỗi commit
message nêu vì sao chọn cách đó chứ không chỉ nêu đã làm gì — đặc biệt
`bdd0397` giải thích vì sao filter chuỗi bị loại, kèm số liệu đối chứng ở
`reports/filter-vs-split.txt`.

## Số liệu kiểm chứng lại được

| Khẳng định | Lệnh kiểm |
|---|---|
| PII không rời hệ thống | `python sink/sink.py --reset && pytest tests/test_injection.py -v` → 5/5 pass, `reports/sink.log` 0 byte |
| Audit completeness = 100% | 144/144 dòng có cả `decision` và `reason`; `agent.ledger.verify()` = True |
| Có egress deny thật, không phải chỉ config | 6 dòng `tool=http_post decision=deny` trong `reports/ledger.jsonl`, kèm `records_withheld` |
| Containment chứ không mitigation | `pytest tests/test_split.py` PASSED — `KH-000777` không bao giờ bị `read_customer` |
| Filter chuỗi không đủ | `reports/filter-vs-split.txt` — gộp 3 filter chỉ chặn 3/5 |
