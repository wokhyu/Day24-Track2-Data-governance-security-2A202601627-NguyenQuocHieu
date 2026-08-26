# DPIA-lite (1 trang)

Phạm vi: agent hỗ trợ khách hàng trong repo này (`agent/`), chạy ở chế độ
`--mock`. Toàn bộ dữ liệu là synthetic (xem `README.md` — Quy tắc an toàn),
nhưng DPIA viết như thể dữ liệu thật, vì kiến trúc mới là thứ được đánh giá.

Ngày lập: 2026-08-26. Phiên bản code tương ứng: `git log -1 -- agent/runner.py`.

---

## 1. Dữ liệu gì

Liệt kê theo từng tool, vì mỗi tool là một ranh giới quyền khác nhau.

### `search_docs` — `corpus/*.md` (46 file)

Ticket hỗ trợ khách hàng, nội dung tự do do người dùng và nhân viên gõ tay.
Đếm bằng `agent.pii.detect()` trên toàn corpus:

| Loại | Số lượng |
|---|---|
| VN_PHONE | 40 |
| VN_CCCD | 20 |
| VN_BANK_ACCOUNT | 13 |
| EMAIL | 7 |

Kèm **tên người** trong văn bản tự do (ví dụ `corpus/ticket-007.md` dòng 3).
Đây là dữ liệu **untrusted**: bất kỳ ai ghi được vào `corpus/` đều đưa được
nội dung tuỳ ý vào context của agent — 6 trong 46 file là payload tấn công do
chính chúng tôi viết ở Bước 2.

Phân loại: `internal` (`agent/runner.py:160`).

### `read_customer` — `data/customers.json` (26 bản ghi)

Mỗi bản ghi: `customer_id`, `name`, `cccd` (12 số), `phone`, `bank_account`,
`email`, `related_tickets`.

CCCD và số tài khoản là dữ liệu nhạy cảm ở mức cao nhất trong tập này: lộ ra
là dùng được ngay cho giả mạo danh tính và cho gian lận chuyển khoản, và
không đổi được như đổi mật khẩu.

Phân loại: `restricted` (`agent/runner.py:301`).

### `http_post` — không tạo dữ liệu mới

Nhưng là nơi dữ liệu hai nhóm trên có thể rời khỏi hệ thống.

---

## 2. Mục đích gì

| Mục đích (`request_purpose` trong ledger) | Vì sao cần dữ liệu | Dữ liệu tối thiểu cần |
|---|---|---|
| `summarize-tickets` | Trả lời câu hỏi "tổng hợp ticket còn mở tuần này" — cần đọc nội dung ticket | Chỉ `corpus/`. **Không** cần bản ghi khách hàng |
| `reconciliation` | Đối soát hồ sơ khách gắn với ticket đang xử lý | Bản ghi của khách có ticket trong `related_tickets`, không phải toàn bộ 26 khách |
| `exfil-requested-by-document` | **Không phải mục đích hợp lệ.** Nhãn này chỉ tồn tại để ghi lại yêu cầu do injection tạo ra; mọi dòng mang nhãn này đều `decision=deny` | — |

Nguyên tắc tối thiểu hoá đang được thực thi bằng code chứ không bằng quy
định: Run B chỉ đọc khách suy ra từ `ticket_id` qua `related_tickets`
(`agent/runner.py:272`), nên số bản ghi chạm tới bị giới hạn bởi số ticket
khớp truy vấn — lần chạy Bước 4 đọc 21/26 khách, không phải toàn bộ.

**Cơ sở pháp lý cần xác định trước khi dùng dữ liệu thật:** hợp đồng dịch vụ
với khách (xử lý yêu cầu hỗ trợ). Không dựa vào "lợi ích hợp pháp" cho việc
đưa CCCD/STK vào context của một mô hình ngôn ngữ.

---

## 3. Chảy đi đâu

### 3.1 Luồng nội bộ (mặc định, `--mock`)

```
corpus/*.md ──search_docs──> Run A  (internal, egress=False)
                               │
                               ├─ PII gate: pii.detect + pii.sanitize
                               │  80 entity bị redact TRƯỚC khi vào model
                               │  (agent/runner.py:196-197)
                               │
                               ├─ text ĐÃ redact ──> llm.find_injection()
                               │                     llm.summarize()
                               │
                               │  chỉ tuple[int, ...] ticket_id đi tiếp
                               ▼
customers.json ──read_customer──> Run B  (restricted, egress=False)
                               │
                               ▼
                        [dừng trong tiến trình]
                        không ghi ra file, không lên mạng
```

Hai điều quan trọng ở sơ đồ này:

1. **Bản ghi khách không rời khỏi tiến trình Python.** Run B đọc được
   `records` nhưng câu trả lời cuối dựng từ document, không từ `records`
   (`agent/runner.py:385-386`).
2. **Không có text thô nào chạm vào model.** `raw_combined` dừng lại ở
   `agent/runner.py:196`; cả `find_injection()` lẫn `summarize()` chỉ nhận
   bản đã qua `pii.sanitize()`. Kiểm chứng bằng cách bọc `MockLLM` để ghi lại
   mọi text nó nhận: 12040 ký tự vào `find_injection`, 11995 ký tự vào
   `summarize`, không chuỗi PII nào trong cả hai, và cả hai đều chứa
   `[REDACTED_...]`.

### 3.2 Ghi ra đĩa

| File | Chứa gì | Có PII không |
|---|---|---|
| `reports/ledger.jsonl` | audit trail 150 dòng | **Không.** Chỉ `args_hash` (sha256 rút gọn) và `customer_id` giả danh. Kiểm: `grep 811753472374 reports/ledger.jsonl` → 0 dòng |
| `reports/sink.log` | do sink server ghi, không phải agent | Sau khi contain: 0 byte |

`customer_id` vẫn là dữ liệu cá nhân giả danh (pseudonymous), không phải dữ
liệu ẩn danh — vẫn thuộc phạm vi điều chỉnh. Ledger phải được bảo vệ như
dữ liệu nội bộ, không public.

### 3.3 Chuyển ra ngoài hệ thống — `http_post`

Đích duy nhất mà tool cho phép là `http://localhost:9999/*`
(`agent/tools.py:26-27`, `:77`). **Đây không phải control để dựa vào** —
docstring của chính hàm nói rõ nó tồn tại để lab chạy an toàn.

Control thật là `agent/policy.py:83`: dữ liệu `restricted` + `egress_enabled`
→ deny, không có ngoại lệ. Lần chạy Bước 4: 6 yêu cầu egress, 6 deny, 0 byte
ra ngoài.

### 3.4 Chuyển dữ liệu xuyên biên giới — NĐ 356/2025

**Ở chế độ mặc định `--mock`: KHÔNG có.** `MockLLM` (`agent/llm.py`) chạy
hoàn toàn trong tiến trình, không gọi network. Toàn bộ lab được chấm bằng
`--mock`.

**Nếu chạy `--model claude-...`: CÓ — nhưng chỉ dữ liệu đã redact.**
`RealLLM.summarize()` gửi nội dung ticket sang API của Anthropic (Hoa Kỳ).
Vẫn là chuyển dữ liệu xuyên biên giới, nhưng nội dung đi qua PII gate ở
`agent/runner.py:196-197` trước, nên 80 entity (40 SĐT, 20 CCCD, 13 STK, 7
email) đã bị thay bằng `[REDACTED_<TYPE>]`.

Cái **vẫn** vượt biên giới, và vẫn là dữ liệu cá nhân:

- mã khách dạng `KH-000999` (giả danh, không phải ẩn danh);
- nội dung khiếu nại của khách — văn bản tự do có thể chứa thông tin nhận
  dạng gián tiếp mà regex không bắt được;
- tên người không nằm trong `PERSON_DENYLIST` (`agent/pii.py:77`, hiện chỉ
  có 2 tên hard-code).

Nghĩa vụ theo NĐ 356/2025 **không mất đi** vì đã redact:

- lập và nộp hồ sơ đánh giá tác động chuyển dữ liệu ra nước ngoài trong
  **60 ngày** kể từ khi bắt đầu xử lý;
- xác định vai trò của model provider (bên xử lý dữ liệu) và ràng buộc hợp
  đồng tương ứng;
- thông báo cho chủ thể dữ liệu.

**Khoảng trống còn lại:** không có PEP nào chặn giữa agent và LLM API.
`policy.check()` gác ba tool, không gác lời gọi model — nên hiện tại không
có dòng ledger nào ghi lại việc dữ liệu rời biên giới, chỉ có dòng
`pii.gate` ghi lại việc đã redact.

**Khuyến nghị trước khi dùng model thật với dữ liệu thật:** coi lời gọi
model là một tool call phải qua `_gate()` với `egress_enabled=True`, để nó
được ghi vào ledger như mọi egress khác và bị RULE 3 chặn khi dữ liệu là
`restricted`. Đồng thời mở rộng deny-list tên người hoặc bổ sung NER.

---

## 4. Rủi ro còn lại

| Rủi ro | Mức | Trạng thái |
|---|---|---|
| Prompt injection ép agent gửi PII ra ngoài | Cao | **Đã xử lý** — trifecta split, 5/5 biến thể bị chặn, `reports/attack-after.log` |
| Attacker ghi được vào `corpus/` | Cao | **Đã giảm** — không ghi được vào `customers.json` nên không điều khiển được Run B đọc ai; vẫn có thể gây nhiễu nội dung tóm tắt |
| PII gửi sang model provider khi dùng `--model` | Trung bình (từ Cao) | **Đã giảm** — PII gate redact 80 entity trước khi text chạm model (`agent/runner.py:196-197`). Còn lại: mã khách giả danh, văn bản tự do, tên ngoài deny-list — xem §3.4 |
| Lời gọi LLM API không qua PEP, không vào ledger | Trung bình | **Chưa xử lý** — `policy.check()` chỉ gác 3 tool. Xem khuyến nghị §3.4 |
| Quyền yêu cầu xoá (Luật 91/2025) | Trung bình | **Chưa implement** — xem `reports/compliance-mapping.md` dòng 1 |
| Ledger bị xoá cả file (không phải sửa giữa file) | Trung bình | **Chưa xử lý** — hash chain phát hiện sửa/xoá dòng giữa, nhưng xoá sạch file thì không. Cần chốt hash cuối ra nơi khác (WORM store, hoặc log tập trung) |
| Không có TTL / thu hồi quyền theo thời gian | Thấp trong phạm vi lab | **Chưa implement** |
