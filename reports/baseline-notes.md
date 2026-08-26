# Bước 1 — Baseline: đọc `_naive_loop`

Đối tượng đọc: `agent/loop.py:31-54` (hàm `_naive_loop`), `agent/tools.py`.

## Luồng thực thi của baseline

```
người dùng
   │  message
   ▼
search_docs(message)            agent/loop.py:31      ← chân 1: untrusted content
   │  docs = [{"id", "text"}]   toàn văn file .md, không lọc gì
   ▼
combined_text = nối toàn bộ     agent/loop.py:32
   │
   ▼
llm.find_injection(text)        agent/loop.py:34      chỉ thị của attacker được
   │  InjectedInstruction       "hiểu" như lệnh hợp lệ
   ▼
read_customer(cid) cho mọi      agent/loop.py:37-41   ← chân 2: private data
   │  customer_id LẤY TỪ TEXT   customer_id do attacker chỉ định
   ▼
http_post(target_url, records)  agent/loop.py:44      ← chân 3: exfil vector
   │                            target_url cũng lấy từ text của attacker
   ▼
sink localhost:9999  →  reports/sink.log
```

Cả ba chân của lethal trifecta nằm trong **một** run, chia sẻ **một** context.
Free text của attacker đi thẳng từ chân 1 sang quyết định của chân 2 và chân 3.

## Ba câu hỏi

### 1. Agent này có identity riêng không (per-run, per-agent id)?

**Không.** `_naive_loop` (`agent/loop.py:31-54`) không tạo `run_id`, `agent_id`
hay bất kỳ định danh nào. Không có tham số identity, không có biến cục bộ nào
mang ý nghĩa đó, và không có gì được truyền xuống ba tool. Ba lời gọi tool
(`agent/loop.py:31`, `:39`, `:44`) đều là lời gọi hàm trần, ẩn danh.

Hệ quả: không thể trả lời "run nào đã đọc dữ liệu của khách nào", không thể
gán TTL hay giới hạn quyền theo từng run, không thể phân biệt Run A với Run B
— vì chỉ có đúng một run.

### 2. Ai quyết định nó được gọi `http_post`?

**Không ai.** Không có Policy Enforcement Point. Điều kiện duy nhất dẫn tới
`http_post` là `if injected is not None` (`agent/loop.py:35`) và
`if collected` (`agent/loop.py:42`) — nghĩa là *chính nội dung document của
attacker* mới là thứ quyết định agent có gọi egress hay không.

Thứ trông giống control duy nhất là allowlist host cứng ở
`agent/tools.py:77-82` (chỉ cho `localhost:9999`). Nhưng docstring của chính
hàm đó (`agent/tools.py:74-76`) nói rõ: allowlist này tồn tại để bài lab chạy
an toàn, **không phải** security control để dựa vào — nó không hề hỏi dữ liệu
sắp gửi thuộc loại gì, cho mục đích gì, run nào yêu cầu.

### 3. Nếu nó gửi sai dữ liệu ra ngoài, bạn biết bằng cách nào?

**Chỉ biết nếu đi soi log của phía nhận.** Agent không ghi một dòng audit nào.
Bằng chứng duy nhất về vụ exfil là `reports/sink.log`, và file đó do
*sink server* ghi (`sink/sink.py:56-60`), tức là do bên nhận ghi — trong thực
tế đó là hạ tầng của attacker, không phải của bạn.

Không có: bản ghi tool call, không có quyết định allow/deny, không có `reason`,
không có hash chain. Nghĩa là không thể chứng minh với regulator rằng dữ liệu
*không* rời hệ thống, và cũng không thể dựng lại chuyện gì đã xảy ra sau sự cố.

## Ba lớp còn thiếu, ánh xạ sang Bước 3

| Thiếu ở baseline | Control sẽ viết |
|---|---|
| Không có identity, không có ai gác cổng tool call | `agent/policy.py` — PEP với `PolicyContext` 5 field |
| Một run cầm cả 3 chân trifecta, free text điều khiển hành vi | `agent/runner.py` — tách Run A / Run B, input typed |
| Không có dấu vết audit nào do chính agent ghi | `agent/ledger.py` — JSONL append-only, hash chain |
| PII đi vào context nguyên văn, không ai nhận diện | `agent/pii.py` — detect/redact trước ingestion |
