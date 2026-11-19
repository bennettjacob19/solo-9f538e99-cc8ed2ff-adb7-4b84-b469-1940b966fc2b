# DNS 值班解析系统（serve-stale + 发布序号演练）

平台值班场景：内部服务的权威 DNS 失联时，解析器继续为已确认的地址提供解析，
但记录被删除（NXDOMAIN）后绝不把旧地址交给调用方。同一域名的权威答复可能来自
**落后副本**：已确认 NXDOMAIN 后收到旧 A，或更高版本重新发布 A 时又应恢复解析。
因此权威端的 A/NXDOMAIN 答复都带**发布序号**，解析器按序号决定接受/丢弃。

## 组成

| 服务 | 模块 | 端口 | 说明 |
|---|---|---|---|
| `auth` | `app.auth_server` | UDP 5354 | 本地权威端（模拟副本），行为与发布序号可由网页实时切换 |
| `resolver` | `app.resolver` | UDP 5353 | 缓存/serve-stale UDP 解析器，按发布序号取舍 |
| `web` | `app.web` | HTTP 8000 | FastAPI 操作网页 |

三者通过共享卷上的 SQLite（WAL 模式）协作：

```
control       权威端行为：mode / ip / delay_seconds / serial（网页写，权威端每查询读）
cache         解析器缓存（绝对时间戳），含该结果的发布序号 serial
replica_state 解析器持久高水位：已接受的最高发布序号 + 该序号对应的结果
query_log     解析器答复记录（来源、序号）
auth_log      权威端接收记录（动作、序号）
```

`replica_state` 独立于 `cache`：缓存过期/清除不影响已接受序号，重启也不会降低它。

## 运行

```bash
docker compose up --build
# 网页:  http://localhost:8000
# 查询:  dig @127.0.0.1 -p 5353 service.example A
```

无 Docker 的本地运行（等价三进程）：

```bash
pip install -r requirements.txt
DB_PATH=/tmp/dns/app.db AUTH_PORT=15354 python -m app.auth_server &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 AUTH_PORT=15354 python -m app.resolver &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 WEB_PORT=8000 python -m app.web &
```

自测（自动拉起三进程，跑全部关键交错，约 3 分钟）：

```bash
python tests/selftest.py
```

## 语义（默认值，可用环境变量调整）

缓存/serve-stale：

- 成功答复 TTL = **5 秒**（`FRESH_TTL`），缓存命中时 TTL 倒数。
- 过期后重新回源；上游不可用（超时 `UPSTREAM_TIMEOUT`=2s、答复不可用、或序号被拒）
  时旧 A 最多沿用 **20 秒**（`STALE_WINDOW`），应答 TTL 为剩余可用时长；超过即
  **SERVFAIL**。
- **NXDOMAIN 只作 5 秒新鲜缓存，绝不作过期备用**：过期+上游不可用 → SERVFAIL。
- 解析器确认 NXDOMAIN 时**立即持久清除旧 A**：此后任何答复都不再含旧 A。
- 每次回源用**独立 socket + 随机事务 ID + 问题匹配**，超时后迟到的旧答复
  无人接收，无法复活旧记录。
- 缓存期限以绝对 epoch 存于 SQLite，**重启不延长旧 A 的有效期**。

发布序号（模拟副本落后/追新）：

- 权威端在 A 与 NXDOMAIN 答复的 additional 段带上
  `_serial.<域名> TXT "serial=<n>"`；延迟应答沿用受理时快照的序号。
- 解析器把"已接受的最高序号 + 结果"持久保存。回源结果：
  - 序号 **更高** → 接受：可覆盖 NXDOMAIN（重新发布的 A 恢复解析），也可覆盖旧 A；
  - 序号 **相同且内容相同** → 接受（幂等重发，刷新 5 秒新鲜期）；
  - 序号 **更低**，或**相同但内容不同** → 视为**回源不可用**：不刷新缓存，
    继续按 5 秒新鲜 / 旧 A 过期后最多 20 秒备用作答（NXDOMAIN 不作过期备用）；
  - 未带序号、rcode 不可缓存的答复同样按不可用处理。
- 一旦确认较高序号，答复永远不会使用较低序号的 A：并发回源乱序时，若较低序号
  的结果后到，只按已接受的高序号结果作答（新鲜期内外均如此）。
- 幂等重发虽被接受，但较旧序号的结果永远不会让缓存或序号后退。
- `replica_state` 与 `cache` 在**同一个 SQLite 事务**里写入（`BEGIN IMMEDIATE`）；
  任一步失败整笔回滚，不会留下"序号已前进、缓存还是旧的"之类半新半旧状态。
  已接受序号持久化，**重启不能降低**它。

网页控制台：

- 可切换权威端 `a`（可改 IP）/ `nxdomain` / `delay`（延迟应答，默认 3s，
  大于上游超时）/ `timeout`（不应答，模拟权威端失联），并设置**发布序号**
  （改小=落后副本，改大=重新发布）。
- "发起查询"经解析器发**真实 UDP 查询**，展示实际答复（rcode、应答、TTL、
  **答复携带的序号**）与来源（`upstream` / `cache-fresh` / `cache-stale` /
  `none`，由解析器在 additional 段 TXT `_src.<域名>` 中带回），并展示缓存状态、
  **已接受最高序号**及双方日志。

固定域名默认 `service.example`（`FIXED_DOMAIN` 可改）。解析器只服务该域名，
其余名称 REFUSED，非 A 查询返回 NODATA。

## 文件

```
app/common.py       配置 + SQLite 状态面 + 事务化的序号接受逻辑
app/auth_server.py  可控权威端（dnslib 编解码，线程并发，答复带序号）
app/resolver.py     缓存/serve-stale 解析器（序号取舍）
app/web.py          FastAPI 操作网页（序号/模式/地址切换 + 真实查询）
tests/selftest.py   端到端自测（A–G 场景）
Dockerfile / docker-compose.yml / requirements.txt
```
