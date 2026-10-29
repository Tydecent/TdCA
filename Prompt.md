以下提示词可直接粘贴给 AI Agent 使用。

---

# 角色

你是一名资深 Python 安全工程师与 CLI 工具开发者。请为一个**个人网站使用的简易 CA 管理程序**生成完整、可运行、可测试的 Python 项目。程序名为 `tdca`，必须以如下方式运行：

```bash
tdca [args]
```

运行环境固定为：

```bash
conda activate CA_env
python --version  # 必须为 Python 3.12.x
```

# 任务

生成一个基于 Python 3.12 的 CLI CA 管理程序，名称为 `tdca`。它用于个人网站证书的签发、查看、导出、吊销和 CRL 生成。不要生成 Web 界面，不要实现 HTTP 服务，不要实现 OCSP，不要依赖系统 `openssl` 命令行。

# 硬性约束

1. 使用 Python 3.12。
2. 使用 `cryptography` 库完成所有密码学操作，不调用 `openssl` 二进制。
3. CLI 使用标准库 `argparse`，不要引入 `click`、`typer` 等额外 CLI 框架。
4. 使用 `pyproject.toml` 定义项目，并提供 console script：
   ```toml
   [project.scripts]
   tdca = "tdca.cli:main"
   ```
5. 用户执行 `pip install -e .` 后，可在 `CA_env` 中直接运行 `tdca --help`。
6. 所有子命令必须支持 `--help`。
7. 默认 CA 工作目录为 `~/.tdca`，所有命令支持 `--ca-dir PATH` 覆盖。
8. 不要将密码作为命令行参数传入。CA 私钥密码通过环境变量 `TDCA_CA_PASSWORD` 或交互式 `getpass` 获取；测试中可使用环境变量。
9. 所有 CA 私钥必须使用密码加密后落盘。私钥文件权限必须为 `0600`，CA 目录权限必须为 `0700`。
10. 不得在 stdout、stderr、日志、审计记录中打印私钥内容或密码。
11. 不得覆盖已有 CA；初始化必须幂等安全，已存在时报错退出。
12. 所有文件写入应尽量使用原子写，避免半写状态。
13. 退出码约定：`0` 成功；`1` 业务错误；`2` 参数错误。
14. 普通结果输出到 stdout，错误信息输出到 stderr。支持 `--json` 的命令输出机器可读 JSON。
15. 不要询问澄清问题。信息不足时做合理假设，并在 README 中记录。
16. 生成完整项目，不要省略文件内容，不要输出伪代码。

# 功能需求

## 1. CA 初始化

支持根 CA 和可选中间 CA。

### `tdca init-root`

用于创建自签名根 CA。

至少支持参数：

```bash
tdca init-root \
  --ca-dir ~/.tdca \
  --cn "My Personal Root CA" \
  --org "Home Lab" \
  --valid-days 3650 \
  --key-type rsa \
  --key-size 4096
```

要求：

- 生成根 CA 私钥和自签名证书。
- 根 CA 私钥必须加密保存。
- 支持 `rsa` 和 `ec` 密钥类型。
- RSA 默认 4096 位，可选 2048；EC 默认 P-256。
- 根 CA 证书扩展至少包括：
  - `BasicConstraints(ca=True, path_length=1)`
  - `KeyUsage(key_cert_sign=True, crl_sign=True, ...)`
  - `SubjectKeyIdentifier`
- 创建后输出根 CA 证书路径、Subject、有效期、指纹。
- 若 `--ca-dir` 中已存在根 CA，报错退出，不覆盖。

### `tdca init-intermediate`

用于由根 CA 签发中间 CA。

至少支持：

```bash
tdca init-intermediate \
  --ca-dir ~/.tdca \
  --cn "My Personal Intermediate CA" \
  --org "Home Lab" \
  --valid-days 1825 \
  --key-type rsa \
  --key-size 4096
```

要求：

- 使用根 CA 私钥签发中间 CA 证书。
- 中间 CA 私钥必须加密保存。
- 中间 CA 证书扩展至少包括：
  - `BasicConstraints(ca=True, path_length=0)`
  - `KeyUsage(key_cert_sign=True, crl_sign=True, ...)`
  - `SubjectKeyIdentifier`
  - `AuthorityKeyIdentifier`
- 中间 CA 有效期不得超过根 CA 有效期。
- 若已存在中间 CA，报错退出，不覆盖。

## 2. 证书签发

### `tdca issue`

用于签发服务器证书。

至少支持：

```bash
tdca issue \
  --ca-dir ~/.tdca \
  --ca intermediate \
  --cn example.com \
  --san DNS:example.com,DNS:www.example.com,IP:192.168.1.10 \
  --valid-days 365 \
  --key-type rsa \
  --key-size 2048 \
  --out ./issued
```

以及从 CSR 签发：

```bash
tdca issue \
  --ca-dir ~/.tdca \
  --ca intermediate \
  --csr ./request.csr \
  --valid-days 365 \
  --out ./issued
```

要求：

- `--ca` 支持 `root` 或 `intermediate`，默认 `intermediate`；若中间 CA 不存在，可回退到 `root` 并明确提示，或报错要求显式指定。请选择安全且清晰的策略并写入 README。
- 支持两种模式：
  1. 无 `--csr`：由 `tdca` 生成密钥对并签发证书。
  2. 有 `--csr`：解析并验证 CSR 签名，按 CSR 的 Subject 和 SAN 签发；不得静默忽略 CSR 中的 SAN。
- `--san` 格式支持逗号分隔的 `DNS:example.com` 和 `IP:192.168.1.10`。
- 若 `--cn` 未出现在 SAN 中，自动将 `DNS:<cn>` 加入 SAN。
- 服务器证书扩展至少包括：
  - `BasicConstraints(ca=False)`
  - `KeyUsage(digital_signature=True, key_encipherment=True)`，RSA 时包含 `key_encipherment`；EC 时按合理方式设置。
  - `ExtendedKeyUsage([serverAuth])`
  - `SubjectAlternativeName`
  - `SubjectKeyIdentifier`
  - `AuthorityKeyIdentifier`
- 证书有效期不得超过签发 CA 的剩余有效期。
- 默认有效期 365 天；`notBefore` 设为当前时间前 5 分钟，容忍时钟偏差。
- 使用随机证书序列号，建议至少 16 字节随机正整数，十六进制显示。
- 输出目录中至少生成：
  - `cert.pem`
  - `chain.pem`
  - `fullchain.pem`
  - `key.pem`（仅无 CSR 模式生成）
- `chain.pem` 应包含签发 CA 及必要上级链；`fullchain.pem` 应包含叶子证书和链。根证书是否包含在 fullchain 中请按 Web 服务器常用做法处理，并在 README 说明。
- 服务器私钥默认不加密，以便 Web 服务器自动加载；若提供 `--encrypt-key`，则通过 `TDCA_KEY_PASSWORD` 或交互式输入加密。README 必须给出安全警告。
- 私钥文件权限 `0600`，证书文件权限 `0644`。
- 输出证书序列号、Subject、SAN、有效期、文件路径。
- 将证书记录写入元数据存储和审计日志。

## 3. 证书列表与详情

### `tdca list`

至少支持：

```bash
tdca list --ca-dir ~/.tdca
tdca list --ca-dir ~/.tdca --json
```

要求：

- 表格显示：序列号、CN、SAN 摘要、签发 CA、生效时间、到期时间、剩余天数、状态。
- 状态至少包括：`valid`、`revoked`、`expired`。
- 自动计算剩余有效天数。
- 支持 `--json` 输出结构化数据。

### `tdca show`

至少支持：

```bash
tdca show --ca-dir ~/.tdca --serial <serial>
tdca show --ca-dir ~/.tdca --cn example.com
tdca show --ca-dir ~/.tdca --cn example.com --json
```

要求：

- 显示 Subject、Issuer、序列号、SAN、有效期、状态、SHA-256 指纹、证书路径、吊销信息（如有）。
- 若按 CN 查找命中多个证书，报错并列出候选序列号，要求用户使用 `--serial`。

## 4. 证书导出

### `tdca export`

至少支持：

```bash
tdca export --ca-dir ~/.tdca --serial <serial> --out ./exported
```

要求：

- 按序列号或 CN 定位证书。
- 输出：
  - `cert.pem`
  - `chain.pem`
  - `fullchain.pem`
  - `key.pem`（若该证书由 `tdca` 生成且私钥存在）
- 不导出 CA 根私钥。
- 若私钥存在且被加密，导出时保持加密状态或明确提示；不得静默解密后明文输出。
- 输出文件权限符合安全要求。

## 5. 吊销与 CRL

### `tdca revoke`

至少支持：

```bash
tdca revoke --ca-dir ~/.tdca --serial <serial> --reason keyCompromise
```

要求：

- 支持按 `--serial` 或 `--cn` 吊销。
- 支持 RFC 5280 常见原因码，至少包括：
  - `unspecified`
  - `keyCompromise`
  - `CACompromise`
  - `affiliationChanged`
  - `superseded`
  - `cessationOfOperation`
  - `certificateHold`
  - `privilegeWithdrawn`
- 重复吊销已吊销证书应幂等成功，并保留首次吊销时间和原因，或明确提示。
- 更新元数据状态并写审计日志。
- 不得删除原证书文件。

### `tdca crl`

至少支持：

```bash
tdca crl --ca-dir ~/.tdca --ca intermediate --out ./crl
```

要求：

- 为指定 CA 生成并签名 CRL。
- CRL 包含该 CA 已吊销且未过期的证书条目。
- 条目包含序列号、吊销时间、原因码。
- 设置 `last_update`、`next_update`，默认 `next_update` 为 7 天后。
- 维护并递增 CRL Number。
- 输出 `crl.pem`。
- 使用对应 CA 私钥签名，签名前通过密码解密。
- 不实现 CRL 分发 HTTP 服务，只生成文件。

## 6. 验证

### `tdca verify`

至少支持：

```bash
tdca verify --ca-dir ~/.tdca --cert ./issued/cert.pem
```

要求：

- 验证证书签名链是否可由本地 CA 验证。
- 检查证书是否在有效期内。
- 检查证书是否已被本地吊销记录标记。
- 输出清晰结果；失败时退出码非 0。
- 不要求实现完整 RFC 5280 路径验证器，但应完成签名、有效期和吊销状态的基础检查。

## 7. 其他命令

至少提供：

```bash
tdca version
tdca --help
```

可选提供：

```bash
tdca audit --ca-dir ~/.tdca --limit 50
```

用于查看审计日志。

# CLI 与输出规范

1. 所有命令采用 `tdca <subcommand> [options]`。
2. 所有命令支持 `--ca-dir`。
3. 对支持机器读取的命令支持 `--json`。
4. 错误信息应可操作，例如：
   - CA 未初始化
   - 密码错误
   - 证书不存在
   - CN 命中多个证书
   - 有效期超过 CA
   - CSR 签名无效
   - SAN 格式错误
5. 不得在异常堆栈中泄露密码或私钥。默认只打印简洁错误；`--verbose` 可打印堆栈，但仍需脱敏。
6. 表格输出应适合终端阅读；JSON 输出不得混入表格文本。

# 存储设计

请使用文件系统保存 PEM 文件，使用 SQLite 保存元数据。建议目录结构：

```text
~/.tdca/
  db.sqlite
  audit.log
  ca/
    root/
      cert.pem
      key.pem
    intermediate/
      cert.pem
      key.pem
  certs/
    <serial>/
      cert.pem
      key.pem
      chain.pem
      fullchain.pem
  crl/
    root/
      crl.pem
    intermediate/
      crl.pem
```

SQLite 至少包含证书表，字段建议：

```text
serial TEXT PRIMARY KEY
common_name TEXT
san TEXT
issuer_ca TEXT
not_before TEXT
not_after TEXT
status TEXT
revoked_at TEXT
revoke_reason TEXT
cert_path TEXT
key_path TEXT
created_at TEXT
```

另需保存 CRL Number。使用事务保证元数据与文件操作尽量一致；若文件写入成功但数据库失败，应给出明确错误。审计日志使用 JSONL，追加写入，记录时间、命令、操作对象、结果；不得记录密码和私钥。

# 安全要求

1. CA 私钥必须使用 `cryptography` 的密码加密机制保存，例如 `BestAvailableEncryption`。
2. 密码来源优先级：
   - 环境变量 `TDCA_CA_PASSWORD`
   - 交互式 `getpass`
3. 初始化根 CA 时若使用交互式输入，要求二次确认。
4. 私钥文件权限必须为 `0600`；CA 目录权限 `0700`。
5. 审计日志不得记录密码、私钥、CSR 私钥内容。
6. README 必须包含安全警告：
   - 该 CA 仅用于个人设备和自己的网站。
   - 不要将个人根 CA 分发给不受控设备。
   - 根 CA 私钥泄露后必须重建信任链。
   - 生产环境建议离线保存根 CA 私钥。
7. 不要实现“跳过密码校验”的后门。

# 项目结构要求

请生成完整项目，建议结构如下，可合理调整但必须完整可运行：

```text
tdca/
  pyproject.toml
  README.md
  src/
    tdca/
      __init__.py
      __main__.py
      cli.py
      ca.py
      crypto.py
      store.py
      crl.py
      audit.py
      errors.py
      utils.py
  tests/
    test_init.py
    test_issue.py
    test_list_show.py
    test_export.py
    test_revoke_crl.py
    test_verify.py
```

要求：

- `python -m tdca` 也可运行。
- 代码模块职责清晰。
- 类型标注完整。
- 使用 `pathlib` 处理路径。
- 使用 `sqlite3` 标准库。
- 依赖尽量少：运行时主要依赖 `cryptography`；测试依赖 `pytest`。
- `pyproject.toml` 中声明 Python `>=3.12`。
- README 使用中文，包含安装、初始化、签发、导出、吊销、CRL、验证示例，以及安全警告。

# 测试要求

使用 `pytest` 编写测试，所有测试使用 `tmp_path`，不得读写真实 `~/.tdca`。测试中通过环境变量设置测试密码。至少覆盖：

1. `init-root` 创建根 CA，重复执行报错不覆盖。
2. `init-intermediate` 由根签发中间 CA。
3. `issue` 生成带多 SAN 的服务器证书。
4. 从 CSR 签发证书。
5. `list` 和 `show` 输出包含预期证书。
6. `export` 输出 `cert.pem`、`chain.pem`、`fullchain.pem`、`key.pem`。
7. `revoke` 后状态变为 `revoked`。
8. `crl` 生成 CRL，包含被吊销证书序列号。
9. `verify` 对有效证书成功，对吊销证书失败。
10. 私钥文件权限为 `0600`。
11. 密码错误时给出业务错误且不泄露敏感信息。

测试不得依赖外部网络。

# 验收标准

生成的项目必须能通过以下流程：

```bash
conda activate CA_env
python --version   # 3.12.x
pip install -e .
tdca --help
tdca version

export TDCA_CA_PASSWORD='test-passphrase'

tdca init-root \
  --ca-dir /tmp/tdca-demo \
  --cn "Demo Personal Root CA" \
  --org "Home Lab" \
  --valid-days 3650

tdca init-intermediate \
  --ca-dir /tmp/tdca-demo \
  --cn "Demo Personal Intermediate CA" \
  --org "Home Lab" \
  --valid-days 1825

tdca issue \
  --ca-dir /tmp/tdca-demo \
  --ca intermediate \
  --cn example.com \
  --san DNS:example.com,DNS:www.example.com,IP:192.168.1.10 \
  --valid-days 365 \
  --out /tmp/tdca-demo/issued

tdca list --ca-dir /tmp/tdca-demo
tdca list --ca-dir /tmp/tdca-demo --json

tdca show --ca-dir /tmp/tdca-demo --cn example.com --json

tdca export \
  --ca-dir /tmp/tdca-demo \
  --cn example.com \
  --out /tmp/tdca-demo/exported

tdca verify \
  --ca-dir /tmp/tdca-demo \
  --cert /tmp/tdca-demo/issued/cert.pem

tdca revoke \
  --ca-dir /tmp/tdca-demo \
  --cn example.com \
  --reason keyCompromise

tdca crl \
  --ca-dir /tmp/tdca-demo \
  --ca intermediate \
  --out /tmp/tdca-demo/crl-out

pytest -q
```

# 输出格式

请按以下顺序输出：

1. 不超过 10 行的实施计划。
2. 完整文件树。
3. 逐文件输出完整代码与文档，每个文件使用带路径的代码块。
4. 最后给出验收命令清单和安全注意事项。

不要省略任何文件内容。不要输出伪代码。不要询问澄清问题。