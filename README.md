# tdca

`tdca` 是一个面向个人网站的本地 CA 管理 CLI，使用 Python 3.12、标准库 `argparse`、SQLite 和 `cryptography`。它不提供 Web/HTTP 服务或 OCSP，也不调用系统 `openssl` 命令。

## 安装

```bash
conda create -n CA_env python=3.12 pip -y
conda activate CA_env
python -m pip install -e ".[dev]"
tdca --help
python -m tdca --help
```

CA 工作目录默认为 `~/.tdca`，每条命令均可用 `--ca-dir PATH` 覆盖。`--ca-dir` 可放在子命令前或后。首次初始化时目录会设为 `0700`，CA 私钥为 `0600`。

CA 密码优先从 `TDCA_CA_PASSWORD` 读取；未设置时使用交互式 `getpass`。根 CA 交互式初始化需二次确认。请勿把密码写入命令行参数、脚本、shell 历史或日志。使用环境变量时注意其可能被同机进程读取。

## 初始化

```bash
export TDCA_CA_PASSWORD='请替换为高强度密码'
tdca init-root --cn "Demo Personal Root CA" --org "Home Lab" --valid-days 3650
tdca init-intermediate --cn "Demo Personal Intermediate CA" --org "Home Lab" --valid-days 1825
```

初始化不会覆盖已存在的根或中间 CA。签发默认为 `--ca intermediate`；中间 CA 不存在时会报错，不会静默降级到根 CA。根 CA 私钥应离线保管、尽量少用。

## 签发

生成密钥并签发：

```bash
tdca issue --ca intermediate --cn example.com \
	--san DNS:example.com,DNS:www.example.com,IP:192.168.1.10 \
	--valid-days 365 --out ./issued
```

从 CSR 签发：

```bash
tdca issue --ca intermediate --csr ./request.csr --valid-days 365 --out ./issued
```

CSR 签名会被验证，Subject 和 SAN 均取自 CSR；传入无效签名或空 SAN 会报错。生成模式中，如果 CN 未列入 SAN，会自动添加 `DNS:<CN>`。输出包含 `cert.pem`、`chain.pem` 和 `fullchain.pem`；由本工具生成的服务器私钥另有 `key.pem`。`chain.pem` 包含签发 CA 及必要中间链；`fullchain.pem` 是叶子证书加中间链，不附根证书，这是常见 Web 服务器部署方式。

服务器私钥默认不加密以便服务自动加载，文件权限为 `0600`。如需加密，添加 `--encrypt-key`，并设置 `TDCA_KEY_PASSWORD` 或在提示时输入。加密私钥可能需要在服务启动/部署时额外解锁，请妥善管理密码；未加密私钥一旦泄露，必须立即吊销相关证书并更换密钥。

## 查看、导出与吊销

```bash
tdca list
tdca list --json
tdca show --cn example.com
tdca show --serial 0123ABCD --json
tdca export --cn example.com --out ./exported
tdca revoke --cn example.com --reason keyCompromise
```

CN 命中多个证书时，`show`、`export` 和 `revoke` 会要求使用序列号。重复吊销保持首次吊销时间和原因。导出会原样保留服务器私钥的加密状态，不导出任何 CA 私钥。

导出根 CA 公钥时，必须指定文件路径；格式支持 PEM（默认）和 DER：

```bash
tdca export-root-pubkey --out ./root-public-key.pem
tdca export-root-pubkey --out ./root-public-key.der --format der
```

该命令只导出根 CA 证书中的公钥，不导出私钥；目标文件已存在时不会覆盖。

## CRL 与验证

```bash
tdca crl --ca intermediate --out ./crl
tdca verify --cert ./issued/cert.pem
tdca audit --limit 50
tdca version
```

CRL 默认 7 天后过期，含对应签发 CA 的未过期吊销条目、原因码和递增的 CRL Number。验证检查本地 CA 签名链、有效期及 SQLite 吊销状态；它是基础校验，不是完整 RFC 5280 路径验证器，也不检查外部 CRL/OCSP。

## 安全警告

- 该 CA 仅用于个人设备和自己的网站，不用于公共 PKI 或未经授权的系统。
- 不要将个人根 CA 分发给不受控设备。
- 根 CA 私钥泄露后必须重建信任链，并从受信设备中移除旧根证书。
- 生产环境建议离线保存根 CA 私钥，仅在需要签发中间 CA 时短暂启用。
- CA 私钥均以密码加密后落盘；密码丢失会导致该私钥不可用。请使用独立备份并保护好 CA 工作目录。

## 测试

```bash
conda activate CA_env
pytest -q
```

测试只使用 pytest 提供的临时目录，不读写真实 `~/.tdca`，不依赖外部网络。

