# AlibabaCloud KMS Skills CLI

阿里云 KMS 命令行工具集。单一 Go 模块，共享 `pkg/kms`，按 `cmd/` 组织多个命令。

## 命令

| 命令 | 目录 | 说明 |
|------|------|------|
| `envelope-encrypt` | `cmd/envelope-encrypt/` | 信封加密 (GenerateDataKey + AES-256-GCM) |
| `envelope-decrypt` | `cmd/envelope-decrypt/` | 信封解密 (Decrypt + AES-256-GCM) |
| `symmetric-encrypt` | `cmd/symmetric-encrypt/` | 对称加密 (KMS Encrypt API) — 待实现 |
| `symmetric-decrypt` | `cmd/symmetric-decrypt/` | 对称解密 (KMS Decrypt API) — 待实现 |
| `get-secret` | `cmd/get-secret/` | 获取凭据值 (使用 alibabacloud-kms-cli) — 待实现 |

## 项目结构

```
pkg/kms/client.go        # 共享：KMS 客户端、凭据链、Region 检测
cmd/
  envelope-encrypt/       # 信封加密入口
  envelope-decrypt/       # 信封解密入口
  symmetric-encrypt/      # 对称加密入口 (todo)
  symmetric-decrypt/      # 对称解密入口 (todo)
  get-secret/             # 获取凭据 (todo)
```

## 构建

```bash
go build -o envelope-encrypt ./cmd/envelope-encrypt/
go build -o envelope-decrypt ./cmd/envelope-decrypt/
```

## 凭据

无需传入 AK/SK。使用 credentials-go 默认凭据链。

## 环境变量

| 变量 | 说明 |
|------|------|
| `REGION_ID` | KMS 地域 |
| `ENDPOINT_TYPE` | `Vpc`(默认) / `Public` |
