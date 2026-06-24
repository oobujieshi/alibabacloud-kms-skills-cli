# AlibabaCloud KMS Skills CLI

阿里云 KMS 信封加密/解密命令行工具。

基于 [alibabacloud-kms-cli](https://github.com/aliyun/alibabacloud-kms-cli) 源码结构和依赖版本开发。

## 工具

| 工具 | 说明 |
|------|------|
| `envelope-encrypt` | 信封加密：KMS GenerateDataKey + AES-256-GCM |
| `envelope-decrypt` | 信封解密：KMS Decrypt + AES-256-GCM |

## 安装

从 [Releases](https://github.com/oobujieshi/alibabacloud-kms-skills-cli/releases) 下载对应平台的二进制文件：

- `envelope-encrypt-{platform}` : 信封加密
- `envelope-decrypt-{platform}` : 信封解密

支持的平台后缀：
- `linux-amd64`, `linux-arm64`
- `windows-amd64.exe`
- `darwin-amd64`, `darwin-arm64`

## 使用

```bash
# 加密
envelope-encrypt encrypt --key-id <cmk-id> --data "hello"

# 解密
envelope-decrypt decrypt --in-file secret.enc
```

详见各工具的 `--help`。

## 构建

```bash
cd envelope-encrypt && go build -o envelope-encrypt .
cd envelope-decrypt && go build -o envelope-decrypt .
```

## 凭据

无需传入 AK/SK。使用 `credentials-go` 默认凭据链：
环境变量 → `~/.aliyun/config.json` → ECS RAM 角色 → ...

Region 通过 `REGION_ID` 环境变量或 ECS metadata 自动获取。

## 依赖

与 [alibabacloud-kms-cli](https://github.com/aliyun/alibabacloud-kms-cli) 完全一致：

| 包 | 版本 |
|----|------|
| `darabonba-openapi/v2` | v2.1.15 |
| `kms-20160120/v3` | v3.4.0 |
| `credentials-go` | v1.4.11 |
| `cobra` | v1.10.2 |
| `tea` | v1.4.0 |

## 可配环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `REGION_ID` | ECS metadata | KMS 地域 |
| `ENDPOINT_TYPE` | Vpc | `Vpc`(内网) / `Public`(公网) |
