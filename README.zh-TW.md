# recon-mcp

[English](./README.md) | **繁體中文**

[![CI](https://github.com/nan786521/recon-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/nan786521/recon-mcp/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

一個 [MCP](https://modelcontextprotocol.io) server,讓 AI coding agent ——
**Claude Code、Codex、Cline,以及任何 MCP 用戶端** —— 能使用安全、
結構化的網路與資安**偵察**工具。

多數 MCP server 只是包裝 CRUD API。`recon-mcp` 提供的是工程師調查一個資產時
會用到的唯讀偵察能力,並回傳乾淨的 JSON ——附帶分級判讀 —— 讓 agent 能直接
推理結果,而不用去解析主控台輸出。

> ⚠️ **僅限授權使用。** 這些工具用於檢測**你擁有、或已取得明確書面授權**的
> 資產、CTF 練習與教學。未經授權請勿對第三方基礎設施使用。你需為自己的使用
> 行為負責。

## 工具

| 工具 | 功能 |
|------|------|
| `dns_recon` | 被動式 DNS + WHOIS + 郵件安全(SPF/DMARC/DKIM)查詢,並附郵件安全分級判讀 |
| `tls_check` | SSL/TLS 檢查:憑證、協定版本、加密套件、forward secrecy、HSTS、OCSP、已知協定漏洞 —— 含分級 |
| `http_headers_audit` | 稽核 HTTP 安全回應標頭(CSP、HSTS、X-Frame-Options、COEP/COOP/CORP……)—— 含分級 |
| `port_scan` | 單一主機 TCP connect 掃描(單次上限 1024 埠),回報開放埠與服務 |

## 範例

對 agent 說「檢查 example.com 的郵件安全」—— 它會呼叫 `dns_recon`,拿回一份
**可直接行動的分級判讀**,而不是一堆原始紀錄:

```json
{
  "email": {
    "assessment": {
      "grade": "A",
      "score": 100,
      "summary": "SPF, DKIM, and DMARC are all configured and enforced.",
      "findings": [
        { "severity": "ok", "check": "SPF",   "message": "SPF present with a hard fail (\"-all\")." },
        { "severity": "ok", "check": "DKIM",  "message": "DKIM present (selector \"default\")." },
        { "severity": "ok", "check": "DMARC", "message": "DMARC enforced (p=reject)." }
      ]
    }
  }
}
```

缺 DMARC 的網域會回傳 `warning` 等級的 finding,附上具體建議與較低的 grade
—— 讓 agent 能直接告訴使用者該修什麼。

## 安裝

需要 Python ≥ 3.10。

**推薦 —— 免 clone,透過 [uv](https://docs.astral.sh/uv/):**

```bash
uvx recon-kit-mcp
```

**或從原始碼安裝(開發用):**

```bash
git clone https://github.com/nan786521/recon-mcp
cd recon-mcp
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
pip install -e .
```

## 在 Claude Code 中使用

新增 server(stdio transport)。用 `uvx` 不需要絕對路徑:

```bash
claude mcp add recon -- uvx recon-kit-mcp
```

或手動加進任何 MCP 用戶端設定:

```json
{
  "mcpServers": {
    "recon": {
      "command": "uvx",
      "args": ["recon-kit-mcp"]
    }
  }
}
```

(從原始碼 checkout 時,改把 command 指向 `/絕對路徑/到/.venv/bin/recon-kit-mcp`。)

接著就能對 agent 說:*「用 dns_recon 查 example.com,告訴我它的郵件安全
設定有沒有做好」* 或 *「稽核 example.com 的 TLS 與安全標頭」*。

## 工具參考

### `dns_recon(domain, checks?, timeout?) -> dict`

- **records** —— A、AAAA、MX、NS、TXT、SOA、CNAME 紀錄
- **whois** —— 解析後的註冊欄位 + 原始 WHOIS 文字
- **email** —— SPF、DMARC、DKIM 設定狀態,並附分級 `assessment`
  (字母等級 A–F、一句總結,以及每項的 findings:含 severity 與建議修法)

`checks` 可填 `["records", "whois", "email"]` 的任意子集;省略則三項全跑。

### `tls_check(host, port=443, timeout?) -> dict`

回傳 `grade`、`certificate`(有效性/到期/金鑰演算法)、`protocols`
(標記過時的 SSLv3 / TLS 1.0 / 1.1)、加密套件資訊、`forward_secrecy`、
`hsts`、`vulnerabilities`(每項含 `vulnerable` 旗標),以及 `findings` 清單。

### `http_headers_audit(host, port?, use_ssl=True, timeout?) -> dict`

回傳 `grade`、`score`、觀察到的安全標頭,以及每項標頭附建議的 `findings`
清單。預設走 HTTPS(port 443)。

### `port_scan(host, ports?, timeout?) -> dict`

對**單一**主機做 TCP connect 掃描。`ports` 為字串 —— `"22,80,443"`、範圍
`"1-1024"`、或混合;省略則掃內建常見埠集合。單次硬上限 1024 埠(單一主機
偵察,非大規模掃描)。回傳 `host`、`ip`、`scanned`、`open_count`、
`open_ports`(埠 + 服務)。僅掃描你有授權檢測的主機。

## 授權

[MIT](./LICENSE)
