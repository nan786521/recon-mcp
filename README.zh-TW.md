# recon-mcp

[English](./README.md) | **繁體中文**

[![CI](https://github.com/nan786521/recon-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/nan786521/recon-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/recon-kit-mcp)](https://pypi.org/project/recon-kit-mcp/)
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
| `recon_report` | **從這開始。** 一次呼叫 → 同時檢查 DNS、TLS、HTTP 標頭,給整體評級 |
| `dns_recon` | DNS + WHOIS + 郵件安全(SPF/DMARC/DKIM),含分級 |
| `subdomain_enum` | 透過 DNS 字典暴力與/或憑證透明度(CT)log 探索子網域 |
| `tls_check` | 憑證、協定、加密套件、已知 TLS 漏洞,含分級 |
| `http_headers_audit` | HTTP 安全標頭(CSP、HSTS、X-Frame-Options……),含分級 |
| `cookie_audit` | 重導鏈 + Cookie 旗標(Secure / HttpOnly / SameSite),含分級 |
| `cors_check` | CORS 政策探測 —— 標記任意 Origin 反射與萬用字元誤用 |
| `well_known_audit` | 抓取並解析 `security.txt`(RFC 9116)與 `robots.txt` |
| `ip_info` | 解析主機並透過 RDAP 富化 IP(擁有者、國家、CIDR、abuse 聯絡) |
| `port_scan` | 單一主機 TCP 埠掃描(單次 ≤1024 埠),回報開放埠 + 服務 |

## 範例

直接對 agent 說「幫 example.com 做一份安全偵察報告」—— 它呼叫一次
`recon_report`,拿回可直接行動的整體評級:

```json
{
  "domain": "example.com",
  "overall_grade": "F",
  "summary": "Overall posture F: email A, TLS B, headers F; 13 actionable issue(s).",
  "components": {
    "email":   { "grade": "A", "issues": [] },
    "tls":     { "grade": "B", "issues": [] },
    "headers": { "grade": "F", "issues": [
      { "severity": "high", "label": "Missing Content-Security-Policy", "detail": "CSP not set; cannot restrict resource load sources" }
    ] }
  }
}
```

想深入某一項?agent 可以直接呼叫 `dns_recon`、`subdomain_enum`、`tls_check`、
`http_headers_audit`、`cookie_audit`、`cors_check`、`well_known_audit`、
`ip_info` 或 `port_scan`。

## 安裝

需要 Python ≥ 3.10。可在 Linux、macOS、Windows 執行(CI 已驗證)。

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

接著直接說:*「幫 example.com 做一份安全偵察報告」* —— 或只查某一項,
例如 *「檢查 example.com 的郵件安全」*。

server 也內建 **`security_recon` prompt**:在用戶端的 prompt 選單選它、給一個
網域,就會引導做一份依嚴重度排序的稽核。

## 工具參考

### `recon_report(domain, timeout?) -> dict`

一次跑完 DNS/郵件、TLS、HTTP 標頭檢查,回傳 `overall_grade`(以最弱的元件
為準)、一行 `summary`,以及 `components`(`email` / `tls` / `headers`),
每項含自己的 `grade` 與可行動的 `issues`。為求快速,TLS 採單次握手的輕量檢查
——要完整的加密套件/漏洞分析請用 `tls_check`。**建議的起點**;要原始細節再用
下面各別工具。

### `dns_recon(domain, checks?, timeout?) -> dict`

- **records** —— A、AAAA、MX、NS、TXT、SOA、CNAME、CAA 紀錄
- **whois** —— 解析後的註冊欄位 + 原始 WHOIS 文字
- **email** —— SPF、DMARC、DKIM 設定狀態,並附分級 `assessment`
  (字母等級 A–F、一句總結,以及每項的 findings:含 severity 與建議修法)

`checks` 可填 `["records", "whois", "email"]` 的任意子集;省略則三項全跑。

### `subdomain_enum(domain, wordlist?, source="dns", timeout?) -> dict`

從兩個互補來源探索子網域:
- `source="dns"`(預設）—— 透過 DNS 解析候選標籤。`wordlist` 為逗號分隔標籤
  (`"www,api,dev"`);省略則用內建常見清單。單次上限 512 個候選,回傳解析到的 `ips`。
- `source="ct"` —— 查詢公開的**憑證透明度(CT)log**(crt.sh),列出該網域歷來
  簽過憑證的所有名稱。完全被動,能找出字典永遠猜不到的真實主機。
- `source="both"` —— 兩者都跑並合併,記錄每個主機由哪個來源發現。

回傳 `sources`、`found_count`、`found`(各含 `subdomain`、發現它的 `sources`,
以及解析到時的 `ips`)。

### `tls_check(host, port=443, timeout?) -> dict`

回傳 `grade`、`certificate`(有效性/到期/金鑰演算法)、`protocols`
(標記過時的 SSLv3 / TLS 1.0 / 1.1)、加密套件資訊、`forward_secrecy`、
`hsts`、`vulnerabilities`(每項含 `vulnerable` 旗標),以及 `findings` 清單。

### `http_headers_audit(host, port?, use_ssl=True, timeout?) -> dict`

回傳 `grade`、`score`、觀察到的安全標頭,以及每項標頭附建議的 `findings`
清單。預設走 HTTPS(port 443)。

### `cookie_audit(host, port?, use_ssl=True, timeout?) -> dict`

跟隨主機的重導鏈(上限 10 跳,標記任何 HTTPS→HTTP 降級),並檢查沿途每個
`Set-Cookie` 的 `Secure`、`HttpOnly`、`SameSite` 旗標。回傳 `redirect_chain`、
`final_url`、`cookies`(只有旗標 —— 絕不回傳 cookie 值)、`cookie_grade`、
`cookie_score`,以及 `findings` 清單。

### `cors_check(host, port?, use_ssl=True, timeout?) -> dict`

送一個帶不受信任 `Origin` 的 GET,檢查 `Access-Control-Allow-Origin` /
`-Allow-Credentials` 回應。反射任意 Origin **且**允許 credentials 屬高風險
(任何網站都能讀取已驗證的回應);萬用字元或信任 `null` origin 則為次要問題。
回傳 `acao`、`allows_credentials`、`reflects_origin`、`wildcard`、`severity`、
`findings`。

### `well_known_audit(host, timeout?) -> dict`

抓取並解析 `security.txt`(RFC 9116,先試 `/.well-known/` 再試舊路徑)與
`robots.txt`。回傳 `security_txt`(解析欄位、結構性 `issues`、`location`)與
`robots_txt`(`sitemaps`、`disallow`/`allow` 路徑、`user_agents`),各含
`present` 旗標。

### `ip_info(host, timeout?) -> dict`

解析主機 IP 並到公開 **RDAP** 註冊資料庫查詢(透過 rdap.org bootstrap 導向對應
RIR)。回傳 `ip` 與 `rdap`(`handle`、`name`、`country`、`cidr`、`org`、
`abuse_email`)。

### `port_scan(host, ports?, timeout?) -> dict`

對**單一**主機做 TCP connect 掃描。`ports` 為字串 —— `"22,80,443"`、範圍
`"1-1024"`、或混合;省略則掃內建常見埠集合。單次硬上限 1024 埠(單一主機
偵察,非大規模掃描)。回傳 `host`、`ip`、`scanned`、`open_count`、
`open_ports`(埠 + 服務)。僅掃描你有授權檢測的主機。

## 授權

[MIT](./LICENSE)
