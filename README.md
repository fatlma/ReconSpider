# 🕷️ ReconSpider Pro v2.0

> Passive web reconnaissance tool for bug bounty & security research.  
> Single command · Live output · JS secret detection · Tech fingerprinting

---

## 🚀 Quick Start

```bash
# Install
pip install scrapy

# Run
python3 recon.py https://target.com results.json
```

That's it. No config files, no scrapy project setup.

---

## 📺 Live Output Example

```
╔══════════════════════════════════════════╗
║        ReconSpider Pro  v2.0             ║
║  JS secrets · Tech FP · Header audit    ║
╚══════════════════════════════════════════╝

  🎯  Target               https://target.com
  💾  Output               results.json

  🤖  robots.txt           4 disallowed paths found
       ↳  /admin
       ↳  /.env
       ↳  /backup
       ↳  /api/internal
  🌐  Page crawled         [200] https://target.com
  🛠  Tech detected        WordPress, jQuery
  🔓  Missing headers      Content-Security-Policy, HSTS
  ⚠   X-Powered-By leak   PHP/8.1.2
  🚪  OPEN PATH            [200] https://target.com/admin
  🗺  sitemap.xml          12 URLs found
  🔗  JS endpoints         3 found → /static/app.bundle.js
  🔑  SECRET [JWT Token]   line 47 → /static/app.bundle.js
  ✉   Email found          admin@target.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✅  Scan complete!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Pages crawled   : 14
  JS files parsed : 6
  Emails found    : 2
  Open paths      : 3
  Secrets found   : 1
  Output saved to : results.json
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## ✨ Features

| Category | What it finds |
|---|---|
| **JS Analysis** | API endpoints, secrets, source-map leaks (vendor libs skipped) |
| **Secret Detection** | AWS keys, GitHub tokens, JWT, Stripe, Slack, Twilio, API keys |
| **Tech Fingerprinting** | WordPress, React, Vue, Angular, Next.js, Django, Laravel, Spring… |
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Powered-By info leak |
| **Interesting Paths** | /admin, /api, /.env, /swagger, /.git/HEAD and 14 more |
| **Forms** | Action URL, method, all input field names |
| **robots.txt** | Disallowed paths, sitemap references |
| **sitemap.xml** | Full URL list |
| **Scope control** | Only crawls the target domain |

---

## 🔍 Filter results

```bash
# Show only secrets
cat results.json | python3 -c "
import json, sys
for i in json.load(sys.stdin):
    if i.get('possible_secrets'):
        print(i['js_url'])
        for s in i['possible_secrets']:
            print(f\"  [{s['type']}] line {s['line']}: {s['match']}\")
"

# Show open paths
cat results.json | python3 -c "
import json, sys
for i in json.load(sys.stdin):
    if i.get('type') == 'interesting_path':
        print(i['status'], i['url'])
"

# Show all emails
cat results.json | python3 -c "
import json, sys
emails = set()
for i in json.load(sys.stdin):
    emails.update(i.get('emails', []))
print('\n'.join(sorted(emails)))
"

# Show missing security headers per page
cat results.json | python3 -c "
import json, sys
for i in json.load(sys.stdin):
    if i.get('type') == 'page':
        missing = [k for k,v in i.get('security_headers',{}).items() if not v and k != 'X-Powered-By']
        if missing:
            print(i['url'], '->', ', '.join(missing))
"
```

---

## 📁 Output Structure

Every object in the JSON has a `type` field:

| type | Description |
|---|---|
| `page` | Full crawl result for one page |
| `js_analysis` | Analysis of one JS file |
| `robots_txt` | robots.txt content and disallowed paths |
| `sitemap` | All URLs from sitemap.xml |
| `interesting_path` | Probe result — accessible sensitive path |

---

## ⚙️ Secret Detection Patterns

| Pattern | Type |
|---|---|
| `AKIA...` | AWS Access Key |
| `AIza...` | Google API Key |
| `ghp_` / `ghs_` | GitHub Token |
| `eyJ...` (3 parts) | JWT Token |
| `sk_live_...` | Stripe Secret Key |
| `xoxb-...` | Slack Token |
| `AC...` (32 chars) | Twilio Account SID |
| `BEGIN PRIVATE KEY` | RSA/EC Private Key |
| `apikey=`, `token=`, `secret=` | Generic credentials |

> Vendor libraries (jQuery, Bootstrap, React, Vue, lodash…) are automatically skipped to avoid false positives.

---

## ⚠️ Legal & Ethics

**Only scan targets you have explicit written permission to test.**  
Use within bug bounty program scope only.  
The author is not responsible for any misuse.

---

## 📄 License

MIT
