#!/usr/bin/env python3
"""
ReconSpider Pro
Usage: python3 recon.py <url> <output.json>
"""

import re
import sys
import json
import hashlib
import scrapy
from urllib.parse import urlparse, urljoin
from scrapy.crawler import CrawlerProcess

# ── ANSI colors ──────────────────────────────────────────────
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
B = "\033[94m"
C = "\033[96m"
W = "\033[97m"
DIM = "\033[2m"
RESET = "\033[0m"

def banner():
    print(f"""
{C}╔══════════════════════════════════════════╗
║        ReconSpider Pro  v2.0             ║
║  JS secrets · Tech FP · Header audit    ║
╚══════════════════════════════════════════╝{RESET}
""")

def log(icon, color, label, msg):
    print(f"  {color}{icon}  {label:<20}{RESET} {W}{msg}{RESET}")

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',                                         "AWS Access Key"),
    (r'AIza[0-9A-Za-z_\-]{35}',                                   "Google API Key"),
    (r'(?:ghp|ghs|gho|github)[_\-]?[0-9a-zA-Z]{36,}',           "GitHub Token"),
    (r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',  "JWT Token"),
    (r'sk_live_[0-9a-zA-Z]{24,}',                                 "Stripe Secret"),
    (r'xox[baprs]\-[0-9]{12}\-[0-9]{12}\-[a-zA-Z0-9]{24}',      "Slack Token"),
    (r'AC[a-zA-Z0-9]{32}',                                        "Twilio SID"),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',                 "Private Key"),
    (r'(?:api[_\-]?key|apikey)["\'\s:=]+([A-Za-z0-9_\-]{20,})', "API Key"),
    (r'(?:secret)["\'\s:=]+([A-Za-z0-9_\-]{20,})',               "Secret"),
    (r'(?:token)["\'\s:=]+([A-Za-z0-9_\-\.]{20,})',              "Token"),
]

SKIP_JS = ["jquery", "bootstrap", "react", "vue", "angular",
           "lodash", "vendor", "polyfill", "modernizr", "webpack-runtime"]

INTERESTING_PATHS = [
    "/admin", "/login", "/api", "/graphql", "/v1", "/v2",
    "/.env", "/config", "/backup", "/phpmyadmin",
    "/wp-admin", "/wp-login.php", "/jenkins", "/dashboard",
    "/swagger", "/api-docs", "/openapi.json", "/.git/HEAD",
]

TECH_FINGERPRINTS = {
    "WordPress":   [r"wp-content", r"wp-includes"],
    "React":       [r"__reactFiber", r"react(?:\.min)?\.js"],
    "Vue":         [r"__vue__", r"vue(?:\.min)?\.js"],
    "Angular":     [r"ng-version", r"angular(?:\.min)?\.js"],
    "Next.js":     [r"__NEXT_DATA__"],
    "Nuxt":        [r"__NUXT__"],
    "Bootstrap":   [r"bootstrap(?:\.min)?\.css"],
    "jQuery":      [r"jquery(?:\.min)?\.js"],
    "Laravel":     [r"laravel_session"],
    "Django":      [r"csrfmiddlewaretoken"],
    "Spring Boot": [r"X-Application-Context"],
    "GraphQL":     [r"graphql", r"__schema"],
}

stats = {"pages": 0, "js_files": 0, "secrets": 0, "emails": 0, "open_paths": 0}


class ReconSpider(scrapy.Spider):
    name = "recon"
    custom_settings = {
        "LOG_ENABLED": False,
        "DEPTH_LIMIT": 3,
        "DOWNLOAD_TIMEOUT": 15,
        "RETRY_TIMES": 2,
        "ROBOTSTXT_OBEY": False,
        "COOKIES_ENABLED": True,
        "CONCURRENT_REQUESTS": 8,
        "DOWNLOAD_DELAY": 0.3,
        "USER_AGENT": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
    }

    def __init__(self, start_url, output_file, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not start_url.startswith("http"):
            start_url = "https://" + start_url
        self.start_url = start_url.rstrip("/")
        self.start_urls = [self.start_url]
        self.allowed_domain = urlparse(self.start_url).netloc
        self.output_file = output_file
        self.results = []
        self.visited = set()

    def start_requests(self):
        yield scrapy.Request(self.start_url, callback=self.parse, errback=self.err)
        yield scrapy.Request(self.start_url + "/robots.txt",  callback=self.parse_robots,  errback=self.err)
        yield scrapy.Request(self.start_url + "/sitemap.xml", callback=self.parse_sitemap, errback=self.err)
        for path in INTERESTING_PATHS:
            yield scrapy.Request(
                self.start_url + path,
                callback=self.parse_probe,
                errback=self.err,
                meta={"path": path},
            )

    def parse(self, response):
        if response.url in self.visited:
            return
        self.visited.add(response.url)
        stats["pages"] += 1

        text = response.text
        headers = dict(response.headers)

        emails = list(set(re.findall(
            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text
        )))
        if emails:
            stats["emails"] += len(emails)
            for e in emails:
                log("✉", G, "Email found", e)

        raw_links = response.css("a::attr(href)").getall()
        internal, external = [], []
        for lnk in raw_links:
            full = urljoin(response.url, lnk)
            if self.allowed_domain in urlparse(full).netloc:
                internal.append(full)
            elif full.startswith("http"):
                external.append(full)
        internal = list(set(internal))
        external = list(set(external))

        js_files = [urljoin(response.url, s)
                    for s in response.css("script::attr(src)").getall() if s]

        forms = []
        for form in response.css("form"):
            forms.append({
                "action": form.attrib.get("action", ""),
                "method": form.attrib.get("method", "GET").upper(),
                "inputs": [
                    {"name": i.attrib.get("name"), "type": i.attrib.get("type", "text")}
                    for i in form.css("input")
                ],
            })
        if forms:
            log("📋", Y, "Form found", f"{len(forms)} form(s) at {response.url}")

        tech = self._fingerprint(text, headers)
        if tech:
            log("🛠", C, "Tech detected", ", ".join(tech))

        sec = self._security_headers(headers)
        missing = [k for k, v in sec.items() if not v and k != "X-Powered-By"]
        if missing:
            log("🔓", Y, "Missing headers", ", ".join(missing))

        powered = sec.get("X-Powered-By")
        if powered:
            log("⚠", R, "X-Powered-By leak", powered)

        comments = [c.strip() for c in response.xpath("//comment()").getall() if len(c.strip()) > 5]
        ext_files = [
            urljoin(response.url, l) for l in raw_links
            if any(l.lower().endswith(e) for e in
                   [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".sql", ".bak"])
        ]

        self.results.append({
            "type": "page",
            "url": response.url,
            "status": response.status,
            "meta": {
                "title":        response.css("title::text").get("").strip(),
                "server":       response.headers.get("Server", b"").decode(),
                "content_type": response.headers.get("Content-Type", b"").decode(),
                "page_hash":    hashlib.md5(text.encode()).hexdigest(),
            },
            "emails":                emails,
            "forms":                 forms,
            "comments":              comments,
            "internal_links":        internal,
            "external_links":        external,
            "js_files":              js_files,
            "images":                response.css("img::attr(src)").getall(),
            "external_files":        ext_files,
            "detected_technologies": tech,
            "security_headers":      sec,
        })

        log("🌐", B, "Page crawled", f"[{response.status}] {response.url}")

        for lnk in internal:
            if lnk not in self.visited:
                yield response.follow(lnk, self.parse, errback=self.err)
        for js in js_files:
            yield scrapy.Request(js, callback=self.parse_js, errback=self.err)

    def parse_js(self, response):
        stats["js_files"] += 1
        url = response.url
        if any(kw in url.lower() for kw in SKIP_JS):
            return

        content = response.text
        rel_ep = list(set(re.findall(
            r'["\'`](/(?:api|v\d|graphql|rest|auth|admin|user)[^\s"\'`<>]{0,100})', content
        )))
        abs_ep = list(set(re.findall(r'https?://[^\s"\'`<>]{10,200}', content)))[:40]

        secrets = []
        for pattern, label in SECRET_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                val = m.group(0)
                line = content[:m.start()].count("\n") + 1
                secrets.append({"type": label, "match": val[:80], "line": line})
                stats["secrets"] += 1
                log("🔑", R, f"SECRET [{label}]", f"line {line} → {url}")

        if rel_ep:
            log("🔗", Y, "JS endpoints", f"{len(rel_ep)} found → {url}")

        sourcemap = re.findall(r'//# sourceMappingURL=(.+)', content)
        if sourcemap:
            log("🗺", C, "Source map leak", f"{sourcemap[0]}")

        self.results.append({
            "type":                 "js_analysis",
            "js_url":               url,
            "relative_endpoints":   rel_ep,
            "absolute_endpoints":   abs_ep,
            "possible_secrets":     secrets,
            "sourcemap_references": sourcemap,
            "size_bytes":           len(content.encode()),
        })

    def parse_robots(self, response):
        if response.status != 200:
            return
        disallowed = [d.strip() for d in re.findall(r"Disallow:\s*(.+)", response.text)]
        sitemaps   = [s.strip() for s in re.findall(r"Sitemap:\s*(.+)",   response.text)]
        log("🤖", G, "robots.txt", f"{len(disallowed)} disallowed paths found")
        for p in disallowed[:5]:
            log("  ↳", DIM, "", p)
        self.results.append({
            "type": "robots_txt",
            "disallowed_paths": disallowed,
            "sitemap_refs": sitemaps,
            "raw": response.text,
        })

    def parse_sitemap(self, response):
        if response.status != 200:
            return
        urls = re.findall(r"<loc>(.*?)</loc>", response.text)
        log("🗺", G, "sitemap.xml", f"{len(urls)} URLs found")
        self.results.append({"type": "sitemap", "sitemap_urls": urls, "total_urls": len(urls)})

    def parse_probe(self, response):
        path = response.meta.get("path", "")
        if response.status not in (403, 404, 410):
            stats["open_paths"] += 1
            log("🚪", R, "OPEN PATH", f"[{response.status}] {self.start_url}{path}")
            self.results.append({
                "type": "interesting_path",
                "url": response.url,
                "path": path,
                "status": response.status,
            })

    def _fingerprint(self, html, headers):
        flat = html + " ".join(
            v.decode() if isinstance(v, (bytes, bytearray)) else str(v)
            for vals in headers.values()
            for v in (vals if isinstance(vals, list) else [vals])
        )
        return [t for t, pats in TECH_FINGERPRINTS.items()
                if any(re.search(p, flat, re.IGNORECASE) for p in pats)]

    def _security_headers(self, headers):
        def h(name):
            val = headers.get(name.encode(), [b""])[0]
            return val.decode() if val else None
        return {
            "Content-Security-Policy":   h("Content-Security-Policy"),
            "X-Frame-Options":           h("X-Frame-Options"),
            "X-Content-Type-Options":    h("X-Content-Type-Options"),
            "Strict-Transport-Security": h("Strict-Transport-Security"),
            "Referrer-Policy":           h("Referrer-Policy"),
            "X-Powered-By":              h("X-Powered-By"),
        }

    def err(self, failure):
        pass

    def closed(self, reason):
        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print(f"""
\033[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
\033[92m  ✅  Scan complete!\033[0m
\033[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
  Pages crawled   : \033[97m{stats['pages']}\033[0m
  JS files parsed : \033[97m{stats['js_files']}\033[0m
  Emails found    : \033[97m{stats['emails']}\033[0m
  Open paths      : \033[91m{stats['open_paths']}\033[0m
  Secrets found   : \033[91m{stats['secrets']}\033[0m
  Output saved to : \033[92m{self.output_file}\033[0m
\033[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
""")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"\n\033[91mUsage: python3 recon.py <url> <output.json>\033[0m\n")
        print(f"  Example: \033[92mpython3 recon.py https://target.com results.json\033[0m\n")
        sys.exit(1)

    target_url  = sys.argv[1]
    output_file = sys.argv[2]

    banner()
    log("🎯", G, "Target", target_url)
    log("💾", G, "Output", output_file)
    print()

    process = CrawlerProcess(settings={"LOG_ENABLED": False})
    process.crawl(ReconSpider, start_url=target_url, output_file=output_file)
    process.start()
