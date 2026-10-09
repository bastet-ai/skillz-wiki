#!/usr/bin/env python3
"""Manual, read-only public HTTPS verification. Never deploys or uses secrets."""
import argparse
import json
from html.parser import HTMLParser
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urljoin, urlsplit
import xml.etree.ElementTree as ET

CUSTOM = "https://skillz.wiki/"
WORKER = "https://skillz-wiki.bcrt43.workers.dev/"
WIKIS = (
    "skillz.wiki", "threat.wiki", "targets.bastet.ai", "deanpierce.net",
    "luminism.net", "opensling.org", "pdxhf.org", "person.actor",
    "sloppy.wiki", "tinyfarm.io", "titor.tech",
)
HOSTS = {"skillz.wiki", "skillz-wiki.bcrt43.workers.dev"}


def allowed(url):
    parts = urlsplit(url)
    return (parts.scheme == "https" and parts.hostname in HOSTS
            and parts.port in (None, 443) and not parts.username and not parts.password)


def require(condition, label):
    if not condition:
        raise RuntimeError(label)
    print("PASS " + label, flush=True)


def fetch(url, label, expected=200):
    if not allowed(url):
        raise RuntimeError("rejected URL outside the two hardcoded public HTTPS hosts")
    with tempfile.TemporaryDirectory() as directory:
        body = Path(directory) / "response"
        result = subprocess.run([
            "curl", "--disable", "--silent", "--show-error", "--proto", "=https",
            "--connect-timeout", "8", "--max-time", "20", "--max-redirs", "0",
            "--max-filesize", "25165824", "--output", str(body),
            "--write-out", "%{http_code} %{ssl_verify_result} %{content_type}", url,
        ], capture_output=True, text=True, timeout=23)
        fields = result.stdout.split(maxsplit=2)
        status, verified = fields[:2] if len(fields) >= 2 else ("unknown", "unknown")
        if result.returncode or status != str(expected) or verified != "0":
            raise RuntimeError(f"{label}: curl_exit={result.returncode} HTTP={status} TLS_verify={verified}")
        print(f"PASS {label}: HTTP={status} TLS_verify=0", flush=True)
        return body.read_bytes(), fields[2].strip() if len(fields) > 2 else ""


def verify_https_redirect(host):
    if host not in WIKIS:
        raise RuntimeError("rejected host outside the hardcoded wiki list")
    result = subprocess.run([
        "curl", "--disable", "--silent", "--show-error", "--proto", "=http",
        "--connect-timeout", "8", "--max-time", "20", "--max-redirs", "0",
        "--max-filesize", "25165824", "--output", "/dev/null",
        "--write-out", "%{http_code} %{redirect_url}", "http://" + host + "/",
    ], capture_output=True, text=True, timeout=23)
    fields = result.stdout.split(maxsplit=1)
    status = fields[0] if fields else "unknown"
    target = fields[1].strip() if len(fields) > 1 else ""
    if (result.returncode or status not in {"301", "302", "307", "308"}
            or target != "https://" + host + "/"):
        raise RuntimeError(f"{host} HTTP-to-HTTPS redirect: curl_exit={result.returncode} HTTP={status}")
    print(f"PASS {host} HTTP-to-HTTPS redirect: HTTP={status}", flush=True)


class Page(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.canonical, self.styles = [], []
        self.feed(body.decode("utf-8"))

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "link" and attrs.get("href"):
            rel = (attrs.get("rel") or "").split()
            if "canonical" in rel:
                self.canonical.append(attrs["href"])
            if "stylesheet" in rel:
                self.styles.append(attrs["href"])


def main(scope="skillz"):
    if scope not in {"skillz", "all-wikis"}:
        raise RuntimeError("rejected verification scope")
    if scope == "all-wikis":
        HOSTS.update(WIKIS)
    worker, _ = fetch(WORKER, "workers.dev HTTPS comparison")
    require(b"Skillz Wiki" in worker, "Worker homepage content")
    home, _ = fetch(CUSTOM, "custom hostname HTTPS homepage")
    require(b"Skillz Wiki" in home, "homepage content")
    page = Page(home)
    require(page.canonical == [CUSTOM], "homepage canonical")
    article, _ = fetch(urljoin(CUSTOM, "skills/httpx/"), "HTTPS representative article")
    require(Page(article).canonical == [urljoin(CUSTOM, "skills/httpx/")], "article canonical")
    style = next((urljoin(CUSTOM, path) for path in page.styles
                  if allowed(urljoin(CUSTOM, path))), None)
    require(style is not None, "allowed stylesheet link")
    css, content_type = fetch(style, "HTTPS linked CSS")
    require(bool(css) and "text/css" in content_type, "stylesheet response type")
    search, _ = fetch(urljoin(CUSTOM, "search/search_index.json"), "HTTPS search index")
    docs = json.loads(search).get("docs", [])
    require(isinstance(docs, list) and len(docs) > 100
            and any(item.get("location", "").split("#")[0] == "skills/httpx/" for item in docs),
            "populated search with representative article")
    feed, _ = fetch(urljoin(CUSTOM, "feed.xml"), "HTTPS RSS")
    require(ET.fromstring(feed).tag.split("}")[-1] == "rss" and CUSTOM.encode() in feed,
            "valid feed with canonical host")
    missing, _ = fetch(urljoin(CUSTOM, "cloudflare-migration-missing-page/"), "HTTPS real 404", 404)
    require(b"404" in missing, "404 page content")
    verify_https_redirect("skillz.wiki")
    if scope == "all-wikis":
        for host in WIKIS[1:]:
            fetch("https://" + host + "/", host + " HTTPS homepage")
            verify_https_redirect(host)
    print("PASS independent HTTPS checks; deployed commit identity must be verified separately", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("skillz", "all-wikis"), default="skillz")
    args = parser.parse_args()
    try:
        main(args.scope)
    except Exception as error:
        # Public status labels only; do not emit response bodies, headers or curl stderr.
        print("FAIL " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), flush=True)
        raise SystemExit(1)
