import html as html_lib
import os
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from scrapling.fetchers import Fetcher, StealthyFetcher

app = FastAPI()

API_KEY = os.environ.get("ANALYZER_API_KEY", "")


class AnalyzeRequest(BaseModel):
    url: str


def parse_count(s: str) -> int:
    s = s.strip().lower()
    mult = 1
    if s.endswith("k"):
        mult = 1_000
        s = s[:-1]
    elif s.endswith("m"):
        mult = 1_000_000
        s = s[:-1]
    s = s.replace(",", "")  # thousands separator, not decimal
    try:
        return int(float(s) * mult)
    except ValueError:
        return 0


def ssl_cert_invalid(url: str) -> bool:
    """True only if we can positively confirm a broken certificate.

    The stealth browser accepts invalid/expired certificates silently (so it
    can still render pages behind quirky TLS setups), which would otherwise
    hide a real SSL problem from us - so we check it independently here.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                pass
        return False
    except ssl.SSLCertVerificationError:
        return True
    except Exception:
        return False  # inconclusive (DNS/timeout/etc.) - let the real fetch surface it


def classify_fetch_error(exc: Exception) -> str:
    msg = str(exc)
    status_match = re.match(r"^(\d{3})\s*status code", msg)
    if status_match:
        code = status_match.group(1)
        if code == "404":
            return "Seite nicht gefunden (404-Fehler)"
        if code == "403":
            return "Zugriff verweigert (blockiert Besucher/Crawler)"
        if code.startswith("5"):
            return "Server-Fehler / Seite vorübergehend down"
        return f"Seite antwortet mit Fehlercode {code}"
    if re.search(r"ENOTFOUND|getaddrinfo|Name or service not known|could not resolve|ERR_NAME_NOT_RESOLVED", msg, re.I):
        return "Domain existiert nicht mehr (DNS-Fehler)"
    if re.search(r"certificate|SSL|CERT_HAS_EXPIRED|self[- ]signed|unable to verify|ERR_CERT", msg, re.I):
        return "SSL-Zertifikat ungültig oder abgelaufen"
    if re.search(r"timeout|timed out", msg, re.I):
        return "Zeitüberschreitung beim Laden der Seite"
    if re.search(r"ECONNREFUSED|connection refused|ERR_CONNECTION_REFUSED", msg, re.I):
        return "Verbindung zum Server verweigert"
    return "Webseite nicht erreichbar / defekt"


def analyze_html(html: str, url: str, metrics: dict) -> dict:
    issues = []
    suggestions = []

    is_https = url.lower().startswith("https://")
    if not is_https:
        issues.append("keine verschlüsselte Verbindung (HTTPS)")
        suggestions.append("HTTPS/SSL-Zertifikat einrichten, damit Besucher:innen und Google der Seite vertrauen")

    has_viewport = bool(re.search(r"<meta[^>]+viewport", html, re.I))
    mobile_overflow = metrics.get("mobile_overflow")
    if mobile_overflow or (not has_viewport and mobile_overflow is not False):
        issues.append("Inhalte passen nicht sauber auf ein Handy-Display (Layout bricht mobil)")
        suggestions.append("Responsive Design für Smartphones/Tablets nachrüsten")

    broken_images = metrics.get("broken_images") or 0
    if broken_images > 0:
        issues.append(f"{broken_images} defekte(s) Bild(er) auf der Seite")
        suggestions.append("Fehlende/kaputte Bilder ersetzen oder entfernen")

    console_errors = metrics.get("console_errors") or 0
    if console_errors >= 5:
        issues.append("zahlreiche technische Fehler beim Laden der Seite (JavaScript-Fehler)")
        suggestions.append("Technische Fehler auf der Seite beheben lassen")

    load_time_ms = metrics.get("load_time_ms")
    if load_time_ms and load_time_ms > 6000:
        issues.append("Seite lädt sehr langsam (mehrere Sekunden)")
        suggestions.append("Ladezeit optimieren (Bilder komprimieren, Hosting prüfen)")

    has_old_tags = bool(re.search(r"<marquee|<frameset|<font[\s>]", html, re.I))
    if has_old_tags:
        issues.append("technisch veraltetes Layout (alte HTML-Tags)")
        suggestions.append("Technischen Unterbau modernisieren (kein Table-/Frame-Layout mehr)")

    current_year_for_filter = datetime.now().year
    years = [int(y) for y in re.findall(r"(?:19|20)\d{2}", html)]
    years = [y for y in years if 1995 <= y <= current_year_for_filter]
    max_year = max(years) if years else None
    current_year = datetime.now().year
    if max_year and (current_year - max_year) >= 4:
        issues.append(f"zuletzt aktualisiert vor ca. {current_year - max_year} Jahren")
        suggestions.append("Inhalte und Design auf aktuellen Stand bringen")

    if len(html) < 1500:
        issues.append("sehr rudimentäre / kaum ausgebaute Seite")
        suggestions.append("Seite inhaltlich ausbauen (Leistungen, Kontakt, Über uns)")

    has_impressum = bool(re.search(r"impressum", html, re.I))
    if not has_impressum:
        issues.append("kein erkennbares Impressum verlinkt")
        suggestions.append("Rechtssicheres Impressum ergänzen (in Deutschland Pflicht)")

    has_contact_form = bool(re.search(r"<form", html, re.I))
    has_phone_or_email = bool(re.search(r"tel:|mailto:|@[a-z0-9.-]+\.[a-z]{2,}", html, re.I))
    if not has_contact_form and not has_phone_or_email:
        issues.append("keine klar erkennbare Kontaktmöglichkeit")
        suggestions.append("Kontaktformular oder gut sichtbare Telefonnummer/E-Mail ergänzen")

    has_cta = bool(re.search(r"jetzt anfragen|termin|kontaktieren|buchen|bestellen|angebot", html, re.I))
    if not has_cta:
        suggestions.append("Klare Handlungsaufforderung (Call-to-Action) ergänzen, z.B. 'Jetzt Termin anfragen'")

    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    title = title_match.group(1).strip() if title_match else ""
    if not title or len(title) < 5:
        issues.append("fehlender oder zu kurzer Seitentitel (schlecht für Google)")
        suggestions.append("Aussagekräftigen Seitentitel für SEO ergänzen")

    return {
        "issues": issues,
        "suggestions": suggestions,
        "title": title,
        "htmlLength": len(html),
    }


@app.post("/analyze")
def analyze(req: AnalyzeRequest, x_api_key: str = Header(default="")):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    url = req.url

    if ssl_cert_invalid(url):
        return {"ok": False, "reason": "SSL-Zertifikat ungültig oder abgelaufen", "usedBrowser": False}

    html = ""
    fetch_error = None
    metrics = {"mobile_overflow": None, "broken_images": None, "console_errors": 0, "load_time_ms": None}

    def page_setup(page):
        def on_console(msg):
            if msg.type == "error":
                metrics["console_errors"] += 1
        page.on("console", on_console)
        return page

    def page_action(page):
        try:
            timing = page.evaluate(
                "JSON.stringify(performance.getEntriesByType('navigation')[0] || {})"
            )
            import json as _json
            nav = _json.loads(timing)
            if nav.get("loadEventEnd") and nav.get("startTime") is not None:
                metrics["load_time_ms"] = int(nav["loadEventEnd"] - nav["startTime"])
        except Exception:
            pass
        try:
            page.set_viewport_size({"width": 375, "height": 812})
            page.wait_for_timeout(500)
            metrics["mobile_overflow"] = page.evaluate(
                "document.documentElement.scrollWidth > window.innerWidth + 20"
            )
            metrics["broken_images"] = page.evaluate(
                "Array.from(document.images).filter(img => img.complete && img.naturalWidth === 0).length"
            )
        except Exception:
            pass
        return page

    # Always render with a real headless browser so we see the page the way an
    # actual visitor (and their phone) would - a raw HTTP fetch misses anything
    # JS-rendered and can't tell us whether the layout actually breaks on mobile.
    try:
        page = StealthyFetcher.fetch(
            url,
            headless=True,
            timeout=45000,
            network_idle=True,
            page_setup=page_setup,
            page_action=page_action,
        )
        if page.status and 200 <= page.status < 400:
            html = page.body if isinstance(page.body, str) else str(page.body)
        else:
            fetch_error = f"{page.status} status code"
    except Exception as e:
        fetch_error = str(e)

    if not html or len(html) < 200:
        print(f"[analyze] fetch failed for {url}: {fetch_error}", flush=True)
        reason = classify_fetch_error(Exception(fetch_error or "empty response"))
        return {
            "ok": False,
            "reason": reason,
            "usedBrowser": True,
            "debug": (fetch_error or "")[:300],
        }

    result = analyze_html(html, url, metrics)
    result["ok"] = True
    result["usedBrowser"] = True
    result["loadTimeMs"] = metrics["load_time_ms"]
    return result


@app.post("/analyze-instagram")
def analyze_instagram(req: AnalyzeRequest, x_api_key: str = Header(default="")):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    url = req.url.rstrip("/")
    handle_match = re.search(r"instagram\.com/([A-Za-z0-9._]+)", url)
    handle = handle_match.group(1) if handle_match else ""

    html = ""
    try:
        page = Fetcher.get(url, stealthy_headers=True, timeout=15)
        if page.status and 200 <= page.status < 400:
            html = page.body if isinstance(page.body, str) else str(page.body)
    except Exception:
        html = ""

    if not html or len(html) < 200:
        try:
            page = StealthyFetcher.fetch(url, headless=True, timeout=25000)
            if page.status and 200 <= page.status < 400:
                html = page.body if isinstance(page.body, str) else str(page.body)
        except Exception:
            html = ""

    if not html or len(html) < 200:
        return {"ok": False, "handle": handle}

    # Instagram exposes basic public stats via its link-preview meta tags
    # (the same data WhatsApp/Slack show when you paste a profile link) -
    # this reads only that public preview data, not authenticated content.
    desc_match = re.search(r'<meta[^>]+property="og:description"[^>]+content="([^"]*)"', html, re.I)
    if not desc_match:
        desc_match = re.search(r'<meta[^>]+content="([^"]*)"[^>]+property="og:description"', html, re.I)
    description = html_lib.unescape(desc_match.group(1)) if desc_match else ""

    followers = following = posts = None
    stats_match = re.search(
        r"([\d.,]+[kKmM]?)\s*Followers,\s*([\d.,]+[kKmM]?)\s*Following,\s*([\d.,]+[kKmM]?)\s*Posts",
        description,
    )
    if stats_match:
        followers = parse_count(stats_match.group(1))
        following = parse_count(stats_match.group(2))
        posts = parse_count(stats_match.group(3))

    bio = ""
    bio_match = re.search(r"Posts?\s*-\s*(?:See Instagram photos and videos from )?(.*?)(?:\(@|$)", description)
    if bio_match:
        bio = bio_match.group(1).strip(" -")
        if bio.startswith("@"):
            bio = ""

    if followers is None and posts is None:
        return {"ok": False, "handle": handle}

    return {
        "ok": True,
        "handle": handle,
        "followers": followers,
        "following": following,
        "posts": posts,
        "bio": bio,
    }


@app.get("/health")
def health():
    return {"status": "ok"}
