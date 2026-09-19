import html as html_lib
import os
import re
from datetime import datetime

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
    if re.search(r"ENOTFOUND|getaddrinfo|Name or service not known|could not resolve", msg, re.I):
        return "Domain existiert nicht mehr (DNS-Fehler)"
    if re.search(r"certificate|SSL|CERT_HAS_EXPIRED|self[- ]signed|unable to verify", msg, re.I):
        return "SSL-Zertifikat ungültig oder abgelaufen"
    if re.search(r"timeout|timed out", msg, re.I):
        return "Zeitüberschreitung beim Laden der Seite"
    if re.search(r"ECONNREFUSED|connection refused", msg, re.I):
        return "Verbindung zum Server verweigert"
    return "Webseite nicht erreichbar / defekt"


def analyze_html(html: str, url: str) -> dict:
    issues = []
    suggestions = []

    is_https = url.lower().startswith("https://")
    if not is_https:
        issues.append("keine verschlüsselte Verbindung (HTTPS)")
        suggestions.append("HTTPS/SSL-Zertifikat einrichten, damit Besucher:innen und Google der Seite vertrauen")

    has_viewport = bool(re.search(r"<meta[^>]+viewport", html, re.I))
    if not has_viewport:
        issues.append("keine mobile Optimierung")
        suggestions.append("Responsive Design für Smartphones/Tablets nachrüsten")

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
    html = ""
    fetch_error = None
    used_browser = False

    try:
        page = Fetcher.get(url, stealthy_headers=True, timeout=20)
        if page.status and 200 <= page.status < 400:
            html = page.body if isinstance(page.body, str) else str(page.body)
        else:
            fetch_error = f"{page.status} status code"
    except Exception as e:
        fetch_error = str(e)

    # A conclusive, page-level or network-level failure (expired cert, dead domain,
    # real 404) won't be fixed by rendering with a real browser - only retry with
    # the heavier browser fallback for likely bot-blocking scenarios (403, empty
    # response, generic connection hiccups).
    first_reason = classify_fetch_error(Exception(fetch_error)) if fetch_error else None
    conclusive_reasons = {
        "Domain existiert nicht mehr (DNS-Fehler)",
        "SSL-Zertifikat ungültig oder abgelaufen",
        "Seite nicht gefunden (404-Fehler)",
    }
    should_try_browser = (not html or len(html) < 200) and first_reason not in conclusive_reasons

    if should_try_browser:
        try:
            page = StealthyFetcher.fetch(url, headless=True, timeout=30000)
            used_browser = True
            if page.status and 200 <= page.status < 400:
                html = page.body if isinstance(page.body, str) else str(page.body)
                fetch_error = None
            else:
                fetch_error = fetch_error or f"{page.status} status code"
        except Exception as e:
            # keep the original (often more informative) error if we had one
            if not fetch_error:
                fetch_error = str(e)

    if not html or len(html) < 200:
        reason = classify_fetch_error(Exception(fetch_error or "empty response"))
        return {
            "ok": False,
            "reason": reason,
            "usedBrowser": used_browser,
        }

    result = analyze_html(html, url)
    result["ok"] = True
    result["usedBrowser"] = used_browser
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
    description = desc_match.group(1) if desc_match else ""

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
        bio = html_lib.unescape(bio_match.group(1).strip(" -"))
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
