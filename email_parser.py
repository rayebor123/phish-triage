"""
Parse .eml files and extract triage signals.

Safety properties of this module:
  - never renders HTML
  - never fetches any URL found in the message
  - never writes attachment bytes to disk (hashes them in memory only)
"""

import email
import hashlib
import ipaddress
import re
from email import policy
from email.utils import getaddresses, parseaddr
from urllib.parse import urlparse

from bs4 import BeautifulSoup

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.I)

PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "0.", "172.16.", "172.17.")

# Reputation lookups on these are worthless -- they're shared infrastructure,
# not the actual destination -- so they shouldn't consume lookup budget.
SHORTENERS = frozenset({
    "t.co", "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cutt.ly", "rebrand.ly", "short.link", "rb.gy", "lnkd.in",
})

# Consumer webmail. Legitimate brand notifications never route replies here.
FREE_WEBMAIL = frozenset({
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.de", "gmx.net", "mail.ru",
})

MAILTO_RE = re.compile(r"mailto:([^\s\"'<>]+)", re.I)

try:
    import tldextract
except ImportError:
    tldextract = None

# Common CSS vocabulary, used to separate real stylesheet tokens from filler
# dictionary words stuffed into <style> blocks / hidden elements to defeat
# hash-based and Bayesian spam filters ("hashbusting").
_CSS_KEYWORDS = frozenset({
    "color", "background", "display", "none", "visibility", "hidden", "width",
    "height", "font", "family", "size", "weight", "margin", "padding", "border",
    "solid", "dashed", "dotted", "double", "block", "inline", "absolute",
    "relative", "fixed", "sticky", "position", "top", "left", "right", "bottom",
    "auto", "rgba", "rgb", "important", "normal", "bold", "italic", "underline",
    "text", "align", "center", "justify", "overflow", "float", "clear",
    "content", "before", "after", "hover", "active", "focus", "transition",
    "transform", "opacity", "index", "line", "letter", "spacing", "decoration",
    "cursor", "pointer", "shadow", "radius", "outline", "min", "max", "flex",
    "grid", "table", "cell", "row", "column", "white", "space", "nowrap",
    "wrap", "break", "word", "vertical", "horizontal", "media", "screen",
    "print", "inherit", "initial", "unset", "calc", "var", "not", "and", "only",
    "style", "class", "div", "span", "body", "html", "webkit", "moz", "sans",
    "serif", "arial", "helvetica", "verdana", "tahoma", "georgia", "times",
    "padding", "box", "sizing", "border", "collapse", "vertical", "middle",
})

_CSS_IDENT_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
_HEX_COLOR_RE = re.compile(r"#[0-9a-fA-F]{3,8}\b")

# Brands most often impersonated, mapped to the domains they legitimately send
# from. Matching on the legitimate domain rather than a substring is what
# catches lookalikes such as paypal-secure-login.ru, which would slip past a
# naive "is 'paypal' in the domain" check.
BRANDS = {
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com"),
    "office365": ("microsoft.com", "office.com"),
    "outlook": ("microsoft.com", "outlook.com", "live.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.co.uk"),
    "netflix": ("netflix.com",),
    "google": ("google.com", "gmail.com", "googlemail.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "chase": ("chase.com",),
    "wells fargo": ("wellsfargo.com",),
    "bank of america": ("bankofamerica.com",),
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "linkedin": ("linkedin.com",),
    "facebook": ("facebook.com", "facebookmail.com"),
    "instagram": ("instagram.com",),
    "coinbase": ("coinbase.com",),
    "irs": ("irs.gov",),
    "usps": ("usps.com", "usps.gov"),
    "adobe": ("adobe.com",),
    "dropbox": ("dropbox.com",),
    "norton": ("norton.com", "nortonlifelock.com"),
    "mcafee": ("mcafee.com",),
}


def defang(value: str) -> str:
    """Make an indicator unclickable for safe display."""
    if not value:
        return value
    if "://" in value:
        parsed = urlparse(value)
        host = (parsed.netloc or "").replace(".", "[.]")
        scheme = parsed.scheme.replace("http", "hxxp")
        tail = value.split(parsed.netloc, 1)[1] if parsed.netloc and parsed.netloc in value else ""
        return f"{scheme}://{host}{tail}"
    return value.replace(".", "[.]")


def _extract_address(raw_header: str):
    """Recover (display_name, address, malformed) from a From/Reply-To/
    Return-Path header.

    parseaddr returns ('', '') on a header like
        Microsoft account team ,_<no-reply@access-accsecurity.com>
    because the unquoted comma in the display name makes RFC 5322 read it as
    an address LIST rather than a single mailbox -- a known parser-evasion
    technique. getaddresses() parses the same header as a list and still
    finds the real mailbox, so it's used to recover the address, taking the
    first entry that actually contains '@'.
    """
    if not raw_header:
        return "", "", False
    naive_name, naive_addr = parseaddr(raw_header)
    entries = getaddresses([raw_header])
    addr_idx = next((i for i, (_, addr) in enumerate(entries) if "@" in addr), None)
    malformed = len(entries) > 1 or (not naive_addr and addr_idx is not None)
    if addr_idx is None:
        return naive_name, naive_addr, malformed
    recovered_addr = entries[addr_idx][1]
    # An unquoted comma splits one display name into several address-list
    # entries. The name a recipient actually sees is still their
    # concatenation, so rebuild it from every fragment up to and including
    # the entry that carries the real mailbox.
    name_parts = []
    for name, addr in entries[: addr_idx + 1]:
        part = name if name else addr
        if part and "@" not in part:
            name_parts.append(part)
    recovered_name = " ".join(name_parts).strip()
    return recovered_name, recovered_addr, malformed


def _valid_ipv4(candidate: str) -> bool:
    """IP_RE matches any four dot-separated 1-3 digit runs, including things
    that aren't IPs at all -- a timestamp like 09.18.10.23 (09/18 10:23)
    matches just as well. Reject leading zeros (not a valid octet
    representation) before handing off to ipaddress for full validation."""
    octets = candidate.split(".")
    if len(octets) != 4 or any(len(o) > 1 and o[0] == "0" for o in octets):
        return False
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


_SPAM_HEADER_NAMES = ("X-Spam-Flag", "X-Spam-Status", "X-Spam-Level", "X-WP-SPAM")
_GENERIC_SPAM_HEADER_RE = re.compile(r"^X-.*-SPAM$", re.I)
_POSITIVE_SPAM_RE = re.compile(r"^\s*(yes|true|1|spam)\b", re.I)


def _spam_filter_findings(msg) -> list:
    """Surface an upstream provider's own spam determination -- if Gmail/
    Outlook/whatever already flagged this at the gateway, that's evidence
    independent of (and usually more informed than) anything derivable from
    the message alone."""
    findings = []
    checked = set()
    header_names = list(_SPAM_HEADER_NAMES)
    for name in msg.keys():
        if _GENERIC_SPAM_HEADER_RE.match(name) and name.lower() not in (h.lower() for h in header_names):
            header_names.append(name)

    for name in header_names:
        if name.lower() in checked:
            continue
        checked.add(name.lower())
        value = msg.get(name)
        if value is None:
            continue
        value = str(value).strip()
        if not value:
            continue

        lname = name.lower()
        if lname == "x-spam-level":
            # No embedded threshold in this header -- just a string of '*'
            # scaled to score. Require a handful before calling it positive,
            # matching the common default spam-flag threshold (~5).
            is_positive = value.count("*") >= 5
        else:
            is_positive = bool(_POSITIVE_SPAM_RE.match(value))

        if is_positive:
            findings.append(
                f"Upstream provider spam filter flagged this message ({name}: {value})"
            )
    return findings


def _registrable_domain(hostname: str) -> str:
    """Best-effort eTLD+1, e.g. scoutcamp.bounces.google.com -> google.com,
    so bulk-sender subdomains aren't flagged as a mismatch against the
    organisation's main domain. Uses tldextract (public-suffix-list aware)
    when installed, else falls back to a naive last-two-labels heuristic."""
    hostname = (hostname or "").lower().strip(".")
    if not hostname:
        return ""
    if tldextract is not None:
        ext = tldextract.extract(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    labels = hostname.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname


def _auth_results(msg) -> dict:
    """Pull SPF / DKIM / DMARC outcomes out of Authentication-Results."""
    raw = " ".join(msg.get_all("Authentication-Results", []) or [])
    raw += " " + " ".join(msg.get_all("ARC-Authentication-Results", []) or [])
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", raw, re.I)
        out[mech] = m.group(1).lower() if m else "none"
    return out


def _received_ips(msg) -> list:
    """Routing IPs feed AbuseIPDB lookups, so only Received headers -- never
    body text -- are scanned, and every match is validated as a real IPv4
    address before being trusted."""
    ips = []
    for hdr in msg.get_all("Received", []) or []:
        for ip in IP_RE.findall(hdr):
            if not _valid_ipv4(ip):
                continue
            if ip.startswith(PRIVATE_PREFIXES) or ip in ips:
                continue
            ips.append(ip)
    return ips


def _bodies(msg):
    text, html = "", ""
    warnings = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            try:
                content = payload.decode(charset, errors="replace")
            except (LookupError, TypeError, ValueError):
                try:
                    content = payload.decode("utf-8", errors="replace")
                except Exception:
                    warnings.append(
                        f"Could not decode {ctype} part (declared charset: {charset})"
                    )
                    continue
        if not isinstance(content, str):
            continue
        if ctype == "text/plain":
            text += content
        elif ctype == "text/html":
            html += content
    return text, html, warnings


def _label_mismatch(label: str, href: str) -> bool:
    """Anchor text claims one domain while the href points somewhere else."""
    m = DOMAIN_RE.search(label or "")
    if not m:
        return False
    claimed = m.group(0).lower().strip(".")
    actual = (urlparse(href).hostname or "").lower()
    if not actual:
        return False
    return not (actual == claimed or actual.endswith("." + claimed))


def _links(text_body: str, html_body: str) -> list:
    links, seen = [], set()
    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href.lower().startswith(("http://", "https://")) or href in seen:
                continue
            seen.add(href)
            label = a.get_text(strip=True)
            links.append({
                "url": href,
                "label": label,
                "mismatch": _label_mismatch(label, href),
            })
    for url in URL_RE.findall(text_body or ""):
        if url not in seen:
            seen.add(url)
            links.append({"url": url, "label": "", "mismatch": False})
    return links


def _mailto_links(text_body: str, html_body: str) -> list:
    """Reply-by-click addresses. Stripped of any ?subject=/&cc= query tail."""
    combined = f"{text_body or ''} {html_body or ''}"
    addrs = []
    for raw in MAILTO_RE.findall(combined):
        addr = raw.split("?", 1)[0].strip().rstrip(".,;:'\")>").lower()
        if addr and addr not in addrs:
            addrs.append(addr)
    return addrs


def _is_hidden_image(width, height, style) -> bool:
    style_l = (style or "").lower().replace(" ", "")
    if "visibility:hidden" in style_l or "display:none" in style_l:
        return True
    for dim in (width, height):
        if dim is None:
            continue
        if str(dim).strip().lower().rstrip("px") == "1":
            return True
    return False


def _images(html_body: str) -> list:
    if not html_body:
        return []
    soup = BeautifulSoup(html_body, "html.parser")
    out = []
    for img in soup.find_all("img"):
        src = (img.get("src") or "").strip()
        if not src:
            continue
        width, height, style = img.get("width"), img.get("height"), img.get("style") or ""
        out.append({
            "src": src,
            "width": width,
            "height": height,
            "style": style,
            "hidden": _is_hidden_image(width, height, style),
        })
    return out


def _strip_declaration_blocks(css_text: str) -> str:
    """Remove {...} declaration blocks (iteratively, so nested @media rule
    blocks are fully unwrapped too), leaving only selector lists, at-rule
    preludes and comments. Real property:value pairs always live inside
    braces, so this is where hashbusting filler words get stuffed instead --
    e.g. a bogus comma-separated "selector" list that's never applied."""
    prev, text = None, css_text
    while text != prev:
        prev = text
        text = re.sub(r"\{[^{}]*\}", " ", text)
    return text


def _hashbust_word_count(html_body: str) -> int:
    """Count filler dictionary words hidden OUTSIDE valid CSS declaration
    syntax -- in <style> selector lists/comments, or in elements hidden via
    visibility:hidden/display:none -- stuffed in to defeat hash-based and
    Bayesian spam filters. Tokens that look like real CSS (hex colors, units,
    property/value keywords, class/id names carrying digits, hyphens or
    underscores) are excluded rather than guessed at by dictionary lookup."""
    if not html_body:
        return 0
    soup = BeautifulSoup(html_body, "html.parser")
    chunks = [_strip_declaration_blocks(tag.get_text()) for tag in soup.find_all("style")]
    for el in soup.find_all(style=True):
        style_l = (el.get("style") or "").lower().replace(" ", "")
        if "visibility:hidden" in style_l or "display:none" in style_l:
            chunks.append(el.get_text(" "))
    blob = _HEX_COLOR_RE.sub(" ", " ".join(chunks))
    count = 0
    for token in _CSS_IDENT_RE.findall(blob):
        if len(token) < 4:
            continue
        if any(c.isdigit() or c in "-_" for c in token):
            continue
        if token.lower() in _CSS_KEYWORDS:
            continue
        count += 1
    return count


def _attachments(msg) -> list:
    """Hash attachments in memory. Nothing is ever written to disk."""
    out = []
    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        out.append({
            "filename": part.get_filename() or "(unnamed)",
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    return out


def parse_email(raw: bytes) -> dict:
    msg = email.message_from_bytes(raw, policy=policy.default)

    from_name, from_addr, from_malformed = _extract_address(msg.get("From", ""))
    _, reply_to, _ = _extract_address(msg.get("Reply-To", ""))
    _, return_path, _ = _extract_address(msg.get("Return-Path", ""))
    subject = msg.get("Subject", "(no subject)")

    # Last resort: if the From header is too mangled for getaddresses() to
    # recover anything at all, X-SID-PRA (Sender ID's Purported Responsible
    # Address) preserves the real sender independently of the From header.
    if "@" not in from_addr:
        sid_pra = msg.get("X-SID-PRA", "")
        if sid_pra:
            pra_name, pra_addr, _ = _extract_address(sid_pra)
            if "@" in pra_addr:
                from_name, from_addr = pra_name, pra_addr
                from_malformed = True

    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    text_body, html_body, parse_warnings = _bodies(msg)

    # HTML-only messages leave text_body empty; derive readable text from the
    # HTML so the model still gets body content, excluding style/script text.
    if not text_body and html_body:
        strip_soup = BeautifulSoup(html_body, "html.parser")
        for tag in strip_soup(["style", "script"]):
            tag.decompose()
        text_body = strip_soup.get_text(" ", strip=True)

    links = _links(text_body, html_body)
    mailto_links = _mailto_links(text_body, html_body)
    images = _images(html_body)
    auth = _auth_results(msg)

    # Body text can claim anything -- it's attacker-controlled lure content,
    # never routing telemetry. Keep it clearly separate from real Received IPs.
    claimed_ips = []
    ip_scan_text = text_body
    if html_body:
        try:
            ip_scan_text += " " + BeautifulSoup(html_body, "html.parser").get_text(" ", strip=True)
        except Exception:
            pass
    for ip in IP_RE.findall(ip_scan_text or ""):
        if _valid_ipv4(ip) and ip not in claimed_ips:
            claimed_ips.append(ip)

    findings = []

    # 1. Authentication outcomes
    for mech in ("spf", "dkim", "dmarc"):
        state = auth[mech]
        if state in ("fail", "softfail", "permerror", "temperror"):
            findings.append(f"{mech.upper()} {state} for sending domain {from_domain or 'unknown'}")
        elif state == "none":
            findings.append(f"No {mech.upper()} result present in Authentication-Results")

    # 1b. Malformed From header (address-list evasion trick)
    if from_malformed and "@" in from_addr:
        findings.append(
            "From header malformed (unquoted comma in display name), a known "
            f"parser-evasion technique — recovered sender: {from_addr}"
        )

    # 1c. Upstream provider already flagged this as spam
    findings.extend(_spam_filter_findings(msg))

    # 2. Display name impersonation
    haystack = f"{from_name} {subject}".lower()
    first_brand_match = None
    for brand, legit_domains in BRANDS.items():
        if brand not in haystack:
            continue
        if first_brand_match is None:
            first_brand_match = brand
        sends_legitimately = any(
            from_domain == d or from_domain.endswith("." + d) for d in legit_domains
        )
        if not sends_legitimately:
            findings.append(
                f"Message impersonates '{brand}' but was sent from "
                f"{from_domain or 'an unknown domain'} (legitimate: {legit_domains[0]})"
            )
            break
    claimed_domain = DOMAIN_RE.search(from_name or "")
    if claimed_domain:
        claimed = claimed_domain.group(0).lower()
        if from_domain and not from_domain.endswith(claimed):
            findings.append(f"Display name shows {claimed} but sender domain is {from_domain}")

    # 2b. Brand-impersonating display name but replies route to free webmail
    if first_brand_match:
        flagged_webmail_domains = set()
        for addr in mailto_links:
            mailto_domain = addr.split("@")[-1].lower()
            if mailto_domain in FREE_WEBMAIL and mailto_domain not in flagged_webmail_domains:
                flagged_webmail_domains.add(mailto_domain)
                findings.append(
                    f"Message impersonates '{first_brand_match}' but its mailto link "
                    f"routes replies to free webmail address {addr} — legitimate brand "
                    "notifications never route replies to consumer webmail"
                )

    # 3. Address inconsistencies -- compared by registrable domain so bulk-
    # sender subdomains (scoutcamp.bounces.google.com vs google.com) don't
    # false-positive as a mismatch.
    if reply_to and from_addr:
        reply_to_domain = reply_to.split("@")[-1].lower()
        if (
            reply_to_domain
            and from_domain
            and _registrable_domain(reply_to_domain) != _registrable_domain(from_domain)
        ):
            findings.append(f"Reply-To ({reply_to}) differs from From ({from_addr})")
    if return_path and from_domain:
        rp_domain = return_path.split("@")[-1].lower()
        if rp_domain and _registrable_domain(rp_domain) != _registrable_domain(from_domain):
            findings.append(f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain})")

    # 4. Link deception
    for link in links:
        if link["mismatch"]:
            findings.append(
                f"Link text reads '{link['label'][:40]}' but resolves to "
                f"{defang(urlparse(link['url']).hostname or '')}"
            )

    # 4b. URL shorteners obscure the real destination
    shortener_hosts = set()
    for link in links:
        host = (urlparse(link["url"]).hostname or "").lower()
        if host in SHORTENERS and host not in shortener_hosts:
            shortener_hosts.add(host)
            findings.append(
                f"Link routed through URL shortener {host}, obscuring the destination"
            )

    # 4c. Hidden tracking pixels
    tracking_hosts = set()
    for img in images:
        if not img["hidden"]:
            continue
        host = (urlparse(img["src"]).hostname or "").lower()
        if host and host not in tracking_hosts:
            tracking_hosts.add(host)
            findings.append(f"Tracking pixel beaconing to {host}")

    # 5. Risky attachments
    for att in _attachments(msg):
        if att["filename"].lower().endswith(
            (".exe", ".scr", ".js", ".vbs", ".jar", ".iso", ".html", ".htm", ".zip", ".rar")
        ):
            findings.append(f"Attachment with risky extension: {att['filename']}")

    # 6. Hashbusting / Bayesian-poisoning filler text
    hashbust_words = _hashbust_word_count(html_body)
    if hashbust_words > 150:
        findings.append(
            f"Message contains {hashbust_words} words of filler text hidden in "
            "CSS, consistent with hashbusting / Bayesian poisoning"
        )

    domains = []
    for link in links:
        host = (urlparse(link["url"]).hostname or "").lower()
        if host and host not in domains:
            domains.append(host)
    for host in tracking_hosts:
        if host not in domains:
            domains.append(host)
    if from_domain and from_domain not in domains:
        domains.insert(0, from_domain)

    return {
        "subject": subject,
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": from_domain,
        "reply_to": reply_to,
        "return_path": return_path,
        "date": msg.get("Date", ""),
        "auth": auth,
        "links": links,
        "mailto_links": mailto_links,
        "images": images,
        "domains": domains,
        "ips": _received_ips(msg),
        "claimed_ips": claimed_ips,
        "attachments": _attachments(msg),
        "text_body": (text_body or "")[:4000],
        "html_present": bool(html_body),
        "header_findings": findings,
        "parse_warnings": parse_warnings,
    }
