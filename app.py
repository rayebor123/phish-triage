"""
Streamlit front end.

SAFETY: the email body is rendered with st.code / st.text only.
Never use st.markdown(..., unsafe_allow_html=True) on message content — that
executes the phishing page's HTML and JavaScript in your own browser and loads
its remote tracking pixels.
"""

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from email_parser import defang, parse_email  # noqa: E402
from enrich import enrich  # noqa: E402
from verdict import get_verdict  # noqa: E402

st.set_page_config(page_title="Phishing Triage", page_icon="🛡", layout="wide")

VERDICT_STYLE = {
    "malicious": ("🔴", "#b00020"),
    "suspicious": ("🟠", "#c77700"),
    "benign": ("🟢", "#1a7f37"),
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# AbuseIPDB confidence at or above this is shown as a detection. Below it, a
# non-zero score is shown as low-confidence -- large mail providers' shared
# outbound relays routinely carry small scores from their abusive users.
ABUSE_DETECTION_SCORE = 50

# Model output and header-derived findings can contain attacker-chosen text
# (the model quotes the body). Streamlit renders markdown in st.write,
# st.markdown, st.caption and st.info, which would turn a quoted
# [link](http://...) or a bare address into something clickable. Everything
# that isn't our own fixed markup goes through st.text instead.

st.title("🛡 Phishing Triage")
st.caption(
    "Upload a raw email. Deterministic checks gather the evidence; "
    "the model synthesizes an analyst-ready verdict."
)

uploaded = st.file_uploader("Raw email (.eml)", type=["eml", "txt"])

if uploaded is not None:
    raw = uploaded.read()

    with st.spinner("Parsing message…"):
        parsed = parse_email(raw)

    with st.spinner("Checking reputation…"):
        enrichment = enrich(parsed)

    with st.spinner("Synthesizing verdict…"):
        try:
            result = get_verdict(parsed, enrichment)
        except Exception as exc:  # keep the demo alive if the API hiccups
            st.error(f"Verdict step failed: {exc}")
            result = None

    if result:
        icon, color = VERDICT_STYLE.get(result["verdict"], ("⚪", "#555"))
        st.markdown(
            f"<div style='padding:1rem 1.25rem;border-radius:.5rem;"
            f"background:{color};color:#fff;'>"
            f"<span style='font-size:1.6rem;font-weight:700;'>"
            f"{icon} {result['verdict'].upper()}</span>"
            f"<span style='float:right;font-size:1.1rem;opacity:.9;'>"
            f"confidence {result['confidence']}%</span></div>",
            unsafe_allow_html=True,  # our own trusted markup, never email content
        )
        st.write("")
        st.subheader("Assessment")
        st.text(result["summary"])
        st.markdown("**Recommended action**")
        st.text(result["recommended_action"])

        st.subheader("Indicators")
        for ind in sorted(
            result["indicators"], key=lambda i: SEVERITY_ORDER.get(i["severity"], 3)
        ):
            badge = {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(ind["severity"], "⚪")
            st.text(f"{badge} {ind['indicator']}\n    {ind['evidence']}")

    st.divider()
    left, right = st.columns(2)

    with left:
        st.subheader("Message metadata")
        st.write(
            {
                "Subject": parsed["subject"],
                "Display name": parsed["from_name"] or "—",
                "From": parsed["from_addr"] or "—",
                "Reply-To": parsed["reply_to"] or "—",
                "Return-Path": parsed["return_path"] or "—",
                "Date": parsed["date"] or "—",
            }
        )

        st.subheader("Authentication")
        a = parsed["auth"]
        cols = st.columns(3)
        for col, mech in zip(cols, ("spf", "dkim", "dmarc")):
            state = a[mech]
            mark = "✅" if state == "pass" else ("❌" if state in ("fail", "softfail") else "⚠️")
            col.metric(mech.upper(), f"{mark} {state}")

        st.subheader("Deterministic findings")
        if parsed["header_findings"]:
            for f in parsed["header_findings"]:
                st.text(f"• {f}")
        else:
            st.caption("No header anomalies detected.")

    with right:
        st.subheader("Indicators extracted")
        if parsed["links"]:
            st.caption("URLs (defanged — safe to read, not clickable)")
            for link in parsed["links"][:15]:
                flag = " ⚠️ anchor text mismatch" if link["mismatch"] else ""
                st.code(defang(link["url"]) + flag, language=None)
        if parsed["ips"]:
            st.caption("Routing IPs")
            st.code("\n".join(defang(ip) for ip in parsed["ips"][:8]), language=None)
        if parsed["attachments"]:
            st.caption("Attachments (hashed in memory, never written to disk)")
            for att in parsed["attachments"]:
                st.code(f"{att['filename']}  {att['sha256'][:32]}…", language=None)

        st.subheader("Threat intelligence")

        def _threat_tier(e):
            if e["status"] in ("unavailable", "rate_limited"):
                return 3  # lookup failed or was skipped
            if e["status"] != "ok":
                return 2  # not_found
            # enrich.py already separates real VirusTotal detections from
            # stray-vendor noise via the "detection" flag -- respect it.
            if e.get("detection") or e.get("score", 0) >= ABUSE_DETECTION_SCORE:
                return 0  # real detection
            if e.get("malicious") or e.get("suspicious") or e.get("score"):
                return 1  # low-confidence signal
            return 2  # clean

        for e in sorted(enrichment, key=_threat_tier):
            label = f"{e['source']} · {defang(e['indicator'])} — {e['status']}: {e['detail']}"
            tier = _threat_tier(e)
            if tier == 0:
                st.error(label, icon="🔴")
            elif tier == 1:
                st.warning(label, icon="🟡")
            else:
                st.text(label)

    with st.expander("Raw body excerpt (inert text — never rendered as HTML)"):
        st.text(parsed["text_body"] or "(no plain-text body)")
else:
    st.info("Upload a .eml file to begin. In Gmail: ⋮ → Show original → Download Original.")
