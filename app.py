"""
Streamlit front end.

SAFETY: the email body is rendered with st.code / st.text only.
Never use st.markdown(..., unsafe_allow_html=True) on message content — that
executes the phishing page's HTML and JavaScript in your own browser and loads
its remote tracking pixels. The one exception is the recommended-action callout
and indicator badges below, which run the model's text through html.escape()
before it ever reaches unsafe_allow_html=True -- any HTML/markdown syntax an
attacker got the model to echo renders as inert escaped text, never as markup.
"""

import html
import altair as alt
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

import storage  # noqa: E402
from email_parser import defang, parse_email  # noqa: E402
from enrich import enrich  # noqa: E402
from verdict import get_verdict  # noqa: E402

st.set_page_config(page_title="Phishing Triage", page_icon="🛡", layout="wide")
storage.init_db()

VERDICT_STYLE = {
    "malicious": ("🔴", "#b00020"),
    "suspicious": ("🟠", "#c77700"),
    "benign": ("🟢", "#1a7f37"),
}
VERDICT_COLOR_SCALE = alt.Scale(
    domain=["Malicious", "Suspicious", "Benign"], range=["#b00020", "#c77700", "#1a7f37"]
)
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SEVERITY_COLOR = {"high": "#b00020", "medium": "#c77700", "low": "#b8860b"}
SEVERITY_COLOR_SCALE = alt.Scale(domain=["high", "medium", "low"], range=["#b00020", "#c77700", "#b8860b"])
SEVERITY_BADGE = {"high": "🔴", "medium": "🟠", "low": "🟡"}

# AbuseIPDB confidence at or above this is shown as a detection. Below it, a
# non-zero score is shown as low-confidence -- large mail providers' shared
# outbound relays routinely carry small scores from their abusive users.
ABUSE_DETECTION_SCORE = 50

# Model output and header-derived findings can contain attacker-chosen text
# (the model quotes the body). Streamlit renders markdown in st.write,
# st.markdown, st.caption and st.info, which would turn a quoted
# [link](http://...) or a bare address into something clickable. Everything
# that isn't our own fixed markup goes through st.text instead.

# A Streamlit rerun re-executes this whole script on every widget interaction
# (e.g. editing a status cell in the Dashboard tab), not just the tab that
# changed. Caching each triage step means switching tabs or editing a status
# doesn't re-hit the paid Anthropic/threat-intel APIs or write duplicate
# history rows for the same upload.


@st.cache_data(show_spinner="Parsing message…")
def _parse(raw: bytes):
    return parse_email(raw)


@st.cache_data(show_spinner="Checking reputation…")
def _enrich(parsed: dict):
    return enrich(parsed)


@st.cache_data(show_spinner="Synthesizing verdict…")
def _verdict(parsed: dict, enrichment: list):
    return get_verdict(parsed, enrichment)


@st.cache_data(show_spinner=False)
def _save(filename: str, parsed: dict, result: dict):
    return storage.save_result(filename, parsed, result)


def _kpi_html(label: str, value: str, color: str) -> str:
    return (
        f"<div style='text-align:center;padding:.5rem 0;'>"
        f"<div style='font-size:2.1rem;font-weight:800;color:{color};line-height:1.1;'>{value}</div>"
        f"<div style='color:#666;font-size:.85rem;margin-top:.25rem;'>{label}</div>"
        f"</div>"
    )


st.title("🛡 Phishing Triage")
st.caption(
    "Upload a raw email. Deterministic checks gather the evidence; "
    "the model synthesizes an analyst-ready verdict."
)

tab_dashboard, tab_assessment, tab_details = st.tabs(["Dashboard", "Assessment", "Details"])

# Assessment runs first in code (regardless of tab order on screen) so parsed/
# enrichment/result are already bound by the time the Details tab reads them --
# Streamlit executes every tab's body on each rerun, only visibility toggles.
with tab_assessment:
    uploaded = st.file_uploader("Raw email (.eml)", type=["eml", "txt"])

    parsed = enrichment = result = None

    if uploaded is not None:
        raw = uploaded.read()

        parsed = _parse(raw)
        enrichment = _enrich(parsed)

        try:
            result = _verdict(parsed, enrichment)
        except Exception as exc:  # keep the demo alive if the API hiccups
            st.error(f"Verdict step failed: {exc}")
            result = None

        if result:
            history_id = _save(uploaded.name, parsed, result)

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
            st.caption(f"Saved to triage history (ID {history_id}). Set its status in the Dashboard tab.")
            st.write("")
            st.subheader("Assessment")
            st.text(result["summary"])

            # The action text is still model output over untrusted evidence. It's
            # HTML-escaped before insertion so it can only ever render as inert
            # text inside this box, never as markup -- see the module SAFETY note.
            escaped_action = html.escape(result["recommended_action"])
            st.markdown(
                f"<div style='border-left:6px solid {color};background:{color}1a;"
                f"padding:0.75rem 1rem;border-radius:.25rem;margin-top:.5rem;'>"
                f"<div style='font-weight:700;font-size:1.05rem;margin-bottom:.35rem;'>"
                f"📋 Recommended action</div>"
                f"<div style='white-space:pre-wrap;'>{escaped_action}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

            st.subheader("Indicators")
            # Both fields are model output over untrusted evidence (the system
            # prompt asks it to cite the observed value verbatim in "evidence"),
            # so they're HTML-escaped before insertion -- same rule as the
            # recommended-action box above.
            indicator_html = []
            for ind in sorted(
                result["indicators"], key=lambda i: SEVERITY_ORDER.get(i["severity"], 3)
            ):
                sev_color = SEVERITY_COLOR.get(ind["severity"], "#666")
                badge = SEVERITY_BADGE.get(ind["severity"], "⚪")
                indicator_html.append(
                    f"<div style='margin-bottom:.6rem;'>"
                    f"<span style='display:inline-block;min-width:110px;font-weight:700;"
                    f"color:{sev_color};'>{badge} {ind['severity'].upper()}</span>"
                    f"<span style='font-weight:600;'>{html.escape(ind['indicator'])}</span>"
                    f"<div style='margin-left:110px;color:#555;white-space:pre-wrap;'>"
                    f"{html.escape(ind['evidence'])}</div>"
                    f"</div>"
                )
            st.markdown("".join(indicator_html), unsafe_allow_html=True)
    else:
        st.info("Upload a .eml file to begin. In Gmail: ⋮ → Show original → Download Original.")

with tab_details:
    if parsed is None:
        st.info("Upload and analyze an email in the Assessment tab to see its details here.")
    else:
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

with tab_dashboard:
    st.subheader("Triage history")
    emails = storage.get_all_emails()

    if not emails:
        st.info("No emails analyzed yet. Results from the Assessment tab are saved here automatically.")
    else:
        history_df = pd.DataFrame(emails)
        total = len(history_df)
        verdict_counts = history_df["verdict"].value_counts()
        avg_confidence = history_df["confidence"].mean()

        malicious_n = int(verdict_counts.get("malicious", 0))
        suspicious_n = int(verdict_counts.get("suspicious", 0))
        benign_n = int(verdict_counts.get("benign", 0))

        kpis = [
            ("Total analyzed", str(total), "#0b0b0b"),
            ("Malicious", f"{malicious_n} ({malicious_n / total:.0%})", "#b00020"),
            ("Suspicious", f"{suspicious_n} ({suspicious_n / total:.0%})", "#c77700"),
            ("Benign", f"{benign_n} ({benign_n / total:.0%})", "#1a7f37"),
            ("Avg. confidence", f"{avg_confidence:.0f}%", "#0b0b0b"),
        ]
        kpi_cols = st.columns(5)
        for col, (label, value, kcolor) in zip(kpi_cols, kpis):
            col.markdown(_kpi_html(label, value, kcolor), unsafe_allow_html=True)

        st.write("")
        chart_left, chart_right = st.columns([1, 2])

        with chart_left:
            st.caption("Verdict breakdown")
            verdict_df = pd.DataFrame(
                {
                    "Verdict": ["Malicious", "Suspicious", "Benign"],
                    "Count": [malicious_n, suspicious_n, benign_n],
                }
            )
            donut = (
                alt.Chart(verdict_df)
                .mark_arc(innerRadius=55, outerRadius=95)
                .encode(
                    theta=alt.Theta("Count:Q"),
                    color=alt.Color(
                        "Verdict:N", scale=VERDICT_COLOR_SCALE, legend=alt.Legend(title=None, orient="bottom")
                    ),
                    tooltip=["Verdict", "Count"],
                )
                .properties(height=260)
            )
            st.altair_chart(donut, width="stretch")

        with chart_right:
            st.caption("Most common indicators")
            top_indicators = storage.indicator_counts(limit=10)
            if top_indicators:
                indicator_df = pd.DataFrame(top_indicators, columns=["Indicator", "Count", "Severity"])
                max_count = int(indicator_df["Count"].max())
                bar_chart = (
                    alt.Chart(indicator_df)
                    .mark_bar(cornerRadiusEnd=4)
                    .encode(
                        x=alt.X(
                            "Count:Q",
                            title="Times cited",
                            axis=alt.Axis(values=list(range(max_count + 1)), format="d"),
                        ),
                        y=alt.Y("Indicator:N", sort="-x", title=None),
                        color=alt.Color(
                            "Severity:N",
                            scale=SEVERITY_COLOR_SCALE,
                            legend=alt.Legend(title=None, orient="bottom"),
                        ),
                        tooltip=["Indicator", "Count", "Severity"],
                    )
                    .properties(height=260)
                )
                st.altair_chart(bar_chart, width="stretch")
            else:
                st.caption("No indicators recorded yet.")

        st.divider()
        st.subheader("Processed emails")
        st.caption("Edit Status inline to track what's been actioned.")

        table_df = history_df[
            ["id", "timestamp", "filename", "subject", "verdict", "confidence", "status"]
        ].rename(
            columns={
                "id": "ID",
                "timestamp": "Analyzed (UTC)",
                "filename": "File",
                "subject": "Subject",
                "verdict": "Verdict",
                "confidence": "Confidence",
                "status": "Status",
            }
        )
        edited_df = st.data_editor(
            table_df,
            hide_index=True,
            disabled=["ID", "Analyzed (UTC)", "File", "Subject", "Verdict", "Confidence"],
            column_config={
                "Confidence": st.column_config.NumberColumn(format="%d%%"),
                "Status": st.column_config.SelectboxColumn(options=storage.STATUSES, required=True),
            },
            key="history_editor",
            width="stretch",
        )

        changed = edited_df[edited_df["Status"] != table_df["Status"]]
        if not changed.empty:
            for _, row in changed.iterrows():
                storage.update_status(int(row["ID"]), row["Status"])
            st.rerun()
