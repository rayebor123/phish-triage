# Phishing Triage

Upload a raw `.eml` file and get an analyst-ready phishing verdict. Deterministic
checks extract the evidence; Claude synthesizes it into a verdict, confidence
score, indicator list, and recommended action.

## How it works

1. **Parse** (`email_parser.py`) — pulls SPF/DKIM/DMARC results, sender/display-name
   inconsistencies, links (including anchor-text mismatches, URL shorteners, and
   mailto: links), hidden tracking pixels, risky attachments, malformed/evasive
   From headers, upstream spam-filter verdicts, and hashbusting/Bayesian-poisoning
   filler text — all as deterministic, code-driven findings.
2. **Enrich** (`enrich.py`) — looks up extracted domains and IPs against
   VirusTotal, urlscan.io, and AbuseIPDB, concurrently and with retry-on-timeout.
   Results with only a couple of stray vendor hits are reported as low-confidence
   noise rather than treated as real detections.
3. **Verdict** (`verdict.py`) — feeds the deterministic evidence (never the raw
   email) to Claude via a tool call, which returns a structured verdict
   (`benign` / `suspicious` / `malicious`), confidence, indicators, and
   recommended action.
4. **Display** (`app.py`) — a Streamlit front end that renders everything,
   including defanged/inert indicators so nothing is ever clickable or rendered
   as live HTML.

## Safety properties

- The email body is only ever rendered as plain text (`st.code`/`st.text`),
  never as HTML — no attacker HTML/JS execution, no remote tracking pixels
  firing in your browser.
- No URL found in a message is ever fetched or visited by this tool.
- Attachments are hashed in memory only; nothing is written to disk.
- The email body is treated as untrusted, attacker-controlled data in the
  prompt sent to Claude — prompt-injection attempts inside the email are
  analyzed, not obeyed.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and fill in your own API keys:

```
VT_API_KEY=...          # https://www.virustotal.com/gui/my-apikey
ABUSEIPDB_API_KEY=...   # https://www.abuseipdb.com/account/api
URLSCAN_API_KEY=...     # https://urlscan.io/user/profile/
ANTHROPIC_API_KEY=...   # https://console.anthropic.com/settings/keys
```

Only `ANTHROPIC_API_KEY` is required for the verdict step. The others are
optional — omit them and the app just reports "no API key configured" for
that vendor instead of failing.

**Never commit `.env`** — it's already gitignored. `.env.example` should only
ever contain placeholder text.

## Run

```bash
streamlit run app.py
```

Upload a `.eml` file (in Gmail: **⋮ → Show original → Download Original**) and
the app will parse, enrich, and triage it.

## Test samples

`samples/` contains two fixtures used to sanity-check the parser:

- `benign-github.eml` — should always produce zero header findings.
- `phish-paypal.eml` — a spoofed PayPal phishing email with failed
  authentication, a sender/Return-Path mismatch, and a deceptive link; should
  always produce a full set of findings and a `malicious` verdict.

```bash
python -c "from email_parser import parse_email; print(parse_email(open('samples/benign-github.eml','rb').read())['header_findings'])"
```

## Project structure

```
app.py            Streamlit front end
email_parser.py   Deterministic .eml parsing and header/content analysis
enrich.py         VirusTotal / AbuseIPDB / urlscan.io lookups
verdict.py        Claude-based verdict synthesis
samples/          Test fixtures (benign + phishing)
```
