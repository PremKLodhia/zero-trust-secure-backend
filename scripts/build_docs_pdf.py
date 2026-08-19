import os
import subprocess
import markdown

DOCS_DIR = os.path.abspath("docs")
PDF_DIR = os.path.join(DOCS_DIR, "pdf")
os.makedirs(PDF_DIR, exist_ok=True)

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
if not os.path.exists(CHROME_PATH):
    CHROME_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

CSS_STYLES = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

@page {
    size: A4;
    margin: 16mm 14mm 16mm 14mm;
    @bottom-right {
        content: "Page " counter(page);
        font-family: 'JetBrains Mono', monospace;
        font-size: 8pt;
        color: #64748b;
    }
}

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    color: #1e293b;
    background-color: #ffffff;
    line-height: 1.55;
    font-size: 10pt;
    margin: 0;
    padding: 0;
}

h1 {
    font-size: 20pt;
    font-weight: 800;
    color: #0f172a;
    border-bottom: 2px solid #38bdf8;
    padding-bottom: 6px;
    margin-top: 0;
    margin-bottom: 12pt;
}

h2 {
    font-size: 14pt;
    font-weight: 700;
    color: #0f172a;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 4px;
    margin-top: 16pt;
    margin-bottom: 8pt;
}

h3 {
    font-size: 11pt;
    font-weight: 600;
    color: #0369a1;
    margin-top: 12pt;
    margin-bottom: 6pt;
}

p, li {
    font-size: 9.5pt;
    color: #334155;
    margin-bottom: 6pt;
}

ul, ol {
    margin-top: 0;
    margin-bottom: 8pt;
    padding-left: 18pt;
}

code {
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 8.5pt;
    background-color: #f1f5f9;
    color: #0f172a;
    padding: 1px 4px;
    border-radius: 4px;
    border: 1px solid #e2e8f0;
}

pre {
    background-color: #0f172a;
    color: #34d399;
    padding: 10pt;
    border-radius: 6px;
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 8pt;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 8pt 0;
    border: 1px solid #1e293b;
}

pre code {
    background-color: transparent;
    color: inherit;
    padding: 0;
    border: none;
}

blockquote {
    border-left: 4px solid #38bdf8;
    background-color: #f8fafc;
    margin: 8pt 0;
    padding: 6pt 12pt;
    color: #475569;
    font-size: 9pt;
    border-radius: 0 4px 4px 0;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 10pt 0;
    font-size: 8.5pt;
}

th, td {
    padding: 6pt 8pt;
    text-align: left;
    border: 1px solid #e2e8f0;
}

th {
    background-color: #0f172a;
    color: #f8fafc;
    font-weight: 600;
}

tr:nth-child(even) {
    background-color: #f8fafc;
}

.header-banner {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #ffffff;
    padding: 14pt 18pt;
    border-radius: 8px;
    margin-bottom: 16pt;
    border-left: 6px solid #38bdf8;
}

.header-title {
    font-size: 16pt;
    font-weight: 800;
    color: #ffffff;
    margin: 0;
}

.header-subtitle {
    font-size: 9.5pt;
    color: #94a3b8;
    margin-top: 4pt;
}

.badge {
    display: inline-block;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 7.5pt;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
}

.badge-pass { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
.badge-tech { background: #e0f2fe; color: #075985; border: 1px solid #7dd3fc; }
.badge-warn { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }

.page-break {
    page-break-before: always;
}
"""

doc_files = [
    ("architecture.md", "01_Architecture_and_Design_Tradeoffs.pdf", "Zero-Trust Architecture & Design Trade-Offs"),
    ("threat-model.md", "02_STRIDE_Threat_Model.pdf", "STRIDE Threat Model & Control Specifications"),
    ("control-mapping.md", "03_ASVS_and_ATTACK_Control_Mapping.pdf", "OWASP ASVS v4.0 & MITRE ATT&CK Control Matrix"),
    ("vuln-writeup.md", "04_JWT_Vulnerability_Disclosure_and_Fix.pdf", "JWT Algorithm Confusion Vulnerability & Remediation"),
    ("results.md", "05_Empirical_Evaluation_and_Benchmarks.pdf", "Empirical Evaluation Metrics & Latency Benchmarks"),
]

all_sections_html = []

for filename, pdf_name, title in doc_files:
    filepath = os.path.join(DOCS_DIR, filename)
    if not os.path.exists(filepath):
        continue

    with open(filepath, "r", encoding="utf-8") as f:
        md_text = f.read()

    body_html = markdown.markdown(md_text, extensions=["tables", "fenced_code", "codehilite"])

    single_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{CSS_STYLES}</style>
</head>
<body>
<div class="header-banner">
    <div class="header-title">{title}</div>
    <div class="header-subtitle">Zero-Trust Secure Backend & Identity Threat Detection · Technical Documentation</div>
</div>
{body_html}
</body>
</html>"""

    tmp_html = os.path.join(PDF_DIR, f"temp_{pdf_name}.html")
    out_pdf = os.path.join(PDF_DIR, pdf_name)

    with open(tmp_html, "w", encoding="utf-8") as f:
        f.write(single_html)

    # Render PDF using headless Chrome/Edge
    cmd = [
        CHROME_PATH,
        "--headless",
        "--disable-gpu",
        "--run-all-compositor-stages-before-draw",
        f"--print-to-pdf={out_pdf}",
        tmp_html
    ]
    subprocess.run(cmd, check=True)
    if os.path.exists(tmp_html):
        os.remove(tmp_html)
    print(f"Generated {pdf_name} successfully!")

    all_sections_html.append(f"""
    <div class="page-break">
        <div class="header-banner">
            <div class="header-title">{title}</div>
            <div class="header-subtitle">Zero-Trust Secure Backend & Identity Threat Detection · Portfolio Technical Dossier</div>
        </div>
        {body_html}
    </div>
    """)

# Now generate the combined comprehensive whitepaper
combined_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Zero-Trust Secure Backend & Identity Threat Detection — Technical Whitepaper</title>
<style>{CSS_STYLES}</style>
</head>
<body>
<div style="text-align:center; padding: 40pt 20pt 30pt; border-bottom: 3px solid #38bdf8; margin-bottom: 24pt;">
    <div style="font-size: 24pt; font-weight: 800; color: #0f172a; margin-bottom: 8pt;">Zero-Trust Secure Backend &amp; Identity Threat Detection</div>
    <div style="font-size: 13pt; color: #0284c7; font-weight: 600; margin-bottom: 14pt;">Comprehensive Engineering Whitepaper &amp; Security Validation Dossier</div>
    <div style="font-size: 9.5pt; color: #64748b; font-family: 'JetBrains Mono', monospace;">Author: Prem Lodhia · Defense Engineering &amp; Threat Detection · Summer 2026</div>
    <div style="margin-top: 12pt; display: flex; justify-content: center; gap: 8px;">
        <span class="badge badge-tech">WebAuthn / Passkeys</span>
        <span class="badge badge-tech">Open Policy Agent (OPA)</span>
        <span class="badge badge-tech">Vault Transit Envelope Crypto</span>
        <span class="badge badge-tech">IsolationForest ML</span>
        <span class="badge badge-pass">Fail-Secure Verified</span>
    </div>
</div>

{''.join(all_sections_html)}
</body>
</html>"""

combined_tmp = os.path.join(PDF_DIR, "temp_combined.html")
combined_pdf = os.path.join(PDF_DIR, "Zero_Trust_Backend_Whitepaper.pdf")

with open(combined_tmp, "w", encoding="utf-8") as f:
    f.write(combined_html)

subprocess.run([
    CHROME_PATH,
    "--headless",
    "--disable-gpu",
    "--run-all-compositor-stages-before-draw",
    f"--print-to-pdf={combined_pdf}",
    combined_tmp
], check=True)

if os.path.exists(combined_tmp):
    os.remove(combined_tmp)

print("Generated comprehensive Zero_Trust_Backend_Whitepaper.pdf successfully!")

# Copy to prem-portfolio/assets
portfolio_asset_pdf = r"C:\Users\shivs\.gemini\antigravity\scratch\prem-portfolio\assets\Zero_Trust_Backend_Whitepaper.pdf"
with open(combined_pdf, "rb") as src, open(portfolio_asset_pdf, "wb") as dst:
    dst.write(src.read())
print(f"Copied Whitepaper to portfolio assets at {portfolio_asset_pdf}")
