#!/usr/bin/env python3
"""Convert the paper markdown to an HTML file for browser-based PDF export."""

import markdown
import os

PAPER_DIR = os.path.dirname(os.path.abspath(__file__))
MD_FILE = os.path.join(PAPER_DIR, "composable-agent-trust-stack.md")
HTML_FILE = os.path.join(PAPER_DIR, "composable-agent-trust-stack.html")

with open(MD_FILE, "r") as f:
    md_content = f.read()

html_body = markdown.markdown(md_content, extensions=["tables", "fenced_code"])

html_doc = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Composable Trust Infrastructure for the Agent Internet</title>
<style>
@page {{
    size: letter;
    margin: 1in 1in 1in 1in;
}}

@media print {{
    body {{
        font-size: 11pt;
    }}
    h1 {{
        font-size: 16pt;
    }}
    h2 {{
        break-after: avoid;
    }}
    h3 {{
        break-after: avoid;
    }}
    table {{
        break-inside: avoid;
    }}
    pre {{
        break-inside: avoid;
    }}
}}

body {{
    font-family: "Times New Roman", Times, Georgia, serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #1a1a1a;
    max-width: 7in;
    margin: 0 auto;
    padding: 0.5in;
}}

h1 {{
    font-size: 16pt;
    text-align: center;
    margin-bottom: 0.3em;
    line-height: 1.3;
}}

h2 {{
    font-size: 14pt;
    margin-top: 1.5em;
    margin-bottom: 0.5em;
    border-bottom: 1px solid #ccc;
    padding-bottom: 0.2em;
}}

h3 {{
    font-size: 12pt;
    margin-top: 1.2em;
    margin-bottom: 0.3em;
}}

p {{
    text-align: justify;
    margin-bottom: 0.8em;
}}

table {{
    border-collapse: collapse;
    width: 100%;
    margin: 1em 0;
    font-size: 10pt;
}}

th, td {{
    border: 1px solid #999;
    padding: 6px 10px;
    text-align: left;
}}

th {{
    background-color: #f0f0f0;
    font-weight: bold;
}}

code {{
    font-family: "Courier New", Courier, monospace;
    font-size: 9.5pt;
    background-color: #f5f5f5;
    padding: 1px 4px;
    border-radius: 2px;
}}

pre {{
    background-color: #f5f5f5;
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 9pt;
    line-height: 1.4;
    overflow-x: auto;
    white-space: pre-wrap;
}}

pre code {{
    background: none;
    padding: 0;
}}

hr {{
    border: none;
    border-top: 1px solid #ccc;
    margin: 2em 0;
}}

ul, ol {{
    margin-bottom: 0.8em;
    padding-left: 2em;
}}

li {{
    margin-bottom: 0.3em;
}}

blockquote {{
    border-left: 3px solid #ccc;
    margin-left: 0;
    padding-left: 1em;
    color: #555;
}}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

with open(HTML_FILE, "w") as f:
    f.write(html_doc)

print(f"HTML generated: {HTML_FILE}")
print(f"Open in browser and use Print -> Save as PDF")
