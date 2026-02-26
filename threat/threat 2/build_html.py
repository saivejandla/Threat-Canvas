import re

src = r'c:\Users\Sai Vejandla\Desktop\Antigravity\threat\threat 2\threat-model-fixed.html'
dst = r'c:\Users\Sai Vejandla\Desktop\Antigravity\threat\threat 2\threat-model-app\index.html'

with open(src, 'r', encoding='utf-8') as f:
    content = f.read()

# Extract from <body> to just before the <script> block
body_start = content.index('<body>') + len('<body>')
script_start = content.index('<script>')
body_html = content[body_start:script_start].strip()

# Remove all inline onclick/onchange/ondragstart handlers
body_html = re.sub(r'\s+onclick="[^"]*"', '', body_html)
body_html = re.sub(r'\s+onchange="[^"]*"', '', body_html)
body_html = re.sub(r'\s+ondragstart="[^"]*"', '', body_html)

# Add data attributes for event delegation where needed
# Step tabs: add click handlers via class (already have class step-tab)
# Scope nav: add data-sec attributes
body_html = body_html.replace("showSec('info',this)", "")
body_html = body_html.replace("showSec('trust',this)", "")
body_html = body_html.replace("showSec('entry',this)", "")
body_html = body_html.replace("showSec('exit',this)", "")
body_html = body_html.replace("showSec('assets',this)", "")
body_html = body_html.replace("showSec('deps',this)", "")

# Build final HTML
output = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatCanvas \u2014 OWASP Threat Modeler</title>
<link rel="stylesheet" href="main.css">
</head>
<body>
{body_html}
<script type="module" src="src/main.js"></script>
</body>
</html>
'''

with open(dst, 'w', encoding='utf-8') as f:
    f.write(output)

print(f'Done: wrote {len(output)} chars to index.html')
