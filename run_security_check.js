const fs = require('fs');
const path = require('path');

const filePath = 'c:\\Users\\Sai Vejandla\\Desktop\\Antigravity\\src\\ui\\panelUI.js';
const code = fs.readFileSync(filePath, 'utf-8');

const prompt = `Please run a comprehensive security check on the following JavaScript code. Look for things like XSS, injections, improper error handling, missing sanitization, and other security vulnerabilities.

Code:
\`\`\`javascript
${code}
\`\`\`
`;

async function run() {
    try {
        console.log('Sending request to local model (qwen2.5-coder:1.5b)...');
        const res = await fetch('http://127.0.0.1:11434/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model: 'qwen2.5-coder:1.5b',
                prompt: prompt,
                stream: false
            })
        });

        if (!res.ok) {
            console.error('Error response API:', res.status, res.statusText);
            return;
        }

        const data = await res.json();
        fs.writeFileSync('security_report.md', data.response);
        console.log('Saved report to security_report.md');
    } catch (err) {
        console.error('Error:', err);
    }
}

run();
