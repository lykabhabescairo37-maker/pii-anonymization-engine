import json
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from dfa_engine import PIIAutomatonEngine

engine = PIIAutomatonEngine()

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PII Anonymization Engine</title>
    <style>
        :root {
            --bg: #111827;
            --card: #1f2937;
            --border: #374151;
            --text: #f3f4f6;
            --muted: #9ca3af;
            --accent: #3b82f6;
            --success: #10b981;
            --danger: #ef4444;
        }
        * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg); color: var(--text); margin: 0; padding: 1.5rem; }
        .container { max-width: 1250px; margin: 0 auto; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--card);
            border: 1px solid var(--border);
            padding: 1.25rem 1.5rem;
            border-radius: 10px;
            margin-bottom: 1.5rem;
        }
        h1 { margin: 0; font-size: 1.35rem; color: #fff; }
        .subtitle { font-size: 0.8rem; color: var(--muted); margin-top: 0.2rem; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
        @media (max-width: 900px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }
        .stat-val { font-size: 1.5rem; font-weight: 700; color: #fff; }
        .stat-lbl { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; margin-top: 0.2rem; }

        .main-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
        @media (max-width: 900px) { .main-grid { grid-template-columns: 1fr; } }
        
        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
        }
        .card h2 { margin: 0 0 0.75rem; font-size: 0.95rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
        
        textarea {
            width: 100%;
            height: 180px;
            background: #0b0f19;
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.75rem;
            font-family: monospace;
            font-size: 0.85rem;
            resize: vertical;
        }
        .output-box {
            background: #0b0f19;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.75rem;
            height: 180px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 0.85rem;
            white-space: pre-wrap;
            color: #d1d5db;
        }
        .btn-group { display: flex; gap: 0.5rem; margin-top: 1rem; }
        button {
            background: var(--accent);
            color: white;
            border: none;
            padding: 0.55rem 1rem;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
        }
        button:hover { opacity: 0.9; }
        button.secondary { background: #374151; color: var(--text); }
        
        table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.85rem; }
        th, td { padding: 0.75rem; border-bottom: 1px solid var(--border); text-align: left; }
        th { color: var(--muted); font-weight: 600; }
        tr.clickable:hover { background: rgba(255,255,255,0.02); cursor: pointer; }
        tr.selected { background: rgba(59, 130, 246, 0.15) !important; border-left: 3px solid var(--accent); }
        
        .badge { padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }
        .badge-accept { background: rgba(16, 185, 129, 0.2); color: var(--success); }
        .badge-reject { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        
        .tape-container { display: flex; gap: 0.4rem; overflow-x: auto; padding: 0.5rem 0; }
        .cell {
            min-width: 48px;
            border: 1px solid var(--border);
            border-radius: 6px;
            text-align: center;
            background: #0b0f19;
            font-family: monospace;
            font-size: 0.8rem;
            flex-shrink: 0;
        }
        .cell.active { border-color: var(--accent); background: rgba(59, 130, 246, 0.2); }
        .cell-char { font-weight: 700; padding: 0.3rem; border-bottom: 1px solid var(--border); color: #fff; }
        .cell-class { color: var(--muted); padding: 0.2rem; border-bottom: 1px solid var(--border); font-size: 0.7rem; }
        .cell-state { padding: 0.3rem; font-weight: 600; color: var(--accent); font-size: 0.7rem; }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div>
            <h1>PII Anonymization Engine</h1>
            <div class="subtitle">DFA-based • In-memory • Zero-dependency pipeline</div>
        </div>
        <div class="stats-grid" style="margin-bottom:0; gap: 0.75rem;">
            <div class="stat-card" style="padding: 0.5rem 1rem;"><div class="stat-val" id="statTokens">0</div><div class="stat-lbl">Tokens</div></div>
            <div class="stat-card" style="padding: 0.5rem 1rem;"><div class="stat-val" id="statEmails">0</div><div class="stat-lbl">Emails</div></div>
            <div class="stat-card" style="padding: 0.5rem 1rem;"><div class="stat-val" id="statApis">0</div><div class="stat-lbl">API Keys</div></div>
            <div class="stat-card" style="padding: 0.5rem 1rem;"><div class="stat-val" id="statPhones">0</div><div class="stat-lbl">Phones</div></div>
            <div class="stat-card" style="padding: 0.5rem 1rem;"><div class="stat-val" id="statRejected">0</div><div class="stat-lbl">Rejected</div></div>
        </div>
    </header>

    <div class="main-grid">
        <div class="card">
            <h2>Input Text</h2>
            <textarea id="rawInput">john.doe@email.com
johndoe.com
sk-proj-abc123xyz789def456
sk-short
+639123456789
abc-phone-num</textarea>
            <div class="btn-group">
                <button onclick="runEngine()">Redact & Process</button>
                <button class="secondary" onclick="clearText()">Clear</button>
            </div>
        </div>

        <div class="card">
            <h2>Redacted Output</h2>
            <div id="sanitizedOutput" class="output-box">Output will appear here...</div>
        </div>
    </div>

    <div class="card" style="margin-bottom: 1.5rem;">
        <h2>Verdicts Log</h2>
        <div style="max-height: 250px; overflow-y: auto;">
            <table>
                <thead>
                    <tr>
                        <th>Input</th>
                        <th>Type</th>
                        <th>Final State</th>
                        <th>Result</th>
                    </tr>
                </thead>
                <tbody id="tokenTableBody">
                    <tr><td colspan="4" style="text-align:center; color:var(--muted);">No tokens evaluated yet.</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="card">
        <h2>DFA State Inspector (<span id="activeTokenLabel" style="color:var(--accent);">Select a token above</span>)</h2>
        <div style="font-size: 0.85rem; color: var(--muted); margin-bottom: 0.5rem;">
            Step: <span id="stepCounter">0 / 0</span> | Note: <span id="stepNote" style="color:#fff;">—</span>
        </div>
        <div id="tapeContainer" class="tape-container">
            <div style="color: var(--muted); font-size: 0.85rem; padding: 0.5rem;">Click any token row in the verdicts table to trace its character states.</div>
        </div>
        <div class="btn-group">
            <button class="secondary" onclick="stepReset()">Reset</button>
            <button class="secondary" onclick="stepPrev()">Previous</button>
            <button class="secondary" onclick="stepNext()">Next</button>
            <button onclick="togglePlay()" id="playBtn">Auto-play</button>
        </div>
    </div>
</div>

<script>
    let tokens = [];
    let selectedIdx = 0;
    let stepIdx = 0;
    let timer = null;

    window.onload = () => { runEngine(); };

    function clearText() {
        stopPlay();
        document.getElementById('rawInput').value = '';
        document.getElementById('sanitizedOutput').textContent = '';
        document.getElementById('tokenTableBody').innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--muted);">No tokens evaluated yet.</td></tr>';
        document.getElementById('tapeContainer').innerHTML = '<div style="color: var(--muted); font-size: 0.85rem; padding: 0.5rem;">Click any token row in the verdicts table to trace its character states.</div>';
        document.getElementById('statTokens').textContent = '0';
        document.getElementById('statEmails').textContent = '0';
        document.getElementById('statApis').textContent = '0';
        document.getElementById('statPhones').textContent = '0';
        document.getElementById('statRejected').textContent = '0';
        document.getElementById('activeTokenLabel').textContent = 'None';
        document.getElementById('stepCounter').textContent = '0 / 0';
        document.getElementById('stepNote').textContent = '—';
    }

    async function runEngine() {
        stopPlay();
        const text = document.getElementById('rawInput').value;
        const res = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });
        const data = await res.json();

        document.getElementById('sanitizedOutput').textContent = data.redacted_text;
        document.getElementById('statTokens').textContent = data.total_tokens;
        document.getElementById('statEmails').textContent = data.email_count;
        document.getElementById('statApis').textContent = data.api_count;
        document.getElementById('statPhones').textContent = data.phone_count;
        document.getElementById('statRejected').textContent = data.rejected_count;
        tokens = data.tokens;

        const tbody = document.getElementById('tokenTableBody');
        if (!tokens.length) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--muted);">No tokens found.</td></tr>';
            return;
        }

        tbody.innerHTML = tokens.map((t, i) => `
            <tr class="clickable ${i === 0 ? 'selected' : ''}" onclick="selectToken(${i})">
                <td><code>${escapeHtml(t.token)}</code></td>
                <td><strong>${t.type}</strong></td>
                <td><code>${t.final_state}</code></td>
                <td><span class="badge ${t.accepted ? 'badge-accept' : 'badge-reject'}">${t.accepted ? 'ACCEPTED → ' + t.redacted_tag : t.reason}</span></td>
            </tr>
        `).join('');

        if (tokens.length > 0) selectToken(0);
    }

    function selectToken(idx) {
        stopPlay();
        selectedIdx = idx;
        document.querySelectorAll('#tokenTableBody tr').forEach((tr, i) => {
            tr.classList.toggle('selected', i === idx);
        });
        const t = tokens[idx];
        stepIdx = t ? t.steps.length : 0;
        renderTape();
    }

    function renderTape() {
        const t = tokens[selectedIdx];
        const container = document.getElementById('tapeContainer');
        if (!t || !t.steps.length) {
            container.innerHTML = '<div style="color: var(--muted); font-size: 0.85rem; padding: 0.5rem;">No steps available.</div>';
            return;
        }
        document.getElementById('activeTokenLabel').textContent = t.token;
        document.getElementById('stepCounter').textContent = `${stepIdx} / ${t.steps.length}`;
        const activeRec = stepIdx > 0 ? t.steps[stepIdx - 1] : null;
        document.getElementById('stepNote').textContent = activeRec ? activeRec.note : 'Start state q0';

        container.innerHTML = t.steps.map((s, i) => {
            const visible = i < stepIdx;
            const current = i === stepIdx - 1;
            const isDead = visible && s.new_state === 'q_d';
            return `
                <div class="cell ${current ? 'active' : ''}" style="opacity: ${visible ? 1 : 0.3}; border-color: ${isDead ? '#ef4444' : ''}">
                    <div class="cell-char">${escapeHtml(s.char)}</div>
                    <div class="cell-class">${s.char_class}</div>
                    <div class="cell-state">${s.new_state}</div>
                </div>
            `;
        }).join('');
    }

    function stepReset() { stopPlay(); stepIdx = 0; renderTape(); }
    function stepPrev() { stopPlay(); if (stepIdx > 0) { stepIdx--; renderTape(); } }
    function stepNext() {
        const t = tokens[selectedIdx];
        if (t && stepIdx < t.steps.length) { stepIdx++; renderTape(); }
        else { stopPlay(); }
    }
    function togglePlay() {
        if (timer) { stopPlay(); return; }
        const t = tokens[selectedIdx];
        if (!t) return;
        if (stepIdx >= t.steps.length) stepIdx = 0;
        document.getElementById('playBtn').textContent = 'Pause';
        timer = setInterval(() => {
            if (stepIdx < t.steps.length) { stepIdx++; renderTape(); }
            else { stopPlay(); }
        }, 350);
    }
    function stopPlay() {
        if (timer) { clearInterval(timer); timer = null; }
        document.getElementById('playBtn').textContent = 'Play';
    }
    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
</script>
</body>
</html>
"""


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(Path(__file__).with_name("dashboard.html").read_bytes())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(body) if body else {}
            result = engine.process_text(payload.get("text", ""))
            response_bytes = json.dumps(result).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 5000), RequestHandler)
    print("Server active at http://127.0.0.1:5000")
    server.serve_forever()