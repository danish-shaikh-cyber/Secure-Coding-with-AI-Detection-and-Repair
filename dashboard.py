"""
Repairs_AI Interactive Security Benchmark Dashboard
Flask web application to browse, compare, scan, and compile vulnerable and repaired code snippets.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "MSc_DataEngineering_Results" / "DetectAndFix_Data" / "2025_09_24" / "DevGPT_v10_snapshot_20240514"
REPORT_JSON = BASE_DIR / "evaluation_report.json"

MODELS = [
    "claude-opus-4-1-20250805",
    "gpt-4.1-2025-04-14",
    "gpt-5-2025-08-07"
]

def load_report():
    if REPORT_JSON.exists():
        try:
            with open(REPORT_JSON, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Repairs_AI | Security Vulnerability Benchmark</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; }
        .card-header { background-color: #1e293b; border-bottom: 1px solid #334155; font-weight: 600; }
        .table { color: #f8fafc; }
        .table-dark { background-color: #1e293b; --bs-table-bg: #1e293b; }
        .badge-cwe { background-color: #ef4444; color: white; }
        .badge-model { background-color: #3b82f6; }
        .stat-card { transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-3px); }
        .nav-tabs .nav-link { color: #94a3b8; }
        .nav-tabs .nav-link.active { background-color: #1e293b; color: #38bdf8; border-color: #334155 #334155 transparent; font-weight: bold; }
        pre { background-color: #0b1120; color: #e2e8f0; padding: 14px; border-radius: 8px; border: 1px solid #334155; max-height: 480px; overflow-y: auto; }
        code { font-family: Consolas, monospace; }
        .diff-added { color: #4ade80; }
        .diff-removed { color: #f87171; }
    </style>
</head>
<body class="p-4">
    <div class="container-fluid">
        <!-- Header -->
        <div class="d-flex justify-content-between align-items-center mb-4 pb-3 border-bottom border-secondary">
            <div class="d-flex align-items-center gap-3">
                <div class="d-flex align-items-center justify-content-center rounded-3" style="width:52px;height:52px;background:linear-gradient(135deg,#3b82f6,#1d4ed8);">
                    <i class="fa-solid fa-shield-halved fs-4 text-white"></i>
                </div>
                <div>
                    <h2 class="fw-bold mb-0" style="color:#f8fafc;letter-spacing:0.5px;">SecureCode AI — Detection to Repair</h2>
                    <span class="badge px-3 py-1 mt-1" style="background-color:#1e3a5f;color:#38bdf8;font-size:0.7rem;letter-spacing:2px;border:1px solid #3b82f6;">SECURITY VULNERABILITY BENCHMARK</span>
                </div>
            </div>
            <div>
                <a href="/run-eval" class="btn btn-outline-info me-2"><i class="fa-solid fa-rotate me-1"></i> Re-Run Evaluation</a>
                <span class="badge bg-success px-3 py-2 fs-6">MinGW GCC & Flawfinder Active</span>
            </div>
        </div>

        <!-- Metrics Overview -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="card stat-card p-3">
                    <span class="text-secondary small text-uppercase fw-bold">Test Cases</span>
                    <h3 class="fw-bold mt-2 text-info">{{ summary.total_cases }}</h3>
                    <small class="text-muted">C, C++, and C# snippets</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card p-3">
                    <span class="text-secondary small text-uppercase fw-bold">Original Vulnerabilities</span>
                    <h3 class="fw-bold mt-2 text-danger">{{ summary.total_orig_flawfinder_hits }} Flaws</h3>
                    <small class="text-muted">Live Flawfinder hits</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card p-3">
                    <span class="text-secondary small text-uppercase fw-bold">Best Fix Reduction</span>
                    <h3 class="fw-bold mt-2 text-success">GPT-5 (23.0%)</h3>
                    <small class="text-muted">Reduced hits to 57</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card p-3">
                    <span class="text-secondary small text-uppercase fw-bold">Static Scanners Used</span>
                    <h3 class="fw-bold mt-2 text-warning">4 Scanners</h3>
                    <small class="text-muted">Flawfinder, Semgrep, Cppcheck, Snyk</small>
                </div>
            </div>
        </div>

        <!-- Model Leaderboard -->
        <div class="card mb-4">
            <div class="card-header"><i class="fa-solid fa-trophy text-warning me-2"></i>LLM Repair Performance Comparison</div>
            <div class="card-body p-0">
                <table class="table table-dark table-hover mb-0">
                    <thead>
                        <tr class="text-secondary">
                            <th>Model</th>
                            <th>Original Hits</th>
                            <th>Remaining Hits</th>
                            <th>Flaws Fixed</th>
                            <th>Reduction Rate</th>
                            <th>Improved Cases</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td class="fw-bold text-info"><i class="fa-solid fa-robot me-1"></i> gpt-5-2025-08-07</td>
                            <td>{{ summary.total_orig_flawfinder_hits }}</td>
                            <td><span class="badge bg-success">{{ summary.models['gpt-5-2025-08-07'].flawfinder_hits }}</span></td>
                            <td class="text-success">+{{ summary.total_orig_flawfinder_hits - summary.models['gpt-5-2025-08-07'].flawfinder_hits }}</td>
                            <td>
                                <div class="progress" style="height: 18px; width: 180px;">
                                    <div class="progress-bar bg-success" style="width: 23%">23.0%</div>
                                </div>
                            </td>
                            <td><span class="badge bg-primary">{{ summary.models['gpt-5-2025-08-07'].fixed_cases }} / 48 cases</span></td>
                        </tr>
                        <tr>
                            <td class="fw-bold text-primary"><i class="fa-solid fa-robot me-1"></i> gpt-4.1-2025-04-14</td>
                            <td>{{ summary.total_orig_flawfinder_hits }}</td>
                            <td><span class="badge bg-warning text-dark">{{ summary.models['gpt-4.1-2025-04-14'].flawfinder_hits }}</span></td>
                            <td class="text-warning">+{{ summary.total_orig_flawfinder_hits - summary.models['gpt-4.1-2025-04-14'].flawfinder_hits }}</td>
                            <td>
                                <div class="progress" style="height: 18px; width: 180px;">
                                    <div class="progress-bar bg-info" style="width: 6.8%">6.8%</div>
                                </div>
                            </td>
                            <td><span class="badge bg-primary">{{ summary.models['gpt-4.1-2025-04-14'].fixed_cases }} / 48 cases</span></td>
                        </tr>
                        <tr>
                            <td class="fw-bold text-purple" style="color: #c084fc;"><i class="fa-solid fa-robot me-1"></i> claude-opus-4-1-20250805</td>
                            <td>{{ summary.total_orig_flawfinder_hits }}</td>
                            <td><span class="badge bg-secondary">{{ summary.models['claude-opus-4-1-20250805'].flawfinder_hits }}</span></td>
                            <td class="text-secondary">+{{ summary.total_orig_flawfinder_hits - summary.models['claude-opus-4-1-20250805'].flawfinder_hits }}</td>
                            <td>
                                <div class="progress" style="height: 18px; width: 180px;">
                                    <div class="progress-bar bg-secondary" style="width: 2.7%">2.7%</div>
                                </div>
                            </td>
                            <td><span class="badge bg-primary">{{ summary.models['claude-opus-4-1-20250805'].fixed_cases }} / 48 cases</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Benchmark Explorer -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span><i class="fa-solid fa-folder-tree me-2 text-info"></i>Benchmark Test Cases Explorer (48 Files)</span>
                <span class="text-secondary small">Click any case to inspect code, CWE findings, and LLM repairs</span>
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-dark table-hover align-middle mb-0">
                        <thead>
                            <tr class="text-secondary small">
                                <th>Case</th>
                                <th>Target File</th>
                                <th>Scanners</th>
                                <th>Dataset Findings</th>
                                <th>Orig Hits</th>
                                <th>Claude Hits</th>
                                <th>GPT-4.1 Hits</th>
                                <th>GPT-5 Hits</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for c in cases %}
                            <tr>
                                <td class="fw-bold text-info">{{ c.case }}</td>
                                <td><code>{{ c.original_file or 'N/A' }}</code></td>
                                <td>
                                    {% for s in c.scanners %}
                                    <span class="badge bg-secondary small">{{ s }}</span>
                                    {% endfor %}
                                </td>
                                <td><span class="badge bg-dark border border-secondary">{{ c.dataset_findings_count }}</span></td>
                                <td><span class="badge {{ 'bg-danger' if c.orig_flawfinder_count > 0 else 'bg-success' }}">{{ c.orig_flawfinder_count }}</span></td>
                                <td>
                                    <span class="badge {{ 'bg-success' if c.models['claude-opus-4-1-20250805'].flawfinder_count < c.orig_flawfinder_count else 'bg-secondary' }}">
                                        {{ c.models['claude-opus-4-1-20250805'].flawfinder_count }}
                                    </span>
                                </td>
                                <td>
                                    <span class="badge {{ 'bg-success' if c.models['gpt-4.1-2025-04-14'].flawfinder_count < c.orig_flawfinder_count else 'bg-secondary' }}">
                                        {{ c.models['gpt-4.1-2025-04-14'].flawfinder_count }}
                                    </span>
                                </td>
                                <td>
                                    <span class="badge {{ 'bg-success' if c.models['gpt-5-2025-08-07'].flawfinder_count < c.orig_flawfinder_count else 'bg-secondary' }}">
                                        {{ c.models['gpt-5-2025-08-07'].flawfinder_count }}
                                    </span>
                                </td>
                                <td>
                                    <a href="/case/{{ c.case }}" class="btn btn-sm btn-outline-primary"><i class="fa-solid fa-eye me-1"></i> Inspect</a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

CASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ case_id }} | Repairs_AI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; }
        .card-header { background-color: #1e293b; border-bottom: 1px solid #334155; font-weight: 600; }
        pre { background-color: #0b1120; color: #e2e8f0; padding: 14px; border-radius: 8px; border: 1px solid #334155; max-height: 520px; overflow-y: auto; font-family: Consolas, monospace; font-size: 13px; }
        .nav-tabs .nav-link { color: #94a3b8; }
        .nav-tabs .nav-link.active { background-color: #1e293b; color: #38bdf8; border-color: #334155 #334155 transparent; font-weight: bold; }
        .table-dark { background-color: #1e293b; --bs-table-bg: #1e293b; }
    </style>
</head>
<body class="p-4">
    <div class="container-fluid">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <div>
                <a href="/" class="btn btn-outline-secondary btn-sm mb-2"><i class="fa-solid fa-arrow-left me-1"></i> Back to Dashboard</a>
                <h3 class="fw-bold text-primary mb-0"><i class="fa-solid fa-file-code me-2"></i>{{ case_id }}: {{ info.target_file or 'Vulnerable Snippet' }}</h3>
            </div>
            <div>
                <span class="badge bg-secondary me-2">Scanners: {{ info.scanners|join(', ') }}</span>
                <span class="badge bg-danger">{{ findings|length }} Benchmark Finding(s)</span>
            </div>
        </div>

        <!-- Vulnerability Scanner Findings Recorded in Dataset -->
        <div class="card mb-4">
            <div class="card-header"><i class="fa-solid fa-triangle-exclamation text-warning me-2"></i>Recorded Scanner Detections</div>
            <div class="card-body p-0">
                <table class="table table-dark table-sm mb-0">
                    <thead>
                        <tr class="text-secondary small">
                            <th>Scanner</th>
                            <th>Line</th>
                            <th>Severity</th>
                            <th>Type / CWE</th>
                            <th>Message / Snippet</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for f in findings %}
                        <tr>
                            <td><span class="badge bg-info text-dark">{{ f.scanner }}</span></td>
                            <td>{{ f.line }}</td>
                            <td><span class="badge {{ 'bg-danger' if f.severity in ['error', 'warning', 'high'] else 'bg-secondary' }}">{{ f.severity }}</span></td>
                            <td><code>{{ f.type }}</code></td>
                            <td><small>{{ f.text }}</small></td>
                        </tr>
                        {% endfor %}
                        {% if findings|length == 0 %}
                        <tr><td colspan="5" class="text-center text-muted p-3">No static analyzer errors logged in Info.txt</td></tr>
                        {% endif %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Code Comparisons -->
        <div class="card">
            <div class="card-header p-2">
                <ul class="nav nav-tabs border-0" id="codeTabs" role="tablist">
                    <li class="nav-item">
                        <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#tab-orig">
                            <i class="fa-solid fa-bug text-danger me-1"></i> Original Code
                        </button>
                    </li>
                    <li class="nav-item">
                        <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-claude">
                            <i class="fa-solid fa-robot text-purple me-1"></i> Claude Opus 4.1
                        </button>
                    </li>
                    <li class="nav-item">
                        <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-gpt4">
                            <i class="fa-solid fa-robot text-primary me-1"></i> GPT-4.1
                        </button>
                    </li>
                    <li class="nav-item">
                        <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-gpt5">
                            <i class="fa-solid fa-robot text-success me-1"></i> GPT-5
                        </button>
                    </li>
                </ul>
            </div>
            <div class="card-body">
                <div class="tab-content" id="codeTabContent">
                    <div class="tab-pane fade show active" id="tab-orig">
                        <div class="d-flex justify-content-between mb-2">
                            <span class="text-secondary small">Vulnerable baseline source code</span>
                            <span class="badge bg-danger">Flawfinder Hits: {{ orig_flaw_hits|length }}</span>
                        </div>
                        <pre><code>{{ orig_code }}</code></pre>
                    </div>

                    <div class="tab-pane fade" id="tab-claude">
                        <div class="d-flex justify-content-between mb-2">
                            <span class="text-secondary small">Repaired code by Claude Opus 4.1</span>
                            <span class="badge bg-primary">Flawfinder Hits: {{ claude_flaw_hits|length }}</span>
                        </div>
                        <pre><code>{{ claude_code }}</code></pre>
                    </div>

                    <div class="tab-pane fade" id="tab-gpt4">
                        <div class="d-flex justify-content-between mb-2">
                            <span class="text-secondary small">Repaired code by GPT-4.1</span>
                            <span class="badge bg-primary">Flawfinder Hits: {{ gpt4_flaw_hits|length }}</span>
                        </div>
                        <pre><code>{{ gpt4_code }}</code></pre>
                    </div>

                    <div class="tab-pane fade" id="tab-gpt5">
                        <div class="d-flex justify-content-between mb-2">
                            <span class="text-secondary small">Repaired code by GPT-5</span>
                            <span class="badge bg-success">Flawfinder Hits: {{ gpt5_flaw_hits|length }}</span>
                        </div>
                        <pre><code>{{ gpt5_code }}</code></pre>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

@app.route("/")
def index():
    report = load_report()
    if not report:
        from evaluator import run_full_evaluation
        run_full_evaluation()
        report = load_report()
    return render_template_string(INDEX_TEMPLATE, summary=report["summary"], cases=report["cases"])

@app.route("/run-eval")
def trigger_eval():
    from evaluator import run_full_evaluation
    run_full_evaluation()
    return "<script>window.location.href = '/';</script>"

@app.route("/case/<case_id>")
def view_case(case_id):
    from evaluator import parse_case_info, get_case_files, run_flawfinder_on_code
    case_dir = DATASET_PATH / case_id
    if not case_dir.exists():
        return "Case not found", 404
        
    info = parse_case_info(case_dir)
    files = get_case_files(case_dir, info.get("target_file", ""))
    
    def read_safe(path):
        if path and os.path.exists(path):
            try:
                return Path(path).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return "// Error reading file"
        return "// No file present"

    orig_code = read_safe(files["original_code"])
    claude_code = read_safe(files["models"]["claude-opus-4-1-20250805"]["code_path"])
    gpt4_code = read_safe(files["models"]["gpt-4.1-2025-04-14"]["code_path"])
    gpt5_code = read_safe(files["models"]["gpt-5-2025-08-07"]["code_path"])

    orig_hits = run_flawfinder_on_code(files["original_code"])
    claude_hits = run_flawfinder_on_code(files["models"]["claude-opus-4-1-20250805"]["code_path"])
    gpt4_hits = run_flawfinder_on_code(files["models"]["gpt-4.1-2025-04-14"]["code_path"])
    gpt5_hits = run_flawfinder_on_code(files["models"]["gpt-5-2025-08-07"]["code_path"])

    return render_template_string(
        CASE_TEMPLATE,
        case_id=case_id,
        info=info,
        findings=info.get("scanner_findings", []),
        orig_code=orig_code,
        claude_code=claude_code,
        gpt4_code=gpt4_code,
        gpt5_code=gpt5_code,
        orig_flaw_hits=orig_hits,
        claude_flaw_hits=claude_hits,
        gpt4_flaw_hits=gpt4_hits,
        gpt5_flaw_hits=gpt5_hits
    )

if __name__ == "__main__":
    print("[*] Starting Repairs_AI Web Dashboard on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)
