"""
Repairs_AI Benchmark Evaluation Engine
Analyzes DevGPT vulnerability benchmark dataset and evaluates LLM security repair performance.
"""

import os
import sys
import json
import csv
import io
import subprocess
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "MSc_DataEngineering_Results" / "DetectAndFix_Data" / "2025_09_24" / "DevGPT_v10_snapshot_20240514"

MODELS = [
    "claude-opus-4-1-20250805",
    "gpt-4.1-2025-04-14",
    "gpt-5-2025-08-07"
]

def run_flawfinder_on_code(file_path):
    """Runs flawfinder with CSV output on a file and returns structured issues.
    
    Uses system flawfinder binary (installed via pip/pipx as CLI tool).
    Falls back to python -m flawfinder if binary not available in PATH.
    Returns empty list if file not found or scanner unavailable.
    """
    import shutil
    if not file_path or not os.path.exists(file_path):
        return []
    
    # Determine the correct flawfinder command
    if shutil.which("flawfinder"):
        cmd = ["flawfinder", "--csv", str(file_path)]
    elif shutil.which("python") and subprocess.run(
        ["python", "-m", "flawfinder", "--version"],
        capture_output=True, timeout=3
    ).returncode == 0:
        cmd = ["python", "-m", "flawfinder", "--csv", str(file_path)]
    elif subprocess.run(
        [sys.executable, "-m", "flawfinder", "--version"],
        capture_output=True, timeout=3
    ).returncode == 0:
        cmd = [sys.executable, "-m", "flawfinder", "--csv", str(file_path)]
    else:
        return []  # flawfinder not available — do not silently return 0 hits

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=15
        )
        hits = []
        if result.stdout.strip():
            reader = csv.DictReader(io.StringIO(result.stdout))
            for row in reader:
                hits.append({
                    "file": Path(row.get("File", "")).name,
                    "line": row.get("Line", "?"),
                    "level": row.get("Level", "1"),
                    "category": row.get("Category", ""),
                    "name": row.get("Name", ""),
                    "warning": row.get("Warning", ""),
                    "suggestion": row.get("Suggestion", ""),
                    "cwe": row.get("CWEs", "")
                })
        return hits
    except Exception as e:
        return []

def test_gcc_compile(file_path):
    """Test syntax checking / compilation using MinGW gcc/g++."""
    if not file_path or not os.path.exists(file_path):
        return {"compiled": False, "error": "File not found"}
    suffix = Path(file_path).suffix.lower()
    if suffix not in [".c", ".cpp"]:
        return {"compiled": None, "error": "Not a C/C++ source"}
    
    compiler = "g++" if suffix == ".cpp" else "gcc"
    try:
        res = subprocess.run(
            [compiler, "-fsyntax-only", str(file_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=5
        )
        return {
            "compiled": res.returncode == 0,
            "compiler": compiler,
            "error": res.stderr.strip() if res.returncode != 0 else ""
        }
    except Exception as e:
        return {"compiled": False, "error": str(e)}

def parse_case_info(case_dir):
    """Parse Info.txt from a test case folder."""
    info_file = case_dir / "Info.txt"
    info = {
        "model_name": "",
        "file_name": "",
        "target_file": "",
        "scanners": [],
        "scanner_findings": []
    }
    if not info_file.exists():
        return info
    
    try:
        content = info_file.read_text(encoding="utf-8", errors="ignore")
        if "Detect info from scanners:" in content:
            meta_part, json_part = content.split("Detect info from scanners:", 1)
            for line in meta_part.splitlines():
                if line.startswith("File name:"):
                    clean_path = line.replace("File name:", "").strip().replace("\\", "/")
                    info["file_name"] = clean_path
                    info["target_file"] = Path(clean_path).name
                elif line.startswith("Scanners:"):
                    raw_sc = line.replace("Scanners:", "").strip()
                    try:
                        info["scanners"] = eval(raw_sc)
                    except:
                        info["scanners"] = [raw_sc]
            try:
                info["scanner_findings"] = json.loads(json_part.strip())
            except Exception:
                pass
    except Exception as e:
        pass
    return info

def get_case_files(case_dir, target_filename=""):
    """Finds original code file and each model's repaired code."""
    result = {
        "original_code": None,
        "original_filename": None,
        "models": {}
    }
    
    llms_dir = case_dir / "LLMs"
    
    # 1. Try finding original code copy in LLMs subfolder
    if target_filename and llms_dir.exists():
        for m in MODELS:
            candidate = llms_dir / m / target_filename
            if candidate.exists():
                result["original_code"] = str(candidate)
                result["original_filename"] = target_filename
                break

    # 2. If not found, walk case_dir
    if not result["original_code"]:
        for root, _, files in os.walk(case_dir):
            if "LLMs" in root:
                continue
            if target_filename and target_filename in files:
                result["original_code"] = os.path.join(root, target_filename)
                result["original_filename"] = target_filename
                break
            for f in files:
                if re.match(r"^Code_\d+\.(c|cpp|cs)$", f):
                    result["original_code"] = os.path.join(root, f)
                    result["original_filename"] = f
                    break
            if result["original_code"]:
                break
            
    # Locate repairs for each model
    for m in MODELS:
        m_dir = llms_dir / m
        result["models"][m] = {
            "code_path": None,
            "filename": None,
            "response_path": None
        }
        if m_dir.exists():
            for f in sorted(os.listdir(m_dir)):
                if f.startswith("New_generated_code_") and f.endswith((".c", ".cpp", ".cs")):
                    result["models"][m]["code_path"] = str(m_dir / f)
                    result["models"][m]["filename"] = f
                    break
            resp_md = m_dir / "LLM_Response.md"
            if resp_md.exists():
                result["models"][m]["response_path"] = str(resp_md)
                
    return result

def run_full_evaluation():
    """Runs end-to-end evaluation across all cases in the dataset."""
    if not DATASET_PATH.exists():
        print(f"[ERROR] Dataset path not found: {DATASET_PATH}")
        return None

    cases = sorted([d for d in os.listdir(DATASET_PATH) if (DATASET_PATH / d).is_dir()])
    print(f"\n========================================================")
    print(f"   REPAIRS_AI: LLM SECURITY VULNERABILITY BENCHMARK     ")
    print(f"========================================================")
    print(f"[*] Found {len(cases)} benchmark test cases.")
    print(f"[*] Evaluated Models: {', '.join(MODELS)}\n")
    
    evaluation_records = []
    summary_stats = {
        "total_cases": len(cases),
        "total_orig_findings": 0,
        "total_orig_flawfinder_hits": 0,
        "models": {m: {"flawfinder_hits": 0, "fixed_cases": 0, "compile_ok": 0} for m in MODELS}
    }

    for idx, case_name in enumerate(cases, 1):
        case_dir = DATASET_PATH / case_name
        info = parse_case_info(case_dir)
        case_files = get_case_files(case_dir, info.get("target_file", ""))
        
        orig_findings_count = len(info["scanner_findings"])
        summary_stats["total_orig_findings"] += orig_findings_count
        
        orig_code_path = case_files["original_code"]
        orig_flawfinder_hits = run_flawfinder_on_code(orig_code_path) if orig_code_path else []
        summary_stats["total_orig_flawfinder_hits"] += len(orig_flawfinder_hits)
        
        orig_compile = test_gcc_compile(orig_code_path) if orig_code_path else {}
        
        case_result = {
            "case": case_name,
            "original_file": case_files["original_filename"],
            "scanners": info["scanners"],
            "dataset_findings_count": orig_findings_count,
            "orig_flawfinder_count": len(orig_flawfinder_hits),
            "orig_flawfinder_details": orig_flawfinder_hits,
            "orig_compile": orig_compile.get("compiled"),
            "models": {}
        }
        
        for m in MODELS:
            m_code = case_files["models"][m]["code_path"]
            m_hits = run_flawfinder_on_code(m_code) if m_code else []
            m_compile = test_gcc_compile(m_code) if m_code else {}
            
            summary_stats["models"][m]["flawfinder_hits"] += len(m_hits)
            if len(orig_flawfinder_hits) > 0 and len(m_hits) < len(orig_flawfinder_hits):
                summary_stats["models"][m]["fixed_cases"] += 1
            if m_compile.get("compiled") is True:
                summary_stats["models"][m]["compile_ok"] += 1
                
            case_result["models"][m] = {
                "file": case_files["models"][m]["filename"],
                "flawfinder_count": len(m_hits),
                "flawfinder_details": m_hits,
                "compiled": m_compile.get("compiled"),
                "has_response": case_files["models"][m]["response_path"] is not None
            }
            
        evaluation_records.append(case_result)
        orig_c = len(orig_flawfinder_hits)
        c_claude = len(case_result['models']['claude-opus-4-1-20250805']['flawfinder_details'])
        c_gpt4 = len(case_result['models']['gpt-4.1-2025-04-14']['flawfinder_details'])
        c_gpt5 = len(case_result['models']['gpt-5-2025-08-07']['flawfinder_details'])
        
        print(f"[{idx:02d}/{len(cases):02d}] {case_name:<7} | Orig: {orig_c:2d} | Claude: {c_claude:2d} | GPT-4.1: {c_gpt4:2d} | GPT-5: {c_gpt5:2d}")

    # Save reports
    report_json_path = BASE_DIR / "evaluation_report.json"
    with open(report_json_path, "w", encoding="utf-8") as fp:
        json.dump({"summary": summary_stats, "cases": evaluation_records}, fp, indent=2)
        
    report_csv_path = BASE_DIR / "evaluation_report.csv"
    with open(report_csv_path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        writer.writerow(["Case", "Target_File", "Scanners", "Dataset_Findings", "Orig_Flawfinder_Hits",
                         "Claude_Hits", "Claude_Compiled", "GPT41_Hits", "GPT41_Compiled", "GPT5_Hits", "GPT5_Compiled"])
        for c in evaluation_records:
            writer.writerow([
                c["case"],
                c["original_file"] or "N/A",
                ";".join(c["scanners"]),
                c["dataset_findings_count"],
                c["orig_flawfinder_count"],
                c["models"]["claude-opus-4-1-20250805"]["flawfinder_count"],
                c["models"]["claude-opus-4-1-20250805"]["compiled"],
                c["models"]["gpt-4.1-2025-04-14"]["flawfinder_count"],
                c["models"]["gpt-4.1-2025-04-14"]["compiled"],
                c["models"]["gpt-5-2025-08-07"]["flawfinder_count"],
                c["models"]["gpt-5-2025-08-07"]["compiled"]
            ])

    print("\n========================================================")
    print("                BENCHMARK EVALUATION SUMMARY             ")
    print("========================================================")
    print(f"Total Test Cases Analyzed: {summary_stats['total_cases']}")
    print(f"Total Static Scanner Findings Recorded in Dataset: {summary_stats['total_orig_findings']}")
    print(f"Total Live Flawfinder Hits in Original Code: {summary_stats['total_orig_flawfinder_hits']}\n")
    print(f"{'Model Name':<28} | {'Remaining Hits':<14} | {'Vulnerability Reduction':<24} | {'Cases Improved':<14}")
    print("-" * 88)
    
    orig_total = summary_stats["total_orig_flawfinder_hits"]
    for m in MODELS:
        m_total = summary_stats["models"][m]["flawfinder_hits"]
        reduction = ((orig_total - m_total) / orig_total * 100) if orig_total > 0 else 0
        improved = summary_stats["models"][m]["fixed_cases"]
        print(f"{m:<28} | {m_total:<14} | {reduction:>21.1f}% | {improved:<14}")
        
    print("========================================================")
    print(f"[+] Output JSON: {report_json_path.name}")
    print(f"[+] Output CSV:  {report_csv_path.name}")
    return evaluation_records

if __name__ == "__main__":
    run_full_evaluation()
