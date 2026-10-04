# AI Code Risk Analyzer

A new module bolted onto SentinelShield that scans **this project's own
codebase** (not WiFi traffic) for security risk in AI-generated code,
implementing six novelties end-to-end.

## Where things live

```
code_risk_analyzer/
  engine.py               orchestrator: CodeRiskEngine.scan_project()
  structural_analysis.py  Novelty 1a - AST/CFG complexity, nesting, shape hashing
  behavioral_patterns.py  Novelty 1b - dangerous call / insecure-pattern detection
  dependency_risk.py      Novelty 1c - requirements.txt / package.json risk
  contextual_metadata.py  Novelty 1d - AI-authorship & review-debt heuristics
  fingerprint.py          Novelty 1  - combines the 4 dimensions into one score
  prompt_intelligence.py  Novelty 3  - risky-prompt detection + code correlation
  propagation_tracker.py  Novelty 4  - repeated insecure templates across files
  remediation.py          Novelty 5  - safe auto-fix generation & application
  rule_engine.py          Novelty 6  - adaptive JSON rule store + feedback loop
  db.py                   sqlite persistence (code_risk.db, created at project root)
  data/
    pattern_rules.json        adaptive/learned rules (auto-created on first run)
    vulnerable_packages.json  seed dependency-CVE database

code_risk_scan.py     Novelty 2 - CI/CD CLI entrypoint (pipeline gate)
code_risk_watch.py    Novelty 2 - real-time local watch mode (watchdog)
.github/workflows/code_risk_scan.yml   ready-made CI pipeline
pages/code_risk_analysis.py            Streamlit UI ("🧪 Code Risk Analyzer" tab)
```

## Running it

**In the app:** launch `dashboard.py` as usual (`streamlit run dashboard.py`)
and open the **🧪 Code Risk Analyzer** tab in the sidebar. Click **Run Full
Scan**.

**From the command line / CI:**
```bash
python code_risk_scan.py --path . --threshold 70 --json code_risk_report.json
# exit code 0 = pass, 1 = risk threshold exceeded, 2 = scan error
```

**Real-time while coding:**
```bash
python code_risk_watch.py --path .
```

## The six novelties, concretely

1. **Multi-Dimensional Risk Analysis** -- every file gets a composite
   score from structural (AST/CFG), behavioral (dangerous calls),
   dependency (manifest/CVE), and contextual (AI-authorship heuristics)
   signals, weighted and combined in `fingerprint.py`.
2. **Real-Time CI/CD Integration** -- `code_risk_scan.py` gates a
   pipeline on score/severity; the included GitHub Actions workflow
   runs it on every push/PR; `code_risk_watch.py` gives sub-second
   local feedback as files are saved.
3. **Prompt-Aware Security Intelligence** -- log the prompt that
   produced a file (UI tab or `--prompt-file`) and the engine escalates
   a file's score when risky prompt language ("disable ssl
   verification", "skip auth", ...) co-occurs with real findings in
   that file.
4. **Vulnerability Propagation Tracking** -- every finding carries a
   structural "shape hash" of its enclosing function; `propagation_tracker.py`
   clusters findings that share a hash across multiple files, surfacing
   copy-pasted/re-prompted insecure templates before they spread further.
5. **Self-Healing Automated Correction** -- `remediation.py` generates
   concrete, reviewable diffs for a defined set of safe rewrites
   (`eval`->`ast.literal_eval`, `md5`->`sha256`, `shell=True`->`shell=False`,
   `yaml.load`->`yaml.safe_load`, etc.) and can apply them (with a
   `.bak` backup) from the UI or programmatically.
6. **Adaptive Continuous Learning** -- new patterns (simulating a fresh
   CVE feed or a developer-submitted signature) are added as *data* to
   `data/pattern_rules.json` via `rule_engine.add_rule()`, no code
   change required; marking a finding as a false positive lowers that
   rule's confidence weight (and eventually suppresses it), while
   confirmed true positives raise it -- both persisted in `code_risk.db`.

## Notes / limitations

- This scans **Python + requirements.txt/package.json** in the
  project; it does not (and is not meant to) touch the WiFi detection
  logic itself.
- The auto-fix engine only rewrites the small set of mechanically-safe
  patterns listed in `remediation.py`; everything else surfaces a
  human-readable `fix_hint` for manual review -- it intentionally does
  not attempt "smart" AI-based rewriting that could itself introduce bugs.
- `networkx` is used for the propagation graph and `watchdog` for the
  real-time watcher; both are already present in this environment.
