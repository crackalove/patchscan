# PatchScan

**PatchScan** is a reverse engineering utility designed to detect and document code changes between two versions of the same binary executable.

It performs function-level comparison, generates unified assembly diffs, builds CFG graphs, and produces structured HTML/JSON reports for patch analysis.

The tool is powered by **radare2 (via r2pipe)**, instruction normalization, SHA-256 hashing, and fuzzy similarity scoring (ssdeep or Python fallback).

---

## Key Features

- Function-level diffing:
  - matched / changed / unchanged / added / removed
- Unified assembly diff with opcode normalization
- CFG graph export (DOT + optional PNG rendering via Graphviz)
- Heuristic fix-likelihood detection (cmp/test additions, new branching, new calls)
- Report formats:
  - HTML
  - JSON
  - BOTH
- Similarity engines:
  - `ssdeep` (preferred)
  - Python fallback (`difflib.SequenceMatcher`)
- Optional caching for faster re-analysis
- Optional parallel extraction mode

---

## Requirements

### Mandatory
- Python 3.8+
- **radare2**
- Python dependencies:
  - `r2pipe`
  - `jinja2`

### Optional (Recommended)
- `tqdm` — progress bars
- `ssdeep` — fuzzy hashing (Linux/macOS only)
- Graphviz (`dot`) — for PNG rendering from DOT graphs

---

## Installation

### Linux / macOS

Install full dependencies (Includes ssdeep for better fuzzy similarity) :

```bash
pip install -r requirements_linux.txt
```
### **Windows**

Install Windows-compatible dependencies:

```bash
pip install -r requirements_windows.txt
```

Windows version does not include ssdeep because it often fails to build.
PatchScan will automatically use the Python fallback similarity engine.

---

## Usage

Basic binary diff:

```bash
python patchscan.py old.bin new.bin --out report_dir
```
