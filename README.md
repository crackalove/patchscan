![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

# PatchScan

---

## PatchScan (EN)

**PatchScan** is a reverse engineering tool for **binary patch analysis and function-level diffing**.

It compares two versions of the same binary executable, matches functions using heuristic similarity scoring, and highlights logic changes, structural differences, and control-flow modifications.

PatchScan generates **interactive HTML reports by default**, with optional JSON/CSV exports and diagnostic graphs.

The tool is powered by **radare2 (via r2pipe)**, instruction normalization, control-flow analysis, hashing, and fuzzy similarity scoring.

### Key Features

- Function-level comparison:
  - matched
  - changed
  - added
  - removed
- Multi-stage similarity matching (seed → propagation → global)
- Opcode-normalized assembly diff
- Control Flow Graph (CFG) analysis
- Heuristic detection of patch-like changes:
  - new `cmp` / `test`
  - new branches
  - callgraph changes
- Report formats:
  - **HTML (default)**
  - JSON (`--json`)
  - CSV (`--csv`)
- Similarity engines:
  - `ssdeep` (if available)
  - Python fallback (`difflib`)
- PNG diagnostic plots (score distribution, precision)
- IDAPython rename script export

### Requirements

**Mandatory**
- Python 3.8+
- radare2
- Python packages:
  - `r2pipe`
  - `jinja2`

**Optional**
- `ssdeep` (Linux/macOS)
- `matplotlib` (PNG plots)
- `graphviz` (`dot`) for CFG rendering
- `tqdm` for progress bars

### Installation

**Linux / macOS**
```bash
pip install -r requirements_linux.txt
```

**Windows**
```bash
pip install -r requirements_windows.txt
```

> On Windows, `ssdeep` is optional. PatchScan will automatically fall back to the Python similarity engine.

### Usage

Default run (HTML report):
```bash
python patchscan.py old.bin new.bin
```

JSON output:
```bash
python patchscan.py old.bin new.bin --json
```

### Output Files

- `*.html` — main analysis report
- `*.json` — structured diff (optional)
- `*.csv` — match table (optional)
- `*_diffs/` — assembly diff files
- `*_score_hist.png` — score distribution plot
- `*_precision_curve.png` — precision curve
- `*_ida_rename.py` — IDA rename script


### Disclaimer

This tool is intended exclusively for **legal reverse engineering**, patch analysis, and research of binary code changes.

---

## PatchScan (RU)

**PatchScan** — это инструмент для реверс-инжиниринга и анализа патчей, предназначенный для сравнения **двух версий одного бинарного файла**.

Он сопоставляет функции, выявляет изменения в логике, анализирует структуру и граф управления потоком, а также формирует удобные отчёты для анализа исправлений.

По умолчанию PatchScan генерирует **HTML-отчёт**, с возможностью экспорта в JSON и CSV.

Инструмент основан на **radare2 (через r2pipe)**, нормализации инструкций, CFG-анализе и эвристическом similarity-скоринге.

### Возможности

- Diff на уровне функций:
  - совпавшие
  - изменённые
  - добавленные
  - удалённые
- Многостадийное сопоставление (seed → propagation → global)
- ASM diff с нормализацией опкодов
- Анализ графа управления потоком (CFG)
- Эвристика patch-изменений:
  - новые `cmp` / `test`
  - новые ветвления
  - изменения вызовов
- Форматы отчётов:
  - **HTML (по умолчанию)**
  - JSON (`--json`)
  - CSV (`--csv`)
- Similarity engine:
  - `ssdeep` (если доступен)
  - Python fallback (`difflib`)
- PNG-графики (распределение score, precision)
- Экспорт IDAPython-скрипта для переименования функций

### Требования

**Обязательно**
- Python 3.8+
- radare2
- Python-библиотеки:
  - `r2pipe`
  - `jinja2`

**Опционально**
- `ssdeep` (Linux/macOS)
- `matplotlib` — PNG-графики
- `graphviz` (`dot`) — визуализация CFG
- `tqdm` — прогресс-бар

### Установка

**Linux / macOS**
```bash
pip install -r requirements_linux.txt
```

**Windows**
```bash
pip install -r requirements_windows.txt
```

> В Windows `ssdeep` не обязателен — PatchScan автоматически использует Python fallback.

### Использование

HTML-отчёт по умолчанию:
```bash
python patchscan.py old.bin new.bin
```

JSON-отчёт:
```bash
python patchscan.py old.bin new.bin --json
```

### Выходные файлы

- `*.html` — основной отчёт анализа
- `*.json` — структурированный diff (опционально)
- `*.csv` — таблица сопоставлений функций (опционально)
- `*_diffs/` — файлы ASM-diff
- `*_score_hist.png` — распределение значений score
- `*_precision_curve.png` — кривая "точность"
- `*_ida_rename.py` — IDAPython-скрипт для переименования функций


### Дисклеймер

Инструмент предназначен исключительно для **легального реверс-инжиниринга**, анализа патчей и исследования изменений бинарного кода.
