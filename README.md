# PatchScan (EN)

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

## **Output Files**

- Depending on enabled options, PatchScan produces:

- report.html — main patch analysis report

- report.json — structured diff export

- graphs/ *.dot — CFG graphs for modified functions

- graphs/ *.png — rendered graphs (if Graphviz is installed)

---

## **CLI Options**

- --out DIR — output directory

- --engine {auto,python,ssdeep} — similarity engine

- --max-funcs N — limit number of analyzed functions

- --no-cache — disable caching

- --fast — lightweight radare2 analysis mode

- --no-graphs — disable CFG generation

- --format {html,json,both} — output report format

- --parallel — parallel extraction mode

- --no-banner — disable startup banner

---

## **Disclaimer**

This tool is intended strictly for legal reverse engineering, patch research, and binary change analysis.

---

# PatchScan (RU)

**PatchScan** - это инструмент для реверс-инжиниринга, предназначенный для обнаружения и документирования изменений кода между двумя версиями одного и того же бинарного исполняемого файла.

Он выполняет сравнение на уровне функций, генерирует unified assembly diff, строит CFG-графы и создаёт структурированные отчёты в форматах HTML/JSON для анализа патчей.

Инструмент основан на **radare2 (через r2pipe)**, нормализации инструкций, SHA-256 хешировании и fuzzy similarity оценке (ssdeep или Python fallback).

---

## Основные возможности

- Diff на уровне функций:
  - совпавшие / изменённые / неизменённые / добавленные / удалённые
- Unified ASM diff с нормализацией опкодов
- Экспорт CFG-графов (DOT + опциональный PNG через Graphviz)
- Эвристика определения fix-изменений (добавление cmp/test, новые ветвления, новые вызовы)
- Форматы отчётов:
  - HTML
  - JSON
  - Оба сразу
- Similarity engine:
  - `ssdeep` (предпочтительный вариант)
  - Python fallback (`difflib.SequenceMatcher`)
- Опциональное кэширование для ускорения повторного анализа
- Опциональный параллельный режим извлечения функций

---

## Требования

### Обязательно
- Python 3.8+
- **radare2**
- Зависимости Python:
  - `r2pipe`
  - `jinja2`

### Необязательно (рекомендуется)
- `tqdm` — прогресс-бар
- `ssdeep` — fuzzy hashing (только Linux/macOS)
- Graphviz (`dot`) — для генерации PNG из DOT-графов

---

## Установка

### Linux / macOS

Установка полного набора зависимостей (включает ssdeep для лучшей similarity оценки):

```bash
pip install -r requirements_linux.txt
```
### **Windows**

Установка зависимостей, совместимых с Windows:

```bash
pip install -r requirements_windows.txt
```

Windows-версия не включает ssdeep, поскольку он часто не собирается.
PatchScan автоматически использует Python fallback similarity engine.
---

## Использование

Базовый binary diff:

```bash
python patchscan.py old.bin new.bin --out report_dir
```

## **Выходные файлы**

В зависимости от выбранных опций PatchScan создаёт:

- report.html — основной отчёт анализа патча

- report.json — структурированный экспорт diff

- graphs/*.dot — CFG-графы изменённых функций

- graphs/*.png — визуализированные графы (если установлен Graphviz)

---

## **CLI Аргументы**

- --out DIR — директория вывода

- --engine {auto,python,ssdeep} — similarity engine

- --max-funcs N — ограничение числа анализируемых функций

- --no-cache — отключить кэширование

- --fast — облегчённый режим анализа radare2

- --no-graphs — отключить генерацию CFG

- --format {html,json,both} — формат отчёта

- --parallel — параллельный режим извлечения

- --no-banner — отключить стартовый баннер

---

## **Предупреждение**

Этот инструмент предназначен исключительно для легального реверс-инжиниринга, анализа патчей и исследования изменений в бинарных файлах.

---
