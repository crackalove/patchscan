![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

# PatchScan

## PatchScan (EN)

**PatchScan** is a standalone engine for **binary patch analysis and function-level diffing**.

It compares two versions of the same binary, matches functions based on semantic and structural similarity, and highlights **real logic changes** instead of raw noise.

PatchScan is designed as a **headless analysis engine**, not an IDE plugin.  
IDA Pro and Ghidra are supported as **optional frontends** via export scripts.

### What PatchScan Does

- Matches functions between old and new binaries
- Detects logic and control-flow changes
- Highlights added, removed, and modified functions
- Produces machine-readable and human-readable reports
- Bridges Radare2 analysis with IDA Pro and Ghidra

### Core Features

- Function-level diff (matched / modified / added / removed)
- Multi-stage matching (seed, propagation, global resolution)
- Opcode-normalized assembly diff
- Control Flow Graph (CFG) analysis
- Callgraph-aware similarity propagation
- Heuristic detection of patch patterns
- Similarity engines: ssdeep / Python fallback
- Diagnostic PNG plots

### IDE Integration

PatchScan does **not depend on any IDE**, but can export results to:

**IDA Pro**
- Function renaming
- Function comments
- Color-coding by confidence score

**Ghidra**
- Python Script Manager integration
- Function renaming
- Function comments
- Color-coding by confidence score

Color semantics:
- 🟢 High confidence
- 🟡 Medium confidence
- 🔴 Low confidence

### Output Formats

- HTML report
- JSON
- CSV
- Assembly diffs
- PNG diagnostics
- IDA rename script
- Ghidra apply script

### Requirements

Mandatory:
- Python 3.8+
- radare2
- r2pipe
- jinja2

Optional:
- ssdeep
- matplotlib
- graphviz
- tqdm

### Usage

Basic launch:
```bash
python patchscan.py old.bin new.bin
```

Exporting results and IDE scripts:
```bash
python patchscan.py old.bin new.bin --json --ida-script --ghidra-script
```

---


## PatchScan (RU)

**PatchScan** — это самостоятельный движок для **анализа бинарных патчей и diff’а на уровне функций**.

Он сравнивает две версии одного бинарного файла, сопоставляет функции по семантическому и структурному сходству и выделяет **реальные изменения логики**, а не шум от дизассемблера.

PatchScan изначально спроектирован как **headless-инструмент**, а не плагин под IDE.  
IDA Pro и Ghidra поддерживаются как **опциональные фронтенды** через экспортируемые скрипты.

### Что делает PatchScan

- Сопоставляет функции между старой и новой версией бинаря
- Определяет изменения логики и управляющего потока
- Показывает добавленные, удалённые и модифицированные функции
- Генерирует машиночитаемые и человекочитаемые отчёты
- Связывает анализ Radare2 с визуализацией в IDA Pro и Ghidra

### Ключевые возможности

- Diff на уровне функций:
  - совпавшие
  - изменённые
  - добавленные
  - удалённые
- Многостадийное сопоставление:
  - seed
  - propagation
  - global resolution
- ASM-diff с нормализацией инструкций
- Анализ графа управления потоком (CFG)
- Propagation с учётом графа вызовов
- Эвристическое обнаружение патчей
- Similarity engine:
  - `ssdeep`
  - Python fallback (`difflib`)
- Диагностические PNG-графики

### Интеграция с IDE

PatchScan **не зависит от IDE**, но умеет экспортировать результаты в:

**IDA Pro**
- Переименование функций
- Комментарии к функциям
- Цветовая маркировка по уверенности сопоставления

**Ghidra**
- Python-скрипт для Script Manager
- Переименование функций
- Комментарии
- Цветовая маркировка по уверенности

Цветовая семантика:
- 🟢 Высокая уверенность
- 🟡 Средняя уверенность
- 🔴 Низкая уверенность / подозрительное совпадение

### Форматы вывода

- HTML-отчёт
- JSON
- CSV
- ASM-diff
- PNG-графики
- IDA rename-скрипт
- Ghidra apply-скрипт

### Требования

Обязательные:
- Python 3.8+
- radare2
- r2pipe
- jinja2

Опциональные:
- ssdeep
- matplotlib
- graphviz
- tqdm

### Использование

Базовый запуск:
```bash
python patchscan.py old.bin new.bin
```

Экспорт результатов и IDE-скриптов:
```bash
python patchscan.py old.bin new.bin --json --ida-script --ghidra-script
```
