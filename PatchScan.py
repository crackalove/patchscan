#!/usr/bin/env python3

import argparse
import difflib
import hashlib
import json
import os
import pickle
import re
import subprocess
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import r2pipe
from jinja2 import Template

try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None

try:
    import ssdeep as _ssdeep  # type: ignore
except Exception:
    _ssdeep = None

BANNER = r"""
╔══════════════════════════════════════╗
║              PatchScan               ║
║     Binary Patch Analysis Tool       ║
║                                      ║
║ Created by Reverse Engineering Team  ║
║            t.me/ReChamo              ║
╚══════════════════════════════════════╝
""".strip("\n")

def show_banner(disabled: bool = False):
    if not disabled:
        print(BANNER)

@dataclass
class Instr:
    offset: int
    opcode: str
    bytes_hex: str


@dataclass
class FuncInfo:
    key: str
    name: str
    offset: int
    size: int
    instrs: List[Instr]
    norm_text: str
    sha_norm: str
    instr_count: int
    fuzzy: Optional[str]


@dataclass
class BlockInfo:
    offset: int
    ops_norm: str
    sha: str
    instr_count: int
    edges_to: List[int]
    fuzzy: Optional[str]

HEX_RE = re.compile(r'0x[0-9a-fA-F]+')
DEC_BIG_RE = re.compile(r'\b\d{4,}\b')


def normalize_opcode(op: str) -> str:
    s = (op or "").lower().strip()
    s = HEX_RE.sub("<ADDR>", s)
    s = DEC_BIG_RE.sub("<IMM>", s)
    s = re.sub(r"\s+", " ", s)
    return s


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seq_sim(a: str, b: str) -> int:
    return int(round(difflib.SequenceMatcher(None, a, b).ratio() * 100))


class SimilarityEngine:
    """Unified similarity interface: ssdeep or python fallback"""

    def __init__(self, mode: str = "auto"):
        mode = (mode or "auto").lower()
        if mode not in ("auto", "ssdeep", "python"):
            raise ValueError("engine must be auto|ssdeep|python")

        self.mode = mode
        self.has_ssdeep = _ssdeep is not None

        if mode == "ssdeep" and not self.has_ssdeep:
            raise RuntimeError("ssdeep requested but not installed")

        if mode == "auto":
            self.use_ssdeep = self.has_ssdeep
        else:
            self.use_ssdeep = (mode == "ssdeep")

    def hash(self, text: str) -> Optional[str]:
        if not self.use_ssdeep:
            return None
        return _ssdeep.hash(text.encode("utf-8", "replace"))

    def compare(
        self,
        a_text: str,
        b_text: str,
        a_hash: Optional[str],
        b_hash: Optional[str]
    ) -> int:
        if self.use_ssdeep and a_hash and b_hash:
            return _ssdeep.compare(a_hash, b_hash)
        return seq_sim(a_text, b_text)

def safe_filename(s: str, max_len: int = 160) -> str:
    """ASCII-only whitelist for safe filenames (portable across file systems)."""
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    out = []
    for c in (s or ""):
        out.append(c if c in allowed else "_")
    name = "".join(out)[:max_len].strip("._-")
    return name or "item"


def cache_key(path: str, engine: str) -> str:
    p = Path(path)
    st = p.stat()
    raw = f"{p.resolve()}|{st.st_size}|{int(st.st_mtime)}|{engine}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def r2_open_checked(path: str):
    """Open radare2 with validation."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Binary not found: {path}")

    r2 = r2pipe.open(path, flags=["-2"])
    try:
        info = r2.cmdj("ij") or {}
        if not info.get("bin"):
            raise ValueError(f"Not a valid binary (r2 'ij' has no bin): {path}")
        return r2
    except Exception:
        r2.quit()
        raise


def r2_analyze(r2, fast: bool = False):
    """Run analysis with optional fast mode."""
    if fast:
        r2.cmd("aa; aac")  # lighter
    else:
        r2.cmd("aaa")      # full


def r2_list_functions(r2) -> List[dict]:
    return r2.cmdj("aflj") or []


def func_key(name: str, offset: int) -> str:
    if name and not name.startswith(("fcn.", "sub.", "sym.imp.")):
        return name
    return f"@{offset:08x}"


def sort_funcs(funcs: List[dict]) -> List[dict]:
    """Sort functions by importance (size + small name heuristics)."""
    def rank(f):
        name = (f.get("name") or "").lower()
        size = int(f.get("size") or 0)
        bonus = 0
        if name in ("main", "wmain", "winmain"):
            bonus += 10_000
        if any(x in name for x in ("validate", "check", "auth", "verify")):
            bonus += 2_000
        return size + bonus

    return sorted(funcs, key=rank, reverse=True)


def r2_pdfj_instrs(r2, fcn_offset: int) -> List[Instr]:
    r2.cmd(f"s {fcn_offset}")
    dj = r2.cmdj("pdfj") or {}
    ops = dj.get("ops") or []
    out: List[Instr] = []
    for o in ops:
        if not o:
            continue
        out.append(Instr(
            offset=int(o.get("offset") or 0),
            opcode=o.get("opcode") or "",
            bytes_hex=o.get("bytes") or ""
        ))
    return out


def build_funcinfo(r2, f: dict, eng: SimilarityEngine) -> Optional[FuncInfo]:
    name = f.get("name") or "fcn.unknown"
    off = int(f.get("offset") or 0)
    size = int(f.get("size") or 0)
    if size <= 0:
        return None

    key = func_key(name, off)
    instrs = r2_pdfj_instrs(r2, off)

    norm_lines = [normalize_opcode(i.opcode) for i in instrs if i.opcode]
    norm_text = "\n".join(norm_lines)
    sha_norm = sha256_hex(norm_text.encode("utf-8", "replace"))
    fuzzy = eng.hash(norm_text)

    return FuncInfo(
        key=key,
        name=name,
        offset=off,
        size=size,
        instrs=instrs,
        norm_text=norm_text,
        sha_norm=sha_norm,
        instr_count=len(norm_lines),
        fuzzy=fuzzy
    )


def extract_funcs(
    path: str,
    eng: SimilarityEngine,
    max_funcs: Optional[int] = None,
    fast: bool = False
) -> Dict[str, FuncInfo]:
    r2 = r2_open_checked(path)
    try:
        r2_analyze(r2, fast=fast)
        funcs = sort_funcs(r2_list_functions(r2))

        if max_funcs:
            funcs = funcs[:max_funcs]

        iterator = funcs
        if tqdm:
            iterator = tqdm(funcs, desc=f"Analyzing {Path(path).name}", unit="func")

        out: Dict[str, FuncInfo] = {}
        for f in iterator:
            fi = build_funcinfo(r2, f, eng)
            if not fi:
                continue
            k = fi.key
            if k in out:
                k = f"{k}:{fi.offset:08x}"
                fi.key = k
            out[k] = fi
        return out
    finally:
        r2.quit()


def extract_funcs_cached(
    path: str,
    eng: SimilarityEngine,
    cache_dir: Optional[str],
    max_funcs: Optional[int] = None,
    fast: bool = False
) -> Dict[str, FuncInfo]:
    if not cache_dir:
        return extract_funcs(path, eng, max_funcs=max_funcs, fast=fast)

    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    key = cache_key(path, "ssdeep" if eng.use_ssdeep else "python")
    cache_file = Path(cache_dir) / f"{key}.pkl"

    if cache_file.exists():
        try:
            with cache_file.open("rb") as f:
                return pickle.load(f)
        except Exception:
            pass

    res = extract_funcs(path, eng, max_funcs=max_funcs, fast=fast)

    try:
        with cache_file.open("wb") as f:
            pickle.dump(res, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass

    return res


# Worker for parallel extraction (must be top-level for Windows spawn)
def _extract_worker(
    path: str,
    engine_mode: str,
    cache_dir: Optional[str],
    max_funcs: Optional[int],
    fast: bool
) -> Dict[str, FuncInfo]:
    eng = SimilarityEngine(engine_mode)
    return extract_funcs_cached(path, eng, cache_dir, max_funcs=max_funcs, fast=fast)

def match_functions(
    a: Dict[str, FuncInfo],
    b: Dict[str, FuncInfo],
    eng: SimilarityEngine,
    threshold_ssdeep: int = 70,
    threshold_python: int = 82,
) -> Tuple[Dict[str, str], List[str], List[str]]:
    matches: Dict[str, str] = {}
    used_b = set()

    # exact key
    for ak in a:
        if ak in b:
            matches[ak] = ak
            used_b.add(ak)

    # SHA exact
    b_by_sha: Dict[str, List[str]] = {}
    for bk, bf in b.items():
        b_by_sha.setdefault(bf.sha_norm, []).append(bk)

    for ak, af in a.items():
        if ak in matches:
            continue
        cand = [x for x in b_by_sha.get(af.sha_norm, []) if x not in used_b]
        if cand:
            cand.sort()
            matches[ak] = cand[0]
            used_b.add(cand[0])

    # similarity
    a_left = [k for k in a if k not in matches]
    b_left = [k for k in b if k not in used_b]

    b_buckets: Dict[int, List[str]] = {}
    for bk in b_left:
        bucket = b[bk].instr_count // 20
        b_buckets.setdefault(bucket, []).append(bk)

    threshold = threshold_ssdeep if eng.use_ssdeep else threshold_python

    for ak in a_left:
        af = a[ak]
        bucket = af.instr_count // 20

        candidates: List[str] = []
        for bb in (bucket - 1, bucket, bucket + 1):
            candidates.extend(b_buckets.get(bb, []))

        candidates = sorted(set(candidates))

        best = (0, None)
        for bk in candidates:
            if bk in used_b:
                continue
            bf = b[bk]
            if abs(af.instr_count - bf.instr_count) > max(30, int(af.instr_count * 0.5)):
                continue

            score = eng.compare(af.norm_text, bf.norm_text, af.fuzzy, bf.fuzzy)
            if score > best[0] or (score == best[0] and best[1] is not None and bk < best[1]):
                best = (score, bk)

        if best[1] and best[0] >= threshold:
            matches[ak] = best[1]
            used_b.add(best[1])

    removed = sorted([k for k in a if k not in matches])
    added = sorted([k for k in b if k not in used_b])
    return matches, removed, added

def unified_asm_diff(a_func: FuncInfo, b_func: FuncInfo, context_lines: int = 3) -> str:
    a_lines = a_func.norm_text.splitlines()
    b_lines = b_func.norm_text.splitlines()
    diff = difflib.unified_diff(
        a_lines,
        b_lines,
        fromfile=f"{a_func.key} (v1)",
        tofile=f"{b_func.key} (v2)",
        n=context_lines,
        lineterm=""
    )
    return "\n".join(diff)

def r2_cfg_blocks(r2, fcn_offset: int, fast: bool = False) -> List[dict]:
    r2.cmd(f"s {fcn_offset}")
    if fast:
        r2.cmd("af")  # stabilize function analysis for CFG
    g = r2.cmdj("agfj") or []
    if not g:
        return []
    return g[0].get("blocks") or []


def block_info_from_json(bl: dict, eng: SimilarityEngine) -> BlockInfo:
    ops = bl.get("ops") or []
    norm_ops = [normalize_opcode(o.get("opcode") or "") for o in ops if o and o.get("opcode")]
    text = "\n".join(norm_ops)
    sha = sha256_hex(text.encode("utf-8", "replace"))

    edges_to = []
    for e in (bl.get("edges") or []):
        to = e.get("to")
        if to is not None:
            edges_to.append(int(to))

    return BlockInfo(
        offset=int(bl.get("offset") or 0),
        ops_norm=text,
        sha=sha,
        instr_count=len(norm_ops),
        edges_to=edges_to,
        fuzzy=eng.hash(text)
    )


def cfg_diff_dot(
    r2a,
    r2b,
    af: FuncInfo,
    bf: FuncInfo,
    eng: SimilarityEngine,
    fast: bool = False,
    block_threshold_ssdeep: int = 70,
    block_threshold_python: int = 85
) -> Tuple[str, Dict[int, int], List[int]]:
    a_blocks = [block_info_from_json(x, eng) for x in r2_cfg_blocks(r2a, af.offset, fast=fast)]
    b_blocks = [block_info_from_json(x, eng) for x in r2_cfg_blocks(r2b, bf.offset, fast=fast)]

    block_match: Dict[int, int] = {}
    used_b = set()

    b_buckets: Dict[int, List[BlockInfo]] = {}
    for bl in b_blocks:
        b_buckets.setdefault(bl.instr_count // 8, []).append(bl)

    threshold = block_threshold_ssdeep if eng.use_ssdeep else block_threshold_python

    for abl in sorted(a_blocks, key=lambda x: x.offset):
        candidates: List[BlockInfo] = []
        bucket = abl.instr_count // 8
        for bb in (bucket - 1, bucket, bucket + 1):
            candidates.extend(b_buckets.get(bb, []))

        candidates = sorted(candidates, key=lambda x: x.offset)

        best = (0, None)
        for bbl in candidates:
            if bbl.offset in used_b:
                continue
            if abs(abl.instr_count - bbl.instr_count) > max(6, int(abl.instr_count * 0.7)):
                continue
            score = 100 if abl.sha == bbl.sha else eng.compare(abl.ops_norm, bbl.ops_norm, abl.fuzzy, bbl.fuzzy)
            if score > best[0] or (score == best[0] and best[1] is not None and bbl.offset < best[1]):
                best = (score, bbl.offset)

        if best[1] is not None and best[0] >= threshold:
            block_match[abl.offset] = best[1]
            used_b.add(best[1])

    b_by_off = {x.offset: x for x in b_blocks}
    a_by_off = {x.offset: x for x in a_blocks}

    changed = set()
    matched_b = set(block_match.values())

    for boff in b_by_off:
        if boff not in matched_b:
            changed.add(boff)

    for aoff, boff in block_match.items():
        if a_by_off[aoff].sha != b_by_off[boff].sha:
            changed.add(boff)

    lines = []
    lines.append("digraph cfg_v2 {")
    lines.append("  node [shape=box];")

    for boff in sorted(b_by_off.keys()):
        bbl = b_by_off[boff]
        label = f"0x{boff:x}\\nins:{bbl.instr_count}"
        if boff in changed:
            lines.append(f'  n{boff} [label="{label}\\nCHANGED", peripheries=2];')
        else:
            lines.append(f'  n{boff} [label="{label}"];')

    for bbl in sorted(b_blocks, key=lambda x: x.offset):
        for dst in bbl.edges_to:
            lines.append(f"  n{bbl.offset} -> n{dst};")

    lines.append("}")
    return "\n".join(lines), block_match, sorted(changed)

JCC = (
    "je", "jne", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "jo", "jno",
    "js", "jns", "jp", "jnp", "jz", "jnz"
)


def fix_hints_from_diff(diff_text: str) -> Dict:
    score = 0
    signals = []
    minus_j = []
    plus_j = []

    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            l = line[1:].strip()
            if l.startswith(("cmp ", "test ")):
                score += 2
                signals.append({"type": "added_check", "line": l})
            if any(l.startswith(p + " ") for p in JCC):
                score += 2
                plus_j.append(l.split(" ", 1)[0])
                signals.append({"type": "added_branch", "line": l})
            if l.startswith(("ret", "leave")):
                score += 1
                signals.append({"type": "added_exit", "line": l})
            if l.startswith("call "):
                score += 1
                signals.append({"type": "added_call", "line": l})

        if line.startswith("-") and not line.startswith("---"):
            l = line[1:].strip()
            if any(l.startswith(p + " ") for p in JCC):
                minus_j.append(l.split(" ", 1)[0])

    if minus_j and plus_j and minus_j[-1] != plus_j[-1]:
        score += 3
        signals.append({"type": "branch_changed", "from": minus_j[-1], "to": plus_j[-1]})

    return {"score": score, "signals": signals[:30]}

# html Report

HTML_TMPL = Template(r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>PatchScan Report</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; background: #fafafa; }
    .summary { padding: 14px 18px; border: 1px solid #ddd; border-radius: 12px; margin-bottom: 20px; background: white; }
    .fn { border: 1px solid #ddd; border-radius: 12px; padding: 14px 18px; margin: 14px 0; background: white; }
    .badges span { display:inline-block; padding:3px 10px; border:1px solid #bbb; border-radius:999px; margin-right:8px; font-size:13px; }
    .badges .changed { background: #fff3cd; border-color: #ffc107; }
    .badges .unchanged { background: #d4edda; border-color: #28a745; }
    pre { background: #f6f8fa; padding: 12px; overflow:auto; border-radius: 8px; font-size: 13px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
    h1 { color: #333; }
    h3 { color: #555; margin-top: 16px; }
    code { background:#f1f3f5; padding:2px 6px; border-radius:6px; }
  </style>
</head>
<body>
  <h1>PatchScan Report</h1>
  <div class="summary">
    <div><b>Engine:</b> {{ engine }}</div>
    <div><b>v1:</b> <code>{{ v1 }}</code> &nbsp; <b>v2:</b> <code>{{ v2 }}</code></div>
    <div><b>matched:</b> {{ matched }} &nbsp; <b>changed:</b> {{ changed }} &nbsp; <b>unchanged:</b> {{ unchanged }}</div>
    <div><b>added:</b> {{ added }} &nbsp; <b>removed:</b> {{ removed }}</div>
  </div>

  {% for f in functions %}
    <div class="fn">
      <div class="badges">
        <span><b>{{ f.a_key }}</b> → <b>{{ f.b_key }}</b></span>
        <span>fix_score: <b>{{ f.fix_score }}</b></span>
        {% if f.unchanged %}
          <span class="unchanged">UNCHANGED</span>
        {% else %}
          <span class="changed">CHANGED</span>
        {% endif %}
      </div>

      <div class="mono" style="margin-top:10px; font-size:12px; color:#666;">
        v1 @ {{ f.a_offset }} ({{ f.a_ins }} ins) &nbsp; | &nbsp; v2 @ {{ f.b_offset }} ({{ f.b_ins }} ins)
      </div>

      {% if not f.unchanged %}
        <h3>ASM Diff</h3>
        <pre class="mono">{{ f.asm_diff }}</pre>

        <h3>Fix Hints</h3>
        <pre class="mono">{{ f.fix_hints_pre }}</pre>

        {% if f.dot_file %}
        <h3>CFG v2</h3>
        <div class="mono" style="font-size:13px;">
          DOT: <a href="graphs/{{ f.dot_file }}">{{ f.dot_file }}</a>
          {% if f.png_file %} | PNG: <a href="graphs/{{ f.png_file }}">{{ f.png_file }}</a>{% endif %}
        </div>
        {% endif %}
      {% endif %}
    </div>
  {% endfor %}
</body>
</html>
""".strip())


def maybe_render_dot_to_png(dot_path: Path) -> Optional[Path]:
    try:
        png_path = dot_path.with_suffix(".png")
        subprocess.run(
            ["dot", "-Tpng", str(dot_path), "-o", str(png_path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30
        )
        return png_path
    except Exception:
        return None

def run(
    v1: str,
    v2: str,
    out_dir: str,
    engine_mode: str,
    max_funcs: Optional[int] = None,
    cache_dir: Optional[str] = None,
    fast: bool = False,
    no_graphs: bool = False,
    output_format: str = "html",
    parallel: bool = False,
):
    eng = SimilarityEngine(engine_mode)

    outp = Path(out_dir)
    graphs = outp / "graphs"
    if not no_graphs:
        graphs.mkdir(parents=True, exist_ok=True)

    if parallel:
        with ProcessPoolExecutor(max_workers=2) as pool:
            fut_a = pool.submit(_extract_worker, v1, engine_mode, cache_dir, max_funcs, fast)
            fut_b = pool.submit(_extract_worker, v2, engine_mode, cache_dir, max_funcs, fast)
            funcs_a = fut_a.result()
            funcs_b = fut_b.result()
    else:
        funcs_a = extract_funcs_cached(v1, eng, cache_dir, max_funcs=max_funcs, fast=fast)
        funcs_b = extract_funcs_cached(v2, eng, cache_dir, max_funcs=max_funcs, fast=fast)

    matches, removed, added = match_functions(funcs_a, funcs_b, eng)

    r2a = r2_open_checked(v1)
    r2b = r2_open_checked(v2)
    r2_analyze(r2a, fast=fast)
    r2_analyze(r2b, fast=fast)

    results = []
    changed_cnt = 0
    unchanged_cnt = 0

    try:
        match_items = list(matches.items())
        if tqdm:
            match_items = tqdm(match_items, desc="Comparing functions", unit="func")

        for ak, bk in match_items:
            af = funcs_a[ak]
            bf = funcs_b[bk]
            unchanged = (af.sha_norm == bf.sha_norm)

            entry = {
                "a_key": ak,
                "b_key": bk,
                "a_offset": hex(af.offset),
                "b_offset": hex(bf.offset),
                "a_ins": af.instr_count,
                "b_ins": bf.instr_count,
                "unchanged": unchanged,
                "fix_score": 0,
            }

            if unchanged:
                unchanged_cnt += 1
                results.append(entry)
                continue

            changed_cnt += 1
            asm_diff = unified_asm_diff(af, bf, context_lines=3)
            fix = fix_hints_from_diff(asm_diff)

            if no_graphs:
                entry.update({
                    "asm_diff": asm_diff,
                    "fix_hints": fix,
                    "fix_score": fix["score"],
                })
            else:
                dot, block_match, changed_blocks = cfg_diff_dot(
                    r2a, r2b, af, bf, eng,
                    fast=fast
                )
                safe_name = safe_filename(f"{ak}__to__{bk}")
                dot_file = f"{safe_name}.dot"
                dot_path = graphs / dot_file
                dot_path.write_text(dot, encoding="utf-8")

                png_path = maybe_render_dot_to_png(dot_path)
                png_file = png_path.name if png_path else None

                entry.update({
                    "asm_diff": asm_diff,
                    "fix_hints": fix,
                    "fix_score": fix["score"],
                    "cfg_v2": {
                        "dot_file": dot_file,
                        "png_file": png_file,
                        "changed_blocks_v2": [hex(x) for x in changed_blocks],
                        "block_match_count": len(block_match),
                    }
                })
            results.append(entry)

        results.sort(key=lambda x: (x.get("fix_score", 0), x.get("b_ins", 0)), reverse=True)

        report = {
            "meta": {"tool": "PatchScan", "v1": v1, "v2": v2, "engine": ("ssdeep" if eng.use_ssdeep else "python")},
            "summary": {
                "funcs_v1": len(funcs_a),
                "funcs_v2": len(funcs_b),
                "matched": len(matches),
                "changed": changed_cnt,
                "unchanged": unchanged_cnt,
                "added": len(added),
                "removed": len(removed),
            },
            "added": added,
            "removed": removed,
            "functions": results,
        }

        outp.mkdir(parents=True, exist_ok=True)

        # json with bom
        if output_format in ("json", "both"):
            json_text = json.dumps(report, ensure_ascii=False, indent=2)
            (outp / "report.json").write_bytes(b"\xef\xbb\xbf" + json_text.encode("utf-8"))

        # html report
        if output_format in ("html", "both"):
            html_functions = []
            for f in results:
                if f["unchanged"]:
                    html_functions.append({
                        "a_key": f["a_key"], "b_key": f["b_key"],
                        "a_offset": f["a_offset"], "b_offset": f["b_offset"],
                        "a_ins": f["a_ins"], "b_ins": f["b_ins"],
                        "unchanged": True, "fix_score": 0,
                        "asm_diff": "", "fix_hints_pre": "",
                        "dot_file": "", "png_file": None
                    })
                else:
                    html_functions.append({
                        "a_key": f["a_key"], "b_key": f["b_key"],
                        "a_offset": f["a_offset"], "b_offset": f["b_offset"],
                        "a_ins": f["a_ins"], "b_ins": f["b_ins"],
                        "unchanged": False,
                        "fix_score": f["fix_score"],
                        "asm_diff": f["asm_diff"],
                        "fix_hints_pre": json.dumps(f["fix_hints"], ensure_ascii=False, indent=2),
                        "dot_file": f.get("cfg_v2", {}).get("dot_file", ""),
                        "png_file": f.get("cfg_v2", {}).get("png_file"),
                    })

            html = HTML_TMPL.render(
                engine=("ssdeep" if eng.use_ssdeep else "python"),
                v1=v1,
                v2=v2,
                matched=len(matches),
                changed=changed_cnt,
                unchanged=unchanged_cnt,
                added=len(added),
                removed=len(removed),
                functions=html_functions
            )
            (outp / "report.html").write_text(html, encoding="utf-8")

    finally:
        r2a.quit()
        r2b.quit()

    print(f"[+] PatchScan engine: {'ssdeep' if eng.use_ssdeep else 'python'}")
    print(f"[+] Matched: {len(matches)} | Changed: {changed_cnt} | Unchanged: {unchanged_cnt}")
    print(f"[+] Added: {len(added)} | Removed: {len(removed)}")
    if output_format in ("html", "both"):
        print(f"[+] Report: {outp / 'report.html'}")
    if output_format in ("json", "both"):
        print(f"[+] JSON: {outp / 'report.json'}")


def main():
    ap = argparse.ArgumentParser(
        description="PatchScan - Binary Patch Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("v1", help="Old binary")
    ap.add_argument("v2", help="New binary")

    ap.add_argument("--out", default="out_patchscan", help="Output directory")
    ap.add_argument("--engine", default="auto", choices=["auto", "python", "ssdeep"],
                    help="Similarity engine (default: auto)")
    ap.add_argument("--max-funcs", type=int, default=None,
                    help="Limit number of functions (sorted by importance)")
    ap.add_argument("--cache-dir", default=".cache", help="Cache directory (default: .cache)")
    ap.add_argument("--no-cache", action="store_true", help="Disable caching")
    ap.add_argument("--fast", action="store_true", help="Fast analysis mode (lighter r2 analysis)")
    ap.add_argument("--no-graphs", action="store_true", help="Skip CFG graph generation")
    ap.add_argument("--format", default="html", choices=["html", "json", "both"],
                    help="Output format (default: html)")
    ap.add_argument("--parallel", action="store_true",
                    help="Parallel extraction of v1/v2 (2 processes)")
    ap.add_argument("--no-banner", action="store_true",
                help="Disable PatchScan startup banner")

    args = ap.parse_args()

    show_banner(disabled=args.no_banner)

    cache = None if args.no_cache else args.cache_dir

    run(
        args.v1,
        args.v2,
        args.out,
        args.engine,
        max_funcs=args.max_funcs,
        cache_dir=cache,
        fast=args.fast,
        no_graphs=args.no_graphs,
        output_format=args.format,
        parallel=args.parallel
    )


if __name__ == "__main__":
    main()

