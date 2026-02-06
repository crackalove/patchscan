from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import math
from dataclasses import dataclass
from collections import Counter, defaultdict, deque
from typing import Dict, List, Optional, Tuple, Set, Any


try:
    import r2pipe
except ImportError:
    r2pipe = None


PERFECT_MATCH_THRESHOLD = 99
DEFAULT_SIMILARITY_THRESHOLD = 78
DEFAULT_BUCKET_GRANULARITY = 15

DEFAULT_SEED_THRESHOLD = 92
DEFAULT_PROP_ROUNDS = 2
DEFAULT_PROP_BONUS_MAX = 8

DEFAULT_GLOBAL_TOPK = 8
DEFAULT_GLOBAL_MIN_SCORE = 65

MAX_ANCHOR_CANDIDATES = 700
MIN_ANCHOR_CANDIDATES_BEFORE_BUCKETS = 30
BUCKET_NEIGHBORHOOD_SMALL = 2
BUCKET_NEIGHBORHOOD_FALLBACK = 3

MAX_DELTA_MIN = 40
MAX_DELTA_FRAC = 0.45
MAX_DELTA_CAP = 220
ANCHOR_OVERRIDE_MIN = 0.35
CFG_OVERRIDE_MIN = 0.60

WL_ITERS = 3
MAX_DIFF_LINES = 600
MAX_REPORT_UNMATCHED_KEYS = 200

DEFAULT_PRECISION_SCORE = 95

DEFAULT_ASSIGN_MODE = "greedy"
DEFAULT_HUNGARIAN_MIN_SCORE = 85
DEFAULT_HUNGARIAN_MAX_N = 120
DEFAULT_HUNGARIAN_MISSING_PENALTY = 50


BANNER = r"""
╔══════════════════════════════════════╗
║              PatchScan               ║
║     Binary Patch Analysis Tool       ║
║                                      ║
║ Created by Reverse Engineering Team  ║
║            t.me/ReChamo              ║
╚══════════════════════════════════════╝
"""



def make_logger(quiet: bool) -> logging.Logger:
    logger = logging.getLogger("PatchScan")
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.ERROR if quiet else logging.INFO)
    handler.setFormatter(logging.Formatter("%(message)s"))
    if not logger.handlers:
        logger.addHandler(handler)
    return logger


class SimilarityEngine:
    def __init__(self, prefer_ssdeep: bool = True, logger: Optional[logging.Logger] = None):
        self._logger = logger or logging.getLogger("PatchScan")
        self._ssdeep = None
        self._difflib = None
        if prefer_ssdeep:
            try:
                import ssdeep
                self._ssdeep = ssdeep
            except ImportError as e:
                self._logger.info(f"[*] ssdeep не найден, использую difflib ({e}).")

    @property
    def has_ssdeep(self) -> bool:
        return self._ssdeep is not None

    def hash(self, text: str) -> Optional[str]:
        if not self._ssdeep:
            return None
        try:
            return self._ssdeep.hash(text)
        except Exception as e:
            self._logger.info(f"[*] ssdeep.hash не сработал: {e}")
            return None

    def compare(self, a_text: str, b_text: str, a_hash: Optional[str], b_hash: Optional[str]) -> int:
        if self._ssdeep and a_hash and b_hash:
            try:
                return int(self._ssdeep.compare(a_hash, b_hash))
            except Exception as e:
                self._logger.info(f"[*] ssdeep.compare не сработал: {e}")
        if self._difflib is None:
            import difflib
            self._difflib = difflib
        try:
            r = self._difflib.SequenceMatcher(None, a_text, b_text).ratio()
            return int(round(r * 100))
        except Exception as e:
            self._logger.info(f"[*] difflib сравнение не сработало: {e}")
            return 0


HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
DEC_BIG_RE = re.compile(r"\b\d{5,}\b")
REG_RE = re.compile(
    r"\b("
    r"r1[0-5]|r[8-9]|r[0-7]|"
    r"e[abcd]x|e[sd]i|e[sb]p|eip|esp|eax|ebx|ecx|edx|esi|edi|"
    r"[abcd]x|[sb]p|[sd]i|"
    r"xmm\d+|ymm\d+|zmm\d+|st\d+|mm\d+"
    r")\b",
    re.IGNORECASE
)
SIZE_RE = re.compile(r"\b(byte|word|dword|qword|tbyte|xword|oword)\b", re.IGNORECASE)
RIP_REL_RE = re.compile(r"\[rip[+-]0x[0-9a-fA-F]+\]", re.IGNORECASE)
STR_TOKEN_RE = re.compile(r"\bstr\.[A-Za-z0-9_.$@?]+\b")
IMP_TOKEN_RE = re.compile(r"\b(?:sym\.imp|imp)\.[A-Za-z0-9_.$@?]+\b")
CALL_TARGET_RE = re.compile(r"\bcall\s+(.+)$", re.IGNORECASE)


def normalize_opcode(op: str) -> str:
    def _hex_norm(m: re.Match) -> str:
        try:
            v = int(m.group(0), 16)
        except Exception:
            return "<ADDR>"
        if v <= 0xFFFF:
            return f"0x{v:x}"
        return "<ADDR>"

    s = (op or "").lower().strip()
    s = RIP_REL_RE.sub("[rip+<ADDR>]", s)
    s = SIZE_RE.sub("<SZ>", s)
    s = REG_RE.sub("<REG>", s)
    s = HEX_RE.sub(_hex_norm, s)
    s = DEC_BIG_RE.sub("<IMM>", s)
    s = re.sub(r"\s+", " ", s)
    return s



def opcode_mnemonic(norm_op: str) -> str:
    return (norm_op.split(" ", 1)[0] if norm_op else "").strip()


def sha256_hex(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()


def validate_binary_path(path: str) -> None:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Бинарник не найден: {path}")
    if not os.access(path, os.R_OK):
        raise PermissionError(f"Нет прав на чтение бинарника: {path}")


def validate_out_prefix(prefix: str) -> str:
    d = os.path.dirname(prefix)
    if d:
        absd = os.path.abspath(d)
        if not os.path.exists(absd):
            os.makedirs(absd, exist_ok=True)
        if not os.path.isdir(absd):
            raise NotADirectoryError(f"Путь вывода не является директорией: {absd}")
    return prefix


def _wl_hash_cfg(edges: List[Tuple[int, int]], node_labels: Dict[int, str], iters: int = WL_ITERS) -> Tuple[str, List[str]]:
    """Weisfeiler–Lehman hashing for CFG.
    Returns (stable_hash, sorted_color_multiset). The multiset is used for *soft* CFG similarity.
    """
    import hashlib
    nodes = set(node_labels.keys())
    for u, v in edges:
        nodes.add(u)
        nodes.add(v)
    adj: Dict[int, List[int]] = {n: [] for n in nodes}
    for u, v in edges:
        adj[u].append(v)

    def h(x: str) -> str:
        return hashlib.sha256(x.encode("utf-8", "replace")).hexdigest()[:16]

    colors: Dict[int, str] = {n: h(node_labels.get(n, "")) for n in nodes}
    for _ in range(iters):
        new_colors: Dict[int, str] = {}
        for n in nodes:
            neigh = sorted(colors[m] for m in adj.get(n, []))
            blob = colors[n] + "|" + "|".join(neigh)
            new_colors[n] = h(blob)
        colors = new_colors

    color_multiset = sorted(colors.values())
    sig = f"n={len(nodes)};e={len(edges)};" + ",".join(color_multiset)
    return hashlib.sha256(sig.encode("utf-8", "replace")).hexdigest(), color_multiset


def _cfg_from_agfj(agfj: Any) -> Tuple[int, int, str, List[str]]:
    if not agfj or not isinstance(agfj, list):
        return 0, 0, "", []
    fn = agfj[0]
    if not isinstance(fn, dict):
        return 0, 0, "", []
    blocks = fn.get("blocks", []) or []
    if not isinstance(blocks, list):
        return 0, 0, "", []

    bb_count = len(blocks)
    edges: List[Tuple[int, int]] = []
    labels: Dict[int, str] = {}
    off_to_id: Dict[int, int] = {}

    for i, b in enumerate(blocks):
        if not isinstance(b, dict):
            continue
        off = int(b.get("offset", 0) or 0)
        off_to_id[off] = i
        labels[i] = f"bb:{int(b.get('size', 0) or 0)}"

    for b in blocks:
        if not isinstance(b, dict):
            continue
        src_off = int(b.get("offset", 0) or 0)
        src = off_to_id.get(src_off)
        if src is None:
            continue
        for j in (b.get("jump"), b.get("fail")):
            if j is None:
                continue
            try:
                dst_off = int(j)
            except (TypeError, ValueError):
                continue
            dst = off_to_id.get(dst_off)
            if dst is None:
                continue
            edges.append((src, dst))

    edge_count = len(edges)
    cfg_wl, wl_colors = _wl_hash_cfg(edges, labels) if bb_count > 0 else ("", [])
    return bb_count, edge_count, cfg_wl, wl_colors


@dataclass
class Instr:
    offset: int
    opcode: str


@dataclass
class FuncInfo:
    key: str
    name: str
    offset: int
    size: int
    instrs: List[Instr]
    raw_text: str
    norm_text: str
    sha_norm: str
    instr_count: int
    fuzzy: Optional[str]
    op_hist: Dict[str, int]
    call_count: int
    jcc_count: int
    ret_count: int

    str_refs: Set[str]
    imp_refs: Set[str]
    const_refs: Dict[str, int]
    mnem3: Dict[str, int]

    callees_raw: Set[str]
    bb_count: int
    edge_count: int
    cfg_wl: str
    cfg_wl_colors: List[str]
    cfg_wl_color_counts: Dict[str, int]

    callees_resolved: Set[str]
    callers_resolved: Set[str]


@dataclass
class Match:
    a_key: str
    b_key: str
    score: int
    reason: str


def r2_open(path: str, flags: Optional[List[str]] = None):
    if r2pipe is None:
        raise RuntimeError("r2pipe не установлен. Установи: pip install r2pipe")
    cmd_flags = flags or []
    return r2pipe.open(path, flags=cmd_flags)


def r2_cmdj(r2, cmd: str) -> Any:
    try:
        return r2.cmdj(cmd)
    except Exception:
        return None


def r2_cmd(r2, cmd: str) -> str:
    try:
        return r2.cmd(cmd)
    except Exception:
        return ""


def analyze_binary(r2, logger: logging.Logger, quiet: bool) -> None:
    if not quiet:
        logger.info("[*] radare2: анализирую (aaa)...")
    r2_cmd(r2, "aaa")
    if not quiet:
        logger.info("[*] radare2: анализ завершён.")


def _extract_anchors_from_ops(ops: List[str]) -> Tuple[Set[str], Set[str]]:
    sset: Set[str] = set()
    iset: Set[str] = set()
    for op in ops:
        for m in STR_TOKEN_RE.findall(op):
            sset.add(m.lower())
        for m in IMP_TOKEN_RE.findall(op):
            iset.add(m.lower())
    return sset, iset


def _normalize_call_target(t: str) -> str:
    s = (t or "").lower().strip()
    for p in ("sym.", "fcn.", "loc.", "obj."):
        if s.startswith(p):
            s = s[len(p):]
            break
    s = HEX_RE.sub("<ADDR>", s)
    return s


def _extract_callees_from_ops(ops: List[str]) -> Set[str]:
    out: Set[str] = set()
    for op in ops:
        m = CALL_TARGET_RE.search(op)
        if not m:
            continue
        t = m.group(1).strip()
        tl = t.lower()
        if tl.startswith("qword") or tl.startswith("dword") or tl.startswith("word") or tl.startswith("byte"):
            out.add("memcall")
            continue
        if "[" in tl and "]" in tl:
            out.add("memcall")
            continue
        if REG_RE.search(tl):
            out.add("regcall")
            continue
        mh = HEX_RE.search(tl)
        if mh:
            try:
                addr = int(mh.group(0), 16)
                out.add(f"addr:0x{addr:x}")
            except Exception:
                out.add("addr:<bad>")
            continue
        out.add(_normalize_call_target(t))
    return out

IMM_DEC_RE = re.compile(r"(?<![A-Za-z0-9_])(-?\d+)(?![A-Za-z0-9_])")

def _extract_constants_from_ops(ops: List[str]) -> Counter:
    """Extract immediates from raw op strings. Keeps small/medium values.
    Filters ultra-common constants to reduce false matches.
    """
    c = Counter()
    common = {0, 1, -1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096}
    for op in ops:
        for hx in HEX_RE.findall(op):
            try:
                v = int(hx, 16)
            except Exception:
                continue
            if v in common:
                continue
            if v >= 0x1000 and (v % 0x1000) == 0:
                continue
            if v <= 0xFFFFF:
                c[f"0x{v:x}"] += 1
        for dm in IMM_DEC_RE.findall(op):
            try:
                v = int(dm, 10)
            except Exception:
                continue
            if v in common:
                continue
            if abs(v) >= 4096 and (abs(v) % 4096) == 0:
                continue
            if abs(v) <= 1_000_000:
                c[str(v)] += 1
    return c


def _mnemonic_3grams(mnems: List[str]) -> Counter:
    c = Counter()
    if len(mnems) < 3:
        return c
    for a, b, d in zip(mnems, mnems[1:], mnems[2:]):
        if not a or not b or not d:
            continue
        c[f"{a}|{b}|{d}"] += 1
    return c


def multiset_overlap_ratio(a: Dict[str, int], b: Dict[str, int]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = 0
    a_sum = 0
    b_sum = 0
    for k, av in a.items():
        a_sum += av
        bv = b.get(k)
        if bv:
            inter += min(av, bv)
    for bv in b.values():
        b_sum += bv
    denom = min(a_sum, b_sum) if min(a_sum, b_sum) > 0 else 1
    return inter / denom


def build_idf_weights(tokens_to_keys: Dict[str, Set[str]], n_docs: int) -> Dict[str, float]:
    """IDF-like weights for anchor tokens to prefer rare anchors."""
    w: Dict[str, float] = {}
    for tok, keys in tokens_to_keys.items():
        df = len(keys)
        w[tok] = math.log((n_docs + 1.0) / (df + 1.0)) + 1.0
    return w


def build_ngram_index(funcs: Dict[str, FuncInfo], max_df: Optional[int] = None) -> Dict[str, Set[str]]:
    idx: Dict[str, Set[str]] = defaultdict(set)
    n_docs = len(funcs) if funcs else 0
    if max_df is None:
        max_df = max(30, int(0.02 * n_docs)) if n_docs else 30
    df = Counter()
    for k, fi in funcs.items():
        for g in fi.mnem3.keys():
            df[g] += 1
    for k, fi in funcs.items():
        for g in fi.mnem3.keys():
            if df[g] <= max_df:
                idx[g].add(k)
    return idx


def candidate_keys_weighted(
    a: FuncInfo,
    b_anchor_idx: Dict[str, Set[str]],
    anchor_w: Dict[str, float],
    b_ngram_idx: Dict[str, Set[str]],
    limit: int
) -> List[str]:
    scores: Dict[str, float] = defaultdict(float)

    for s in a.str_refs:
        tok = "S:" + s
        w = anchor_w.get(tok, 1.0)
        for k in b_anchor_idx.get(tok, set()):
            scores[k] += w

    for imp in a.imp_refs:
        tok = "I:" + imp
        w = anchor_w.get(tok, 1.0)
        for k in b_anchor_idx.get(tok, set()):
            scores[k] += w

    for g, cnt in a.mnem3.items():
        if cnt <= 0:
            continue
        w = 0.25 * min(3, cnt)
        for k in b_ngram_idx.get(g, set()):
            scores[k] += w

    if not scores:
        return []
    return [k for k, _ in sorted(scores.items(), key=lambda x: (-x[1], x[0]))[:limit]]


def tie_break_bonus(af: FuncInfo, bf: FuncInfo) -> int:
    const_sim = multiset_overlap_ratio(af.const_refs, bf.const_refs)
    ng_sim = multiset_overlap_ratio(af.mnem3, bf.mnem3)

    def rel(x: int, y: int) -> float:
        m = max(1, x, y)
        return 1.0 - (abs(x - y) / m)

    deg = 0.5 * rel(len(af.callers_resolved), len(bf.callers_resolved)) + 0.5 * rel(len(af.callees_resolved), len(bf.callees_resolved))
    val = 0.45 * const_sim + 0.45 * ng_sim + 0.10 * deg
    return int(round(min(2.0, val * 2.0)))




def _disasm_function_instrs(r2, f: dict) -> List[Instr]:
    off = int(f.get("offset", 0) or 0)
    size = int(f.get("size", 0) or 0)
    if size <= 0:
        return []

    r2_cmd(r2, f"s {off}")
    pdfj = r2_cmdj(r2, "pdfj")

    instrs: List[Instr] = []
    if isinstance(pdfj, dict):
        ops = pdfj.get("ops")
        if isinstance(ops, list):
            for o in ops:
                if not isinstance(o, dict):
                    continue
                if o.get("type") == "invalid":
                    continue
                oo = o.get("opcode")
                if not oo:
                    continue
                try:
                    ooff = int(o.get("offset", off) or off)
                except (TypeError, ValueError):
                    ooff = off
                instrs.append(Instr(offset=ooff, opcode=str(oo)))
            if instrs:
                return instrs

    pdj = r2_cmdj(r2, f"pDj {size}")
    if isinstance(pdj, list):
        for o in pdj:
            if not isinstance(o, dict):
                continue
            if o.get("type") == "invalid":
                continue
            oo = o.get("opcode")
            if not oo:
                continue
            try:
                ooff = int(o.get("offset", off) or off)
            except (TypeError, ValueError):
                ooff = off
            instrs.append(Instr(offset=ooff, opcode=str(oo)))
    return instrs


def _cfg_features(r2, f: dict) -> Tuple[int, int, str, List[str]]:
    off = int(f.get("offset", 0) or 0)
    r2_cmd(r2, f"s {off}")
    agfj = r2_cmdj(r2, "agfj")
    return _cfg_from_agfj(agfj)


def build_funcinfo(r2, f: dict, eng: SimilarityEngine, use_cfg: bool) -> Optional[FuncInfo]:
    name = str(f.get("name", ""))
    off = int(f.get("offset", 0) or 0)
    size = int(f.get("size", 0) or 0)
    if size <= 0:
        return None

    key = f"{name}@0x{off:x}"
    instrs = _disasm_function_instrs(r2, f)
    if not instrs:
        return None

    raw_ops = [i.opcode for i in instrs if i.opcode]
    raw_text = "\n".join(raw_ops)

    const_refs = _extract_constants_from_ops(raw_ops)

    norm_lines = [normalize_opcode(op) for op in raw_ops]
    norm_text = "\n".join(norm_lines)
    sha_norm = sha256_hex(norm_text.encode("utf-8", "replace"))
    fuzzy = eng.hash(norm_text)

    mnem = [opcode_mnemonic(x) for x in norm_lines]
    hist = Counter(mnem)
    mnem3 = _mnemonic_3grams(mnem)

    call_count = int(hist.get("call", 0))
    ret_count = int(hist.get("ret", 0) + hist.get("leave", 0))
    jcc_count = int(sum(v for k, v in hist.items() if k.startswith("j") and k not in ("jmp",)))

    str_refs, imp_refs = _extract_anchors_from_ops(raw_ops)
    callees_raw = _extract_callees_from_ops(raw_ops)

    bb_count = 0
    edge_count = 0
    cfg_wl = ""
    cfg_wl_colors: List[str] = []
    if use_cfg:
        bb_count, edge_count, cfg_wl, cfg_wl_colors = _cfg_features(r2, f)

    return FuncInfo(
        key=key,
        name=name,
        offset=off,
        size=size,
        instrs=instrs,
        raw_text=raw_text,
        norm_text=norm_text,
        sha_norm=sha_norm,
        instr_count=len(norm_lines),
        fuzzy=fuzzy,
        op_hist=dict(hist),
        call_count=call_count,
        jcc_count=jcc_count,
        ret_count=ret_count,
        str_refs=str_refs,
        imp_refs=imp_refs,
        const_refs=dict(const_refs),
        mnem3=dict(mnem3),
        callees_raw=callees_raw,
        bb_count=int(bb_count),
        edge_count=int(edge_count),
        cfg_wl=cfg_wl or "",
        cfg_wl_colors=list(cfg_wl_colors),
        cfg_wl_color_counts=dict(Counter(cfg_wl_colors)) if cfg_wl_colors else {},
        callees_resolved=set(),
        callers_resolved=set()
    )


def _name_index(funcs: Dict[str, FuncInfo]) -> Dict[str, str]:
    idx: Dict[str, str] = {}
    for k, f in funcs.items():
        idx[_norm_name_for_index(f.name)] = k
    return idx

def _norm_name_for_index(name: str) -> str:
    s = (name or "").lower().strip()
    for p in ("sym.", "fcn.", "loc.", "obj."):
        if s.startswith(p):
            s = s[len(p):]
            break
    s = HEX_RE.sub("<ADDR>", s)
    return s

def _resolve_callgraph(funcs: Dict[str, FuncInfo]) -> None:
    name_to_key = _name_index(funcs)
    callers: Dict[str, Set[str]] = defaultdict(set)

    ranges, starts = _build_range_index(funcs)

    for k, f in funcs.items():
        resolved: Set[str] = set()
        for t in f.callees_raw:
            if t in name_to_key:
                resolved.add(name_to_key[t])
                continue

            if t.startswith("imp.") or t.startswith("sym.imp."):
                continue

            if t.startswith("addr:0x"):
                try:
                    addr = int(t.split(":", 1)[1], 16)
                except Exception:
                    continue
                fk = _find_func_by_addr(ranges, starts, addr)
                if fk:
                    resolved.add(fk)
                continue

        f.callees_resolved = resolved
        for cal in resolved:
            callers[cal].add(k)

    for k, f in funcs.items():
        f.callers_resolved = callers.get(k, set())

def _build_range_index(funcs: Dict[str, FuncInfo]) -> Tuple[List[Tuple[int, int, str]], List[int]]:
    ranges: List[Tuple[int, int, str]] = []
    for k, f in funcs.items():
        start = int(f.offset)
        end = int(f.offset + max(1, f.size))
        ranges.append((start, end, k))
    ranges.sort(key=lambda x: x[0])
    starts = [x[0] for x in ranges]
    return ranges, starts


def _find_func_by_addr(ranges: List[Tuple[int, int, str]], starts: List[int], addr: int) -> Optional[str]:
    import bisect
    i = bisect.bisect_right(starts, addr) - 1
    if i < 0:
        return None
    s, e, k = ranges[i]
    if s <= addr < e:
        return k
    return None


def _get_strings_map(r2) -> Dict[int, str]:
    out: Dict[int, str] = {}
    izj = r2_cmdj(r2, "izj")
    if isinstance(izj, list):
        for it in izj:
            if not isinstance(it, dict):
                continue
            va = it.get("vaddr")
            st = it.get("string")
            if va is None or st is None:
                continue
            try:
                a = int(va)
            except (TypeError, ValueError):
                continue
            s = str(st)
            if not s:
                continue
            out[a] = "str:" + s
    return out


def _get_imports_map(r2) -> Dict[int, str]:
    out: Dict[int, str] = {}
    iij = r2_cmdj(r2, "iij")
    if isinstance(iij, list):
        for it in iij:
            if not isinstance(it, dict):
                continue
            nm = it.get("name") or it.get("plt_name") or it.get("symbol")
            if not nm:
                continue
            addr = it.get("plt")
            if addr is None:
                addr = it.get("vaddr")
            if addr is None:
                addr = it.get("addr")
            if addr is None:
                continue
            try:
                a = int(addr)
            except (TypeError, ValueError):
                continue
            name = str(nm)
            if not name:
                continue
            out[a] = "imp:" + name
    return out


def apply_xrefs_anchors(r2, funcs: Dict[str, FuncInfo], xrefs_limit: int, logger: logging.Logger, quiet: bool) -> None:
    ranges, starts = _build_range_index(funcs)
    s_map = _get_strings_map(r2)
    i_map = _get_imports_map(r2)

    total = 0

    def feed_target(addr: int, token: str, is_imp: bool) -> None:
        nonlocal total
        if total >= xrefs_limit:
            return
        refs = r2_cmdj(r2, f"axtj @ 0x{addr:x}")
        if not isinstance(refs, list):
            return
        for r in refs:
            if total >= xrefs_limit:
                break
            if not isinstance(r, dict):
                continue
            frm = r.get("from")
            if frm is None:
                continue
            try:
                fa = int(frm)
            except (TypeError, ValueError):
                continue
            fk = _find_func_by_addr(ranges, starts, fa)
            if not fk:
                continue
            fi = funcs.get(fk)
            if not fi:
                continue
            if is_imp:
                fi.imp_refs.add(token.lower())
            else:
                fi.str_refs.add(token.lower())
            total += 1

    for addr, tok in s_map.items():
        if total >= xrefs_limit:
            break
        feed_target(addr, tok, False)

    for addr, tok in i_map.items():
        if total >= xrefs_limit:
            break
        feed_target(addr, tok, True)

    if not quiet:
        logger.info(f"[*] XREFS: строк={len(s_map)}, импортов={len(i_map)}, назначено ссылок={total}")


def load_functions(r2, eng: SimilarityEngine, use_cfg: bool, use_xrefs: bool, xrefs_limit: int, logger: logging.Logger, quiet: bool) -> Dict[str, FuncInfo]:
    funcs = r2_cmdj(r2, "aflj")
    out: Dict[str, FuncInfo] = {}
    if not isinstance(funcs, list):
        return out
    for f in funcs:
        if not isinstance(f, dict):
            continue
        size = int(f.get("size", 0) or 0)
        if size <= 0:
            continue
        fi = build_funcinfo(r2, f, eng, use_cfg)
        if not fi:
            continue
        out[fi.key] = fi
    _resolve_callgraph(out)
    if use_xrefs:
        apply_xrefs_anchors(r2, out, xrefs_limit, logger, quiet)
    if not quiet:
        logger.info(f"[*] Загружено функций: {len(out)}")
    return out


def hist_overlap(a: Dict[str, int], b: Dict[str, int]) -> float:
    if not a or not b:
        return 0.0
    inter_keys = set(a.keys()) & set(b.keys())
    if not inter_keys:
        return 0.0
    inter_sum = sum(min(a[k], b[k]) for k in inter_keys)
    a_sum = sum(a.values())
    b_sum = sum(b.values())
    denom = min(a_sum, b_sum) if min(a_sum, b_sum) > 0 else 1
    return inter_sum / denom


def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def shape_sim(af: FuncInfo, bf: FuncInfo) -> float:
    def rel(x: int, y: int) -> float:
        m = max(1, x, y)
        return 1.0 - (abs(x - y) / m)
    return (rel(af.call_count, bf.call_count) + rel(af.jcc_count, bf.jcc_count) + rel(af.ret_count, bf.ret_count)) / 3.0


def cfg_sim(af: FuncInfo, bf: FuncInfo) -> float:
    def rel(x: int, y: int) -> float:
        m = max(1, x, y)
        return 1.0 - (abs(x - y) / m)

    sh = 0.5 * rel(af.bb_count, bf.bb_count) + 0.5 * rel(af.edge_count, bf.edge_count)

    if not af.cfg_wl or not bf.cfg_wl:
        return sh

    if af.cfg_wl == bf.cfg_wl:
        return 0.85 * 1.0 + 0.15 * sh

    soft = multiset_overlap_ratio(af.cfg_wl_color_counts, bf.cfg_wl_color_counts) if af.cfg_wl_color_counts or bf.cfg_wl_color_counts else 0.0
    return 0.55 * soft + 0.45 * sh


def anchors_sim(af: FuncInfo, bf: FuncInfo) -> float:
    return 0.4 * jaccard(af.str_refs, bf.str_refs) + 0.6 * jaccard(af.imp_refs, bf.imp_refs)


def callees_raw_sim(af: FuncInfo, bf: FuncInfo) -> float:
    return jaccard(af.callees_raw, bf.callees_raw)



def combined_score_stage1(af: FuncInfo, bf: FuncInfo) -> int:
    """Fast pre-score without expensive text similarity. Returns 0..100."""
    h = hist_overlap(af.op_hist, bf.op_hist)
    sh = shape_sim(af, bf)
    an = anchors_sim(af, bf)
    cal = callees_raw_sim(af, bf)
    cg = cfg_sim(af, bf)
    const_sim = multiset_overlap_ratio(af.const_refs, bf.const_refs)
    ng_sim = multiset_overlap_ratio(af.mnem3, bf.mnem3)

    score = (
        0.16 * h +
        0.10 * sh +
        0.14 * an +
        0.07 * cal +
        0.10 * cg +
        0.04 * const_sim +
        0.03 * ng_sim
    ) / 0.64

    return int(round(max(0.0, min(1.0, score)) * 100))

def combined_score_base(af: FuncInfo, bf: FuncInfo, eng: SimilarityEngine) -> int:
    text = eng.compare(af.norm_text, bf.norm_text, af.fuzzy, bf.fuzzy) / 100.0
    h = hist_overlap(af.op_hist, bf.op_hist)
    sh = shape_sim(af, bf)
    an = anchors_sim(af, bf)
    cal = callees_raw_sim(af, bf)
    cg = cfg_sim(af, bf)

    const_sim = multiset_overlap_ratio(af.const_refs, bf.const_refs)
    ng_sim = multiset_overlap_ratio(af.mnem3, bf.mnem3)

    score = (
        0.36 * text +
        0.16 * h +
        0.10 * sh +
        0.14 * an +
        0.07 * cal +
        0.10 * cg +
        0.04 * const_sim +
        0.03 * ng_sim
    )

    if af.sha_norm == bf.sha_norm:
        score = max(score, 0.98)
    return int(round(score * 100))


def bucket_key(instr_count: int, gran: int) -> int:
    return instr_count // gran


def build_buckets(funcs: Dict[str, FuncInfo], gran: int) -> Dict[int, List[str]]:
    b: Dict[int, List[str]] = defaultdict(list)
    for k, fi in funcs.items():
        b[bucket_key(fi.instr_count, gran)].append(k)
    return b


def build_anchor_index(funcs: Dict[str, FuncInfo]) -> Dict[str, Set[str]]:
    idx: Dict[str, Set[str]] = defaultdict(set)
    for k, fi in funcs.items():
        for s in fi.str_refs:
            idx["S:" + s].add(k)
        for imp in fi.imp_refs:
            idx["I:" + imp].add(k)
    return idx


def candidate_keys_by_anchors(a: FuncInfo, b_anchor_idx: Dict[str, Set[str]], limit: int) -> List[str]:
    keys: Set[str] = set()
    for s in a.str_refs:
        keys |= b_anchor_idx.get("S:" + s, set())
        if len(keys) >= limit:
            break
    if len(keys) < limit:
        for imp in a.imp_refs:
            keys |= b_anchor_idx.get("I:" + imp, set())
            if len(keys) >= limit:
                break
    return list(keys)


def max_delta(instr_count: int) -> int:
    return min(MAX_DELTA_CAP, max(MAX_DELTA_MIN, int(instr_count * MAX_DELTA_FRAC)))


def gate_by_size(af: FuncInfo, bf: FuncInfo) -> bool:
    if abs(af.instr_count - bf.instr_count) <= max_delta(af.instr_count):
        return True
    if anchors_sim(af, bf) >= ANCHOR_OVERRIDE_MIN:
        return True
    if cfg_sim(af, bf) >= CFG_OVERRIDE_MIN:
        return True
    return False


def prop_bonus(
    ak: str,
    bk: str,
    a_funcs: Dict[str, FuncInfo],
    b_funcs: Dict[str, FuncInfo],
    matched_map: Dict[str, str],
    prop_bonus_max: int
) -> int:
    af = a_funcs.get(ak)
    bf = b_funcs.get(bk)
    if not af or not bf:
        return 0

    a_callee_targets = {matched_map.get(x) for x in af.callees_resolved if x in matched_map}
    a_callee_targets.discard(None)
    b_callees = bf.callees_resolved

    a_caller_targets = {matched_map.get(x) for x in af.callers_resolved if x in matched_map}
    a_caller_targets.discard(None)
    b_callers = bf.callers_resolved

    callee_j = jaccard(set(a_callee_targets), set(b_callees)) if a_callee_targets or b_callees else 0.0
    caller_j = jaccard(set(a_caller_targets), set(b_callers)) if a_caller_targets or b_callers else 0.0

    val = 0.6 * caller_j + 0.4 * callee_j
    return int(round(min(prop_bonus_max, val * prop_bonus_max)))


def estimate_precision(matches: List[Match], score_cut: int) -> float:
    if not matches:
        return 0.0
    high = sum(1 for m in matches if m.score >= score_cut)
    return high / len(matches)


class ScoreCache:
    def __init__(self):
        self._cache: Dict[Tuple[str, str], int] = {}

    def get(self, ak: str, bk: str) -> Optional[int]:
        return self._cache.get((ak, bk))

    def set(self, ak: str, bk: str, sc: int) -> None:
        self._cache[(ak, bk)] = sc


def greedy_assign(pairs: List[Tuple[str, str, int]], used_a: Set[str], used_b: Set[str]) -> List[Tuple[str, str, int]]:
    pairs_sorted = sorted(pairs, key=lambda x: (-x[2], x[0], x[1]))
    out: List[Tuple[str, str, int]] = []
    for ak, bk, sc in pairs_sorted:
        if ak in used_a or bk in used_b:
            continue
        used_a.add(ak)
        used_b.add(bk)
        out.append((ak, bk, sc))
    return out


def _hungarian_rect(cost: List[List[int]]) -> List[int]:
    n = len(cost)
    m = len(cost[0]) if n else 0
    if n == 0:
        return []
    if m == 0:
        return [-1] * n
    inf = 10**18
    u = [0] * (n + 1)
    v = [0] * (m + 1)
    p = [0] * (m + 1)
    way = [0] * (m + 1)

    for i in range(1, n + 1):
        p[0] = i
        j0 = 0
        minv = [inf] * (m + 1)
        used = [False] * (m + 1)
        while True:
            used[j0] = True
            i0 = p[j0]
            delta = inf
            j1 = 0
            for j in range(1, m + 1):
                if used[j]:
                    continue
                cur = cost[i0 - 1][j - 1] - u[i0] - v[j]
                if cur < minv[j]:
                    minv[j] = cur
                    way[j] = j0
                if minv[j] < delta:
                    delta = minv[j]
                    j1 = j
            for j in range(0, m + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
            if j0 == 0:
                break

    ans = [-1] * n
    for j in range(1, m + 1):
        if p[j] != 0:
            ans[p[j] - 1] = j - 1
    return ans


def _component_hungarian(
    pairs: List[Tuple[str, str, int]],
    used_a: Set[str],
    used_b: Set[str],
    min_score: int,
    max_n: int,
    missing_penalty: int
) -> List[Tuple[str, str, int]]:
    out: List[Tuple[str, str, int]] = []

    filt = [(ak, bk, sc) for (ak, bk, sc) in pairs if sc >= min_score and ak not in used_a and bk not in used_b]
    if not filt:
        return out

    a_to_bs: Dict[str, Set[str]] = defaultdict(set)
    b_to_as: Dict[str, Set[str]] = defaultdict(set)
    score_map: Dict[Tuple[str, str], int] = {}
    for ak, bk, sc in filt:
        a_to_bs[ak].add(bk)
        b_to_as[bk].add(ak)
        score_map[(ak, bk)] = max(score_map.get((ak, bk), -1), sc)

    seen_a: Set[str] = set()
    seen_b: Set[str] = set()

    def bfs_component(start_a: Optional[str], start_b: Optional[str]) -> Tuple[Set[str], Set[str]]:
        comp_a: Set[str] = set()
        comp_b: Set[str] = set()
        dq = deque()
        if start_a is not None:
            dq.append(("A", start_a))
        else:
            dq.append(("B", start_b))
        while dq:
            side, node = dq.popleft()
            if side == "A":
                if node in comp_a:
                    continue
                comp_a.add(node)
                for nb in a_to_bs.get(node, set()):
                    if nb not in comp_b:
                        dq.append(("B", nb))
            else:
                if node in comp_b:
                    continue
                comp_b.add(node)
                for na in b_to_as.get(node, set()):
                    if na not in comp_a:
                        dq.append(("A", na))
        return comp_a, comp_b

    components: List[Tuple[Set[str], Set[str]]] = []
    for ak in list(a_to_bs.keys()):
        if ak in seen_a:
            continue
        ca, cb = bfs_component(start_a=ak, start_b=None)
        seen_a |= ca
        seen_b |= cb
        components.append((ca, cb))
    for bk in list(b_to_as.keys()):
        if bk in seen_b:
            continue
        ca, cb = bfs_component(start_a=None, start_b=bk)
        seen_a |= ca
        seen_b |= cb
        components.append((ca, cb))

    leftovers: List[Tuple[str, str, int]] = []
    for ca, cb in components:
        if not ca or not cb:
            continue
        nA = len(ca)
        nB = len(cb)
        if max(nA, nB) > max_n:
            for ak in ca:
                for bk in a_to_bs.get(ak, set()):
                    sc = score_map.get((ak, bk))
                    if sc is not None:
                        leftovers.append((ak, bk, sc))
            continue

        a_list = sorted(list(ca))
        b_list = sorted(list(cb))
        maxw = 0
        for ak in a_list:
            for bk in a_to_bs.get(ak, set()):
                if bk in cb:
                    maxw = max(maxw, score_map.get((ak, bk), 0))
        if maxw <= 0:
            continue

        dummy_cost = maxw
        miss_cost = maxw + max(1, missing_penalty)

        m = nB + nA
        cost: List[List[int]] = []
        for i, ak in enumerate(a_list):
            row = [0] * m
            for j, bk in enumerate(b_list):
                w = score_map.get((ak, bk))
                if w is None:
                    row[j] = miss_cost
                else:
                    row[j] = maxw - w
            for j in range(nB, m):
                row[j] = dummy_cost
            cost.append(row)

        assign = _hungarian_rect(cost)
        for i, j in enumerate(assign):
            if j < 0:
                continue
            ak = a_list[i]
            if j < nB:
                bk = b_list[j]
                sc = score_map.get((ak, bk))
                if sc is None:
                    continue
                if ak in used_a or bk in used_b:
                    continue
                used_a.add(ak)
                used_b.add(bk)
                out.append((ak, bk, sc))

    if leftovers:
        out.extend(greedy_assign(leftovers, used_a, used_b))
    return out


def assign_pairs(
    pairs: List[Tuple[str, str, int]],
    used_a: Set[str],
    used_b: Set[str],
    mode: str,
    hungarian_min_score: int,
    hungarian_max_n: int,
    hungarian_missing_penalty: int
) -> List[Tuple[str, str, int]]:
    if mode == "hungarian":
        selected = _component_hungarian(
            pairs=pairs,
            used_a=used_a,
            used_b=used_b,
            min_score=hungarian_min_score,
            max_n=hungarian_max_n,
            missing_penalty=hungarian_missing_penalty
        )
        return selected
    return greedy_assign(pairs, used_a, used_b)


def match_functions(
    a_funcs: Dict[str, FuncInfo],
    b_funcs: Dict[str, FuncInfo],
    eng: SimilarityEngine,
    threshold: int,
    gran: int,
    seed_threshold: int,
    prop_rounds: int,
    prop_bonus_max: int,
    global_topk: int,
    global_min_score: int,
    assign_mode: str,
    hungarian_min_score: int,
    hungarian_max_n: int,
    hungarian_missing_penalty: int,
    logger: logging.Logger,
    quiet: bool
) -> Tuple[List[Match], List[str], List[str]]:
    matches: List[Match] = []
    used_b: Set[str] = set()
    matched_map: Dict[str, str] = {}

    cache = ScoreCache()

    b_by_sha: Dict[str, str] = {}
    for bk, bf in b_funcs.items():
        if bf.sha_norm not in b_by_sha:
            b_by_sha[bf.sha_norm] = bk

    b_buckets = build_buckets(b_funcs, gran)
    b_anchor_idx = build_anchor_index(b_funcs)
    anchor_w = build_idf_weights(b_anchor_idx, n_docs=len(b_funcs) if len(b_funcs) > 0 else 1)
    b_ngram_idx = build_ngram_index(b_funcs)

    for ak, af in a_funcs.items():
        bk = b_by_sha.get(af.sha_norm)
        if bk and bk not in used_b:
            matches.append(Match(a_key=ak, b_key=bk, score=100, reason="sha_norm"))
            used_b.add(bk)
            matched_map[ak] = bk

    matched_a: Set[str] = {m.a_key for m in matches}

    if not quiet:
        logger.info(f"[*] Первичные совпадения по sha_norm: {len(matches)}")

    def score_base_cached(ak: str, bk: str) -> int:
        v = cache.get(ak, bk)
        if v is not None:
            return v
        af = a_funcs[ak]
        bf = b_funcs[bk]
        sc = combined_score_base(af, bf, eng)
        cache.set(ak, bk, sc)
        return sc

    seed_pairs: List[Tuple[str, str, int]] = []
    for ak, af in a_funcs.items():
        if ak in matched_a:
            continue

        cand_keys = candidate_keys_weighted(af, b_anchor_idx, anchor_w, b_ngram_idx, MAX_ANCHOR_CANDIDATES)
        if len(cand_keys) < MIN_ANCHOR_CANDIDATES_BEFORE_BUCKETS:
            bk0 = bucket_key(af.instr_count, gran)
            for bb in range(bk0 - BUCKET_NEIGHBORHOOD_SMALL, bk0 + BUCKET_NEIGHBORHOOD_SMALL + 1):
                cand_keys.extend(b_buckets.get(bb, []))
            cand_keys = list(dict.fromkeys(cand_keys))

        if not cand_keys:
            continue

        local: List[Tuple[str, str, int]] = []
        for bk in cand_keys:
            if bk in used_b:
                continue
            bf = b_funcs.get(bk)
            if not bf:
                continue
            if not gate_by_size(af, bf):
                continue
            sc1 = combined_score_stage1(af, bf)
            local.append((ak, bk, sc1))

        local.sort(key=lambda x: -x[2])
        local = local[:60]
        local = [(ak, bk, score_base_cached(ak, bk)) for (ak, bk, _sc1) in local]
        local.sort(key=lambda x: -x[2])

        local.sort(key=lambda x: -x[2])
        if len(local) >= 2 and (local[0][2] - local[1][2]) <= 2:
            ak0, bk0, sc0 = local[0]
            af0 = a_funcs.get(ak0)
            bf0 = b_funcs.get(bk0)
            if af0 and bf0:
                local[0] = (ak0, bk0, sc0 + tie_break_bonus(af0, bf0))
            local.sort(key=lambda x: -x[2])

        for item in local[:2]:
            if item[2] >= seed_threshold:
                seed_pairs.append(item)

    used_a_seed = set(matched_a)
    used_b_seed = set(used_b)
    seed_selected = assign_pairs(
        pairs=seed_pairs,
        used_a=used_a_seed,
        used_b=used_b_seed,
        mode=assign_mode,
        hungarian_min_score=hungarian_min_score,
        hungarian_max_n=hungarian_max_n,
        hungarian_missing_penalty=hungarian_missing_penalty
    )

    for ak, bk, sc in seed_selected:
        if ak in matched_a or bk in used_b:
            continue
        matches.append(Match(a_key=ak, b_key=bk, score=min(100, sc), reason="seed"))
        matched_a.add(ak)
        used_b.add(bk)
        matched_map[ak] = bk

    if not quiet:
        logger.info(f"[*] Seed-совпадения: {len(seed_selected)}")

    for r in range(prop_rounds):
        prop_pairs: List[Tuple[str, str, int]] = []
        total_bonus = 0
        bonus_cnt = 0
        passed_threshold = 0

        for ak, af in a_funcs.items():
            if ak in matched_a:
                continue

            cand_keys = candidate_keys_weighted(af, b_anchor_idx, anchor_w, b_ngram_idx, MAX_ANCHOR_CANDIDATES)
            bk0 = bucket_key(af.instr_count, gran)
            for bb in range(bk0 - BUCKET_NEIGHBORHOOD_SMALL, bk0 + BUCKET_NEIGHBORHOOD_SMALL + 1):
                cand_keys.extend(b_buckets.get(bb, []))
            cand_keys = list(dict.fromkeys(cand_keys))

            if not cand_keys:
                for bb in range(bk0 - BUCKET_NEIGHBORHOOD_FALLBACK, bk0 + BUCKET_NEIGHBORHOOD_FALLBACK + 1):
                    cand_keys.extend(b_buckets.get(bb, []))
                cand_keys = list(dict.fromkeys(cand_keys))

            local: List[Tuple[str, str, int]] = []
            for bk in cand_keys:
                if bk in used_b:
                    continue
                bf = b_funcs.get(bk)
                if not bf:
                    continue
                if not gate_by_size(af, bf):
                    continue
                        
                bonus = prop_bonus(ak, bk, a_funcs, b_funcs, matched_map, prop_bonus_max)
                total_bonus += bonus
                bonus_cnt += 1
                sc = score_base_cached(ak, bk) + bonus
                local.append((ak, bk, sc))

            local.sort(key=lambda x: -x[2])
            local = local[:30]
            local = [(ak, bk, score_base_cached(ak, bk) + prop_bonus(ak, bk, a_funcs, b_funcs, matched_map, prop_bonus_max)) for (ak, bk, _sc1) in local]
            local.sort(key=lambda x: -x[2])
            if len(local) >= 2 and (local[0][2] - local[1][2]) <= 2:
                ak0, bk0, sc0 = local[0]
                af0 = a_funcs.get(ak0)
                bf0 = b_funcs.get(bk0)
                if af0 and bf0:
                    local[0] = (ak0, bk0, sc0 + tie_break_bonus(af0, bf0))
                local.sort(key=lambda x: -x[2])

            for item in local[:3]:
                if item[2] >= threshold:
                    prop_pairs.append(item)
                    passed_threshold += 1

        used_a_prop = set(matched_a)
        used_b_prop = set(used_b)
        selected = assign_pairs(
            pairs=prop_pairs,
            used_a=used_a_prop,
            used_b=used_b_prop,
            mode=assign_mode,
            hungarian_min_score=hungarian_min_score,
            hungarian_max_n=hungarian_max_n,
            hungarian_missing_penalty=hungarian_missing_penalty
        )

        if not quiet:
            avg_bonus = (total_bonus / bonus_cnt) if bonus_cnt else 0.0
            logger.info(f"[*] Propagation раунд {r+1}: кандидатов {len(prop_pairs)}, прошли порог {passed_threshold}, средний бонус {avg_bonus:.2f}, выбрано {len(selected)}")

        if not selected:
            break

        for ak, bk, sc in selected:
            if ak in matched_a or bk in used_b:
                continue
            matches.append(Match(a_key=ak, b_key=bk, score=min(100, sc), reason=f"prop{r+1}"))
            matched_a.add(ak)
            used_b.add(bk)
            matched_map[ak] = bk

    global_pairs: List[Tuple[str, str, int]] = []
    for ak, af in a_funcs.items():
        if ak in matched_a:
            continue

        cand_keys = candidate_keys_weighted(af, b_anchor_idx, anchor_w, b_ngram_idx, MAX_ANCHOR_CANDIDATES)
        bk0 = bucket_key(af.instr_count, gran)
        for bb in range(bk0 - BUCKET_NEIGHBORHOOD_FALLBACK, bk0 + BUCKET_NEIGHBORHOOD_FALLBACK + 1):
            cand_keys.extend(b_buckets.get(bb, []))
        cand_keys = list(dict.fromkeys(cand_keys))

        local: List[Tuple[str, str, int]] = []
        for bk in cand_keys:
            if bk in used_b:
                continue
            bf = b_funcs.get(bk)
            if not bf:
                continue
            if not gate_by_size(af, bf):
                continue
            base1 = combined_score_stage1(af, bf)
            bonus = prop_bonus(ak, bk, a_funcs, b_funcs, matched_map, prop_bonus_max)
            sc = base1 + bonus
            if sc >= global_min_score:
                local.append((ak, bk, sc))

        local.sort(key=lambda x: -x[2])
        if len(local) >= 2 and (local[0][2] - local[1][2]) <= 2:
            ak0, bk0, sc0 = local[0]
            af0 = a_funcs.get(ak0)
            bf0 = b_funcs.get(bk0)
            if af0 and bf0:
                local[0] = (ak0, bk0, sc0 + tie_break_bonus(af0, bf0))
            local.sort(key=lambda x: -x[2])

        for item in local[:max(1, global_topk)]:
            global_pairs.append(item)

    used_a_g = set(matched_a)
    used_b_g = set(used_b)
    selected_g = assign_pairs(
        pairs=global_pairs,
        used_a=used_a_g,
        used_b=used_b_g,
        mode=assign_mode,
        hungarian_min_score=hungarian_min_score,
        hungarian_max_n=hungarian_max_n,
        hungarian_missing_penalty=hungarian_missing_penalty
    )

    added_global = 0
    for ak, bk, sc in selected_g:
        if ak in matched_a or bk in used_b:
            continue
        if sc < threshold:
            continue
        matches.append(Match(a_key=ak, b_key=bk, score=min(100, sc), reason="global"))
        matched_a.add(ak)
        used_b.add(bk)
        matched_map[ak] = bk
        added_global += 1

    unmatched_a = [k for k in a_funcs.keys() if k not in matched_a]
    unmatched_b = [k for k in b_funcs.keys() if k not in used_b]

    if not quiet:
        logger.info(f"[*] Global: добавлено {added_global}")
        logger.info(f"[*] Совпало: {len(matches)} | Не сопоставлено в A: {len(unmatched_a)} | Не сопоставлено в B: {len(unmatched_b)}")

    return matches, unmatched_a, unmatched_b


def match_summary_json(
    matches: List[Match],
    a_funcs: Dict[str, FuncInfo],
    b_funcs: Dict[str, FuncInfo],
    unmatched_a: List[str],
    unmatched_b: List[str],
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"matches": [], "unmatched_a": [], "unmatched_b": []}

    for m in sorted(matches, key=lambda x: (-x.score, x.a_key)):
        af = a_funcs.get(m.a_key)
        bf = b_funcs.get(m.b_key)
        out["matches"].append({
            "a_key": m.a_key,
            "b_key": m.b_key,
            "a_name": af.name if af else "",
            "b_name": bf.name if bf else "",
            "a_offset": af.offset if af else 0,
            "b_offset": bf.offset if bf else 0,
            "a_size": af.size if af else 0,
            "b_size": bf.size if bf else 0,
            "score": m.score,
            "reason": m.reason,
            "a_instr_count": af.instr_count if af else 0,
            "b_instr_count": bf.instr_count if bf else 0,
            "a_bb": af.bb_count if af else 0,
            "b_bb": bf.bb_count if bf else 0,
            "a_edges": af.edge_count if af else 0,
            "b_edges": bf.edge_count if bf else 0,
            "anchors_strings": sorted(list((af.str_refs if af else set()) & (bf.str_refs if bf else set()))),
            "anchors_imports": sorted(list((af.imp_refs if af else set()) & (bf.imp_refs if bf else set()))),
        })

    for k in unmatched_a:
        af = a_funcs.get(k)
        out["unmatched_a"].append({
            "key": k,
            "name": af.name if af else "",
            "offset": af.offset if af else 0,
            "size": af.size if af else 0,
            "instr_count": af.instr_count if af else 0,
        })

    for k in unmatched_b:
        bf = b_funcs.get(k)
        out["unmatched_b"].append({
            "key": k,
            "name": bf.name if bf else "",
            "offset": bf.offset if bf else 0,
            "size": bf.size if bf else 0,
            "instr_count": bf.instr_count if bf else 0,
        })

    return out


HTML_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>PatchScan отчёт</title>
<style>
body {{ font-family: sans-serif; margin: 18px; }}
h1 {{ margin-bottom: 0; }}
.small {{ color: #666; margin-top: 4px; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 14px; }}
th, td {{ border: 1px solid #ddd; padding: 6px 8px; font-size: 13px; }}
th {{ background: #f7f7f7; text-align: left; }}
.badge {{ display:inline-block; padding: 2px 6px; border-radius: 10px; background:#eee; font-size: 12px; }}
pre {{ background:#f8f8f8; padding:10px; overflow:auto; }}
details {{ margin-top: 6px; }}
</style>
</head>
<body>
<h1>PatchScan</h1>
<div class="small">Сгенерировано: {generated}</div>

<h2>Совпадения ({n_matches})</h2>
<table>
<tr>
<th>Скор</th>
<th>A</th>
<th>B</th>
<th>Адреса</th>
<th>Размеры</th>
<th>Инструкции</th>
<th>CFG (bb/edges)</th>
<th>Якоря</th>
<th>Diff</th>
</tr>
{rows}
</table>

<h2>Не сопоставлено в A ({n_ua})</h2>
<details><summary>Показать</summary>
<pre>{unmatched_a}</pre>
</details>

<h2>Не сопоставлено в B ({n_ub})</h2>
<details><summary>Показать</summary>
<pre>{unmatched_b}</pre>
</details>

</body>
</html>
"""


def escape_html(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def anchors_txt_toggle(af: FuncInfo, bf: FuncInfo) -> str:
    common_str = sorted(list(af.str_refs & bf.str_refs))
    common_imp = sorted(list(af.imp_refs & bf.imp_refs))
    parts: List[str] = []
    if common_imp:
        parts.append("imports=" + ",".join(common_imp[:6]) + ("…" if len(common_imp) > 6 else ""))
    if common_str:
        parts.append("strings=" + ",".join(common_str[:6]) + ("…" if len(common_str) > 6 else ""))
    return " | ".join(parts) if parts else ""


def render_html_report(matches, a_funcs, b_funcs, unmatched_a, unmatched_b, html_diffs: int = 5, diff_raw: bool = False) -> str:
    rows: List[str] = []
    shown = 0
    for m in sorted(matches, key=lambda x: (-x.score, x.a_key)):
        af = a_funcs.get(m.a_key)
        bf = b_funcs.get(m.b_key)
        if not af or not bf:
            continue

        diff_html = ""
        if html_diffs > 0 and shown < html_diffs and m.score < 100:
            d = diff_text(af, bf, raw=diff_raw, max_lines=200)
            if d.strip():
                diff_html = (
                    "<details><summary>show</summary>"
                    f"<pre>{escape_html(d)}</pre>"
                    "</details>"
                )
                shown += 1

        row = (
            "<tr>"
            f"<td><span class='badge'>{m.score}</span> <span class='small'>{escape_html(m.reason)}</span></td>"
            f"<td>{escape_html(af.name)}<br><span class='small'>{escape_html(af.key)}</span></td>"
            f"<td>{escape_html(bf.name)}<br><span class='small'>{escape_html(bf.key)}</span></td>"
            f"<td>A 0x{af.offset:x}<br>B 0x{bf.offset:x}</td>"
            f"<td>A {af.size}<br>B {bf.size}</td>"
            f"<td>A {af.instr_count}<br>B {bf.instr_count}</td>"
            f"<td>A {af.bb_count}/{af.edge_count}<br>B {bf.bb_count}/{bf.edge_count}</td>"
            f"<td>{escape_html(anchors_txt_toggle(af, bf))}</td>"
            f"<td>{diff_html}</td>"
            "</tr>"
        )
        rows.append(row)

    ua_txt = "\n".join(unmatched_a[:MAX_REPORT_UNMATCHED_KEYS]) + ("\n..." if len(unmatched_a) > MAX_REPORT_UNMATCHED_KEYS else "")
    ub_txt = "\n".join(unmatched_b[:MAX_REPORT_UNMATCHED_KEYS]) + ("\n..." if len(unmatched_b) > MAX_REPORT_UNMATCHED_KEYS else "")

    return HTML_TEMPLATE.format(
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
        n_matches=len(matches),
        rows="\n".join(rows),
        n_ua=len(unmatched_a),
        n_ub=len(unmatched_b),
        unmatched_a=escape_html(ua_txt),
        unmatched_b=escape_html(ub_txt),
    )


def diff_text(a: FuncInfo, b: FuncInfo, raw: bool = False, max_lines: int = MAX_DIFF_LINES) -> str:
    import difflib
    a_lines = (a.raw_text if raw else a.norm_text).splitlines()
    b_lines = (b.raw_text if raw else b.norm_text).splitlines()
    ud = difflib.unified_diff(
        a_lines[:max_lines],
        b_lines[:max_lines],
        fromfile=f"A:{a.key}" + ("(raw)" if raw else "(norm)"),
        tofile=f"B:{b.key}" + ("(raw)" if raw else "(norm)"),
        lineterm=""
    )
    return "\n".join(ud)


def render_csv(matches: List[Match], a_funcs: Dict[str, FuncInfo], b_funcs: Dict[str, FuncInfo]) -> str:
    def esc(x: str) -> str:
        s = (x or "").replace('"', '""')
        return f"\"{s}\""
    lines: List[str] = []
    lines.append("score,reason,a_name,a_offset,a_size,a_instr,b_name,b_offset,b_size,b_instr")
    for m in sorted(matches, key=lambda x: (-x.score, x.a_key)):
        af = a_funcs.get(m.a_key)
        bf = b_funcs.get(m.b_key)
        if not af or not bf:
            continue
        lines.append(
            ",".join([
                str(m.score),
                esc(m.reason),
                esc(af.name),
                f"0x{af.offset:x}",
                str(af.size),
                str(af.instr_count),
                esc(bf.name),
                f"0x{bf.offset:x}",
                str(bf.size),
                str(bf.instr_count),
            ])
        )
    return "\n".join(lines)




def save_match_plots_png(matches: List[Match], out_prefix: str, score_cut: int, quiet: bool, logger: logging.Logger) -> None:
    """Save diagnostic plots to PNG files (headless-safe with Agg).

    Outputs:
      - <prefix>_score_hist.png
      - <prefix>_precision_curve.png
      - <prefix>_precision_at_k.png
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        if not quiet:
            logger.info(f"[*] matplotlib недоступен, PNG не сохранён: {e}")
        return

    scores = [m.score for m in matches] if matches else []
    if not scores:
        if not quiet:
            logger.info("[*] PNG: нет матчей, графики не построены.")
        return

    hist_path = out_prefix + "_score_hist.png"
    fig = plt.figure(figsize=(6.6, 4.2))
    ax = fig.add_subplot(1, 1, 1)
    ax.hist(scores, bins=20)
    ax.set_title("Match score distribution")
    ax.set_xlabel("score")
    ax.set_ylabel("count")
    fig.tight_layout()
    try:
        fig.savefig(hist_path, dpi=140)
    finally:
        plt.close(fig)
    if not quiet:
        logger.info(f"[*] Записал {hist_path}")

    curve_path = out_prefix + "_precision_curve.png"
    xs = list(range(0, 101))
    ys = [sum(1 for s in scores if s >= t) / len(scores) for t in xs]

    fig = plt.figure(figsize=(6.6, 4.2))
    ax = fig.add_subplot(1, 1, 1)
    ax.plot(xs, ys)
    ax.set_title("Precision curve")
    ax.set_xlabel("threshold")
    ax.set_ylabel("fraction score≥t")
    ax.set_ylim(0, 1.02)
    fig.tight_layout()
    try:
        fig.savefig(curve_path, dpi=140)
    finally:
        plt.close(fig)
    if not quiet:
        logger.info(f"[*] Записал {curve_path}")

    at_k_path = out_prefix + "_precision_at_k.png"
    sorted_scores = sorted(scores, reverse=True)
    kmax = min(200, len(sorted_scores))
    ks = list(range(1, kmax + 1))
    prec_at_k = []
    good = 0
    for i in range(kmax):
        if sorted_scores[i] >= score_cut:
            good += 1
        prec_at_k.append(good / (i + 1))

    fig = plt.figure(figsize=(6.6, 4.2))
    ax = fig.add_subplot(1, 1, 1)
    ax.plot(ks, prec_at_k)
    ax.set_title(f"Precision@K (score≥{score_cut})")
    ax.set_xlabel("K (top matches by score)")
    ax.set_ylabel("precision@K")
    ax.set_ylim(0, 1.02)
    fig.tight_layout()
    try:
        fig.savefig(at_k_path, dpi=140)
    finally:
        plt.close(fig)
    if not quiet:
        logger.info(f"[*] Записал {at_k_path}")


def _ida_safe_name(name: str) -> str:
    s = name or ""
    s = re.sub(r"[^A-Za-z0-9_.$@?]+", "_", s)
    if not s:
        s = "sub_unnamed"
    if s[0].isdigit():
        s = "_" + s
    return s[:200]


def export_ida_rename_script(
    matches: List[Match],
    a_funcs: Dict[str, FuncInfo],
    b_funcs: Dict[str, FuncInfo],
    threshold: int,
    prefix: str
) -> str:
    lines: List[str] = []
    lines.append("import idc")
    lines.append("import idaapi")
    lines.append("import ida_kernwin")
    lines.append("")
    lines.append("renamed = 0")
    lines.append("skipped = 0")
    lines.append("for item in []:")
    lines.append("    pass")
    lines.append("")

    for m in sorted(matches, key=lambda x: (-x.score, x.a_key)):
        if m.score < threshold:
            continue
        af = a_funcs.get(m.a_key)
        bf = b_funcs.get(m.b_key)
        if not af or not bf:
            continue
        new_name = _ida_safe_name(prefix + af.name)
        lines.append(f"ea = 0x{bf.offset:x}")
        lines.append(f"name = {new_name!r}")
        lines.append("ok = idc.set_name(ea, name, idc.SN_NOWARN | idc.SN_NOCHECK)")
        lines.append("if ok:")
        lines.append("    renamed += 1")
        lines.append("else:")
        lines.append("    skipped += 1")
        lines.append("")

    lines.append("ida_kernwin.msg(f'[PatchScan] renamed={renamed} skipped={skipped}\\n')")
    return "\n".join(lines)


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PatchScan: сравнение двух бинарников (функции).")
    p.add_argument("old", help="Путь к старой версии бинарника")
    p.add_argument("new", help="Путь к новой версии бинарника")
    p.add_argument("-o", "--out", default="patchscan_report", help="Префикс вывода (без расширения)")
    p.add_argument("--json", action="store_true", help="Сохранить JSON-отчёт")
    p.add_argument("--diffs", action="store_true", help="Сохранить диффы (нормализованные)")
    p.add_argument("--diff-threshold", type=int, default=95, help="Диффы писать только если score < X")
    p.add_argument("--max-diffs", type=int, default=200, help="Максимум файлов диффов (защита от спама)")
    p.add_argument("--diff-raw", action="store_true", help="Дифф по raw-опкодам (без нормализации)")
    p.add_argument("--html-diffs", type=int, default=5, help="Сколько диффов встроить в HTML (0=выкл)")
    p.add_argument("--threshold", type=int, default=DEFAULT_SIMILARITY_THRESHOLD, help="Порог совпадения (0..100)")
    p.add_argument("--gran", type=int, default=DEFAULT_BUCKET_GRANULARITY, help="Гранулярность бакетов (instr_count//gran)")
    p.add_argument("--seed-threshold", type=int, default=DEFAULT_SEED_THRESHOLD, help="Порог seed-совпадений (0..100)")
    p.add_argument("--prop-rounds", type=int, default=DEFAULT_PROP_ROUNDS, help="Количество раундов propagation")
    p.add_argument("--prop-bonus", type=int, default=DEFAULT_PROP_BONUS_MAX, help="Максимальный бонус propagation")
    p.add_argument("--prop-bonus-max", type=int, default=None, help="Синоним для --prop-bonus")
    p.add_argument("--global-topk", type=int, default=DEFAULT_GLOBAL_TOPK, help="Сколько лучших кандидатов сохранять на глобальную фазу")
    p.add_argument("--global-min-score", type=int, default=DEFAULT_GLOBAL_MIN_SCORE, help="Минимальный скор кандидата для глобальной фазы")
    p.add_argument("--precision-score", type=int, default=DEFAULT_PRECISION_SCORE, help="Порог для оценки точности (доля матчей с score>=X)")
    p.add_argument("--assign", choices=["greedy", "hungarian"], default=DEFAULT_ASSIGN_MODE, help="Стратегия снятия конфликтов")
    p.add_argument("--hungarian-min-score", type=int, default=DEFAULT_HUNGARIAN_MIN_SCORE, help="Минимальный скор пары для Hungarian-компонент")
    p.add_argument("--hungarian-max-n", type=int, default=DEFAULT_HUNGARIAN_MAX_N, help="Максимальный размер компоненты (max(|A|,|B|)) для Hungarian")
    p.add_argument("--hungarian-missing-penalty", type=int, default=DEFAULT_HUNGARIAN_MISSING_PENALTY, help="Штраф за отсутствующее ребро в матрице стоимости")
    p.add_argument("--no-ssdeep", action="store_true", help="Отключить ssdeep даже если доступен")
    p.add_argument("--no-cfg", action="store_true", help="Отключить CFG (быстрее, но хуже точность)")
    p.add_argument("--quiet", action="store_true", help="Меньше вывода")
    p.add_argument("--ida-script", action="store_true", help="Сохранить IDAPython скрипт переименования для новой версии")
    p.add_argument("--ida-threshold", type=int, default=90, help="Порог скора для переименования в IDA")
    p.add_argument("--ida-prefix", type=str, default="", help="Префикс к именам при переименовании в IDA")
    p.add_argument("--csv", action="store_true", help="Сохранить CSV отчёт по совпадениям")
    p.add_argument("--png", action="store_true", help="Сохранить PNG-графики по матчам (score распределение и precision curve)")
    p.add_argument("--xrefs", action="store_true", help="Якоря через xrefs (строки/импорты) вместо regex по опкодам")
    p.add_argument("--xrefs-limit", type=int, default=50000, help="Лимит обработанных xref-записей (защита от тормозов)")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    logger = make_logger(args.quiet)

    print(BANNER)

    use_xrefs = bool(getattr(args, "xrefs", False))
    xrefs_limit = int(getattr(args, "xrefs_limit", 50000))

    prop_bonus_max = args.prop_bonus
    if args.prop_bonus_max is not None:
        prop_bonus_max = args.prop_bonus_max

    try:
        validate_binary_path(args.old)
        validate_binary_path(args.new)
        out_prefix = validate_out_prefix(args.out)
    except Exception as e:
        logger.error(f"[-] Ошибка параметров: {e}")
        return 2

    if r2pipe is None:
        logger.error("[-] r2pipe не установлен. Установи: pip install r2pipe")
        return 2

    use_cfg = not args.no_cfg
    eng = SimilarityEngine(prefer_ssdeep=(not args.no_ssdeep), logger=logger)

    if not args.quiet:
        logger.info(f"[*] ssdeep: {'ВКЛ' if eng.has_ssdeep else 'ВЫКЛ'}")
        logger.info(f"[*] CFG: {'ВКЛ' if use_cfg else 'ВЫКЛ'}")
        logger.info(f"[*] XREFS: {'ВКЛ' if use_xrefs else 'ВЫКЛ'} (limit={xrefs_limit})")

    try:
        r2a = r2_open(args.old, flags=["-2"])
        r2b = r2_open(args.new, flags=["-2"])
    except Exception as e:
        logger.error(f"[-] Не смог открыть бинарники в radare2: {e}")
        return 2

    try:
        analyze_binary(r2a, logger, args.quiet)
        analyze_binary(r2b, logger, args.quiet)

        a_funcs = load_functions(r2a, eng, use_cfg, use_xrefs, xrefs_limit, logger, args.quiet)
        b_funcs = load_functions(r2b, eng, use_cfg, use_xrefs, xrefs_limit, logger, args.quiet)

        matches, ua, ub = match_functions(
            a_funcs=a_funcs,
            b_funcs=b_funcs,
            eng=eng,
            threshold=args.threshold,
            gran=args.gran,
            seed_threshold=args.seed_threshold,
            prop_rounds=args.prop_rounds,
            prop_bonus_max=prop_bonus_max,
            global_topk=args.global_topk,
            global_min_score=args.global_min_score,
            assign_mode=args.assign,
            hungarian_min_score=args.hungarian_min_score,
            hungarian_max_n=args.hungarian_max_n,
            hungarian_missing_penalty=args.hungarian_missing_penalty,
            logger=logger,
            quiet=args.quiet
        )

        if args.diffs:
            diffs_dir = out_prefix + "_diffs"
            os.makedirs(diffs_dir, exist_ok=True)

            written = 0
            for m in sorted(matches, key=lambda x: (x.score, x.a_key)):
                if written >= args.max_diffs:
                    break
                if m.score >= args.diff_threshold:
                    continue

                af = a_funcs.get(m.a_key)
                bf = b_funcs.get(m.b_key)
                if not af or not bf:
                    continue

                d = diff_text(af, bf, raw=args.diff_raw)
                if not d.strip():
                    continue

                safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", af.name)[:80]
                mode = "raw" if args.diff_raw else "norm"
                fn = f"{m.score:03d}_{safe_name}_0x{af.offset:x}_to_0x{bf.offset:x}.{mode}.diff.txt"
                with open(os.path.join(diffs_dir, fn), "w", encoding="utf-8") as f:
                    f.write(d)
                written += 1

            if not args.quiet:
                logger.info(f"[*] Диффы записаны в {diffs_dir}/ (written={written}, mode={'raw' if args.diff_raw else 'norm'})")



        if not args.quiet:
            prec = estimate_precision(matches, args.precision_score)
            logger.info(f"[*] Оценка точности (score≥{args.precision_score}): {prec:.1%}")


        if args.json:
            js = match_summary_json(matches, a_funcs, b_funcs, ua, ub)
            json_path = out_prefix + ".json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(js, f, indent=2, ensure_ascii=False)
            if not args.quiet:
                logger.info(f"[*] Записал {json_path}")

        else:
            html = render_html_report(matches, a_funcs, b_funcs, ua, ub, html_diffs=args.html_diffs, diff_raw=args.diff_raw)
            html_path = out_prefix + ".html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)
            if not args.quiet:
                logger.info(f"[*] Записал {html_path}")


        if args.ida_script:
            script = export_ida_rename_script(matches, a_funcs, b_funcs, args.ida_threshold, args.ida_prefix)
            ida_path = out_prefix + "_ida_rename.py"
            with open(ida_path, "w", encoding="utf-8") as f:
                f.write(script)
            if not args.quiet:
                logger.info(f"[*] Записал {ida_path}")

        if args.csv:
            csv_txt = render_csv(matches, a_funcs, b_funcs)
            csv_path = out_prefix + ".csv"
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_txt)
            if not args.quiet:
                logger.info(f"[*] Записал {csv_path}")

        if args.png:
            save_match_plots_png(matches, out_prefix, args.precision_score, args.quiet, logger)

    finally:
        try:
            r2a.quit()
        except Exception:
            pass
        try:
            r2b.quit()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))