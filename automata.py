"""
automata.py - a tiny DFA toolkit plus the four PII automata.

A DFA (deterministic finite automaton) is defined by five things:
    states, alphabet, transition table, start state, accepting states.

Here each automaton is literally that: a transition TABLE, a dict that maps
(current_state, symbol) -> next_state. If a pair is missing from the table the
automaton falls into the dead state "q_d" and the token is rejected.

Reading the tables is the best way to understand the project.
"""
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

DEAD = "q_d"                      # reject / dead state
ACCEPT = "q1"                     # label reported for any accepted token
ALLOWED_SYMBOLS = set("._%+-@!#$^&*=~/?")
MIN_KEY_LENGTH = 20               # API keys must have at least this many chars

Table = Dict[Tuple[str, str], str]


def char_class(ch: str) -> str:
    """L = letter, D = digit, S = allowed symbol, O = anything else."""
    if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
        return "L"
    if "0" <= ch <= "9":
        return "D"
    if ch in ALLOWED_SYMBOLS:
        return "S"
    return "O"


@dataclass
class StepRecord:
    """One row of the trace: reading `char` moved the DFA old_state -> new_state."""
    step_num: int
    char: str
    char_class: str          # the alphabet symbol the DFA actually saw
    old_state: str
    new_state: str
    note: str = ""


@dataclass
class RunResult:
    accepted: bool
    final_state: str         # "q1" if accepted, otherwise "q_d"
    steps: List[StepRecord]
    reason: str


def add(table: Table, state: str, symbols: str, target: str) -> None:
    """Helper that keeps the tables readable: add(t, 'q0', ['L','D'], 'q_local')."""
    for symbol in symbols:
        table[(state, symbol)] = target


class DFA:
    def __init__(
        self,
        dfa_id: str,
        name: str,
        pii_type: str,
        description: str,
        legend: str,
        start: str,
        accepting: Set[str],
        table: Table,
        symbol_of: Callable[[str], str],
        group_of: Callable[[str], str],
        explain_failure: Callable[[str, List[StepRecord]], str],
        edge_label: Optional[Callable[[str, str], str]] = None,
    ):
        self.id = dfa_id
        self.name = name
        self.pii_type = pii_type
        self.description = description
        self.legend = legend
        self.start = start
        self.accepting = accepting
        self.table = table
        self.symbol_of = symbol_of
        self.group_of = group_of            # merges many states into one drawn node
        self.explain_failure = explain_failure
        self.edge_label = edge_label or (lambda state, symbol: symbol)

    # ------------------------------------------------------------ running
    def run(self, token: str) -> RunResult:
        """Feed the token through the table one character at a time."""
        state = self.start
        steps: List[StepRecord] = []
        for i, ch in enumerate(token, start=1):
            symbol = self.symbol_of(ch)
            new_state = self.table.get((state, symbol), DEAD)
            note = "No transition -> dead state" if new_state == DEAD else ""
            steps.append(StepRecord(i, ch, symbol, state, new_state, note))
            state = new_state
            if state == DEAD:        # nothing can recover from the dead state
                break
        if state in self.accepting:
            return RunResult(True, ACCEPT, steps, "Verified " + self.name)
        return RunResult(False, DEAD, steps, self.explain_failure(state, steps))

    def path_of(self, steps: List[StepRecord]) -> List[str]:
        """Drawn-node ids visited, used to highlight the path in the diagram."""
        return [self.group_of(self.start)] + [self.group_of(s.new_state) for s in steps]

    # ------------------------------------------------------------ drawing
    def diagram(self) -> Dict:
        """Collapse the table into a small graph (nodes + labelled edges) for the dashboard."""
        outgoing: Dict[str, List[Tuple[str, str]]] = {}
        for (state, symbol), target in self.table.items():
            outgoing.setdefault(state, []).append((symbol, target))

        order, seen, queue = [], {self.start}, deque([self.start])
        while queue:                                   # breadth-first = left-to-right layout
            state = queue.popleft()
            order.append(state)
            for _, target in sorted(outgoing.get(state, [])):
                if target not in seen:
                    seen.add(target)
                    queue.append(target)

        node_ids: List[str] = []
        accepting_nodes: Set[str] = set()
        for state in order:
            group = self.group_of(state)
            if group not in node_ids:
                node_ids.append(group)
            if state in self.accepting:
                accepting_nodes.add(group)

        edges: Dict[Tuple[str, str], Set[str]] = {}
        for state in order:
            for symbol, target in outgoing.get(state, []):
                key = (self.group_of(state), self.group_of(target))
                edges.setdefault(key, set()).add(self.edge_label(state, symbol))

        return {
            "id": self.id,
            "name": self.name,
            "pii_type": self.pii_type,
            "description": self.description,
            "legend": self.legend,
            "nodes": [{"id": n, "accepting": n in accepting_nodes} for n in node_ids],
            "edges": [
                {"from": a, "to": b, "label": ", ".join(sorted(labels))}
                for (a, b), labels in edges.items()
            ],
        }


# =====================================================================
# 1) EMAIL  -  local-part @ domain . tld
# =====================================================================
def _email_symbol(ch: str) -> str:
    if ch in ".@-":
        return ch
    if ch in "_%+":
        return "S"
    cls = char_class(ch)
    return cls if cls in ("L", "D") else "O"


def build_email_dfa() -> DFA:
    t: Table = {}
    add(t, "q0",       ["L", "D", "S", "-"],           "q_local")   # first char of local part
    add(t, "q_local",  ["L", "D", ".", "S", "-"],      "q_local")
    add(t, "q_local",  "@",                            "q_at")
    add(t, "q_at",     ["L", "D"],                     "q_domain")
    add(t, "q_domain", ["L", "D", "-"],                "q_domain")
    add(t, "q_domain", ".",                            "q_dot")
    add(t, "q_dot",    "L",                            "q_tld1")    # TLD must be letters only
    add(t, "q_tld1",   "L",                            "q_tld2")
    add(t, "q_tld2",   "L",                            "q_tld2")
    add(t, "q_tld2",   ".",                            "q_dot")     # sub-domains: a.b.edu.ph

    names = {
        "q0": "start", "q_local": "local part", "q_at": "after @", "q_domain": "domain",
        "q_dot": "after dot", "q_tld1": "TLD (1 letter)", "q_tld2": "TLD (2+ letters)",
    }

    def explain(state: str, steps: List[StepRecord]) -> str:
        if state == DEAD:
            return f"Invalid email structure at '{steps[-1].char}'"
        return {"q0": "Empty", "q_local": "Missing @", "q_at": "Missing domain after @",
                "q_domain": "Missing .tld", "q_dot": "Missing TLD after dot",
                "q_tld1": "TLD needs 2+ letters"}.get(state, "Invalid email structure")

    return DFA("email", "Email", "EMAIL",
               "local-part @ domain . tld  (TLD = 2 or more letters)",
               "L = letter, D = digit, S = one of _ % +",
               "q0", {"q_tld2"}, t, _email_symbol, lambda s: names.get(s, s), explain)


# =====================================================================
# 2) PHONE  -  optional '+', then 10-13 digits, single '-' allowed between digits
# =====================================================================
def _phone_symbol(ch: str) -> str:
    if ch in "+-":
        return ch
    return "D" if "0" <= ch <= "9" else "O"


def build_phone_dfa() -> DFA:
    t: Table = {}
    add(t, "q0", "+", "q_plus")
    add(t, "q0", "D", "d1")                 # d3 = "seen 3 digits so far"
    add(t, "q_plus", "D", "d1")
    for n in range(1, 14):
        if n < 13:
            add(t, f"d{n}", "D", f"d{n + 1}")
        if n < 13:
            add(t, f"d{n}", "-", f"h{n}")   # h3 = "dash after 3 digits"; a digit must follow
    for n in range(1, 13):
        add(t, f"h{n}", "D", f"d{n + 1}")

    def group(state: str) -> str:
        if state == "q0":
            return "start"
        if state == "q_plus":
            return "+ sign"
        if state == DEAD:
            return DEAD
        n = int(state[1:])
        if state[0] == "d":
            return "digits (1-9)" if n < 10 else "digits (10-13)"
        return "dash (<10 digits)" if n < 10 else "dash (10+ digits)"

    def explain(state: str, steps: List[StepRecord]) -> str:
        if state == DEAD:
            return f"Invalid phone character or too many digits at '{steps[-1].char}'"
        if state.startswith("d"):
            return f"Too few digits ({state[1:]}); need 10-13"
        return "Invalid phone format"

    accepting = {f"d{n}" for n in range(10, 14)}
    return DFA("phone", "Phone", "PHONE",
               "Optional +, then 10-13 digits; a single '-' may sit between digits",
               "D = digit",
               "q0", accepting, t, _phone_symbol, group, explain)


# =====================================================================
# 3) API KEY with a known vendor prefix (sk-, ghp_, AKIA, ...)
#    The prefix is a "trie" of states; after it, any L/D/S char is fine,
#    and we count characters until we reach MIN_KEY_LENGTH.
# =====================================================================
def build_vendor_api_dfa(prefixes: Tuple[str, ...]) -> DFA:
    # "sk-proj-" already starts with "sk-", so only the shortest prefixes are needed.
    minimal = [p for p in prefixes if not any(q != p and p.startswith(q) for q in prefixes)]
    prefix_chars = set("".join(minimal))
    proper = {p[:i] for p in minimal for i in range(len(p))}      # includes "" (start)
    name = lambda w: "q0" if w == "" else f"pfx:{w}"

    t: Table = {}
    for w in proper:                                  # part 1: spell the prefix
        for c in prefix_chars:
            if w + c in minimal:
                t[(name(w), c)] = f"body_{len(w) + 1}"
            elif w + c in proper:
                t[(name(w), c)] = name(w + c)
    body_symbols = list(prefix_chars) + ["L", "D", "S"]
    for n in range(1, MIN_KEY_LENGTH + 1):            # part 2: count the rest
        for sym in body_symbols:
            if char_class(sym if len(sym) == 1 and sym in prefix_chars else sym) != "O":
                t[(f"body_{n}", sym)] = f"body_{min(n + 1, MIN_KEY_LENGTH)}"

    def symbol_of(ch: str) -> str:
        return ch if ch in prefix_chars else char_class(ch)

    def group(state: str) -> str:
        if state == "q0":
            return "start"
        if state.startswith("pfx:"):
            return "reading prefix"
        if state == DEAD:
            return DEAD
        return "body (<20 chars)" if int(state.split("_")[1]) < MIN_KEY_LENGTH else "body (20+ chars)"

    def label(state: str, symbol: str) -> str:
        if state == "q0" or state.startswith("pfx:"):
            return "prefix char"
        return char_class(symbol) if symbol in prefix_chars else symbol

    def explain(state: str, steps: List[StepRecord]) -> str:
        if state == DEAD:
            return f"Invalid character '{steps[-1].char}'"
        if state.startswith("body_"):
            return "Length below 20 chars"
        return "Incomplete vendor prefix"

    return DFA("api_vendor", "API Key", "API_KEY",
               "Known prefix (sk-, ghp_, AKIA, ...) then letters/digits/symbols, 20+ chars total",
               "L = letter, D = digit, S = allowed symbol",
               "q0", {f"body_{MIN_KEY_LENGTH}"}, t, symbol_of, group, explain, label)


# =====================================================================
# 4) GENERIC API KEY (no known prefix)
#    20+ chars that contain BOTH a letter and a digit. The state remembers
#    (length so far, seen a letter?, seen a digit?).
#    This stops long plain words from being redacted as keys.
# =====================================================================
def build_generic_api_dfa() -> DFA:
    flag_after = {("-", "L"): "L", ("-", "D"): "D", ("-", "S"): "-",
                  ("L", "L"): "L", ("L", "D"): "LD", ("L", "S"): "L",
                  ("D", "L"): "LD", ("D", "D"): "D", ("D", "S"): "D",
                  ("LD", "L"): "LD", ("LD", "D"): "LD", ("LD", "S"): "LD"}
    t: Table = {}
    for sym in "LDS":
        t[("q0", sym)] = f"g1_{flag_after[('-', sym)]}"
    for n in range(1, MIN_KEY_LENGTH + 1):
        for flags in ("-", "L", "D", "LD"):
            for sym in "LDS":
                t[(f"g{n}_{flags}", sym)] = f"g{min(n + 1, MIN_KEY_LENGTH)}_{flag_after[(flags, sym)]}"

    def group(state: str) -> str:
        if state == "q0":
            return "start"
        if state == DEAD:
            return DEAD
        n, flags = state[1:].split("_")
        if int(n) < MIN_KEY_LENGTH:
            return "<20 chars"
        return "20+ chars, letter+digit" if flags == "LD" else "20+ chars, missing letter/digit"

    def explain(state: str, steps: List[StepRecord]) -> str:
        if state == DEAD:
            return f"Invalid character '{steps[-1].char}'"
        n, _ = state[1:].split("_") if state != "q0" else ("0", "")
        if int(n) < MIN_KEY_LENGTH:
            return "Length below 20 chars"
        return "Needs both letters and digits"

    return DFA("api_generic", "API Key", "API_KEY",
               "No known prefix: 20+ chars of letters/digits/symbols with at least one letter AND one digit",
               "L = letter, D = digit, S = allowed symbol",
               "q0", {f"g{MIN_KEY_LENGTH}_LD"}, t, char_class, group, explain)