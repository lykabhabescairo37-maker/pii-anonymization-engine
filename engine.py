"""
engine.py - scans text, runs the right DFA on each token, and redacts matches.

Redaction works on character POSITIONS in the original text, so line breaks,
tabs and spacing come out exactly as they went in.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List

from automata import (
    DFA, StepRecord, build_email_dfa, build_generic_api_dfa,
    build_phone_dfa, build_vendor_api_dfa, char_class, MIN_KEY_LENGTH, DEAD,
)

# A token is a run of characters that can't be separators (space, comma, quotes, brackets ...).
TOKEN_PATTERN = re.compile(r"[^\s,;:|\"'<>()\[\]{}]+")
TRAILING_PUNCT = ".,;:!?\"')]>"
DOMAIN_LIKE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")


@dataclass
class TokenResult:
    token: str
    pii_type: str
    accepted: bool
    final_state: str
    reason: str
    redacted_tag: str
    steps: List[StepRecord] = field(default_factory=list)
    start: int = 0              # position in the original text
    end: int = 0
    dfa_id: str = ""            # which automaton ran ("" for plain text)
    path: List[str] = field(default_factory=list)


class PIIAutomatonEngine:
    API_PREFIXES = (
        "sk-proj-", "sk-live-", "sk-test-", "sk-",
        "pk_live_", "pk_test_", "sk_live_", "sk_test_",
        "AIza", "ghp_", "gho_", "ghu_", "AKIA", "xoxb-", "ya29.",
    )

    def __init__(self):
        self.email = build_email_dfa()
        self.phone = build_phone_dfa()
        self.api_vendor = build_vendor_api_dfa(self.API_PREFIXES)
        self.api_generic = build_generic_api_dfa()
        self.automata: List[DFA] = [self.email, self.phone, self.api_vendor, self.api_generic]

    @staticmethod
    def classify_char(ch: str) -> str:
        return char_class(ch)

    # ------------------------------------------------------------------
    def _run(self, dfa: DFA, token: str) -> TokenResult:
        run = dfa.run(token)
        return TokenResult(token, dfa.pii_type, run.accepted, run.final_state, run.reason,
                           "" if run.accepted else token, run.steps,
                           dfa_id=dfa.id, path=dfa.path_of(run.steps))

    def inspect_token(self, raw_token: str) -> TokenResult:
        """Decide which automaton(s) apply to one token and return the verdict."""
        token = raw_token.rstrip(TRAILING_PUNCT)
        if not token:
            return TokenResult(raw_token, "NONE", False, DEAD, "Empty", raw_token)

        if token.startswith(self.API_PREFIXES):
            return self._run(self.api_vendor, token)

        if "@" in token:
            email_res = self._run(self.email, token)
            if email_res.accepted:
                return email_res
            if len(token) >= MIN_KEY_LENGTH:          # "x9K@..." may be a key, not an email
                key_res = self._run(self.api_generic, token)
                if key_res.accepted:
                    return key_res
            return email_res

        if len(token) >= MIN_KEY_LENGTH:
            key_res = self._run(self.api_generic, token)
            if key_res.accepted:
                return key_res

        if token.startswith("+") or (token[0].isdigit() and len(token) >= 7):
            return self._run(self.phone, token)

        if DOMAIN_LIKE.match(token):                  # "johndoe.com" -> email missing its '@'
            return self._run(self.email, token)

        steps = [StepRecord(i, ch, char_class(ch), "q0", "q_text")
                 for i, ch in enumerate(token, start=1)]
        return TokenResult(token, "NONE", False, DEAD, "Standard text", token, steps)

    # ------------------------------------------------------------------
    def process_text(self, text: str) -> Dict:
        pieces: List[str] = []
        results: List[Dict] = []
        counts = {"EMAIL": 0, "API_KEY": 0, "PHONE": 0}
        pii_counter = rejected = pos = 0

        for match in TOKEN_PATTERN.finditer(text):
            core = match.group().rstrip(TRAILING_PUNCT)
            if not core:
                continue
            start, end = match.start(), match.start() + len(core)
            res = self.inspect_token(core)
            res.start, res.end = start, end

            if res.accepted:
                pii_counter += 1
                counts[res.pii_type] += 1
                res.redacted_tag = f"[{res.pii_type}_{pii_counter:02d}]"
                pieces.append(text[pos:start])        # untouched text before the match
                pieces.append(res.redacted_tag)
                pos = end
            else:
                res.redacted_tag = core
                if res.pii_type != "NONE":
                    rejected += 1
            results.append(self._to_dict(res))

        pieces.append(text[pos:])
        return {
            "original_text": text,
            "redacted_text": "".join(pieces),
            "total_tokens": len(results),
            "pii_count": pii_counter,
            "email_count": counts["EMAIL"],
            "api_count": counts["API_KEY"],
            "phone_count": counts["PHONE"],
            "rejected_count": rejected,
            "tokens": results,
        }

    @staticmethod
    def _to_dict(res: TokenResult) -> Dict:
        shown_type = res.pii_type if res.pii_type != "NONE" else "TEXT"
        return {
            "token": res.token, "type": shown_type, "accepted": res.accepted,
            "final_state": res.final_state, "reason": res.reason,
            "redacted_tag": res.redacted_tag, "start": res.start, "end": res.end,
            "dfa_id": res.dfa_id, "path": res.path,
            "steps": [{"step": s.step_num, "char": s.char, "char_class": s.char_class,
                       "old_state": s.old_state, "new_state": s.new_state, "note": s.note}
                      for s in res.steps],
        }

    def describe_automata(self) -> List[Dict]:
        return [dfa.diagram() for dfa in self.automata]