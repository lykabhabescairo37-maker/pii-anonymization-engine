from dataclasses import dataclass, field
from typing import List, Dict, Tuple


@dataclass
class StepRecord:
    step_num: int
    char: str
    char_class: str
    old_state: str
    new_state: str
    note: str = ""


@dataclass
class TokenResult:
    token: str
    pii_type: str
    accepted: bool
    final_state: str
    reason: str
    redacted_tag: str
    steps: List[StepRecord] = field(default_factory=list)


class PIIAutomatonEngine:
    ALLOWED_SYMBOLS = set("._%+-@!#$^&*=~/?")
    API_PREFIXES = (
        "sk-proj-", "sk-live-", "sk-test-", "sk-",
        "pk_live_", "pk_test_", "sk_live_", "sk_test_",
        "AIza", "ghp_", "gho_", "ghu_", "AKIA", "xoxb-", "ya29."
    )

    @classmethod
    def classify_char(cls, ch: str) -> str:
        if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
            return "L"
        elif "0" <= ch <= "9":
            return "D"
        elif ch in cls.ALLOWED_SYMBOLS:
            return "S"
        return "O"

    def _trace_api_key_dfa(self, token: str) -> TokenResult:
        steps: List[StepRecord] = []
        state = "q0"

        matched_prefix = ""
        for prefix in self.API_PREFIXES:
            if token.startswith(prefix):
                matched_prefix = prefix
                break

        for idx, ch in enumerate(token, start=1):
            c_class = self.classify_char(ch)
            old_state = state

            if c_class == "O":
                state = "q_d"
                steps.append(StepRecord(idx, ch, c_class, old_state, state, "Invalid character"))
                return TokenResult(token, "API_KEY", False, "q_d", "Invalid character", token, steps)

            state = "q1" if len(token) >= 20 else "q_body"
            steps.append(StepRecord(idx, ch, c_class, old_state, state, "Processing token body"))

        if len(token) < 20:
            return TokenResult(token, "API_KEY", False, "q_d", "Length below 20 chars", token, steps)

        return TokenResult(token, "API_KEY", True, "q1", "Verified API Key", "", steps)

    def _trace_email_dfa(self, token: str) -> TokenResult:
        steps: List[StepRecord] = []
        state = "q0"
        tld_len = 0
        domain_len = 0

        if token.startswith(self.API_PREFIXES):
            return TokenResult(token, "EMAIL", False, "q_d", "Matches API prefix", token, steps)

        for idx, ch in enumerate(token, start=1):
            c_class = self.classify_char(ch)
            old_state = state

            if c_class == "O":
                state = "q_d"
            elif state == "q0":
                state = "q_local" if c_class in ("L", "D") or ch in "_%+-" else "q_d"
            elif state == "q_local":
                if ch == "@":
                    state = "q_at"
                elif c_class in ("L", "D") or ch in "._%+-":
                    state = "q_local"
                else:
                    state = "q_d"
            elif state == "q_at":
                if c_class in ("L", "D"):
                    state = "q_domain"
                    domain_len = 1
                else:
                    state = "q_d"
            elif state == "q_domain":
                if ch == "." and domain_len >= 1:
                    state = "q_dot"
                    tld_len = 0
                elif c_class in ("L", "D") or ch == "-":
                    state = "q_domain"
                    domain_len += 1
                else:
                    state = "q_d"
            elif state == "q_dot":
                if c_class == "L":
                    state = "q1"
                    tld_len = 1
                else:
                    state = "q_d"
            elif state == "q1":
                if ch == ".":
                    state = "q_dot"
                    tld_len = 0
                elif c_class == "L":
                    state = "q1"
                    tld_len += 1
                else:
                    state = "q_d"
            else:
                state = "q_d"

            steps.append(StepRecord(idx, ch, c_class, old_state, state))

        if state == "q1" and tld_len >= 2:
            return TokenResult(token, "EMAIL", True, "q1", "Verified Email", "", steps)

        return TokenResult(token, "EMAIL", False, "q_d", "Invalid email structure", token, steps)

    def _trace_phone_dfa(self, token: str) -> TokenResult:
        steps: List[StepRecord] = []
        state = "q0"
        digit_count = 0

        for idx, ch in enumerate(token, start=1):
            c_class = self.classify_char(ch)
            old_state = state

            if state == "q0":
                if ch == "+":
                    state = "q_plus"
                elif c_class == "D":
                    state = "q_digits"
                    digit_count = 1
                else:
                    state = "q_d"
            elif state in ("q_plus", "q_digits", "q1"):
                if c_class == "D":
                    digit_count += 1
                    state = "q1" if 10 <= digit_count <= 13 else "q_digits"
                elif ch == "-":
                    state = "q_digits"
                else:
                    state = "q_d"
            else:
                state = "q_d"

            steps.append(StepRecord(idx, ch, c_class, old_state, state))

        if state == "q1" and 10 <= digit_count <= 13:
            return TokenResult(token, "PHONE", True, "q1", "Verified Phone", "", steps)

        return TokenResult(token, "PHONE", False, "q_d", "Invalid phone format", token, steps)

    def inspect_token(self, raw_token: str) -> TokenResult:
        token = raw_token.rstrip(".,;:!?\"')")
        if not token:
            return TokenResult(raw_token, "NONE", False, "q_d", "Empty", raw_token, [])

        if token.startswith(self.API_PREFIXES):
            return self._trace_api_key_dfa(token)

        if "@" in token:
            email_res = self._trace_email_dfa(token)
            if email_res.accepted:
                return email_res
            if len(token) >= 20:
                api_res = self._trace_api_key_dfa(token)
                if api_res.accepted:
                    return api_res
            return email_res

        if len(token) >= 20:
            api_res = self._trace_api_key_dfa(token)
            if api_res.accepted:
                return api_res

        if token.startswith("+") or (token[0].isdigit() and len(token) >= 7):
            return self._trace_phone_dfa(token)

        steps = [
            StepRecord(i, ch, self.classify_char(ch), "q0", "q_text")
            for i, ch in enumerate(token, start=1)
        ]
        return TokenResult(token, "NONE", False, "q_d", "Standard text", token, steps)

    def process_text(self, text: str) -> Dict:
        words = text.split()
        redacted_words = []
        results = []
        pii_counter = 0

        email_count = 0
        api_count = 0
        phone_count = 0
        rejected_count = 0

        for word in words:
            if not word:
                continue
            stripped = word.rstrip(".,;:!?\"')")
            trailing = word[len(stripped):]
            res = self.inspect_token(stripped)

            if res.accepted:
                pii_counter += 1
                tag = f"[{res.pii_type}_{pii_counter:02d}]"
                res.redacted_tag = tag
                redacted_words.append(tag + trailing)
                if res.pii_type == "EMAIL": email_count += 1
                elif res.pii_type == "API_KEY": api_count += 1
                elif res.pii_type == "PHONE": phone_count += 1
            else:
                res.redacted_tag = stripped
                redacted_words.append(word)
                if res.pii_type != "NONE":
                    rejected_count += 1

            results.append({
                "token": res.token,
                "type": res.pii_type if res.accepted else (res.pii_type if res.pii_type != "NONE" else "TEXT"),
                "accepted": res.accepted,
                "final_state": res.final_state,
                "reason": res.reason,
                "redacted_tag": res.redacted_tag,
                "steps": [{
                    "step": s.step_num, "char": s.char, "char_class": s.char_class,
                    "old_state": s.old_state, "new_state": s.new_state, "note": s.note
                } for s in res.steps]
            })

        return {
            "original_text": text,
            "redacted_text": " ".join(redacted_words),
            "total_tokens": len(words),
            "pii_count": pii_counter,
            "email_count": email_count,
            "api_count": api_count,
            "phone_count": phone_count,
            "rejected_count": rejected_count,
            "tokens": results,
        }