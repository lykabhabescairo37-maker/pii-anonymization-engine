# PII Anonymization Engine

A DFA-based web app that detects and redacts emails, API keys, and phone numbers
from pasted text or uploaded files. Python standard library only, no installs.

## Run

```bash
python app.py          # then open http://127.0.0.1:5000
python test_engine.py  # run the tests
```

## Files

| File             | What it does                                                                |
| ---------------- | --------------------------------------------------------------------------- |
| `automata.py`    | The DFA class and the four automata, each defined as a transition table     |
| `engine.py`      | Splits text into tokens, picks the right DFA, redacts by position           |
| `app.py`         | Web server: dashboard, `/scan`, `/redact-file`, `/api/dfas`                 |
| `dashboard.html` | UI: redact text/files, click a result to see its path through the automaton |
| `test_engine.py` | 32 original cases plus tests for formatting, CSV, diagrams                  |

## How a DFA is defined here

A DFA = states, alphabet, transition table, start state, accepting states.
In `automata.py` the table is a dict `{(state, symbol): next_state}`.
A missing entry means the dead state `q_d` (rejected). Accepted tokens report `q1`.

Example (email): `q0 -L,D,S,-> q_local -@-> q_at -L,D-> q_domain -.-> q_dot -L-> q_tld1 -L-> q_tld2 (accept)`

## Detection order (`engine.inspect_token`)

1. Known vendor prefix (`sk-`, `ghp_`, `AKIA`, ...) -> vendor API-key DFA
2. Contains `@` -> email DFA, then generic API-key DFA as a fallback
3. 20+ chars -> generic API-key DFA (needs a letter AND a digit)
4. Starts with `+` or 7+ digits -> phone DFA
5. Looks like a domain with no `@` (e.g. `johndoe.com`) -> email DFA, reported as rejected
6. Otherwise plain text

## Known limits

- Phone numbers containing spaces or parentheses (`0917 123 4567`) are not detected.
- File names such as `report.txt` look like domains and show up as rejected emails.
- Uploads are limited to 5 MB and to .txt .csv .tsv .log .json .md.
