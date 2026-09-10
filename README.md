# untrusted-content-guard

A `PostToolUse` hook for [Claude Code](https://claude.com/claude-code) that scans
web content the agent just fetched for **prompt-injection** and
**credential-leak** patterns, quarantines what it finds, and tells the model to
treat the content as data rather than instructions.

It never blocks. It always exits 0.

```
WebFetch / WebSearch  ──▶  sanitize_hook.py  ──┬──▶  additionalContext warning (CRITICAL / HIGH)
                                               └──▶  quarantine record  (all severities)
```

## Why

An agent that fetches a page and an agent that reads instructions are the same
agent. Anything retrieved from the network arrives inside the same context window
as the operator's own instructions, and the model has no channel-level way to tell
them apart. This is a demonstrated attack rather than a hypothetical one: the
Poisoned-LangChain work ([arXiv:2406.18122](https://arxiv.org/abs/2406.18122))
reports 88.56 % / 79.04 % / 82.69 % success across three jailbreak categories by
poisoning the retrieval layer alone.

This hook is one cheap layer at the boundary where that content enters. It does
not solve the problem. It marks the boundary and leaves evidence.

## What it detects

| Severity | Detector | Reaches the model? |
|---|---|---|
| CRITICAL | credential shapes — `sk-…`, `ghp_…`, `xoxb-…`, `AIza…`, `Bearer …`, assigned `*_API_KEY` / `*_TOKEN` env vars | yes |
| HIGH | injection shapes — `ignore previous instructions`, `disregard all prior`, `you are now`, a `system:` line, `override behavior`, `<\|im_start\|>`, a fenced `role: system` block | yes |
| MEDIUM | repeated fixed-shape uppercase tokens (canary heuristic) | no — silent quarantine |

**Findings never carry the secret.** A credential is recorded as a truncated
SHA-256 digest, and injection excerpts pass through a redaction pass first — so a
quarantine file is safe to read, ship, diff and attach to a ticket. `test_sanitize.py`
asserts this directly (T7).

## Measured quality

```
TP=10  FP=4  TN=6  FN=0   (n=20)
precision = 0.714    recall = 1.000    f1 = 0.833
```

Four false positives out of ten deliberately-hard benign documents, including a
security article that quotes the attack string. **[EVALS.md](EVALS.md)** explains
the set, lists every false positive by name, and works through why — given how
rare injections are in a normal fetch stream — even a detector with a 0.1 % false
positive rate is wrong more often than it is right, and why that arithmetic is the
reason this hook warns instead of blocking.

## Install

```bash
git clone https://github.com/Kolenkovskin/untrusted-content-guard
cp untrusted-content-guard/sanitize_hook.py ~/.claude/hooks/
```

`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "WebFetch|WebSearch",
        "hooks": [
          { "type": "command", "command": "python3 ~/.claude/hooks/sanitize_hook.py" }
        ]
      }
    ]
  }
}
```

Quarantine defaults to `~/.claude/logs/quarantine/`; set `SANITIZE_QUARANTINE_DIR`
to move it.

Standard library only. Python 3.10+.

## Verify

```bash
python test_sanitize.py     # 10/10 — behaviour, secret-leak regression, fail-open contract
python evals/run_evals.py   # precision / recall against evals/cases.json
```

The test suite includes two negative controls that matter more than the positive
cases: **T8** asserts a `Bash` tool result containing a key is *not* analysed
(scope discipline), and **T10** feeds the hook empty input, malformed JSON, a bare
array and a null tool name, asserting exit 0 on every one. A guard that can crash
the workflow it guards will be removed by its own user within a week.

## Design rules

1. **Fail open, always.** Every path exits 0. A detector must never be the reason
   work stops.
2. **The finding must not become the leak.** Nothing that matched a secret pattern
   is written anywhere in plaintext.
3. **Atomic quarantine.** `tempfile` + `os.replace`, so a crash mid-write cannot
   leave a half-parsed record.
4. **Spend attention only at the top tier.** MEDIUM is quarantined silently.
5. **Warn, do not decide.** The model is told to treat the content as untrusted
   data; the operator keeps the judgement call.

## Scope

Defensive only. This repository contains detectors and a threat model. It contains
no exploit code, no payload generator and no bypass technique.

Regex matching is a first layer and a weak one — it has no paraphrase robustness,
no coverage of non-English injections, and no handling of homoglyph or zero-width
obfuscation. It raises the cost of the laziest attacks and produces a durable
record of the rest. Treat it accordingly.

[THREAT_MODEL.md](THREAT_MODEL.md) covers the layer above: what a compromised
agent helper holding device-automation capability can do, and the five controls
that bound it.

## Licence

MIT — see [LICENSE](LICENSE).
