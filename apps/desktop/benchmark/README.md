# External detection benchmark

Runs the **shipped** detection pipeline (regex + dampeners + Prompt Guard 2
CoreML, exactly as the gateway invokes it via `InjectionInspectionPass.inspect`)
against **third-party** corpora — not Bouclier's own pattern examples — so
"how good is detection" is a real number instead of a self-referential one.

```bash
python3 benchmark/fetch-corpora.py           # writes data/ (gitignored)
BOUCLIER_BENCH=1 swift test --filter ExternalBenchmarkTests
```

Each corpus string is wrapped as an untrusted `tool_result` span, so the test
measures the engine's detection capability on external strings of each class.

## Corpora

| Source                               | Role             | Notes                                                                                                                 |
| ------------------------------------ | ---------------- | --------------------------------------------------------------------------------------------------------------------- |
| `Lakera/gandalf_ignore_instructions` | attacks          | Instruction-override payloads — **Bouclier's actual target class**.                                                   |
| `deepset/prompt-injections`          | attacks + benign | Attack split is mostly **direct jailbreak/role-play** — _out of_ Bouclier's threat model, so it scores low by design. |
| `leolee99/NotInject`                 | benign           | Benign prompts loaded with trigger words — the over-defense stress test.                                              |

## What the numbers mean, and don't

- The ML tier is Prompt Guard 2, so ML detection is bounded by PG2; the fusion
  can also underperform raw PG2 (a mid-range ML score carries only 0.40 weight).
- These are **static-corpus** results. They say nothing about **adaptive**
  attacks (an attacker optimizing against the detector), where every detector of
  this architecture — PG2 included — is bypassed at high rates. A clean pass is
  not evidence of safety.
- gandalf/deepset are direct-injection strings tested for detection capability;
  a true **indirect**-injection-in-agent-context benchmark (AgentDojo, BIPIA) is
  the natural next addition.
- The shipped default is monitor mode — a real install blocks nothing until
  `injectionBlockEnabled` is set.
