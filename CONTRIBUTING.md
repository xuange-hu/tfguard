# Contributing

tfguard is small on purpose: one parser, one rule engine, no dependencies.
Contributions that keep it that way are welcome.

## Setup

```bash
git clone https://github.com/xuange-hu/tfguard
cd tfguard
pip install -e ".[mcp]" pytest ruff
pytest
ruff check src tests
```

No `pip install` is needed to run the tests after a clone — the root
`conftest.py` puts `src/` on `sys.path`. `tests/test_bootstrap.py` asserts
that stays true.

## Adding a rule

A rule is five things, and all five are required:

1. **The entry** in `src/tfguard/rules.py`. Give it a title a reader can act
   on, a severity, a category, and both `why` and `fix` in plain language.
   The `fix` says what to change, not what the concept is called.
2. **The check** in `src/tfguard/analyze.py`, in the pass that matches:
   one block at a time, the credential pass, or the relationship pass.
3. **A trigger sample** in `tests/test_rules.py` named `test_tfgNNN`.
   `test_every_rule_has_a_trigger_sample` fails if a rule has none.
4. **The negative case** in the same file — the configuration that should
   *not* fire it. A rule that fires on correct configuration is worse than
   a rule that never fires.
5. **A line in the demo** (`src/tfguard/demo.py`) if the rule can fire there.
   `tests/test_demo.py` asserts the demo still exercises every rule.

Then update the rule table and the badge count in `README.md`. There is a CI
job that warns when the badge and pytest disagree.

## Rules of the road

- **Zero dependencies in `src/tfguard/` outside `mcp_server.py`.**
  `tests/test_packaging.py` fails on an `import mcp` anywhere else, and the
  core is imported in CI with only base deps installed.
- **No network access.** Not in the scanner, not in the tests. Tests that
  need a file write it to `tmp_path`.
- **Every finding carries a line and its source text.** A report that says
  "something is wrong" without saying where gets closed and forgotten.
- **`absent` and `empty` are different.** If you add a rule that fires on a
  missing argument, decide what the explicit empty form means first.
- **Line numbers come from the parser.** Do not compute them in the rule.

## The HCL2 parser

`src/tfguard/hcl.py` is the part everything stands on. If you extend it:

- add the shape to `tests/test_hcl.py` using real Terraform syntax, not a
  synthetic minimum;
- a new node type needs `as_py()` and `refs()`;
- an expression that resolves at apply time should render symbolically
  (`"<cond>"`), never as a guessed value — a rule must not conclude
  "encrypted" because one branch of a conditional says so.

## Commit and PR

- One logical change per commit.
- Rebase rather than merge to keep the history readable.
- CI runs on 3.10–3.13 across Ubuntu and Windows. A test that passes only on
  your machine will be caught there, so run `pytest` before pushing.
