# Security policy

## Scope

tfguard reads files and prints a report. It is a static analysis tool, and the
security questions that apply to it are the ones that apply to any tool that
parses untrusted input.

Supported: the current release.

## What this tool does with your files

Nothing leaves your machine. There is no network client in the codebase — the
scanner opens `.tf` files, parses them, and writes a report. The only outbound
thing the project does is the optional MCP server, and that only speaks the
stdio/HTTP transport you point it at.

## Reporting a vulnerability in tfguard

Use [GitHub private vulnerability reporting](https://github.com/xuange-hu/tfguard/security/advisories)
on the Security tab. If private reporting is unavailable to you, open an issue
marked `security`.

Include:

1. the version (`tfguard --version`);
2. the input that triggers it — a `.tf` file is preferred over a description;
3. what you expected and what happened.

For a parser crash, the smallest file that reproduces it is the whole report.

## What counts as a vulnerability here

- **A crash on valid Terraform.** The lexer and parser are written from
  scratch, so an input that real Terraform accepts and tfguard rejects is a
  bug worth filing.
- **A parse that silently loses content.** Missing a block is worse than
  failing on it, because a clean report then means the opposite of what it
  says.
- **A crash on hostile input.** A `.tf` file can be arbitrarily large; unbounded
  recursion or a hang is a defect.
- **Path handling.** The scanner must never follow a path outside the directory
  it was pointed at.

## What does not count

- A rule firing on configuration you consider correct. That is a false positive:
  open an issue with the snippet and it gets a regression test.
- A rule you want added. Open an issue or a PR.

## Timing

I triage within a week and will confirm receipt. If a fix needs to sit in a
branch for a while, the advisory goes out when the fix lands, not before.
