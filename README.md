# skillspector-guard

A Claude mod that scans a skill's GitHub repo with [NVIDIA SkillSpector](https://docs.nvidia.com/skills/scanning-agent-skills) before Claude downloads or installs it.

## What it does

- Watches Bash commands that fetch code: `git clone <repo>`, `npx skills add <repo>`, and `pip/uv install git+<repo>`.
- Before the command runs, it shallow-clones the repo to a temp folder and runs `skillspector scan --no-llm` (static analysis, no API key needed). It installs SkillSpector with `uv` the first time if it is missing.
- **Blocks** the command on any CRITICAL finding, or a HIGH finding (confidence 0.8 or higher) in prompt injection, hidden instructions, supply chain, external script fetching, malware, obfuscation, exfiltration or credential harvesting. Claude is shown the findings and told to stop.
- **Allows** everything else and tells Claude what other findings there were. If the scan itself fails, the command still runs and Claude is told it ran unscanned.
- Saying "pull this skill" or "let's try this skill out" tells Claude to fetch the skill through a scanned command and report the result.

## Commands

- `/skillspector-allow <github url or owner/repo>` lets a flagged repo through. Only works when typed by you in the prompt box.
- `/skillspector-list` shows the repos you have allowed.

## Install

```
/plugin install skillspector-guard --marketplace inodroc/skillspector-guard
```

Needs `git` and `uv` (or an existing `skillspector` on PATH). Large repos can take a minute or more to scan.

## Tests

```
claude plugin test .
```
