# dsh-guardrail

双清单哨兵（guardrail sentinel）for DeepSeek Harness — a guardrail plugin with
two checklists: a hard safety list (secrets, system paths, dangerous writes,
governance-file writes, firewall/credential operations — stop and report on
hit) and a soft gaps list (rollback/acceptance gaps, key-usage hints,
three-questions receipt, "no evidence, not done" — suggestions only, never
scores, never rules).

## Status

Alpha, in development. Spec first, implementation second: the behavior contract
comes from a running multi-agent system in which the same double-checklist
guard already operates as a platform agent. This plugin ports that contract
into a DSH bundle. No silent acceptance: on a safety hit the plugin pauses the
task instead of passing it through.

## Install (once published)

```bash
dsh plugin --profile web add git+https://github.com/weft-audit/dsh-guardrail
```

## Contract

1. Hard list (stop): secret patterns; writes outside the workspace
   (Windows/system dirs, registry, firewall); destructive recursive deletes;
   writes to governance files (AGENTS.md / 公共件.md / 目标.md / 个人事实.md /
   红线*); reading .credentials files; Defender policy changes; printing keys;
   Linux hazards (iptables/nft flush, firewalld/ufw disable, sudoers writes,
   /etc/hosts·passwd·shadow·sudoers·sshd_config paths, dd to /dev/sd*).
2. Soft list (advise): missing rollback point, undefined acceptance criteria,
   key-usage hint, three-questions receipt unanswered, and a `tools/result`
   check that flags "done/success" claims without evidence marks
   (【命令】/【原始输出】).
3. Output shape: `{ hard: [...], soft: [...] }`, each at most 8 lines.

## Rules honored

The plugin never scores and never rules. The human (or the main auditor) is
the only arbiter. The "three questions" (rules changed? key used? firewall
touched?) are asked by the platform-side micro-auditor; this plugin only marks
them as unanswered — it never interrogates other agents.
