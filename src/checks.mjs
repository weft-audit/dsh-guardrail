// 双清单检查逻辑（纯函数，可独立测试）。
// 依据：小审计双清单契约（_求职/插件/dsh-guardrail/规格-草案.md）。
// 2026-10-18 扩展（所有者拍板）：硬清单加"治理文件写保护、防火墙/凭据操作"；
// 软清单加"密钥使用提示、无证据不算完成、办事三问未答"。

export const SECRET_PATTERNS = [
  { id: 'deepseek-key', re: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { id: 'dashscope-key', re: /\bsk-[A-Za-z0-9]{16,}\b/ },
  { id: 'openrouter-key', re: /\bsk-or-[A-Za-z0-9_-]{16,}\b/ },
  { id: 'aws-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
]

export const DANGEROUS_PATHS = [
  /^[a-z]:\\windows/i, /\\windows\\/i, /\\system32\\/i,
  /\\drivers\\etc\\hosts/i, /\\registry/i, /firewall/i,
  // Linux 危险面（2026-10-18 补）
  /^\/etc\/hosts$/i, /^\/etc\/(passwd|shadow|sudoers|sudoers\.d\/)/i,
  /^\/etc\/ssh\/sshd_config$/i, /^\/root\//i, /^\/boot\//i,
]

export const DANGEROUS_CMDS = [
  { id: 'rm-rf', re: /\brm\s+-rf\b/ },
  { id: 'remove-item-recursive', re: /\bRemove-Item\b[^\n]*?(-Recurse|-Force)/i },
  { id: 'format', re: /\bformat\s+[a-z]:/i },
  { id: 'reg-delete', re: /\breg\s+(delete|del)\b/i },
  { id: 'netsh', re: /\bnetsh\b[^\n]*(firewall|advfirewall)/i },
  { id: 'defender-policy', re: /\b(Set|Add)-MpPreference\b/i },
  { id: 'reg-firewall', re: /\breg\s+(add|delete|del)\b[^\n]*firewall/i },
  { id: 'credential-file-read', re: /(Get-Content|cat|type)\s+[^\n]*\.credentials[^\n]*/i },
  { id: 'print-key', re: /(setx|echo|Write-Output|printenv|Get-ChildItem\s+Env:)[^\n]*(API_KEY|SECRET|TOKEN|CREDENTIAL)[^\n]*/i },
  // Linux 危险命令（2026-10-18 补）
  { id: 'iptables-nft', re: /\b(iptables|ip6tables|nft)\b[^\n]*(-F|-X|flush)/i },
  { id: 'firewall-service', re: /\b(systemctl|service)\b[^\n]*(stop|disable|mask)[^\n]*(firewalld|ufw)/i },
  { id: 'ufw-disable', re: /\bufw\s+(disable|--force\s+reset)/i },
  { id: 'sudoers-write', re: /(visudo|tee[^\n]*sudoers|sed\s+-i[^\n]*(passwd|shadow|sudoers))/i },
  { id: 'recursive-chmod-root', re: /\bchmod\b[^\n]*-R[^\n]*7{3,}/i },
  { id: 'dd-destructive', re: /\bdd\b[^\n]*of=\/dev\/(sd|nvme)/i },
]

export const GOVERNANCE_FILES = [
  /(^|[\\/])AGENTS\.md$/i,
  /(^|[\\/])公共件\.md$/i,
  /(^|[\\/])目标\.md$/i,
  /(^|[\\/])个人事实\.md$/i,
  /(^|[\\/])红线[^\\/]*\.md$/i,
]

export const KEY_USE_PATTERNS = [
  /\$env:[A-Za-z0-9_]*(KEY|TOKEN|SECRET|CREDENTIAL)[A-Za-z0-9_]*/i,
  /%[A-Za-z0-9_]*(KEY|TOKEN|SECRET|CREDENTIAL)[A-Za-z0-9_]*%/,
  /process\.env\.[A-Za-z0-9_]*(KEY|TOKEN|SECRET|CREDENTIAL)[A-Za-z0-9_]*/i,
  /Authorization\s*[:=]\s*(Bearer|Basic)/i,
]

export function scan({ text = '', paths = [], commands = [], ctxFlags = {} } = {}) {
  const hard = []
  const soft = []
  for (const p of SECRET_PATTERNS) {
    if (p.re.test(text)) hard.push(`secret:${p.id}`)
  }
  for (const path of paths) {
    if (DANGEROUS_PATHS.some((re) => re.test(path))) hard.push(`path:${path}`)
    if (GOVERNANCE_FILES.some((re) => re.test(path))) hard.push(`governance-write:${path}`)
  }
  for (const cmd of commands) {
    for (const d of DANGEROUS_CMDS) {
      if (d.re.test(cmd)) hard.push(`cmd:${d.id}:${cmd}`)
    }
  }
  if (!ctxFlags.rollback) soft.push('no rollback point declared')
  if (!ctxFlags.acceptance) soft.push('no acceptance criteria declared')
  if (KEY_USE_PATTERNS.some((re) => re.test(text))) soft.push('key-use detected: use managed credential channel')
  if (ctxFlags.requireThreeQuestions && !ctxFlags.threeQuestionsAnswered) {
    soft.push('turn three-questions unanswered (rules changed? key used? firewall touched?)')
  }
  return { hard, soft }
}

// 结果侧判据：出现完成/成功措辞却没有证据标记。
export function evidenceGap(text = '') {
  const claimsDone = /(已完成|已成功|完成|成功)/.test(text)
  const hasEvidence = /【(命令|原始输出|回读)】/.test(text) || /(^|\s)(exit=0|PASS|FAIL)(\s|$)/.test(text)
  return claimsDone && !hasEvidence
}
