// dsh-guardrail — 双清单哨兵（alpha）。
// 接口依据（官方原文，装包内 .d.ts）：
//   'tools/pre-execute'(this, exec: ToolExecution,
//     next: () => Promise<PreToolDecision>): Promise<PreToolDecision>
//   PreToolDecision = {kind:'allow'} | {kind:'deny',reason} | {kind:'cancel'} | {kind:'ask'}
// waterfall 不调用 next() 即短路流水线，官方明确用于拦截/网关逻辑。
import { scan, evidenceGap } from './src/checks.mjs'

export const name = 'dsh-guardrail'

// 办事三问：由平台侧小审计向办事者问（改没改规则/用没用 key/触没触防火墙），
// 插件只负责在未答时标记，不越权代问。
const REQUIRE_THREE_QUESTIONS = true

function collectStrings(value, out = []) {
  if (typeof value === 'string') { out.push(value); return out }
  if (Array.isArray(value)) { for (const v of value) collectStrings(v, out); return out }
  if (value && typeof value === 'object') {
    for (const k of Object.keys(value)) collectStrings(value[k], out)
  }
  return out
}

function looksLikeCommand(s) {
  return /^(bash|pwsh|sh|cmd|powershell|Remove-Item|rm\s|del\s|reg\s|netsh\s|format\s)/i.test(s)
    || (/^[a-zA-Z]:\\/.test(s) && /(recurse|force|delete)/i.test(s))
}

export function apply(ctx) {
  console.log('[dsh-guardrail] loaded: hard/soft double checklist active')

  ctx.on('tools/pre-execute', async (exec, next) => {
    try {
      const strings = collectStrings(exec.arguments)
      const text = JSON.stringify(exec.arguments ?? {})
      const paths = strings.filter((s) => /^[a-zA-Z]:\\/.test(s) || /(^|[\\/])(windows|system32|drivers|registry)([\\/]|$)/i.test(s))
      const commands = strings.filter((s) => looksLikeCommand(s))
      const r = scan({
        text, paths, commands,
        ctxFlags: { requireThreeQuestions: REQUIRE_THREE_QUESTIONS },
      })
      if (r.hard.length > 0) {
        const reason = `guardrail hard-block on ${exec.name}: ${r.hard.join('; ')}`
        console.error(`[dsh-guardrail] HARD BLOCK ${reason}`)
        // 短路：不调用 next()，按官方拦截范式直接返回 deny。
        return { kind: 'deny', reason }
      }
      if (r.soft.length > 0) {
        console.warn(`[dsh-guardrail] soft: ${r.soft.join('; ')}`)
      }
    } catch (e) {
      console.error(`[dsh-guardrail] check failed, passing through: ${String(e)}`)
    }
    return next()
  })

  // 结果侧软检查（接口原文 dsh-tools/lib/types/index.d.ts:92：
  // 'tools/result'(this, exec, result) => undefined）
  ctx.on('tools/result', (exec, result) => {
    try {
      const text = (result?.content ?? [])
        .filter((b) => b && b.type === 'text')
        .map((b) => String(b.text ?? ''))
        .join(' ')
      if (evidenceGap(text)) {
        console.warn(`[dsh-guardrail] soft: 无证据不算完成 (${exec.name})`)
      }
    } catch (e) {
      console.error(`[dsh-guardrail] result check failed: ${String(e)}`)
    }
  })
}
