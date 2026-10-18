import { scan, evidenceGap } from '../src/checks.mjs'

const cases = [
  {
    name: '反例1：密钥明文命中',
    input: { text: 'key=sk-abcdefghijklmnopqrstuvwxyz123456789' },
    expectHard: (h) => h.some((x) => x.startsWith('secret:')),
  },
  {
    name: '反例2：系统路径越界',
    input: { paths: ['C:\\Windows\\System32\\config\\SAM'] },
    expectHard: (h) => h.some((x) => x.startsWith('path:')),
  },
  {
    name: '反例3：危险删除命令',
    input: { commands: ['Remove-Item -LiteralPath D:\\data -Recurse -Force'] },
    expectHard: (h) => h.some((x) => x.startsWith('cmd:')),
  },
  {
    name: '负例：正常内容不误报',
    input: { text: '今天写 README', paths: ['D:\\work\\notes.md'], commands: ['git status'], ctxFlags: { rollback: true, acceptance: true } },
    expectHard: (h) => h.length === 0,
  },
  {
    name: '软清单：缺回滚点与验收标准',
    input: { text: '', paths: [], commands: [], ctxFlags: {} },
    expectSoft: (s) => s.length === 2,
  },
  {
    name: '反例4：写治理文件',
    input: { paths: ['C:\\repo\\AGENTS.md'] },
    expectHard: (h) => h.some((x) => x.startsWith('governance-write:')),
  },
  {
    name: '反例5：读凭据文件',
    input: { commands: ['Get-Content C:\\Users\\x\\.credentials.yaml'] },
    expectHard: (h) => h.some((x) => x.startsWith('cmd:credential-file-read')),
  },
  {
    name: '反例6：改 Defender 策略',
    input: { commands: ['Set-MpPreference -DisableRealtimeMonitoring $true'] },
    expectHard: (h) => h.some((x) => x.startsWith('cmd:defender-policy')),
  },
  {
    name: '软检查：密钥使用提示',
    input: { text: 'export DEEPSEEK_API_KEY=$env:DEEPSEEK_API_KEY', ctxFlags: { rollback: true, acceptance: true } },
    expectSoft: (s) => s.some((x) => x.startsWith('key-use')),
  },
  {
    name: '软检查：办事三问未答标记',
    input: { text: '', paths: [], commands: [], ctxFlags: { rollback: true, acceptance: true, requireThreeQuestions: true } },
    expectSoft: (s) => s.some((x) => x.includes('three-questions')),
  },
  {
    name: '结果侧：无证据不算完成',
    input: { text: '', paths: [], commands: [], ctxFlags: {} },
    expectGap: () => evidenceGap('任务已完成，共 10 条'),
  },
  {
    name: '结果侧：有证据不误报',
    input: { text: '', paths: [], commands: [], ctxFlags: {} },
    expectNoGap: () => !evidenceGap('任务已完成【命令】git status【原始输出】exit=0'),
  },
  {
    name: '反例7：Linux 防火墙清空',
    input: { commands: ['iptables -F'] },
    expectHard: (h) => h.some((x) => x.startsWith('cmd:iptables-nft')),
  },
  {
    name: '反例8：Linux 系统文件路径',
    input: { paths: ['/etc/sudoers'] },
    expectHard: (h) => h.some((x) => x.startsWith('path:')),
  },
  {
    name: '负例2：Linux 正常命令不误报',
    input: { text: '', paths: ['/home/user/notes.md'], commands: ['ls -la', 'git status'], ctxFlags: { rollback: true, acceptance: true, requireThreeQuestions: false } },
    expectHard: (h) => h.length === 0,
  },
]

let fail = 0
for (const c of cases) {
  const r = scan(c.input)
  const ok = (c.expectHard ? c.expectHard(r.hard) : true)
    && (c.expectSoft ? c.expectSoft(r.soft) : true)
    && (c.expectGap ? c.expectGap() : true)
    && (c.expectNoGap ? c.expectNoGap() : true)
  console.log(`${ok ? 'PASS' : 'FAIL'} ${c.name} -> hard=${JSON.stringify(r.hard)} soft=${JSON.stringify(r.soft)}`)
  if (!ok) fail += 1
}
process.exit(fail === 0 ? 0 : 1)
