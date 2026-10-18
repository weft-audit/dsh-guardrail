import { apply } from '../client.js'

// 用假 ctx 捕获 pre-execute 监听器，验证拦截决策（不依赖完整 Harness）。
const listeners = {}
const fakeCtx = {
  on: (ev, fn) => { listeners[ev] = fn },
}
apply(fakeCtx)

if (typeof listeners['tools/pre-execute'] !== 'function') {
  console.error('FAIL pre-execute listener not registered')
  process.exit(1)
}

const next = () => Promise.resolve({ kind: 'allow' })

const dangerous = await listeners['tools/pre-execute'](
  { name: 'bash', arguments: { command: 'Remove-Item -LiteralPath D:\\data -Recurse -Force' } },
  next,
)
console.log(`dangerous -> ${JSON.stringify(dangerous)}`)
if (dangerous.kind !== 'deny') { console.error('FAIL hard hit did not deny'); process.exit(1) }

const secret = await listeners['tools/pre-execute'](
  { name: 'write_file', arguments: { path: 'C:\\tmp\\a.txt', content: 'sk-abcdefghijklmnopqrstuvwxyz123456789' } },
  next,
)
console.log(`secret -> ${JSON.stringify(secret)}`)
if (secret.kind !== 'deny') { console.error('FAIL secret did not deny'); process.exit(1) }

const benign = await listeners['tools/pre-execute'](
  { name: 'bash', arguments: { command: 'git status' } },
  next,
)
console.log(`benign -> ${JSON.stringify(benign)}`)
if (benign.kind !== 'allow') { console.error('FAIL benign was blocked'); process.exit(1) }

console.log('HOOK_TESTS_PASS')
