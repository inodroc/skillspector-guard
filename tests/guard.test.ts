import { expect, test } from 'claude-code/testing'

const ok = (stdout = '') => ({ value: { exitCode: 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } })

function engine(on: any, report: object, seen: string[][]) {
  on('store.get', () => ({ value: undefined }))
  on('ui.status', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('process.run', (_: any, e: any) => {
    seen.push([...e.argv])
    if (e.argv[0] === 'sh') return ok('/root/.local/bin/skillspector')
    if (e.argv[0] === 'mktemp') return ok('/tmp/x')
    return ok()
  })
  on('fs.read', () => ({ value: JSON.stringify(report) }))
  on('tool.call', () => ({ result: { stdout: 'cloned' } }))
}

test('high supply-chain finding blocks the clone', async ($, on) => {
  const seen: string[][] = []
  engine(on, { issues: [{ severity: 'HIGH', confidence: 0.9, category: 'Supply Chain', pattern: 'External Script Fetching' }] }, seen)
  const r: any = await $.tool.call({ tool: 'Bash', command: 'git clone --depth 1 https://github.com/evil/skill.git' })
  expect(String(r.deny ?? r.text)).toContain('SkillSpector blocked https://github.com/evil/skill')
  expect(seen.some(a => a.includes('https://github.com/evil/skill'))).toBe(true)
})

test('only README snooping passes with a note', async ($, on) => {
  const seen: string[][] = []
  engine(on, { issues: [{ severity: 'HIGH', confidence: 0.9, category: 'Agent Snooping', pattern: 'Agent Config Directory Access' }] }, seen)
  const r: any = await $.tool.call({ tool: 'Bash', command: 'npx skills add latent-spaces/brag --skill brag' })
  expect(r.deny).toBe(undefined)
  expect(String(r.context?.[0])).toContain('no blocking findings')
})

test('unrelated commands are not scanned', async ($, on) => {
  const seen: string[][] = []
  engine(on, {}, seen)
  await $.tool.call({ tool: 'Bash', command: 'ls -la' })
  expect(seen.length).toBe(0)
})

test('trigger phrases add the fetch-through-scan note', async ($, on) => {
  const got: (readonly string[] | undefined)[] = []
  on('prompt.submit', (_: any, e: any) => { got.push(e.context); return { text: e.text } as any })
  await $.prompt.submit({ text: "yo lets try this skill out https://github.com/a/b" } as any)
  await $.prompt.submit({ text: 'pull this skill' } as any)
  await $.prompt.submit({ text: 'what time is it' } as any)
  expect(String(got[0]?.[0])).toContain('skillspector-guard')
  expect(String(got[1]?.[0])).toContain('skillspector-guard')
  expect(got[2]).toBe(undefined)
})
