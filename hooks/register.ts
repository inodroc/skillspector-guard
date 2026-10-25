import type { Register } from 'claude-code'

// Scans a repo with NVIDIA SkillSpector (static mode, no API key) before a
// Bash command clones or installs it. Blocks only high-confidence, high-severity
// findings in the dangerous categories; everything else passes with a summary.

const SKIP = [/github\.com\/nvidia\/skillspector/i]
const DANGER =
  /prompt injection|hidden instruction|supply chain|external script|malware|obfuscat|exfiltrat|credential|harvest|backdoor|reverse shell/i
const ALLOW_KEY = 'allowlist'
const TRIGGER = /\b(pull|grab|get|install)\s+(this|that|the)\s+skill\b|\blet'?s\s+try\s+(this|that|the)\s+skill\b/i
const TRIGGER_NOTE =
  'skillspector-guard: the user wants to fetch a skill. Find its GitHub repo (from the message, a linked post, or by searching), ' +
  'then fetch it with a Bash `git clone --depth 1 <repo url>` (or `npx skills add <repo>`) so the SkillSpector hook scans it first. ' +
  'Never fetch it another way (WebFetch, curl, manual file writes) to skip the scan. Report the scan result: blocked findings, or the scan note. ' +
  'If blocked, show the findings and stop; only the user can run /skillspector-allow.'
const SCAN_TIMEOUT = 9 * 60_000

type Issue = {
  category?: string
  pattern?: string
  severity?: string
  confidence?: number
  finding?: string
  location?: { file?: string; start_line?: number }
}

// Pull the repo a command would fetch: git clone, npx skills add, pip/uv git+.
function targetOf(cmd: string): string | undefined {
  const patterns = [
    /\bgit\s+clone\b(?:\s+-{1,2}[\w-]+(?:[ =](?!https?:|git@)\S+)?)*\s+(\S+)/,
    /\bskills\s+add\s+(\S+)/,
    /\bgit\+(https?:\/\/\S+)/,
  ]
  for (const p of patterns) {
    const m = cmd.match(p)
    if (m?.[1]) return normalize(m[1])
  }
  return undefined
}

function normalize(raw: string): string | undefined {
  let t = raw.replace(/^['"]|['"]$/g, '').replace(/@[^/]*$/, '')
  if (/^git@github\.com:/.test(t)) t = 'https://github.com/' + t.split(':')[1]
  if (/^[\w.-]+\/[\w.-]+$/.test(t)) t = 'https://github.com/' + t
  if (!/^https?:\/\//.test(t)) return undefined
  const gh = t.match(/^https?:\/\/github\.com\/([\w.-]+)\/([\w.-]+)/)
  return gh?.[1] && gh[2] ? `https://github.com/${gh[1]}/${gh[2].replace(/\.git$/, '')}` : t.replace(/\.git$/, '')
}

const fmt = (i: Issue) =>
  `- [${i.severity}] ${i.category} / ${i.pattern} (${i.location?.file ?? '?'}:${i.location?.start_line ?? '?'}) ${String(i.finding ?? '').slice(0, 120)}`

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'skillspector-allow',
      description: 'Let a repo flagged by SkillSpector through (usage: /skillspector-allow <github url or owner/repo>)',
    })
    await $.command.register({
      name: 'skillspector-list',
      description: 'Show repos you have allowed past SkillSpector',
    })
    return next(e)
  })

  // "pull this skill" / "let's try this skill out" → fetch through Bash so the guard scans it.
  on('prompt.submit', ($, e, next) => {
    if (e.command || !TRIGGER.test(e.text)) return next(e)
    return next({ ...e, context: [...(e.context ?? []), TRIGGER_NOTE] })
  })

  on('command.run', { command: 'skillspector-allow' }, async ($, e) => {
    if (e.origin.kind !== 'composer') return { text: 'Only you can allow a repo, from the prompt box.' }
    const t = normalize(e.args.trim())
    if (!t) return { text: 'Usage: /skillspector-allow <github url or owner/repo>' }
    const list = ((await $.store.get(ALLOW_KEY)) as string[] | undefined) ?? []
    await $.store.set(ALLOW_KEY, [...new Set([...list, t.toLowerCase()])])
    return { text: `SkillSpector will let ${t} through.` }
  })

  on('command.run', { command: 'skillspector-list' }, async $ => {
    const list = ((await $.store.get(ALLOW_KEY)) as string[] | undefined) ?? []
    return { text: list.length ? list.join('\n') : 'No repos allowed yet.' }
  })

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const target = targetOf(e.command)
    if (!target || SKIP.some(r => r.test(target))) return next(e)
    const allowed = ((await $.store.get(ALLOW_KEY)) as string[] | undefined) ?? []
    if (allowed.includes(target.toLowerCase())) return next(e)

    $.ui.status(`SkillSpector scanning ${target}`)
    let report: { risk_assessment?: { severity?: string; recommendation?: string }; issues?: Issue[] } | undefined
    let problem = ''
    let dir = ''
    try {
      const which = await $.process.run(['sh', '-c', 'command -v skillspector || ls ~/.local/bin/skillspector'])
      let bin = which.stdout.trim().split('\n')[0]
      if (which.exitCode !== 0 || !bin) {
        await $.process.run(['uv', 'tool', 'install', 'git+https://github.com/NVIDIA/skillspector.git'], { timeoutMs: 300_000 })
        bin = (await $.process.run(['sh', '-c', 'ls ~/.local/bin/skillspector'])).stdout.trim()
      }
      dir = (await $.process.run(['mktemp', '-d'])).stdout.trim()
      const clone = await $.process.run(['git', 'clone', '-q', '--depth', '1', target, `${dir}/repo`], { timeoutMs: 120_000 })
      if (clone.exitCode !== 0) throw new Error(`clone failed: ${clone.stderr.slice(0, 200)}`)
      await $.process.run([bin, 'scan', `${dir}/repo`, '--no-llm', '--format', 'json', '-o', `${dir}/report.json`], {
        timeoutMs: SCAN_TIMEOUT,
      })
      report = JSON.parse(await $.fs.read(`${dir}/report.json`))
    } catch (err) {
      problem = String(err).slice(0, 300)
    } finally {
      if (dir) void $.process.run(['rm', '-rf', dir])
      $.ui.status(undefined)
    }

    if (!report) {
      const ran = await next(e)
      if (ran.deny !== undefined) return ran
      return { ...ran, context: [...(ran.context ?? []), `SkillSpector could not scan ${target} (${problem}). Tell the user it ran unscanned.`] }
    }

    const issues = report.issues ?? []
    const blockers = issues.filter(
      i =>
        i.severity === 'CRITICAL' ||
        (i.severity === 'HIGH' && (i.confidence ?? 0) >= 0.8 && DANGER.test(`${i.category} ${i.pattern}`)),
    )
    const rest = issues.filter(i => !blockers.includes(i))
    const counts = Object.entries(
      rest.reduce<Record<string, number>>((a, i) => ((a[i.severity ?? '?'] = (a[i.severity ?? '?'] ?? 0) + 1), a), {}),
    )
      .map(([k, v]) => `${v} ${k}`)
      .join(', ')

    if (blockers.length) {
      void $.ui.toast(`SkillSpector blocked ${target}`)
      return {
        deny:
          `SkillSpector blocked ${target}: ${blockers.length} high-severity finding(s).\n` +
          blockers.slice(0, 8).map(fmt).join('\n') +
          `\nShow these to the user. Do not retry or work around this. If they review it and still want it, they type /skillspector-allow ${target}`,
      }
    }

    const ran = await next(e)
    if (ran.deny !== undefined) return ran
    const note = `SkillSpector scanned ${target}: no blocking findings${counts ? ` (other findings: ${counts})` : ''}.`
    return { ...ran, context: [...(ran.context ?? []), note] }
  })
}
