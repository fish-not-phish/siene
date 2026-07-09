import type { AuditLog } from '@/services/registry'

/**
 * Renders a human-readable one-line description of an audit log entry.
 * e.g. "added alice as maintainer" or "deleted tag nginx:latest (sha256:abc…)"
 */
export function describeLog(log: AuditLog): string {
  const d = log.detail ?? {}
  const op = log.operation
  const rt = log.resource_type

  // ── project ────────────────────────────────────────────────────────────────
  if (rt === 'project') {
    if (op === 'create') return `created project "${log.resource}"`
    if (op === 'delete') return `deleted project "${log.resource}"`
    if (op === 'update') {
      const changes = d.changes as Record<string, unknown> | undefined
      if (changes) {
        const parts: string[] = []
        if ('display_name' in changes) parts.push(`renamed to "${changes.display_name}"`)
        if ('description' in changes) parts.push(`updated description`)
        if ('public' in changes) parts.push(changes.public ? 'made public' : 'made private')
        if (parts.length) return `updated project "${log.resource}": ${parts.join(', ')}`
      }
      return `updated project "${log.resource}"`
    }
  }

  // ── member ─────────────────────────────────────────────────────────────────
  if (rt === 'member') {
    const username = (d.username as string) ?? log.resource
    if (op === 'create') return `added ${username} as ${d.role ?? 'member'}`
    if (op === 'delete') return `removed ${username} (was ${d.role ?? 'member'})`
    if (op === 'update') return `changed ${username}'s role from ${d.old_role ?? '?'} to ${d.new_role ?? '?'}`
  }

  // ── repository ─────────────────────────────────────────────────────────────
  if (rt === 'repository') {
    if (op === 'delete') return `deleted repository "${log.resource}"`
    if (op === 'update') {
      const changes = d.changes as Record<string, unknown> | undefined
      if (changes && 'description' in changes) return `updated description of repository "${log.resource}"`
      return `updated repository "${log.resource}"`
    }
  }

  // ── tag ────────────────────────────────────────────────────────────────────
  if (rt === 'tag') {
    const digest = d.digest as string | undefined
    const short = digest ? ` (${digest.slice(0, 19)}…)` : ''
    if (op === 'delete') return `deleted tag ${log.resource}${short}`
    if (op === 'push')   return `pushed tag ${log.resource}${short}`
    if (op === 'pull')   return `pulled tag ${log.resource}`
  }

  // ── robot ──────────────────────────────────────────────────────────────────
  if (rt === 'robot') {
    const name = (d.name as string) ?? log.resource
    if (op === 'create') {
      const exp = d.expires_at ? ` (expires ${new Date(d.expires_at as string).toLocaleDateString()})` : ''
      return `created robot account "${name}"${exp}`
    }
    if (op === 'delete') return `deleted robot account "${name}"`
    if (op === 'update') {
      const changes = d.changes as Record<string, unknown> | undefined
      if (changes) {
        if ('disabled' in changes) return changes.disabled ? `disabled robot "${name}"` : `enabled robot "${name}"`
        if ('description' in changes) return `updated description of robot "${name}"`
      }
      return `updated robot account "${name}"`
    }
  }

  // ── label ──────────────────────────────────────────────────────────────────
  if (rt === 'label') {
    if (op === 'create') return `created label "${log.resource}"`
    if (op === 'delete') return `deleted label "${log.resource}"`
    if (op === 'update') return `updated label "${log.resource}"`
  }

  // ── scan lifecycle ─────────────────────────────────────────────────────────
  // resource_type: 'scan' | 'secret_scan' | 'misconfig_scan' | 'sbom'
  // operation:     'create' (queued by user) | 'scan_started' | 'scan_finished' | 'scan_error'

  const _scanLabel: Record<string, string> = {
    scan: 'vulnerability scan',
    secret_scan: 'secret scan',
    misconfig_scan: 'misconfiguration scan',
    sbom: 'SBOM generation',
  }
  const _scanKind = _scanLabel[rt]

  if (_scanKind) {
    if (op === 'create') return `triggered ${_scanKind} on ${log.resource}`

    if (op === 'scan_started') {
      const byMap: Record<string, string> = {
        on_push: ' (on push)',
        rescan:  ' (automated rescan)',
      }
      const by = byMap[d.triggered_by as string] ?? ''
      return `${_scanKind} started on ${log.resource}${by}`
    }

    if (op === 'scan_finished') {
      const dur = typeof d.duration_seconds === 'number'
        ? ` in ${d.duration_seconds}s`
        : ''
      // Vulnerability scan summary
      if (rt === 'scan') {
        const crit = d.critical ?? 0
        const high = d.high ?? 0
        const med  = d.medium ?? 0
        const low  = d.low ?? 0
        const total = d.total ?? 0
        if (total === 0) return `vulnerability scan completed on ${log.resource}${dur} — no CVEs found`
        return `vulnerability scan completed on ${log.resource}${dur} — ${crit} critical, ${high} high, ${med} medium, ${low} low`
      }
      // Secret scan summary
      if (rt === 'secret_scan') {
        const n = d.secrets_found ?? 0
        if (n === 0) return `secret scan completed on ${log.resource}${dur} — no secrets found`
        return `secret scan completed on ${log.resource}${dur} — ${n} secret${n !== 1 ? 's' : ''} found`
      }
      // Misconfig scan summary
      if (rt === 'misconfig_scan') {
        const fail = d.fail ?? 0
        const warn = d.warn ?? 0
        return `misconfiguration scan completed on ${log.resource}${dur} — ${fail} fail, ${warn} warn`
      }
      // SBOM summary
      if (rt === 'sbom') {
        const pkgs = d.packages ?? 0
        return `SBOM generated for ${log.resource}${dur} — ${pkgs} package${pkgs !== 1 ? 's' : ''}`
      }
      return `${_scanKind} completed on ${log.resource}${dur}`
    }

    if (op === 'scan_error') {
      const reason = (d.error as string) ?? 'unknown error'
      return `${_scanKind} failed on ${log.resource}: ${reason}`
    }
  }

  // ── quota ──────────────────────────────────────────────────────────────────
  if (rt === 'quota') {
    const newQ = d.new_quota_gb
    if (newQ === null || newQ === undefined) return `removed storage quota on project "${log.resource}"`
    return `set storage quota to ${newQ} GB on project "${log.resource}"`
  }

  // ── policy ─────────────────────────────────────────────────────────────────
  if (rt === 'policy') {
    const changes = d.changes as Record<string, unknown> | undefined
    if (changes) {
      const parts: string[] = []
      if ('scanning_enabled' in changes)
        parts.push(changes.scanning_enabled ? 'enabled vulnerability scanning' : 'disabled vulnerability scanning')
      if ('sbom_enabled' in changes)
        parts.push(changes.sbom_enabled ? 'enabled SBOM generation' : 'disabled SBOM generation')
      if ('cosign_required' in changes)
        parts.push(changes.cosign_required ? 'required Cosign signatures' : 'removed Cosign requirement')
      if ('notation_required' in changes)
        parts.push(changes.notation_required ? 'required Notation signatures' : 'removed Notation requirement')
      if ('prevent_vulnerable_images' in changes)
        parts.push(changes.prevent_vulnerable_images ? 'enabled pull prevention for vulnerable images' : 'disabled pull prevention')
      if ('vuln_block_rules' in changes)
        parts.push('updated vulnerability block rules')
      if ('tag_immutability' in changes)
        parts.push(changes.tag_immutability ? 'enabled tag immutability' : 'disabled tag immutability')
      if ('tag_retention_rules' in changes)
        parts.push('updated tag retention rules')
      if (parts.length) return `updated security policy: ${parts.join('; ')}`
    }
    return `updated project policy`
  }

  // ── gc ─────────────────────────────────────────────────────────────────────
  if (rt === 'gc_run') return 'triggered garbage collection'
  if (rt === 'gc_config') {
    const changes = d.changes as Record<string, unknown> | undefined
    if (changes && 'gc_enabled' in changes)
      return changes.gc_enabled ? 'enabled scheduled garbage collection' : 'disabled scheduled garbage collection'
    if (changes && 'gc_interval_hours' in changes)
      return `set GC interval to ${changes.gc_interval_hours}h`
    return 'updated garbage collection config'
  }

  // ── user (system) ──────────────────────────────────────────────────────────
  if (rt === 'user') {
    if (op === 'delete') return `deleted user "${(d.username as string) ?? log.resource}"`
  }

  // ── fallback ───────────────────────────────────────────────────────────────
  return `${op} ${rt} "${log.resource}"`
}
