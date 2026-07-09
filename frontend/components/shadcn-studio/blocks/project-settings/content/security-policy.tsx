'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Trash2Icon, PlusIcon, RefreshCwIcon, TriangleAlertIcon } from 'lucide-react'
import type { VulnBlockRules, VulnSeverity, AllowlistEntry, SecretAllowlistEntry, MisconfigAllowlistEntry } from '@/services/registry'
import {
  createAllowlistEntry, deleteAllowlistEntry,
  createProjectSecretAllowlistEntry, deleteProjectSecretAllowlistEntry,
  createProjectMisconfigAllowlistEntry, deleteProjectMisconfigAllowlistEntry,
} from '@/services/registry'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface SecurityPolicyProps {
  // Scanning
  scanningEnabled: boolean
  onScanningChange: (v: boolean) => void

  // Automated re-scanning
  vulnRescanEnabled: boolean
  onVulnRescanEnabledChange: (v: boolean) => void
  vulnRescanIntervalDays: number
  onVulnRescanIntervalDaysChange: (v: number) => void
  vulnRescanActiveOnly: boolean
  onVulnRescanActiveOnlyChange: (v: boolean) => void
  vulnRescanActiveDays: number
  onVulnRescanActiveDaysChange: (v: number) => void

  // Secret scanning
  secretScanningEnabled: boolean
  onSecretScanningChange: (v: boolean) => void

  // Misconfiguration scanning
  misconfigScanningEnabled: boolean
  onMisconfigScanningChange: (v: boolean) => void

  // SBOM
  sbomEnabled: boolean
  onSbomChange: (v: boolean) => void

  // Content trust
  cosignRequired: boolean
  onCosignChange: (v: boolean) => void
  notationRequired: boolean
  onNotationChange: (v: boolean) => void

  // Vulnerability prevention
  preventVulnerable: boolean
  onPreventVulnerableChange: (v: boolean) => void
  vulnBlockRules: VulnBlockRules
  onVulnBlockRulesChange: (rules: VulnBlockRules) => void

  // Secret prevention
  preventSecrets: boolean
  onPreventSecretsChange: (v: boolean) => void
  secretBlockThreshold: number | null
  onSecretBlockThresholdChange: (val: number | null) => void

  // Misconfig prevention
  preventMisconfigs: boolean
  onPreventMisconfigsChange: (v: boolean) => void
  misconfigFailThreshold: number | null
  onMisconfigFailThresholdChange: (val: number | null) => void

  saving: boolean
  onSave: () => void

  // CVE allowlist
  projectName: string
  csrfToken: string
  allowlist: AllowlistEntry[]
  onAllowlistChange: () => void

  // Secret allowlist (project-wide)
  secretAllowlist: SecretAllowlistEntry[]
  onSecretAllowlistChange: () => void

  // Misconfig allowlist (project-wide)
  misconfigAllowlist: MisconfigAllowlistEntry[]
  onMisconfigAllowlistChange: () => void
}

// ── Shared toggle row ─────────────────────────────────────────────────────────

interface PolicyRowProps {
  id: string
  label: string
  description: string
  checked: boolean
  onCheckedChange: (v: boolean) => void
  disabled?: boolean
  badge?: string
}

function PolicyRow({ id, label, description, checked, onCheckedChange, disabled, badge }: PolicyRowProps) {
  return (
    <div className={`flex items-center justify-between rounded-lg border px-4 py-3 transition-opacity ${disabled ? 'opacity-50' : ''}`}>
      <div className='space-y-0.5 pr-4'>
        <div className='flex items-center gap-2'>
          <Label htmlFor={id} className='cursor-pointer text-sm font-medium'>
            {label}
          </Label>
          {badge && (
            <span className='rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground'>
              {badge}
            </span>
          )}
        </div>
        <p className='text-muted-foreground text-xs'>{description}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} disabled={disabled} />
    </div>
  )
}

// ── Per-severity threshold row ────────────────────────────────────────────────

const SEVERITY_META: { key: VulnSeverity; label: string; color: string }[] = [
  { key: 'critical', label: 'Critical', color: 'text-red-600 dark:text-red-400' },
  { key: 'high',     label: 'High',     color: 'text-orange-500 dark:text-orange-400' },
  { key: 'medium',   label: 'Medium',   color: 'text-yellow-500 dark:text-yellow-400' },
  { key: 'low',      label: 'Low',      color: 'text-blue-500 dark:text-blue-400' },
]

interface SeverityRowProps {
  severity: typeof SEVERITY_META[number]
  value: number | null | undefined   // undefined = key absent from rules object
  onChange: (val: number | null) => void
  disabled: boolean
}

function SeverityRow({ severity, value, onChange, disabled }: SeverityRowProps) {
  // Row is "active" (threshold enforced) when value is a number (including 0)
  const active = typeof value === 'number'
  // Controlled input string
  const inputVal = active ? String(value) : ''

  const handleToggle = (on: boolean) => {
    onChange(on ? 0 : null)
  }

  const handleInput = (raw: string) => {
    if (raw === '') { onChange(0); return }
    const n = parseInt(raw, 10)
    if (!isNaN(n) && n >= 0) onChange(n)
  }

  return (
    <div className={`flex items-center gap-4 rounded-lg border px-4 py-3 transition-opacity ${disabled ? 'pointer-events-none opacity-40' : ''}`}>
      {/* Severity label */}
      <div className='w-20 shrink-0'>
        <span className={`text-sm font-semibold ${severity.color}`}>{severity.label}</span>
      </div>

      {/* Enable threshold toggle */}
      <Switch
        id={`sev-toggle-${severity.key}`}
        checked={active && value !== null}
        onCheckedChange={handleToggle}
        disabled={disabled}
        aria-label={`Enforce ${severity.label} threshold`}
      />

      {/* Max count input — shown when active */}
      {active ? (
        <div className='flex flex-1 items-center gap-2'>
          <Label htmlFor={`sev-input-${severity.key}`} className='text-xs text-muted-foreground whitespace-nowrap'>
            Max allowed
          </Label>
          <Input
            id={`sev-input-${severity.key}`}
            type='number'
            min='0'
            step='1'
            className='h-8 w-24 text-sm'
            value={inputVal}
            onChange={(e) => handleInput(e.target.value)}
            disabled={disabled}
            placeholder='0'
          />
          <span className='text-xs text-muted-foreground'>
            {value === 0 ? '— zero tolerance' : value === 1 ? 'vulnerability' : 'vulnerabilities'}
          </span>
        </div>
      ) : (
        <span className='flex-1 text-xs text-muted-foreground italic'>Not enforced</span>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

const SecurityPolicy = ({
  scanningEnabled,
  onScanningChange,
  vulnRescanEnabled,
  onVulnRescanEnabledChange,
  vulnRescanIntervalDays,
  onVulnRescanIntervalDaysChange,
  vulnRescanActiveOnly,
  onVulnRescanActiveOnlyChange,
  vulnRescanActiveDays,
  onVulnRescanActiveDaysChange,
  secretScanningEnabled,
  onSecretScanningChange,
  misconfigScanningEnabled,
  onMisconfigScanningChange,
  sbomEnabled,
  onSbomChange,
  cosignRequired,
  onCosignChange,
  notationRequired,
  onNotationChange,
  preventVulnerable,
  onPreventVulnerableChange,
  vulnBlockRules,
  onVulnBlockRulesChange,
  preventSecrets,
  onPreventSecretsChange,
  secretBlockThreshold,
  onSecretBlockThresholdChange,
  preventMisconfigs,
  onPreventMisconfigsChange,
  misconfigFailThreshold,
  onMisconfigFailThresholdChange,
  saving,
  onSave,
  projectName,
  csrfToken,
  allowlist,
  onAllowlistChange,
  secretAllowlist,
  onSecretAllowlistChange,
  misconfigAllowlist,
  onMisconfigAllowlistChange,
}: SecurityPolicyProps) => {
  // CVE allowlist state
  const [newCveId, setNewCveId] = useState('')
  const [newReason, setNewReason] = useState('')
  const [addingEntry, setAddingEntry] = useState(false)

  // Secret allowlist state
  const [newRuleId, setNewRuleId] = useState('')
  const [newSecretReason, setNewSecretReason] = useState('')
  const [addingSecret, setAddingSecret] = useState(false)

  // Misconfig allowlist state
  const [newCheckId, setNewCheckId] = useState('')
  const [newMisconfigReason, setNewMisconfigReason] = useState('')
  const [addingMisconfig, setAddingMisconfig] = useState(false)

  const addEntry = async () => {
    if (!newCveId.trim()) return
    setAddingEntry(true)
    try {
      await createAllowlistEntry(projectName, { cve_id: newCveId.trim(), reason: newReason.trim() || undefined }, csrfToken)
      setNewCveId('')
      setNewReason('')
      onAllowlistChange()
    } catch { /* ignore */ }
    setAddingEntry(false)
  }

  const removeEntry = async (id: number) => {
    await deleteAllowlistEntry(projectName, id, csrfToken)
    onAllowlistChange()
  }

  const addSecretEntry = async () => {
    if (!newRuleId.trim()) return
    setAddingSecret(true)
    try {
      await createProjectSecretAllowlistEntry(projectName, { rule_id: newRuleId.trim(), reason: newSecretReason.trim() || undefined }, csrfToken)
      setNewRuleId('')
      setNewSecretReason('')
      onSecretAllowlistChange()
    } catch { /* ignore */ }
    setAddingSecret(false)
  }

  const removeSecretEntry = async (id: number) => {
    await deleteProjectSecretAllowlistEntry(projectName, id, csrfToken)
    onSecretAllowlistChange()
  }

  const addMisconfigEntry = async () => {
    if (!newCheckId.trim()) return
    setAddingMisconfig(true)
    try {
      await createProjectMisconfigAllowlistEntry(projectName, { check_id: newCheckId.trim(), reason: newMisconfigReason.trim() || undefined }, csrfToken)
      setNewCheckId('')
      setNewMisconfigReason('')
      onMisconfigAllowlistChange()
    } catch { /* ignore */ }
    setAddingMisconfig(false)
  }

  const removeMisconfigEntry = async (id: number) => {
    await deleteProjectMisconfigAllowlistEntry(projectName, id, csrfToken)
    onMisconfigAllowlistChange()
  }

  const updateSeverity = (key: VulnSeverity, val: number | null) => {
    const next = { ...vulnBlockRules }
    if (val === null) {
      delete next[key]
    } else {
      next[key] = val
    }
    onVulnBlockRulesChange(next)
  }

  const handleSecretThresholdInput = (raw: string) => {
    if (raw === '') { onSecretBlockThresholdChange(null); return }
    const n = parseInt(raw, 10)
    if (!isNaN(n) && n >= 0) onSecretBlockThresholdChange(n)
  }

  const handleMisconfigFailThresholdInput = (raw: string) => {
    if (raw === '') { onMisconfigFailThresholdChange(null); return }
    const n = parseInt(raw, 10)
    if (!isNaN(n) && n >= 0) onMisconfigFailThresholdChange(n)
  }

  return (
    <div className='grid grid-cols-1 gap-10 lg:grid-cols-3'>
      <div className='flex flex-col space-y-1'>
        <h3 className='font-semibold'>Security &amp; Compliance</h3>
        <p className='text-muted-foreground text-sm'>
          Configure vulnerability scanning, SBOM generation, signature enforcement,
          and pull-prevention thresholds per severity.
        </p>
      </div>

      <div className='space-y-4 lg:col-span-2'>

        {/* Vulnerability scanning */}
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Trivy Scanning</p>
        <PolicyRow
          id='scanning-enabled'
          label='Scan images on push'
          description='Automatically run a Trivy vulnerability scan whenever an image is pushed to this project.'
          badge='requires Trivy'
          checked={scanningEnabled}
          onCheckedChange={onScanningChange}
        />

        {/* Automated re-scan — only meaningful when scanning is on */}
        <div className={`space-y-2 transition-opacity ${scanningEnabled ? 'opacity-100' : 'pointer-events-none opacity-40'}`}>
          <div className='flex items-center justify-between rounded-lg border px-4 py-3'>
            <div className='space-y-0.5 pr-4'>
              <Label htmlFor='vuln-rescan-enabled' className='cursor-pointer text-sm font-medium'>
                Automated re-scanning
              </Label>
              <p className='text-muted-foreground text-xs'>
                Periodically re-scan images to catch newly published CVEs without requiring a re-push.
                Each image is re-queued independently based on when it was last scanned, not on a
                shared schedule — so a large project naturally spreads work across multiple scan windows.
              </p>
            </div>
            <Switch
              id='vuln-rescan-enabled'
              checked={vulnRescanEnabled}
              onCheckedChange={onVulnRescanEnabledChange}
              disabled={!scanningEnabled}
            />
          </div>

          {vulnRescanEnabled && (
            <div className='space-y-2'>
              <div className='flex items-center gap-3 rounded-lg border px-4 py-3'>
                <Label htmlFor='vuln-rescan-interval' className='text-sm text-muted-foreground whitespace-nowrap'>
                  Re-scan every
                </Label>
                <Select
                  value={String(vulnRescanIntervalDays)}
                  onValueChange={(v) => onVulnRescanIntervalDaysChange(Number(v))}
                  disabled={!scanningEnabled}
                >
                  <SelectTrigger id='vuln-rescan-interval' className='h-8 w-36'>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value='1'>1 day</SelectItem>
                    <SelectItem value='7'>7 days</SelectItem>
                    <SelectItem value='14'>14 days</SelectItem>
                    <SelectItem value='30'>30 days</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {vulnRescanIntervalDays === 1 && (
                <div className='flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-amber-700 dark:text-amber-400'>
                  <TriangleAlertIcon className='mt-0.5 size-4 shrink-0' />
                  <p className='text-xs leading-relaxed'>
                    <span className='font-semibold'>High resource impact.</span>{' '}
                    A 1-day re-scan interval means every image in this project is re-queued
                    every 24 hours. On projects with many tags this can backlog the scan
                    queue indefinitely and compete with on-push scans. Consider 7 days or
                    longer, or enable <span className='font-medium'>Active inventory only</span> below
                    to limit re-scans to recently used images.
                  </p>
                </div>
              )}

              {/* Active-inventory filter */}
              <div className='flex items-center justify-between rounded-lg border px-4 py-3'>
                <div className='space-y-0.5 pr-4'>
                  <Label htmlFor='vuln-rescan-active-only' className='cursor-pointer text-sm font-medium'>
                    Active inventory only
                  </Label>
                  <p className='text-muted-foreground text-xs'>
                    Skip re-scanning images that have had no push or pull activity within the staleness window.
                    Stale tags are labelled in the UI but are not deleted.
                  </p>
                </div>
                <Switch
                  id='vuln-rescan-active-only'
                  checked={vulnRescanActiveOnly}
                  onCheckedChange={onVulnRescanActiveOnlyChange}
                  disabled={!scanningEnabled}
                />
              </div>

              {vulnRescanActiveOnly && (
                <div className='flex items-center gap-3 rounded-lg border px-4 py-3'>
                  <Label htmlFor='vuln-rescan-active-days' className='text-sm text-muted-foreground whitespace-nowrap'>
                    Staleness window
                  </Label>
                  <Select
                    value={String(vulnRescanActiveDays)}
                    onValueChange={(v) => onVulnRescanActiveDaysChange(Number(v))}
                    disabled={!scanningEnabled}
                  >
                    <SelectTrigger id='vuln-rescan-active-days' className='h-8 w-36'>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value='30'>30 days</SelectItem>
                      <SelectItem value='60'>60 days</SelectItem>
                      <SelectItem value='90'>90 days</SelectItem>
                      <SelectItem value='180'>6 months</SelectItem>
                      <SelectItem value='365'>1 year</SelectItem>
                    </SelectContent>
                  </Select>
                  <span className='text-xs text-muted-foreground'>of inactivity</span>
                </div>
              )}
            </div>
          )}
        </div>

        <PolicyRow
          id='secret-scanning-enabled'
          label='Secret scanning on push'
          description='Automatically scan for hardcoded credentials, API keys, and tokens in image layers on every push.'
          badge='requires Trivy'
          checked={secretScanningEnabled}
          onCheckedChange={onSecretScanningChange}
        />
        <PolicyRow
          id='misconfig-scanning-enabled'
          label='Misconfiguration scanning on push'
          description='Automatically check for Dockerfile and runtime misconfigurations (e.g. running as root, writable root filesystem) on every push.'
          badge='requires Trivy'
          checked={misconfigScanningEnabled}
          onCheckedChange={onMisconfigScanningChange}
        />

        <Separator />

        {/* SBOM */}
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>SBOM</p>
        <PolicyRow
          id='sbom-enabled'
          label='Generate SBOM on push'
          description='Automatically generate a Software Bill of Materials using Syft whenever an image is pushed.'
          badge='requires Syft'
          checked={sbomEnabled}
          onCheckedChange={onSbomChange}
        />

        <Separator />

        {/* Content trust */}
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Content Trust</p>
        <PolicyRow
          id='cosign-required'
          label='Require Cosign signature'
          description='Block pulls of any image that does not have a valid Cosign (Sigstore) signature attached.'
          badge='requires Cosign'
          checked={cosignRequired}
          onCheckedChange={onCosignChange}
        />
        <PolicyRow
          id='notation-required'
          label='Require Notation signature'
          description='Block pulls of any image that does not carry a valid CNCF Notation (Notary v2) signature.'
          badge='requires Notation'
          checked={notationRequired}
          onCheckedChange={onNotationChange}
        />

        <Separator />

        {/* Vulnerability prevention */}
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Pull Prevention</p>
        <PolicyRow
          id='prevent-vulnerable'
          label='Block pulls of vulnerable images'
          description='Reject pulls when the image has vulnerabilities exceeding any enforced threshold below. Requires a finished scan.'
          badge='requires Trivy'
          checked={preventVulnerable}
          onCheckedChange={onPreventVulnerableChange}
        />

        {/* Per-severity threshold grid */}
        <div className={`space-y-2 transition-opacity ${preventVulnerable ? 'opacity-100' : 'pointer-events-none opacity-40'}`}>
          <p className='text-xs text-muted-foreground px-1'>
            Toggle a severity to enforce a threshold. Set the max allowed count — use&nbsp;
            <span className='font-mono font-medium'>0</span> for zero tolerance.
            Unenforced severities are ignored during pull checks.
          </p>
          {SEVERITY_META.map((sev) => (
            <SeverityRow
              key={sev.key}
              severity={sev}
              value={vulnBlockRules[sev.key]}
              onChange={(val) => updateSeverity(sev.key, val)}
              disabled={!preventVulnerable}
            />
          ))}
        </div>

        {/* Secret prevention */}
        <PolicyRow
          id='prevent-secrets'
          label='Block pulls of images with secrets'
          description='Reject pulls when the image has more detected secrets than the threshold below. Requires a finished secret scan.'
          badge='requires Trivy'
          checked={preventSecrets}
          onCheckedChange={onPreventSecretsChange}
        />
        <div className={`transition-opacity ${preventSecrets ? 'opacity-100' : 'pointer-events-none opacity-40'}`}>
          <p className='text-xs text-muted-foreground px-1 mb-2'>
            Set the maximum number of secrets allowed — use&nbsp;
            <span className='font-mono font-medium'>0</span> for zero tolerance.
            Suppressed (allowlisted) secrets are not counted.
          </p>
          <div className='flex items-center gap-4 rounded-lg border px-4 py-3'>
            <div className='w-20 shrink-0'>
              <span className='text-sm font-semibold text-purple-600 dark:text-purple-400'>Secrets</span>
            </div>
            <Switch
              id='secret-threshold-toggle'
              checked={secretBlockThreshold !== null}
              onCheckedChange={(on) => onSecretBlockThresholdChange(on ? 0 : null)}
              disabled={!preventSecrets}
              aria-label='Enforce secrets threshold'
            />
            {secretBlockThreshold !== null ? (
              <div className='flex flex-1 items-center gap-2'>
                <Label htmlFor='secret-threshold-input' className='text-xs text-muted-foreground whitespace-nowrap'>
                  Max allowed
                </Label>
                <Input
                  id='secret-threshold-input'
                  type='number'
                  min='0'
                  step='1'
                  className='h-8 w-24 text-sm'
                  value={String(secretBlockThreshold)}
                  onChange={(e) => handleSecretThresholdInput(e.target.value)}
                  disabled={!preventSecrets}
                  placeholder='0'
                />
                <span className='text-xs text-muted-foreground'>
                  {secretBlockThreshold === 0 ? '— zero tolerance' : secretBlockThreshold === 1 ? 'secret' : 'secrets'}
                </span>
              </div>
            ) : (
              <span className='flex-1 text-xs text-muted-foreground italic'>Not enforced</span>
            )}
          </div>
        </div>

        {/* Misconfig prevention */}
        <PolicyRow
          id='prevent-misconfigs'
          label='Block pulls of misconfigured images'
          description='Reject pulls when the image has FAIL misconfigurations above the threshold. Requires a finished misconfig scan.'
          badge='requires Trivy'
          checked={preventMisconfigs}
          onCheckedChange={onPreventMisconfigsChange}
        />
        <div className={`transition-opacity ${preventMisconfigs ? 'opacity-100' : 'pointer-events-none opacity-40'}`}>
          <p className='text-xs text-muted-foreground px-1 mb-2'>
            Set the maximum number of FAIL misconfigurations allowed — use&nbsp;
            <span className='font-mono font-medium'>0</span> for zero tolerance.
            Suppressed (allowlisted) checks are not counted.
          </p>
          <div className='flex items-center gap-4 rounded-lg border px-4 py-3'>
            <div className='w-20 shrink-0'>
              <span className='text-sm font-semibold text-red-600 dark:text-red-400'>FAIL</span>
            </div>
            <Switch
              id='misconfig-fail-threshold-toggle'
              checked={misconfigFailThreshold !== null}
              onCheckedChange={(on) => onMisconfigFailThresholdChange(on ? 0 : null)}
              disabled={!preventMisconfigs}
              aria-label='Enforce FAIL misconfig threshold'
            />
            {misconfigFailThreshold !== null ? (
              <div className='flex flex-1 items-center gap-2'>
                <Label htmlFor='misconfig-fail-threshold-input' className='text-xs text-muted-foreground whitespace-nowrap'>
                  Max allowed
                </Label>
                <Input
                  id='misconfig-fail-threshold-input'
                  type='number'
                  min='0'
                  step='1'
                  className='h-8 w-24 text-sm'
                  value={String(misconfigFailThreshold)}
                  onChange={(e) => handleMisconfigFailThresholdInput(e.target.value)}
                  disabled={!preventMisconfigs}
                  placeholder='0'
                />
                <span className='text-xs text-muted-foreground'>
                  {misconfigFailThreshold === 0 ? '— zero tolerance' : misconfigFailThreshold === 1 ? 'finding' : 'findings'}
                </span>
              </div>
            ) : (
              <span className='flex-1 text-xs text-muted-foreground italic'>Not enforced</span>
            )}
          </div>
        </div>

        <div className='flex justify-end pt-2'>
          <Button type='button' disabled={saving} onClick={onSave} className='max-sm:w-full'>
            {saving ? 'Saving…' : 'Save security policy'}
          </Button>
        </div>

        <Separator />

        {/* CVE Allowlist */}
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>CVE Allowlist</p>
        <p className='text-xs text-muted-foreground'>
          Suppressed CVEs are hidden from scan reports and do not count toward pull-prevention thresholds.
          Project-wide entries apply to all images; tag-specific suppressions can be added per image from the tag detail page.
        </p>

        {/* Add entry row */}
        <div className='flex gap-2'>
          <Input
            placeholder='CVE-2024-1234 or AVD-GO-0001'
            value={newCveId}
            onChange={e => setNewCveId(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') addEntry() }}
            className='h-8 text-xs font-mono w-52'
          />
          <Input
            placeholder='Reason (optional)'
            value={newReason}
            onChange={e => setNewReason(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') addEntry() }}
            className='h-8 text-xs flex-1'
          />
          <Button size='sm' variant='outline' disabled={addingEntry || !newCveId.trim()} onClick={addEntry} className='h-8'>
            {addingEntry ? <RefreshCwIcon className='size-3.5 animate-spin' /> : <PlusIcon className='size-3.5' />}
          </Button>
        </div>

        {/* Allowlist table */}
        {allowlist.filter(e => e.tag_id === null).length === 0 ? (
          <p className='text-xs text-muted-foreground italic px-1'>No project-wide suppressions.</p>
        ) : (
          <div className='rounded-md border text-xs overflow-x-auto'>
            <table className='w-full'>
              <thead>
                <tr className='border-b bg-muted/50'>
                  <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>CVE / ID</th>
                  <th className='px-3 py-2 text-left font-medium'>Reason</th>
                  <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>Added by</th>
                  <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>Expires</th>
                  <th className='w-8 px-2 py-2' />
                </tr>
              </thead>
              <tbody>
                {allowlist.filter(e => e.tag_id === null).map(entry => (
                  <tr key={entry.id} className={`border-b last:border-0 ${entry.is_expired ? 'opacity-40' : ''}`}>
                    <td className='px-3 py-1.5 font-mono whitespace-nowrap'>
                      {entry.cve_id}
                      {entry.is_expired && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>expired</span>}
                    </td>
                    <td className='px-3 py-1.5 text-muted-foreground'>{entry.reason || '—'}</td>
                    <td className='px-3 py-1.5 text-muted-foreground whitespace-nowrap'>{entry.added_by_username ?? '—'}</td>
                    <td className='px-3 py-1.5 text-muted-foreground whitespace-nowrap'>
                      {entry.expires_at ? new Date(entry.expires_at).toLocaleDateString() : '—'}
                    </td>
                    <td className='px-2 py-1.5'>
                      <button
                        type='button'
                        onClick={() => removeEntry(entry.id)}
                        className='text-muted-foreground hover:text-destructive transition-colors'
                        title='Remove'
                      >
                        <Trash2Icon className='size-3.5' />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <Separator />

        {/* Secret Rule Allowlist */}
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Secret Rule Allowlist</p>
        <p className='text-xs text-muted-foreground'>
          Suppressed rules are hidden from secret scan reports for all images in this project.
          Tag-specific suppressions can be added per image from the tag detail page.
        </p>
        <div className='flex gap-2'>
          <Input
            placeholder='rule_id, e.g. aws-access-key-id'
            value={newRuleId}
            onChange={e => setNewRuleId(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') addSecretEntry() }}
            className='h-8 text-xs font-mono w-52'
          />
          <Input
            placeholder='Reason (optional)'
            value={newSecretReason}
            onChange={e => setNewSecretReason(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') addSecretEntry() }}
            className='h-8 text-xs flex-1'
          />
          <Button size='sm' variant='outline' disabled={addingSecret || !newRuleId.trim()} onClick={addSecretEntry} className='h-8'>
            {addingSecret ? <RefreshCwIcon className='size-3.5 animate-spin' /> : <PlusIcon className='size-3.5' />}
          </Button>
        </div>
        {secretAllowlist.length === 0 ? (
          <p className='text-xs text-muted-foreground italic px-1'>No project-wide secret suppressions.</p>
        ) : (
          <div className='rounded-md border text-xs overflow-x-auto'>
            <table className='w-full'>
              <thead>
                <tr className='border-b bg-muted/50'>
                  <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>Rule ID</th>
                  <th className='px-3 py-2 text-left font-medium'>Reason</th>
                  <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>Added by</th>
                  <th className='w-8 px-2 py-2' />
                </tr>
              </thead>
              <tbody>
                {secretAllowlist.map(entry => (
                  <tr key={entry.id} className={`border-b last:border-0 ${entry.is_expired ? 'opacity-40' : ''}`}>
                    <td className='px-3 py-1.5 font-mono whitespace-nowrap'>
                      {entry.rule_id}
                      {entry.is_expired && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>expired</span>}
                    </td>
                    <td className='px-3 py-1.5 text-muted-foreground'>{entry.reason || '—'}</td>
                    <td className='px-3 py-1.5 text-muted-foreground whitespace-nowrap'>{entry.added_by_username ?? '—'}</td>
                    <td className='px-2 py-1.5'>
                      <button type='button' onClick={() => removeSecretEntry(entry.id)}
                        className='text-muted-foreground hover:text-destructive transition-colors' title='Remove'>
                        <Trash2Icon className='size-3.5' />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <Separator />

        {/* Misconfig Check Allowlist */}
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Misconfig Check Allowlist</p>
        <p className='text-xs text-muted-foreground'>
          Suppressed checks are hidden from misconfiguration scan reports for all images in this project.
          Tag-specific suppressions can be added per image from the tag detail page.
        </p>
        <div className='flex gap-2'>
          <Input
            placeholder='AVD-DS-0002 or DS002'
            value={newCheckId}
            onChange={e => setNewCheckId(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') addMisconfigEntry() }}
            className='h-8 text-xs font-mono w-52'
          />
          <Input
            placeholder='Reason (optional)'
            value={newMisconfigReason}
            onChange={e => setNewMisconfigReason(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') addMisconfigEntry() }}
            className='h-8 text-xs flex-1'
          />
          <Button size='sm' variant='outline' disabled={addingMisconfig || !newCheckId.trim()} onClick={addMisconfigEntry} className='h-8'>
            {addingMisconfig ? <RefreshCwIcon className='size-3.5 animate-spin' /> : <PlusIcon className='size-3.5' />}
          </Button>
        </div>
        {misconfigAllowlist.length === 0 ? (
          <p className='text-xs text-muted-foreground italic px-1'>No project-wide misconfig suppressions.</p>
        ) : (
          <div className='rounded-md border text-xs overflow-x-auto'>
            <table className='w-full'>
              <thead>
                <tr className='border-b bg-muted/50'>
                  <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>Check ID</th>
                  <th className='px-3 py-2 text-left font-medium'>Reason</th>
                  <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>Added by</th>
                  <th className='w-8 px-2 py-2' />
                </tr>
              </thead>
              <tbody>
                {misconfigAllowlist.map(entry => (
                  <tr key={entry.id} className={`border-b last:border-0 ${entry.is_expired ? 'opacity-40' : ''}`}>
                    <td className='px-3 py-1.5 font-mono whitespace-nowrap'>
                      {entry.check_id}
                      {entry.is_expired && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>expired</span>}
                    </td>
                    <td className='px-3 py-1.5 text-muted-foreground'>{entry.reason || '—'}</td>
                    <td className='px-3 py-1.5 text-muted-foreground whitespace-nowrap'>{entry.added_by_username ?? '—'}</td>
                    <td className='px-2 py-1.5'>
                      <button type='button' onClick={() => removeMisconfigEntry(entry.id)}
                        className='text-muted-foreground hover:text-destructive transition-colors' title='Remove'>
                        <Trash2Icon className='size-3.5' />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

export default SecurityPolicy
