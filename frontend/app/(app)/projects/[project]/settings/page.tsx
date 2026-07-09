'use client'

import { useParams, useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { SettingsIcon } from 'lucide-react'
import { toast } from 'sonner'

import { baseUrl } from '@/constants/constants'
import { useAuthContext } from '@/store/AuthContext'
import { csrfFetch } from '@/utils/csrfFetch'
import {
  fetchProjectPolicy,
  updateProjectPolicy,
  fetchAllowlist,
  fetchProjectSecretAllowlist,
  fetchProjectMisconfigAllowlist,
  type ProjectPolicy,
  type TagRetentionRule,
  type VulnBlockRules,

  type AllowlistEntry,
  type SecretAllowlistEntry,
  type MisconfigAllowlistEntry,
} from '@/services/registry'

import ProjectSettings from '@/components/shadcn-studio/blocks/project-settings/project-settings'

// ── Types ─────────────────────────────────────────────────────────────────────

interface ProjectData {
  id: number
  name: string
  display_name: string
  description: string
  public: boolean
  quota_gb: number | null
}

interface QuotaData {
  quota_gb: number | null
  used_bytes: number
  quota_bytes: number | null
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ProjectSettingsPage() {
  const { project } = useParams<{ project: string }>()
  const { user } = useAuthContext()
  const router = useRouter()

  const [projectData, setProjectData] = useState<ProjectData | null>(null)
  const [quotaData, setQuotaData] = useState<QuotaData | null>(null)
  const [diskFreeBytes, setDiskFreeBytes] = useState<number | null>(null)
  const [policy, setPolicy] = useState<ProjectPolicy | null>(null)
  const [loading, setLoading] = useState(true)

  // General form state
  const [displayName, setDisplayName] = useState('')
  const [description, setDescription] = useState('')
  const [isPublic, setIsPublic] = useState(false)
  const [savingGeneral, setSavingGeneral] = useState(false)

  // Quota form state
  const [limited, setLimited] = useState(false)
  const [quotaGb, setQuotaGb] = useState('')
  const [savingQuota, setSavingQuota] = useState(false)

  // Security policy form state
  const [scanningEnabled, setScanningEnabled] = useState(true)
  const [vulnRescanEnabled, setVulnRescanEnabled] = useState(true)
  const [vulnRescanIntervalDays, setVulnRescanIntervalDays] = useState(7)
  const [vulnRescanActiveOnly, setVulnRescanActiveOnly] = useState(false)
  const [vulnRescanActiveDays, setVulnRescanActiveDays] = useState(90)
  const [secretScanningEnabled, setSecretScanningEnabled] = useState(false)
  const [misconfigScanningEnabled, setMisconfigScanningEnabled] = useState(false)
  const [sbomEnabled, setSbomEnabled] = useState(false)
  const [cosignRequired, setCosignRequired] = useState(false)
  const [notationRequired, setNotationRequired] = useState(false)
  const [preventVulnerable, setPreventVulnerable] = useState(false)
  const [vulnBlockRules, setVulnBlockRules] = useState<VulnBlockRules>({})
  const [preventSecrets, setPreventSecrets] = useState(false)
  const [secretBlockThreshold, setSecretBlockThreshold] = useState<number | null>(null)
  const [preventMisconfigs, setPreventMisconfigs] = useState(false)
  const [misconfigFailThreshold, setMisconfigFailThreshold] = useState<number | null>(null)
  const [savingSecurity, setSavingSecurity] = useState(false)

  // Tag policy form state
  const [tagImmutability, setTagImmutability] = useState(false)
  const [retentionRules, setRetentionRules] = useState<TagRetentionRule[]>([])
  const [savingTags, setSavingTags] = useState(false)

  // Danger zone
  const [deleting, setDeleting] = useState(false)

  // CVE Allowlist
  const [allowlist, setAllowlist] = useState<AllowlistEntry[]>([])
  const loadAllowlist = () => { fetchAllowlist(project).then(setAllowlist).catch(() => {}) }

  // Secret Allowlist (project-wide)
  const [secretAllowlist, setSecretAllowlist] = useState<SecretAllowlistEntry[]>([])
  const loadSecretAllowlist = () => { fetchProjectSecretAllowlist(project).then(setSecretAllowlist).catch(() => {}) }

  // Misconfig Allowlist (project-wide)
  const [misconfigAllowlist, setMisconfigAllowlist] = useState<MisconfigAllowlistEntry[]>([])
  const loadMisconfigAllowlist = () => { fetchProjectMisconfigAllowlist(project).then(setMisconfigAllowlist).catch(() => {}) }

  // ── Load ──────────────────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false
    setLoading(true)

    Promise.all([
      fetch(`${baseUrl}registry/projects/${project}`, { credentials: 'include' })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
      fetch(`${baseUrl}registry/projects/${project}/quota`, { credentials: 'include' })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
      fetchProjectPolicy(project).catch(() => null),
      fetch(`${baseUrl}registry/system/disk`, { credentials: 'include' })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
    ]).then(([proj, quota, pol, disk]: [ProjectData | null, QuotaData | null, ProjectPolicy | null, { free_bytes: number | null } | null]) => {
      if (cancelled) return

      if (proj) {
        setProjectData(proj)
        setDisplayName(proj.display_name)
        setDescription(proj.description)
        setIsPublic(proj.public)
      }
      if (quota) {
        setQuotaData(quota)
        setLimited(quota.quota_gb !== null)
        setQuotaGb(quota.quota_gb != null ? String(quota.quota_gb) : '')
      }
      if (disk?.free_bytes != null) setDiskFreeBytes(disk.free_bytes)
      if (pol) {
        setPolicy(pol)
        setScanningEnabled(pol.scanning_enabled)
        setVulnRescanEnabled(pol.vuln_rescan_enabled)
        setVulnRescanIntervalDays(pol.vuln_rescan_interval_days)
        setVulnRescanActiveOnly(pol.vuln_rescan_active_only)
        setVulnRescanActiveDays(pol.vuln_rescan_active_days)
        setSecretScanningEnabled(pol.secret_scanning_enabled)
        setMisconfigScanningEnabled(pol.misconfig_scanning_enabled)
        setSbomEnabled(pol.sbom_enabled)
        setCosignRequired(pol.cosign_required)
        setNotationRequired(pol.notation_required)
        setPreventVulnerable(pol.prevent_vulnerable_images)
        setVulnBlockRules(pol.vuln_block_rules ?? {})
        setPreventSecrets(pol.prevent_secret_images)
        setSecretBlockThreshold(pol.secret_block_threshold ?? null)
        setPreventMisconfigs(pol.prevent_misconfig_images)
        setMisconfigFailThreshold(pol.misconfig_fail_threshold ?? null)
        setTagImmutability(pol.tag_immutability)
        setRetentionRules(Array.isArray(pol.tag_retention_rules) ? pol.tag_retention_rules : [])
      }

      setLoading(false)
    })

    return () => { cancelled = true }
  }, [project])

  useEffect(() => { loadAllowlist() }, [project])
  useEffect(() => { loadSecretAllowlist() }, [project])
  useEffect(() => { loadMisconfigAllowlist() }, [project])

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleSaveGeneral = async () => {
    if (!projectData) return
    // Only send fields that actually changed
    const patch: Record<string, unknown> = {}
    if (displayName !== projectData.display_name) patch.display_name = displayName
    if (description !== projectData.description)   patch.description = description
    if (isPublic !== projectData.public)           patch.public = isPublic
    if (Object.keys(patch).length === 0) {
      toast.info('No changes to save.')
      return
    }
    setSavingGeneral(true)
    try {
      const res = await csrfFetch(
        `${baseUrl}registry/projects/${project}`,
        { method: 'PATCH', body: JSON.stringify(patch) },
        user.csrfToken,
      )
      if (res.ok) {
        const updated = await res.json()
        setProjectData(updated)
        toast.success('Settings saved.')
      } else {
        toast.error('Failed to save settings.')
      }
    } finally {
      setSavingGeneral(false)
    }
  }

  const handleSaveQuota = async () => {
    const gb = limited ? parseFloat(quotaGb) : null
    if (limited && (isNaN(gb!) || gb! <= 0)) {
      toast.error('Enter a valid quota in GB.')
      return
    }
    setSavingQuota(true)
    try {
      const url = new URL(`${baseUrl}registry/projects/${project}/quota`)
      if (gb !== null) url.searchParams.set('quota_gb', String(gb))
      const res = await fetch(url.toString(), {
        method: 'PATCH',
        credentials: 'include',
        headers: { 'X-CSRFToken': user.csrfToken ?? '' },
      })
      if (res.ok) {
        const updated: QuotaData = await res.json()
        setQuotaData(updated)
        setLimited(updated.quota_gb !== null)
        setQuotaGb(updated.quota_gb != null ? String(updated.quota_gb) : '')
        toast.success('Quota saved.')
      } else {
        toast.error('Failed to save quota.')
      }
    } finally {
      setSavingQuota(false)
    }
  }

  const handleSaveSecurity = async () => {
    const patch: Partial<ProjectPolicy> = {}
    if (policy) {
      if (scanningEnabled          !== policy.scanning_enabled)           patch.scanning_enabled = scanningEnabled
      if (vulnRescanEnabled        !== policy.vuln_rescan_enabled)        patch.vuln_rescan_enabled = vulnRescanEnabled
      if (vulnRescanIntervalDays   !== policy.vuln_rescan_interval_days)  patch.vuln_rescan_interval_days = vulnRescanIntervalDays
      if (vulnRescanActiveOnly     !== policy.vuln_rescan_active_only)    patch.vuln_rescan_active_only = vulnRescanActiveOnly
      if (vulnRescanActiveDays     !== policy.vuln_rescan_active_days)    patch.vuln_rescan_active_days = vulnRescanActiveDays
      if (secretScanningEnabled    !== policy.secret_scanning_enabled)    patch.secret_scanning_enabled = secretScanningEnabled
      if (misconfigScanningEnabled !== policy.misconfig_scanning_enabled) patch.misconfig_scanning_enabled = misconfigScanningEnabled
      if (sbomEnabled              !== policy.sbom_enabled)               patch.sbom_enabled = sbomEnabled
      if (cosignRequired           !== policy.cosign_required)            patch.cosign_required = cosignRequired
      if (notationRequired         !== policy.notation_required)          patch.notation_required = notationRequired
      if (preventVulnerable        !== policy.prevent_vulnerable_images)  patch.prevent_vulnerable_images = preventVulnerable
      // Always diff vuln_block_rules by serialised value
      if (JSON.stringify(vulnBlockRules) !== JSON.stringify(policy.vuln_block_rules ?? {}))
        patch.vuln_block_rules = vulnBlockRules
      if (preventSecrets           !== policy.prevent_secret_images)      patch.prevent_secret_images = preventSecrets
      if (secretBlockThreshold     !== (policy.secret_block_threshold ?? null))
        patch.secret_block_threshold = secretBlockThreshold
      if (preventMisconfigs        !== policy.prevent_misconfig_images)    patch.prevent_misconfig_images = preventMisconfigs
      if (misconfigFailThreshold   !== (policy.misconfig_fail_threshold ?? null))
        patch.misconfig_fail_threshold = misconfigFailThreshold
    } else {
      // No saved policy yet — send everything
      Object.assign(patch, {
        scanning_enabled: scanningEnabled,
        vuln_rescan_enabled: vulnRescanEnabled,
        vuln_rescan_interval_days: vulnRescanIntervalDays,
        vuln_rescan_active_only: vulnRescanActiveOnly,
        vuln_rescan_active_days: vulnRescanActiveDays,
        secret_scanning_enabled: secretScanningEnabled,
        misconfig_scanning_enabled: misconfigScanningEnabled,
        sbom_enabled: sbomEnabled,
        cosign_required: cosignRequired, notation_required: notationRequired,
        prevent_vulnerable_images: preventVulnerable, vuln_block_rules: vulnBlockRules,
        prevent_secret_images: preventSecrets, secret_block_threshold: secretBlockThreshold,
        prevent_misconfig_images: preventMisconfigs, misconfig_fail_threshold: misconfigFailThreshold,
      })
    }
    if (Object.keys(patch).length === 0) {
      toast.info('No changes to save.')
      return
    }
    setSavingSecurity(true)
    try {
      const updated = await updateProjectPolicy(project, patch, user.csrfToken ?? '')
      setPolicy(updated)
      setVulnBlockRules(updated.vuln_block_rules ?? {})
      setVulnRescanEnabled(updated.vuln_rescan_enabled)
      setVulnRescanIntervalDays(updated.vuln_rescan_interval_days)
      setVulnRescanActiveOnly(updated.vuln_rescan_active_only)
      setVulnRescanActiveDays(updated.vuln_rescan_active_days)
      setSecretBlockThreshold(updated.secret_block_threshold ?? null)
      setMisconfigFailThreshold(updated.misconfig_fail_threshold ?? null)
      toast.success('Security policy saved.')
    } catch {
      toast.error('Failed to save security policy.')
    } finally {
      setSavingSecurity(false)
    }
  }

  const handleSaveTagPolicy = async () => {
    const patch: Partial<ProjectPolicy> = {}
    if (policy) {
      if (tagImmutability !== policy.tag_immutability) patch.tag_immutability = tagImmutability
      if (JSON.stringify(retentionRules) !== JSON.stringify(policy.tag_retention_rules ?? []))
        patch.tag_retention_rules = retentionRules
    } else {
      patch.tag_immutability = tagImmutability
      patch.tag_retention_rules = retentionRules
    }
    if (Object.keys(patch).length === 0) {
      toast.info('No changes to save.')
      return
    }
    setSavingTags(true)
    try {
      const updated = await updateProjectPolicy(project, patch, user.csrfToken ?? '')
      setPolicy(updated)
      setRetentionRules(Array.isArray(updated.tag_retention_rules) ? updated.tag_retention_rules : [])
      toast.success('Tag policy saved.')
    } catch {
      toast.error('Failed to save tag policy.')
    } finally {
      setSavingTags(false)
    }
  }

  const handleDelete = async () => {
    setDeleting(true)
    try {
      const res = await csrfFetch(
        `${baseUrl}registry/projects/${project}`,
        { method: 'DELETE' },
        user.csrfToken,
      )
      if (res.ok) {
        toast.success(`Project "${project}" deleted.`)
        router.push('/dashboard')
      } else {
        toast.error('Failed to delete project.')
      }
    } finally {
      setDeleting(false)
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <SettingsIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>{project}</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Settings</span>
      </header>

      <main className='flex-1 px-6 py-8'>
        {loading ? (
          <div className='mx-auto max-w-7xl space-y-10'>
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className='grid grid-cols-1 gap-10 lg:grid-cols-3'>
                <Skeleton className='h-16 w-full rounded-lg' />
                <div className='space-y-3 lg:col-span-2'>
                  <Skeleton className='h-10 w-full rounded-md' />
                  <Skeleton className='h-10 w-full rounded-md' />
                  <Skeleton className='h-10 w-2/3 rounded-md' />
                </div>
              </div>
            ))}
          </div>
        ) : !projectData ? (
          <p className='text-muted-foreground'>Project not found.</p>
        ) : (
          <ProjectSettings
            general={{
              slug: projectData.name,
              displayName,
              description,
              isPublic,
              saving: savingGeneral,
              onDisplayNameChange: setDisplayName,
              onDescriptionChange: setDescription,
              onPublicChange: setIsPublic,
              onSave: handleSaveGeneral,
            }}
            storage={{
              usedBytes: quotaData?.used_bytes ?? 0,
              quotaBytes: quotaData?.quota_bytes ?? null,
              limited,
              quotaGb,
              saving: savingQuota,
              diskFreeBytes,
              onLimitedChange: setLimited,
              onQuotaGbChange: setQuotaGb,
              onSave: handleSaveQuota,
            }}
            security={{
              scanningEnabled,
              onScanningChange: setScanningEnabled,
              vulnRescanEnabled,
              onVulnRescanEnabledChange: setVulnRescanEnabled,
              vulnRescanIntervalDays,
              onVulnRescanIntervalDaysChange: setVulnRescanIntervalDays,
              vulnRescanActiveOnly,
              onVulnRescanActiveOnlyChange: setVulnRescanActiveOnly,
              vulnRescanActiveDays,
              onVulnRescanActiveDaysChange: setVulnRescanActiveDays,
              secretScanningEnabled,
              onSecretScanningChange: setSecretScanningEnabled,
              misconfigScanningEnabled,
              onMisconfigScanningChange: setMisconfigScanningEnabled,
              sbomEnabled,
              onSbomChange: setSbomEnabled,
              cosignRequired,
              onCosignChange: setCosignRequired,
              notationRequired,
              onNotationChange: setNotationRequired,
              preventVulnerable,
              onPreventVulnerableChange: setPreventVulnerable,
              vulnBlockRules,
              onVulnBlockRulesChange: setVulnBlockRules,
              preventSecrets,
              onPreventSecretsChange: setPreventSecrets,
              secretBlockThreshold,
              onSecretBlockThresholdChange: setSecretBlockThreshold,
              preventMisconfigs,
              onPreventMisconfigsChange: setPreventMisconfigs,
              misconfigFailThreshold,
              onMisconfigFailThresholdChange: setMisconfigFailThreshold,
              saving: savingSecurity,
              onSave: handleSaveSecurity,
              projectName: project,
              csrfToken: user.csrfToken ?? '',
              allowlist,
              onAllowlistChange: loadAllowlist,
              secretAllowlist,
              onSecretAllowlistChange: loadSecretAllowlist,
              misconfigAllowlist,
              onMisconfigAllowlistChange: loadMisconfigAllowlist,
            }}
            tags={{
              projectName: project,
              csrfToken: user.csrfToken ?? '',
              tagImmutability,
              onTagImmutabilityChange: setTagImmutability,
              retentionRules,
              onRetentionRulesChange: setRetentionRules,
              saving: savingTags,
              onSave: handleSaveTagPolicy,
            }}
            danger={{
              projectSlug: projectData.name,
              isAdmin: user.isAdmin ?? false,
              onDelete: handleDelete,
              deleting,
            }}
          />
        )}
      </main>
    </>
  )
}
