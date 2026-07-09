'use client'

import { useEffect, useRef, useState } from 'react'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { useAuthContext } from '@/store/AuthContext'
import { baseUrl } from '@/constants/constants'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  SettingsIcon,
  DatabaseIcon,
  BoxesIcon,
  UsersIcon,
  TagIcon,
  LayoutDashboardIcon,
  ShieldCheckIcon,
  SlidersHorizontalIcon,
  ScrollTextIcon,
  TriangleAlertIcon,
  ScanSearchIcon,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SiteSettings {
  allow_registration: boolean
  oidc_enabled: boolean
  oidc_provider_type: string
  oidc_client_id: string
  oidc_server_url: string
  oidc_client_secret_set: boolean
  audit_log_retention_days: number
  job_log_retention_days: number
  rescan_batch_size: number
}

interface SystemStats {
  project_count: number
  repository_count: number
  tag_count: number
  user_count: number
  storage_bytes: number
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

const QUOTA_BYTES = 100 * 1024 ** 3

// ── Nav items ─────────────────────────────────────────────────────────────────

const NAV = [
  { id: 'overview',  label: 'Overview',         icon: LayoutDashboardIcon },
  { id: 'general',   label: 'General',          icon: SlidersHorizontalIcon },
  { id: 'sso',       label: 'SSO / OIDC',       icon: ShieldCheckIcon },
  { id: 'scanning',  label: 'Scanning',         icon: ScanSearchIcon },
  { id: 'logs',      label: 'Logs & Retention', icon: ScrollTextIcon },
]

const RETENTION_OPTIONS = [
  { value: '0',   label: 'Keep forever' },
  { value: '7',   label: '7 days' },
  { value: '14',  label: '14 days' },
  { value: '30',  label: '30 days' },
  { value: '60',  label: '60 days' },
  { value: '90',  label: '90 days' },
  { value: '180', label: '6 months' },
  { value: '365', label: '1 year' },
]

// ── Stat tile ─────────────────────────────────────────────────────────────────

function StatTile({ icon, label, value }: { icon: React.ReactNode; label: string; value: React.ReactNode }) {
  return (
    <div className='flex items-center gap-3 rounded-lg border px-4 py-3'>
      <div className='text-muted-foreground'>{icon}</div>
      <div>
        <p className='text-xs text-muted-foreground'>{label}</p>
        <p className='text-lg font-semibold leading-tight'>{value}</p>
      </div>
    </div>
  )
}

// ── Section wrapper ───────────────────────────────────────────────────────────

function Section({ id, title, description, children }: {
  id: string
  title: string
  description: string
  children: React.ReactNode
}) {
  return (
    <section id={id} className='scroll-mt-20 space-y-4'>
      <div>
        <h2 className='text-base font-semibold'>{title}</h2>
        <p className='text-sm text-muted-foreground'>{description}</p>
      </div>
      <Separator />
      {children}
    </section>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AdminSettingsPage() {
  const { user } = useAuthContext()
  const [activeSection, setActiveSection] = useState('overview')

  // Stats
  const [stats, setStats] = useState<SystemStats | null>(null)
  const [statsLoading, setStatsLoading] = useState(true)

  // Site settings
  const [settings, setSettings] = useState<SiteSettings | null>(null)
  const [settingsLoading, setSettingsLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // Local editable copies
  const [allowReg, setAllowReg] = useState(true)
  const [oidcEnabled, setOidcEnabled] = useState(false)
  const [oidcType, setOidcType] = useState('')
  const [oidcClientId, setOidcClientId] = useState('')
  const [oidcSecret, setOidcSecret] = useState('')
  const [oidcUrl, setOidcUrl] = useState('')
  const [auditRetention, setAuditRetention] = useState('7')
  const [jobRetention, setJobRetention] = useState('30')
  const [rescanBatchSize, setRescanBatchSize] = useState('200')

  // Scroll spy
  const mainRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetch(`${baseUrl}registry/system/statistics`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : null)
      .then(setStats)
      .catch(() => {})
      .finally(() => setStatsLoading(false))

    fetch(`${baseUrl}accounts/site-settings`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : null)
      .then((data: SiteSettings | null) => {
        if (!data) return
        setSettings(data)
        setAllowReg(data.allow_registration)
        setOidcEnabled(data.oidc_enabled)
        setOidcType(data.oidc_provider_type)
        setOidcClientId(data.oidc_client_id)
        setOidcUrl(data.oidc_server_url)
        setAuditRetention(String(data.audit_log_retention_days))
        setJobRetention(String(data.job_log_retention_days))
        setRescanBatchSize(String(data.rescan_batch_size))
      })
      .catch(() => {})
      .finally(() => setSettingsLoading(false))
  }, [])

  // Scroll spy — update active nav item as user scrolls
  useEffect(() => {
    const el = mainRef.current
    if (!el) return
    const handler = () => {
      for (const { id } of [...NAV].reverse()) {
        const section = document.getElementById(id)
        if (section && section.getBoundingClientRect().top <= 100) {
          setActiveSection(id)
          break
        }
      }
    }
    el.addEventListener('scroll', handler, { passive: true })
    return () => el.removeEventListener('scroll', handler)
  }, [])

  const saveSettings = async () => {
    setSaving(true)
    setSaveMsg(null)
    const body: Record<string, unknown> = {
      allow_registration: allowReg,
      oidc_enabled: oidcEnabled,
      oidc_provider_type: oidcType,
      oidc_client_id: oidcClientId,
      oidc_server_url: oidcUrl,
      audit_log_retention_days: parseInt(auditRetention, 10),
      job_log_retention_days: parseInt(jobRetention, 10),
      rescan_batch_size: Math.max(1, parseInt(rescanBatchSize, 10) || 200),
    }
    if (oidcSecret) body.oidc_client_secret = oidcSecret
    const res = await fetch(`${baseUrl}accounts/site-settings`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': user.csrfToken ?? '' },
      body: JSON.stringify(body),
    })
    setSaving(false)
    if (res.ok) {
      const data: SiteSettings = await res.json()
      setSettings(data)
      setOidcSecret('')
      setAuditRetention(String(data.audit_log_retention_days))
      setJobRetention(String(data.job_log_retention_days))
      setRescanBatchSize(String(data.rescan_batch_size))
      setSaveMsg({ ok: true, text: 'Settings saved.' })
    } else {
      setSaveMsg({ ok: false, text: 'Failed to save settings.' })
    }
    setTimeout(() => setSaveMsg(null), 3000)
  }

  const scrollTo = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    setActiveSection(id)
  }

  const usagePercent = stats
    ? Math.min(Math.round((stats.storage_bytes / QUOTA_BYTES) * 100), 100)
    : 0

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <SettingsIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>System</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Settings</span>
      </header>

      <div className='flex flex-1 overflow-hidden'>

        {/* Left nav */}
        <aside className='hidden w-52 shrink-0 border-r lg:block'>
          <nav className='sticky top-[49px] p-4 space-y-1'>
            {NAV.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => scrollTo(id)}
                className={`flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors text-left ${
                  activeSection === id
                    ? 'bg-primary/10 text-primary font-medium'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                }`}
              >
                <Icon className='size-4 shrink-0' />
                {label}
              </button>
            ))}
          </nav>
        </aside>

        {/* Scrollable content */}
        <div ref={mainRef} className='flex-1 overflow-y-auto'>
          <div className='mx-auto max-w-2xl px-6 py-8 space-y-12'>

            {/* ── Overview ── */}
            <Section
              id='overview'
              title='Overview'
              description='Live statistics for this registry instance.'
            >
              {statsLoading ? (
                <div className='grid grid-cols-2 gap-3 sm:grid-cols-4'>
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className='h-20 w-full rounded-lg' />
                  ))}
                </div>
              ) : stats ? (
                <div className='space-y-4'>
                  <div className='grid grid-cols-2 gap-3 sm:grid-cols-4'>
                    <StatTile icon={<BoxesIcon className='size-4' />}    label='Projects'     value={stats.project_count} />
                    <StatTile icon={<TagIcon className='size-4' />}      label='Repositories' value={stats.repository_count} />
                    <StatTile icon={<UsersIcon className='size-4' />}    label='Users'        value={stats.user_count} />
                    <StatTile icon={<DatabaseIcon className='size-4' />} label='Storage'      value={formatBytes(stats.storage_bytes)} />
                  </div>
                  <Card className='shadow-none'>
                    <CardHeader className='pb-2'>
                      <CardTitle className='text-sm font-medium'>Storage usage</CardTitle>
                      <CardDescription className='text-xs'>
                        {formatBytes(stats.storage_bytes)} of {formatBytes(QUOTA_BYTES)} soft limit
                      </CardDescription>
                    </CardHeader>
                    <CardContent className='space-y-1'>
                      <Progress value={usagePercent} className='h-1.5' />
                      <p className='text-xs text-muted-foreground'>{usagePercent}% used</p>
                    </CardContent>
                  </Card>
                </div>
              ) : (
                <p className='text-sm text-muted-foreground'>Failed to load statistics.</p>
              )}
            </Section>

            {/* ── General ── */}
            <Section
              id='general'
              title='General'
              description='Control who can sign up and access this registry.'
            >
              {settingsLoading ? (
                <Skeleton className='h-16 w-full rounded-lg' />
              ) : (
                <div className='flex items-center justify-between rounded-lg border px-4 py-3'>
                  <div className='space-y-0.5'>
                    <Label htmlFor='allow-reg' className='text-sm font-medium cursor-pointer'>
                      Open registration
                    </Label>
                    <p className='text-xs text-muted-foreground'>
                      Allow new users to self-register via the public sign-up page. Disable to make
                      registration invite-only. Admins can always create accounts via the Users
                      panel{oidcEnabled ? ' (not available while OIDC is enabled)' : ''}.
                    </p>
                  </div>
                  <Switch
                    id='allow-reg'
                    checked={allowReg}
                    onCheckedChange={setAllowReg}
                  />
                </div>
              )}
            </Section>

            {/* ── SSO / OIDC ── */}
            <Section
              id='sso'
              title='SSO / OIDC'
              description='Configure single sign-on via an external OpenID Connect provider.'
            >
              {settingsLoading ? (
                <div className='space-y-3'>
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className='h-10 w-full rounded-md' />
                  ))}
                </div>
              ) : (
                <div className='space-y-4'>
                  <div className='flex items-center justify-between rounded-lg border px-4 py-3'>
                    <div className='space-y-0.5'>
                      <Label htmlFor='oidc-enabled' className='text-sm font-medium cursor-pointer'>
                        Enable SSO
                      </Label>
                      <p className='text-xs text-muted-foreground'>
                        Let users sign in via an external OIDC provider.
                      </p>
                    </div>
                    <Switch
                      id='oidc-enabled'
                      checked={oidcEnabled}
                      onCheckedChange={setOidcEnabled}
                    />
                  </div>

                  <div className={`space-y-3 transition-opacity duration-150 ${oidcEnabled ? 'opacity-100' : 'opacity-40 pointer-events-none'}`}>
                    <div className='space-y-1.5'>
                      <Label htmlFor='oidc-type'>Provider type</Label>
                      <Input
                        id='oidc-type'
                        placeholder='keycloak, authelia, or authentik'
                        value={oidcType}
                        onChange={(e) => setOidcType(e.target.value)}
                        disabled={!oidcEnabled}
                      />
                    </div>

                    {oidcEnabled && oidcType && (
                      <div className='space-y-1.5'>
                        <Label className='text-sm font-medium'>Callback / Redirect URI</Label>
                        <Input
                          readOnly
                          value={`${window.location.origin}/accounts/oidc/${oidcType}/login/callback/`}
                          onClick={(e) => (e.target as HTMLInputElement).select()}
                          className='cursor-pointer select-all font-mono text-xs'
                        />
                        <p className='text-xs text-muted-foreground'>
                          Register this URI in your IDP&apos;s allowed redirect/callback URLs.
                        </p>
                      </div>
                    )}
                    <div className='space-y-1.5'>
                      <Label htmlFor='oidc-client-id'>Client ID</Label>
                      <Input
                        id='oidc-client-id'
                        placeholder='your-client-id'
                        value={oidcClientId}
                        onChange={(e) => setOidcClientId(e.target.value)}
                        disabled={!oidcEnabled}
                      />
                    </div>
                    <div className='space-y-1.5'>
                      <Label htmlFor='oidc-secret'>
                        Client secret{' '}
                        {settings?.oidc_client_secret_set && (
                          <span className='text-xs font-normal text-muted-foreground'>(set — leave blank to keep)</span>
                        )}
                      </Label>
                      <Input
                        id='oidc-secret'
                        type='password'
                        placeholder={settings?.oidc_client_secret_set ? '••••••••' : 'your-client-secret'}
                        value={oidcSecret}
                        onChange={(e) => setOidcSecret(e.target.value)}
                        disabled={!oidcEnabled}
                        autoComplete='off'
                      />
                    </div>
                    <div className='space-y-1.5'>
                      <Label htmlFor='oidc-url'>Discovery URL</Label>
                      <Input
                        id='oidc-url'
                        placeholder='https://sso.example.com/.well-known/openid-configuration'
                        value={oidcUrl}
                        onChange={(e) => setOidcUrl(e.target.value)}
                        disabled={!oidcEnabled}
                      />
                    </div>
                  </div>
                </div>
              )}
            </Section>

            {/* ── Scanning ── */}
            <Section
              id='scanning'
              title='Scanning'
              description='Control how automated vulnerability re-scanning behaves across all projects.'
            >
              {settingsLoading ? (
                <Skeleton className='h-10 w-full rounded-md' />
              ) : (
                <div className='space-y-4'>
                  <div className='space-y-1.5'>
                    <Label htmlFor='rescan-batch-size' className='text-sm font-medium'>
                      Re-scan batch size
                    </Label>
                    <Input
                      id='rescan-batch-size'
                      type='number'
                      min={1}
                      max={10000}
                      className='w-36'
                      value={rescanBatchSize}
                      onChange={(e) => setRescanBatchSize(e.target.value)}
                    />
                    <p className='text-xs text-muted-foreground'>
                      Maximum vulnerability re-scan tasks enqueued per Beat tick (every 6 hours).
                      Remaining tags are deferred to the next tick, oldest-scanned first.
                    </p>

                    {/* Backlog warning — shown when batch size cannot drain all tags within one day */}
                    {(() => {
                      const tagCount = stats?.tag_count ?? 0
                      const batch = Math.max(1, parseInt(rescanBatchSize, 10) || 200)
                      // 4 ticks per day (every 6 h)
                      const tagsPerDay = batch * 4
                      const backlogPerDay = tagCount - tagsPerDay

                      if (tagCount === 0 || backlogPerDay <= 0) {
                        // All good — show a confirmation
                        return tagCount > 0 ? (
                          <div className='flex items-start gap-2 rounded-md border border-green-200 bg-green-50 px-3 py-2 dark:border-green-800 dark:bg-green-950/40'>
                            <ShieldCheckIcon className='mt-0.5 size-3.5 shrink-0 text-green-600 dark:text-green-400' />
                            <p className='text-xs text-green-700 dark:text-green-300'>
                              At this batch size, all {tagCount.toLocaleString()} tags can be re-scanned within a single day ({tagsPerDay.toLocaleString()} capacity/day).
                            </p>
                          </div>
                        ) : null
                      }

                      const daysToFullCoverage = Math.ceil(tagCount / tagsPerDay)
                      const recommended = Math.ceil(tagCount / 4)
                      return (
                        <div className='flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 dark:border-amber-800 dark:bg-amber-950/40'>
                          <TriangleAlertIcon className='mt-0.5 size-3.5 shrink-0 text-amber-600 dark:text-amber-400' />
                          <p className='text-xs text-amber-700 dark:text-amber-300'>
                            With {tagCount.toLocaleString()} tags and a batch size of {batch.toLocaleString()}, full coverage takes ~{daysToFullCoverage} day{daysToFullCoverage !== 1 ? 's' : ''} per rescan cycle — {backlogPerDay.toLocaleString()} tags/day will be deferred.
                            {' '}Consider increasing the batch size to <strong>{recommended.toLocaleString()}</strong> for daily full coverage, or enabling <em>active inventory only</em> on projects to reduce the eligible tag count.
                          </p>
                        </div>
                      )
                    })()}
                  </div>
                </div>
              )}
            </Section>

            {/* ── Logs & Retention ── */}
            <Section
              id='logs'
              title='Logs & Retention'
              description='Control how long audit logs and job logs are kept. Pruning runs automatically during each GC sweep.'
            >
              {settingsLoading ? (
                <div className='space-y-3'>
                  <Skeleton className='h-10 w-full rounded-md' />
                  <Skeleton className='h-10 w-full rounded-md' />
                </div>
              ) : (
                <div className='space-y-4'>
                  <div className='space-y-1.5'>
                    <Label htmlFor='audit-retention' className='text-sm font-medium'>Audit log retention</Label>
                    <Select value={auditRetention} onValueChange={setAuditRetention}>
                      <SelectTrigger id='audit-retention' className='w-48'>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {RETENTION_OPTIONS.map((o) => (
                          <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className='text-xs text-muted-foreground'>
                      Audit log entries older than this are deleted during GC runs.
                    </p>
                    {(() => {
                      const current = settings?.audit_log_retention_days ?? 0
                      const next = parseInt(auditRetention, 10)
                      const isReduction = next > 0 && (current === 0 || next < current)
                      return isReduction ? (
                        <div className='flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 dark:border-amber-800 dark:bg-amber-950/40'>
                          <TriangleAlertIcon className='mt-0.5 size-3.5 shrink-0 text-amber-600 dark:text-amber-400' />
                          <p className='text-xs text-amber-700 dark:text-amber-300'>
                            Reducing audit log retention will permanently delete existing log entries once GC runs.
                            Dashboard charts and graphs that rely on historical audit data may show a degraded or incomplete view.
                          </p>
                        </div>
                      ) : null
                    })()}
                  </div>

                  <div className='space-y-1.5'>
                    <Label htmlFor='job-retention' className='text-sm font-medium'>Job log retention</Label>
                    <Select value={jobRetention} onValueChange={setJobRetention}>
                      <SelectTrigger id='job-retention' className='w-48'>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {RETENTION_OPTIONS.map((o) => (
                          <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className='text-xs text-muted-foreground'>
                      GC, catalog sync, replication, and Trivy update job records older than this are deleted during GC runs.
                    </p>
                  </div>
                </div>
              )}
            </Section>

            {/* Save bar */}
            {!settingsLoading && (
              <div className='flex items-center justify-between rounded-lg border bg-muted/40 px-4 py-3'>
                <p className={`text-sm ${saveMsg ? (saveMsg.ok ? 'text-green-600 dark:text-green-400' : 'text-destructive') : 'text-muted-foreground'}`}>
                  {saveMsg ? saveMsg.text : 'Save changes when ready.'}
                </p>
                <Button size='sm' onClick={saveSettings} disabled={saving}>
                  {saving ? 'Saving…' : 'Save changes'}
                </Button>
              </div>
            )}

          </div>
        </div>
      </div>
    </>
  )
}
