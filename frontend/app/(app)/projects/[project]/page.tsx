'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import {
  BoxesIcon,
  GaugeIcon,
  HardDriveIcon,
  ImageIcon,
  KeySquareIcon,
  PackageIcon,
  ShieldAlertIcon,
  TagIcon,
  ArrowUpRight,
  WrenchIcon,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  getProjectSummary,
  fetchProjectAuditLogs,
  fetchProjectActivity,
  fetchProjectSecurity,
  fetchProjectSecuritySecrets,
  fetchProjectSecurityMisconfigs,
  fetchMembers,
  fetchProjectTopRepos,
  fetchProjectOperationMix,
  fetchProjectImagePlatforms,
  fetchProjectScanCoverage,
  fetchProjectImageStats,
  fetchProjectMemberRoles,
  type ProjectSummary,
  type AuditLog,
  type Member,
  type ActivityDay,
  type TopRepo,
  type OperationCount,
  type ImagePlatform,
  type ImageStats,
  type MemberRoleCount,
  type VulnSummary,
  type SecretSummary,
  type MisconfigSummary,
} from '@/services/registry'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { ScrollArea } from '@/components/ui/scroll-area'
import Link from 'next/link'
import { RegistryActivityChart } from '@/components/registry-activity-chart'
import { RegistryDonutChart, type DonutSlice } from '@/components/registry-donut-chart'
import { RegistryHorizontalBarChart, type HBarRow } from '@/components/registry-horizontal-bar-chart'
import { RegistryScanCoverage } from '@/components/registry-scan-coverage'
import { RegistryVulnVenn } from '@/components/registry-vuln-venn'

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

function relativeTime(ts: string) {
  const diff = Date.now() - new Date(ts).getTime()
  const mins  = Math.floor(diff / 60000)
  const hours = Math.floor(diff / 3600000)
  const days  = Math.floor(diff / 86400000)
  if (mins  < 1)  return 'just now'
  if (mins  < 60) return `${mins}m ago`
  if (hours < 24) return `${hours}h ago`
  return `${days}d ago`
}

const OPERATION_COLORS: Record<string, string> = {
  push:   'bg-blue-100   text-blue-700   dark:bg-blue-900/40   dark:text-blue-300',
  pull:   'bg-slate-100  text-slate-600  dark:bg-slate-800/60  dark:text-slate-300',
  delete: 'bg-red-100    text-red-700    dark:bg-red-900/40    dark:text-red-300',
  create: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300',
  update: 'bg-amber-100  text-amber-700  dark:bg-amber-900/40  dark:text-amber-300',
  login:  'bg-violet-100 text-violet-700 dark:bg-violet-900/40 dark:text-violet-300',
}

const ROLE_COLORS: Record<string, string> = {
  admin:      'bg-violet-100 text-violet-700 dark:bg-violet-900/40 dark:text-violet-300',
  developer:  'bg-blue-100   text-blue-700   dark:bg-blue-900/40   dark:text-blue-300',
  maintainer: 'bg-amber-100  text-amber-700  dark:bg-amber-900/40  dark:text-amber-300',
  guest:      'bg-slate-100  text-slate-600  dark:bg-slate-800/60  dark:text-slate-300',
}

const OPERATION_CHART_COLORS: Record<string, string> = {
  push:   'var(--chart-1)',   // blue
  pull:   'var(--chart-2)',   // cyan
  create: 'var(--chart-4)',   // emerald
  delete: 'oklch(0.62 0.22 27)',  // red (destructive)
  update: 'var(--chart-5)',   // amber
  login:  'var(--chart-3)',   // violet
}

const ROLE_CHART_COLORS: Record<string, string> = {
  admin:      'var(--chart-3)',   // violet
  developer:  'var(--chart-1)',   // blue
  maintainer: 'var(--chart-5)',   // amber
  guest:      'var(--chart-2)',   // cyan
}

// ── Stat card ─────────────────────────────────────────────────────────────────

type StatCardProps = {
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>
  label: string
  value: string | number
  href?: string
  loading: boolean
}

function StatCard({ icon: Icon, label, value, href, loading }: StatCardProps) {
  const inner = (
    <div className={cn(
      'group flex h-[92px] flex-col justify-between rounded-xl border bg-card px-4 py-3 transition-colors',
      href && 'hover:bg-accent/10',
    )}>
      <div className='flex items-start justify-between gap-3'>
        <Icon className='size-5 shrink-0 text-muted-foreground' />
        {href && <ArrowUpRight className='size-3.5 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5' />}
      </div>
      {loading
        ? <Skeleton className='h-5 w-20' />
        : <div>
            <p className='text-xl font-semibold tabular-nums'>{value}</p>
            <p className='text-[11px] text-muted-foreground'>{label}</p>
          </div>
      }
    </div>
  )
  return href ? <Link href={href}>{inner}</Link> : inner
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ProjectOverviewPage() {
  const { project } = useParams<{ project: string }>()

  const [summary,      setSummary]      = useState<ProjectSummary | null>(null)
  const [members,      setMembers]      = useState<Member[]>([])
  const [logs,         setLogs]         = useState<AuditLog[]>([])
  const [activity,     setActivity]     = useState<ActivityDay[] | undefined>(undefined)
  const [topRepos,     setTopRepos]     = useState<TopRepo[] | undefined>(undefined)
  const [opMix,        setOpMix]        = useState<OperationCount[] | undefined>(undefined)
  const [platforms,    setPlatforms]    = useState<ImagePlatform[] | undefined>(undefined)
  const [coverage,     setCoverage]     = useState<{ total: number; scanned: number } | undefined>(undefined)
  const [imageStats,   setImageStats]   = useState<ImageStats | undefined>(undefined)
  const [memberRoles,  setMemberRoles]  = useState<MemberRoleCount[] | undefined>(undefined)
  const [vulnSummary,     setVulnSummary]     = useState<VulnSummary[] | undefined>(undefined)
  const [secretSummary,   setSecretSummary]   = useState<SecretSummary[] | undefined>(undefined)
  const [misconfigSummary,setMisconfigSummary]= useState<MisconfigSummary[] | undefined>(undefined)

  const [summaryLoading,   setSummaryLoading]   = useState(true)
  const [membersLoading,   setMembersLoading]   = useState(true)
  const [logsLoading,      setLogsLoading]      = useState(true)
  const [activityLoading,  setActivityLoading]  = useState(true)
  const [topReposLoading,  setTopReposLoading]  = useState(true)
  const [opMixLoading,     setOpMixLoading]     = useState(true)
  const [platformsLoading, setPlatformsLoading] = useState(true)
  const [coverageLoading,  setCoverageLoading]  = useState(true)
  const [imageStatsLoading,setImageStatsLoading]= useState(true)
  const [rolesLoading,     setRolesLoading]     = useState(true)
  const [vulnLoading,      setVulnLoading]      = useState(true)
  const [secretLoading,    setSecretLoading]    = useState(true)
  const [misconfigLoading, setMisconfigLoading] = useState(true)

  useEffect(() => {
    setSummaryLoading(true)
    setMembersLoading(true)
    setLogsLoading(true)
    setActivityLoading(true)
    setTopReposLoading(true)
    setOpMixLoading(true)
    setPlatformsLoading(true)
    setCoverageLoading(true)
    setImageStatsLoading(true)
    setRolesLoading(true)
    setVulnLoading(true)
    setSecretLoading(true)
    setMisconfigLoading(true)

    getProjectSummary(project)
      .then(s => setSummary(s)).catch(() => {}).finally(() => setSummaryLoading(false))

    fetchMembers(project)
      .then(m => setMembers(m)).catch(() => {}).finally(() => setMembersLoading(false))

    fetchProjectAuditLogs(project, { limit: 20 })
      .then(l => setLogs(l)).catch(() => {}).finally(() => setLogsLoading(false))

    fetchProjectActivity(project)
      .then(a => setActivity(a)).catch(() => setActivity([])).finally(() => setActivityLoading(false))

    fetchProjectTopRepos(project, 8)
      .then(d => setTopRepos(d)).catch(() => setTopRepos([])).finally(() => setTopReposLoading(false))

    fetchProjectOperationMix(project, 30)
      .then(d => setOpMix(d)).catch(() => setOpMix([])).finally(() => setOpMixLoading(false))

    fetchProjectImagePlatforms(project)
      .then(d => setPlatforms(d)).catch(() => setPlatforms([])).finally(() => setPlatformsLoading(false))

    fetchProjectScanCoverage(project)
      .then(d => setCoverage(d)).catch(() => setCoverage({ total: 0, scanned: 0 })).finally(() => setCoverageLoading(false))

    fetchProjectImageStats(project)
      .then(d => setImageStats(d)).catch(() => setImageStats(undefined)).finally(() => setImageStatsLoading(false))

    fetchProjectMemberRoles(project)
      .then(d => setMemberRoles(d)).catch(() => setMemberRoles([])).finally(() => setRolesLoading(false))

    fetchProjectSecurity(project)
      .then(d => setVulnSummary(d)).catch(() => setVulnSummary([])).finally(() => setVulnLoading(false))

    fetchProjectSecuritySecrets(project)
      .then(d => setSecretSummary(d)).catch(() => setSecretSummary([])).finally(() => setSecretLoading(false))

    fetchProjectSecurityMisconfigs(project)
      .then(d => setMisconfigSummary(d)).catch(() => setMisconfigSummary([])).finally(() => setMisconfigLoading(false))
  }, [project])

  // Derived chart data
  const topRepoBars: HBarRow[] = (topRepos ?? []).map(r => ({
    label: r.name,
    value: r.push_count,
    value2: r.pull_count,
  }))

  const opSlices: DonutSlice[] = (opMix ?? []).map(r => ({
    label: r.operation,
    value: r.count,
    color: OPERATION_CHART_COLORS[r.operation],
  }))

  const platformSlices: DonutSlice[] = (platforms ?? []).map(r => ({
    label: r.label,
    value: r.count,
  }))

  const roleSlices: DonutSlice[] = (memberRoles ?? []).map(r => ({
    label: r.role,
    value: r.count,
    color: ROLE_CHART_COLORS[r.role],
  }))

  const vulnCounts = (vulnSummary ?? []).reduce(
    (acc, r) => ({
      critical: acc.critical + r.critical,
      high:     acc.high     + r.high,
      medium:   acc.medium   + r.medium,
      low:      acc.low      + r.low,
    }),
    { critical: 0, high: 0, medium: 0, low: 0 },
  )

  // Totals across all tags for the threat strip
  const totalSecrets = (secretSummary ?? []).reduce((a, r) => a + r.total, 0)
  const totalMisconfigFails = (misconfigSummary ?? []).reduce((a, r) => a + r.fail, 0)

  // Per-scan-type coverage for extended scan coverage ring
  const secretCoverage = {
    total: secretSummary?.length ?? 0,
    scanned: (secretSummary ?? []).filter(r => r.scan_status === 'finished').length,
  }
  const misconfigCoverage = {
    total: misconfigSummary?.length ?? 0,
    scanned: (misconfigSummary ?? []).filter(r => r.scan_status === 'finished').length,
  }

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <GaugeIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>{project}</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Overview</span>
      </header>

      <main className='flex-1 space-y-6 px-6 py-6'>

        {/* Primary stat cards */}
        <div className='grid grid-cols-2 gap-3 sm:grid-cols-4'>
          <StatCard icon={BoxesIcon}     label='Repositories' value={summary?.repo_count  ?? '—'} href={`/projects/${project}/repositories`} loading={summaryLoading} />
          <StatCard icon={TagIcon}       label='Tags'         value={summary?.tag_count   ?? '—'} href={`/projects/${project}/repositories`} loading={summaryLoading} />
          <StatCard icon={HardDriveIcon} label='Storage'      value={summary ? formatBytes(summary.storage_bytes) : '—'} loading={summaryLoading} />
          <StatCard icon={PackageIcon}   label='Members'      value={membersLoading ? '—' : members.length} href={`/projects/${project}/members`} loading={membersLoading} />
        </div>

        {/* Security posture strip */}
        <div className='grid grid-cols-3 gap-3'>
          <StatCard
            icon={ShieldAlertIcon}
            label='Critical vulnerabilities'
            value={vulnLoading ? '—' : vulnCounts.critical}
            href={`/projects/${project}/security`}
            loading={vulnLoading}
          />
          <StatCard
            icon={KeySquareIcon}
            label='Secrets detected'
            value={secretLoading ? '—' : totalSecrets}
            href={`/projects/${project}/security`}
            loading={secretLoading}
          />
          <StatCard
            icon={WrenchIcon}
            label='Misconfig failures'
            value={misconfigLoading ? '—' : totalMisconfigFails}
            href={`/projects/${project}/security`}
            loading={misconfigLoading}
          />
        </div>

        {/* Image stat cards */}
        <div className='grid grid-cols-2 gap-3 sm:grid-cols-4'>
          <StatCard
            icon={ImageIcon}
            label='Avg Image Size'
            value={imageStats ? formatBytes(imageStats.avg_bytes) : '—'}
            loading={imageStatsLoading}
          />
          <StatCard
            icon={HardDriveIcon}
            label='Largest Tag'
            value={imageStats ? formatBytes(imageStats.max_bytes) : '—'}
            loading={imageStatsLoading}
          />
          <StatCard
            icon={ShieldAlertIcon}
            label='Scan Coverage'
            value={coverage ? `${coverage.total > 0 ? Math.round((coverage.scanned / coverage.total) * 100) : 0}%` : '—'}
            loading={coverageLoading}
          />
          <StatCard
            icon={TagIcon}
            label='Total Tags'
            value={imageStats?.total_tags ?? '—'}
            loading={imageStatsLoading}
          />
        </div>

        {/* Activity chart + Vuln venn */}
        <div className='flex flex-col gap-4 sm:gap-6 xl:flex-row'>
          <RegistryActivityChart data={activity} loading={activityLoading} />
          <RegistryVulnVenn counts={vulnCounts} loading={vulnLoading} className='xl:w-[340px] xl:shrink-0' />
        </div>

        {/* Top repos + Operation mix */}
        <div className='grid gap-4 xl:grid-cols-2'>
          <RegistryHorizontalBarChart
            title='Top Repositories'
            subtitle='By push count (pulls in secondary)'
            primaryLabel='Pushes'
            secondaryLabel='Pulls'
            data={topRepoBars}
            loading={topReposLoading}
          />
          <RegistryDonutChart
            title='Operation Mix'
            subtitle='Last 30 days'
            data={opSlices}
            loading={opMixLoading}
          />
        </div>

        {/* Platform donut + Scan coverage ring + Member roles donut */}
        <div className='grid gap-4 sm:grid-cols-2 xl:grid-cols-3'>
          <RegistryDonutChart
            title='Image Platforms'
            subtitle='OS / architecture distribution'
            data={platformSlices}
            loading={platformsLoading}
          />
          <RegistryScanCoverage
            total={coverage?.total}
            scanned={coverage?.scanned}
            secretTotal={secretSummary !== undefined ? secretCoverage.total : undefined}
            secretScanned={secretCoverage.scanned}
            misconfigTotal={misconfigSummary !== undefined ? misconfigCoverage.total : undefined}
            misconfigScanned={misconfigCoverage.scanned}
            loading={coverageLoading || secretLoading || misconfigLoading}
          />
          <RegistryDonutChart
            title='Member Roles'
            subtitle='Role distribution'
            data={roleSlices}
            loading={rolesLoading}
          />
        </div>

        <div className='grid gap-6 xl:grid-cols-[1fr_300px]'>

          {/* Recent activity */}
          <div className='rounded-xl border bg-card'>
            <div className='flex items-center justify-between gap-3 px-5 pt-4'>
              <div className='flex items-center gap-2'>
                <h2 className='text-sm font-medium'>Recent Activity</h2>
                {!logsLoading && (
                  <span className='inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-[11px] text-muted-foreground'>{logs.length}</span>
                )}
              </div>
              <Button variant='ghost' size='sm' className='h-8 px-3 text-xs' asChild>
                <Link href={`/projects/${project}/logs`}>View all</Link>
              </Button>
            </div>
            <div className='mt-3 border-t'>
              <ScrollArea className='h-[360px]'>
                <Table>
                  <TableHeader className='sticky top-0 z-10 bg-muted/40'>
                    <TableRow className='border-b hover:bg-muted/40'>
                      <TableHead className='h-9 px-4 text-[11px] font-medium text-muted-foreground w-[130px]'>User</TableHead>
                      <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[90px]'>Operation</TableHead>
                      <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground'>Resource</TableHead>
                      <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[90px]'>Result</TableHead>
                      <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[90px] text-right'>When</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {logsLoading
                      ? Array.from({ length: 6 }).map((_, i) => (
                          <TableRow key={i} className='h-12'>
                            {Array.from({ length: 5 }).map((_, j) => (
                              <TableCell key={j} className='px-3'><Skeleton className='h-4 w-full' /></TableCell>
                            ))}
                          </TableRow>
                        ))
                      : logs.length === 0
                        ? <TableRow><TableCell colSpan={5} className='h-24 text-center text-sm text-muted-foreground'>No activity yet</TableCell></TableRow>
                        : logs.map(log => (
                            <TableRow key={log.id} className='h-12 hover:bg-muted/20'>
                              <TableCell className='px-4'>
                                <div className='flex items-center gap-2'>
                                  <Avatar className='size-6'>
                                    <AvatarFallback className='text-[9px]'>{log.username.slice(0, 2).toUpperCase()}</AvatarFallback>
                                  </Avatar>
                                  <span className='max-w-[80px] truncate text-sm font-medium'>{log.username}</span>
                                </div>
                              </TableCell>
                              <TableCell className='px-3'>
                                <Badge variant='secondary' className={cn('border-0 px-2 py-0 text-[11px] font-medium', OPERATION_COLORS[log.operation] ?? 'bg-muted text-muted-foreground')}>
                                  {log.operation}
                                </Badge>
                              </TableCell>
                              <TableCell className='px-3 text-sm text-muted-foreground'>
                                <span className='block max-w-[200px] truncate' title={log.resource}>{log.resource}</span>
                              </TableCell>
                              <TableCell className='px-3'>
                                <span className={cn('text-xs font-medium', log.result ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-500')}>
                                  {log.result ? 'Success' : 'Failed'}
                                </span>
                              </TableCell>
                              <TableCell className='px-3 text-right text-xs text-muted-foreground tabular-nums'>{relativeTime(log.timestamp)}</TableCell>
                            </TableRow>
                          ))
                    }
                  </TableBody>
                </Table>
              </ScrollArea>
            </div>
          </div>

          {/* Members panel */}
          <div className='rounded-xl border bg-card'>
            <div className='flex items-center justify-between gap-3 px-5 pt-4'>
              <h2 className='text-sm font-medium'>Members</h2>
              <Button variant='ghost' size='sm' className='h-8 px-3 text-xs' asChild>
                <Link href={`/projects/${project}/members`}>Manage</Link>
              </Button>
            </div>
            <div className='mt-3 border-t'>
              <ScrollArea className='h-[360px]'>
                {membersLoading
                  ? Array.from({ length: 5 }).map((_, i) => (
                      <div key={i} className='flex items-center gap-3 px-5 py-3'>
                        <Skeleton className='size-8 rounded-full' />
                        <div className='flex-1 space-y-1.5'>
                          <Skeleton className='h-3.5 w-24' />
                          <Skeleton className='h-3 w-32' />
                        </div>
                      </div>
                    ))
                  : members.length === 0
                    ? <p className='px-5 py-8 text-center text-sm text-muted-foreground'>No members yet</p>
                    : members.map(m => (
                        <div key={m.id} className='flex items-center gap-3 px-5 py-3 hover:bg-muted/20 transition-colors'>
                          <Avatar className='size-8'>
                            <AvatarFallback className='text-xs'>{m.username.slice(0, 2).toUpperCase()}</AvatarFallback>
                          </Avatar>
                          <div className='min-w-0 flex-1'>
                            <p className='truncate text-sm font-medium'>{m.username}</p>
                            <p className='truncate text-xs text-muted-foreground'>{m.email}</p>
                          </div>
                          <Badge variant='secondary' className={cn('border-0 px-2 py-0 text-[11px] font-medium shrink-0', ROLE_COLORS[m.role] ?? '')}>
                            {m.role}
                          </Badge>
                        </div>
                      ))
                }
              </ScrollArea>
            </div>
          </div>

        </div>
      </main>
    </>
  )
}
