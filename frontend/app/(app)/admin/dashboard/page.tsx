'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import {
  ArrowUpRight,
  BoxesIcon,
  CheckIcon,
  ChevronDownIcon,
  FolderOpenIcon,
  GaugeIcon,
  HardDriveIcon,
  ImageIcon,
  KeySquareIcon,
  PackageIcon,
  ShieldAlertIcon,
  TagIcon,
  UsersIcon,
  WrenchIcon,
  XIcon,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchProjects,
  fetchSystemStats,
  fetchAuditLogs,
  fetchSystemActivity,
  getProjectSummary,
  fetchSystemStorageByProject,
  fetchSystemTopRepos,
  fetchSystemOperationMix,
  fetchSystemImagePlatforms,
  fetchSystemScanCoverage,
  fetchSystemVulnByProject,
  fetchSystemImageStats,
  fetchSystemSecuritySecrets,
  fetchSystemSecurityMisconfigs,
  type Project,
  type ProjectSummary,
  type SystemStats,
  type AuditLog,
  type ActivityDay,
  type StorageByProject,
  type TopRepo,
  type OperationCount,
  type ImagePlatform,
  type ScanCoverage,
  type VulnByProject,
  type ImageStats,
  type SecretSummary,
  type MisconfigSummary,
} from '@/services/registry'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import { ScrollArea } from '@/components/ui/scroll-area'
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
import { RegistryActivityChart } from '@/components/registry-activity-chart'
import { RegistryVulnVenn } from '@/components/registry-vuln-venn'
import { RegistryDonutChart, type DonutSlice } from '@/components/registry-donut-chart'
import { RegistryHorizontalBarChart, type HBarRow } from '@/components/registry-horizontal-bar-chart'
import { RegistryVulnScatter } from '@/components/registry-vuln-scatter'
import { RegistryScanCoverage } from '@/components/registry-scan-coverage'

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

const OPERATION_CHART_COLORS: Record<string, string> = {
  push:   'var(--chart-1)',   // blue
  pull:   'var(--chart-2)',   // cyan
  create: 'var(--chart-4)',   // emerald
  delete: 'oklch(0.62 0.22 27)',  // red (destructive)
  update: 'var(--chart-5)',   // amber
  login:  'var(--chart-3)',   // violet
}

// ── Multi-select project filter ───────────────────────────────────────────────

type ProjectFilterProps = {
  projects: Project[]
  selected: Set<string>
  onChange: (next: Set<string>) => void
}

function ProjectFilter({ projects, selected, onChange }: ProjectFilterProps) {
  const [open, setOpen] = useState(false)

  const allSelected = selected.size === 0
  const label = allSelected
    ? 'All projects'
    : selected.size === 1
      ? [...selected][0]
      : `${selected.size} projects`

  function toggle(name: string) {
    const next = new Set(selected)
    if (next.has(name)) next.delete(name)
    else next.add(name)
    onChange(next)
  }

  function selectAll() { onChange(new Set()) }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant='outline' size='sm' className='h-8 gap-1.5 text-xs max-w-[220px]'>
          <FolderOpenIcon className='size-3.5 shrink-0' />
          <span className='truncate'>{label}</span>
          {!allSelected && (
            <span className='ml-0.5 flex size-4 shrink-0 items-center justify-center rounded-full bg-primary text-[10px] text-primary-foreground'>
              {selected.size}
            </span>
          )}
          <ChevronDownIcon className='ml-auto size-3 shrink-0 text-muted-foreground' />
        </Button>
      </PopoverTrigger>
      <PopoverContent className='w-64 p-0' align='end'>
        <Command>
          <CommandInput placeholder='Filter projects…' className='h-8 text-sm' />
          <CommandList>
            <CommandEmpty>No projects found.</CommandEmpty>
            <CommandGroup>
              <CommandItem onSelect={selectAll} className='gap-2 text-sm'>
                <span className={cn('flex size-4 items-center justify-center rounded border', allSelected ? 'border-primary bg-primary text-primary-foreground' : 'border-border')}>
                  {allSelected && <CheckIcon className='size-2.5' />}
                </span>
                All projects
              </CommandItem>
            </CommandGroup>
            <Separator />
            <CommandGroup>
              {projects.map(p => {
                const checked = selected.has(p.name)
                return (
                  <CommandItem key={p.name} onSelect={() => toggle(p.name)} className='gap-2 text-sm'>
                    <span className={cn('flex size-4 shrink-0 items-center justify-center rounded border', checked ? 'border-primary bg-primary text-primary-foreground' : 'border-border')}>
                      {checked && <CheckIcon className='size-2.5' />}
                    </span>
                    <span className='truncate'>{p.name}</span>
                    {p.public && <span className='ml-auto text-[10px] text-muted-foreground'>public</span>}
                  </CommandItem>
                )
              })}
            </CommandGroup>
          </CommandList>
        </Command>
        {!allSelected && (
          <div className='border-t p-2'>
            <Button variant='ghost' size='sm' className='h-7 w-full text-xs text-muted-foreground' onClick={selectAll}>
              <XIcon className='mr-1.5 size-3' />Clear filter
            </Button>
          </div>
        )}
      </PopoverContent>
    </Popover>
  )
}

// ── Stat card ─────────────────────────────────────────────────────────────────

type StatCardProps = {
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>
  label: string
  value: string | number
  sub?: string
  href?: string
  loading: boolean
}

function StatCard({ icon: Icon, label, value, sub, href, loading }: StatCardProps) {
  const inner = (
    <div className={cn('group flex h-[92px] flex-col justify-between rounded-xl border bg-card px-4 py-3 transition-colors', href && 'hover:bg-accent/10')}>
      <div className='flex items-start justify-between gap-3'>
        <Icon className='size-5 shrink-0 text-muted-foreground' />
        {href && <ArrowUpRight className='size-3.5 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5' />}
      </div>
      {loading ? <Skeleton className='h-5 w-20' /> : (
        <div>
          <p className='text-xl font-semibold tabular-nums'>{value}</p>
          <p className='text-[11px] text-muted-foreground'>{sub ?? label}</p>
        </div>
      )}
    </div>
  )
  return href ? <Link href={href}>{inner}</Link> : inner
}

// ── Per-project breakdown table ───────────────────────────────────────────────

type ProjectRow = { project: Project; summary: ProjectSummary | null; loading: boolean }

type BreakdownTableProps = { rows: ProjectRow[] }

function BreakdownTable({ rows }: BreakdownTableProps) {
  return (
    <div className='rounded-xl border bg-card'>
      <div className='flex items-center justify-between gap-3 px-5 pt-4 pb-3'>
        <h2 className='text-sm font-medium'>Project Breakdown</h2>
        <span className='inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-[11px] text-muted-foreground'>{rows.length}</span>
      </div>
      <div className='border-t'>
        <Table>
          <TableHeader className='bg-muted/40'>
            <TableRow className='border-b hover:bg-muted/40'>
              <TableHead className='h-9 px-5 text-[11px] font-medium text-muted-foreground'>Project</TableHead>
              <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[110px]'>Repositories</TableHead>
              <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[90px]'>Tags</TableHead>
              <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[120px]'>Storage</TableHead>
              <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[80px]'>Visibility</TableHead>
              <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[60px] text-right'></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 && (
              <TableRow><TableCell colSpan={6} className='h-24 text-center text-sm text-muted-foreground'>No projects match the filter</TableCell></TableRow>
            )}
            {rows.map(({ project: p, summary, loading }) => (
              <TableRow key={p.name} className='h-12 hover:bg-muted/20'>
                <TableCell className='px-5'>
                  <div className='flex items-center gap-2'>
                    <div className='flex size-6 shrink-0 items-center justify-center rounded bg-primary/10'>
                      <BoxesIcon className='size-3 text-primary' />
                    </div>
                    <span className='text-sm font-medium'>{p.name}</span>
                  </div>
                </TableCell>
                <TableCell className='px-3 text-sm text-muted-foreground tabular-nums'>
                  {loading ? <Skeleton className='h-4 w-10' /> : (summary?.repo_count ?? '—')}
                </TableCell>
                <TableCell className='px-3 text-sm text-muted-foreground tabular-nums'>
                  {loading ? <Skeleton className='h-4 w-10' /> : (summary?.tag_count ?? '—')}
                </TableCell>
                <TableCell className='px-3 text-sm text-muted-foreground'>
                  {loading ? <Skeleton className='h-4 w-16' /> : (summary ? formatBytes(summary.storage_bytes) : '—')}
                </TableCell>
                <TableCell className='px-3'>
                  <span className={cn('text-xs font-medium', p.public ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground')}>
                    {p.public ? 'Public' : 'Private'}
                  </span>
                </TableCell>
                <TableCell className='px-3 text-right'>
                  <Button variant='ghost' size='icon' className='size-7' asChild>
                    <Link href={`/projects/${p.name}`}><ArrowUpRight className='size-3.5' /></Link>
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}

// ── Vuln summary strip ────────────────────────────────────────────────────────

type VulnCounts = { critical: number; high: number; medium: number; low: number }

function VulnStrip({ counts, loading }: { counts: VulnCounts; loading: boolean }) {
  const items = [
    { label: 'Critical', value: counts.critical, color: 'text-red-600 dark:text-red-400' },
    { label: 'High',     value: counts.high,     color: 'text-orange-500 dark:text-orange-400' },
    { label: 'Medium',   value: counts.medium,   color: 'text-amber-500 dark:text-amber-400' },
    { label: 'Low',      value: counts.low,      color: 'text-blue-500 dark:text-blue-400' },
  ]
  return (
    <div className='flex flex-wrap gap-3'>
      {items.map(item => (
        <div key={item.label} className='flex flex-1 flex-col gap-1.5 rounded-xl border bg-card px-4 py-3 min-w-[100px]'>
          <p className='text-[11px] text-muted-foreground'>{item.label}</p>
          {loading ? <Skeleton className='h-6 w-12' /> : (
            <p className={cn('text-2xl font-semibold tabular-nums', item.value > 0 ? item.color : 'text-muted-foreground')}>{item.value}</p>
          )}
        </div>
      ))}
    </div>
  )
}

// ── Audit log panel ───────────────────────────────────────────────────────────

function AuditLogPanel({ logs, loading, projectNames }: { logs: AuditLog[]; loading: boolean; projectNames: string[] }) {
  const filtered = useMemo(() => {
    if (projectNames.length === 0) return logs
    return logs.filter(l => l.project_name !== null && projectNames.includes(l.project_name))
  }, [logs, projectNames])

  return (
    <div className='rounded-xl border bg-card'>
      <div className='flex items-center justify-between gap-3 px-5 pt-4'>
        <div className='flex items-center gap-2'>
          <h2 className='text-sm font-medium'>Recent Activity</h2>
          {!loading && (
            <span className='inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-[11px] text-muted-foreground'>{filtered.length}</span>
          )}
        </div>
        <Button variant='ghost' size='sm' className='h-8 px-3 text-xs' asChild>
          <Link href='/admin/logs'>View all</Link>
        </Button>
      </div>
      <div className='mt-3 border-t'>
        <ScrollArea className='h-[400px]'>
          <div className='min-w-[680px]'>
            <Table>
              <TableHeader className='sticky top-0 z-10 bg-muted/40'>
                <TableRow className='border-b hover:bg-muted/40'>
                  <TableHead className='h-9 px-4 text-[11px] font-medium text-muted-foreground w-[130px]'>User</TableHead>
                  <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[90px]'>Operation</TableHead>
                  <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[120px]'>Project</TableHead>
                  <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground'>Resource</TableHead>
                  <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[80px]'>Result</TableHead>
                  <TableHead className='h-9 px-3 text-[11px] font-medium text-muted-foreground w-[90px] text-right'>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading
                  ? Array.from({ length: 8 }).map((_, i) => (
                      <TableRow key={i} className='h-12'>
                        {Array.from({ length: 6 }).map((_, j) => (
                          <TableCell key={j} className='px-3'><Skeleton className='h-4 w-full' /></TableCell>
                        ))}
                      </TableRow>
                    ))
                  : filtered.length === 0
                    ? <TableRow><TableCell colSpan={6} className='h-24 text-center text-sm text-muted-foreground'>No activity for selected projects</TableCell></TableRow>
                    : filtered.map(log => (
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
                            {log.project_name
                              ? <Link href={`/projects/${log.project_name}`} className='hover:underline'>{log.project_name}</Link>
                              : <span className='italic text-muted-foreground/50'>system</span>
                            }
                          </TableCell>
                          <TableCell className='px-3 text-sm text-muted-foreground'>
                            <span className='block max-w-[180px] truncate' title={log.resource}>{log.resource}</span>
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
          </div>
        </ScrollArea>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AdminDashboardPage() {
  const [projects,     setProjects]     = useState<Project[]>([])
  const [stats,        setStats]        = useState<SystemStats | null>(null)
  const [summaries,    setSummaries]    = useState<Map<string, ProjectSummary>>(new Map())
  const [summaryLoading, setSummaryLoading] = useState<Set<string>>(new Set())
  const [logs,         setLogs]         = useState<AuditLog[]>([])
  const [activity,     setActivity]     = useState<ActivityDay[] | undefined>(undefined)

  // insight state
  const [storageByProject,  setStorageByProject]  = useState<StorageByProject[] | undefined>(undefined)
  const [topRepos,           setTopRepos]           = useState<TopRepo[] | undefined>(undefined)
  const [operationMix,       setOperationMix]       = useState<OperationCount[] | undefined>(undefined)
  const [platforms,          setPlatforms]          = useState<ImagePlatform[] | undefined>(undefined)
  const [scanCoverage,       setScanCoverage]       = useState<ScanCoverage | undefined>(undefined)
  const [vulnByProject,      setVulnByProject]      = useState<VulnByProject[] | undefined>(undefined)
  // unfiltered vuln-by-project — always all projects, used for the scatter chart
  const [vulnByProjectAll,   setVulnByProjectAll]   = useState<VulnByProject[] | undefined>(undefined)
  const [vulnAllLoading,     setVulnAllLoading]     = useState(true)
  const [imageStats,         setImageStats]         = useState<ImageStats | undefined>(undefined)
  const [secretSummary,      setSecretSummary]      = useState<SecretSummary[] | undefined>(undefined)
  const [misconfigSummary,   setMisconfigSummary]   = useState<MisconfigSummary[] | undefined>(undefined)

  const [statsLoading,         setStatsLoading]         = useState(true)
  const [logsLoading,          setLogsLoading]          = useState(true)
  const [activityLoading,      setActivityLoading]      = useState(true)
  const [projectsLoading,      setProjectsLoading]      = useState(true)
  const [storageLoading,       setStorageLoading]       = useState(true)
  const [topReposLoading,      setTopReposLoading]      = useState(true)
  const [opMixLoading,         setOpMixLoading]         = useState(true)
  const [platformsLoading,     setPlatformsLoading]     = useState(true)
  const [coverageLoading,      setCoverageLoading]      = useState(true)
  const [vulnLoading,          setVulnLoading]          = useState(true)
  const [imageStatsLoading,    setImageStatsLoading]    = useState(true)
  const [secretLoading,        setSecretLoading]        = useState(true)
  const [misconfigLoading,     setMisconfigLoading]     = useState(true)

  const [selectedProjects, setSelectedProjects] = useState<Set<string>>(new Set())

  useEffect(() => {
    fetchProjects()
      .then(ps => { setProjects(ps); setProjectsLoading(false) })
      .catch(() => setProjectsLoading(false))

    fetchSystemStats()
      .then(s => setStats(s)).catch(() => {}).finally(() => setStatsLoading(false))

    fetchAuditLogs({ limit: 100 })
      .then(l => setLogs(l)).catch(() => {}).finally(() => setLogsLoading(false))

    // insight fetches that are always system-wide (not affected by project filter)
    fetchSystemStorageByProject()
      .then(d => setStorageByProject(d)).catch(() => setStorageByProject([])).finally(() => setStorageLoading(false))

    // unfiltered vuln-by-project for the scatter chart (always all projects)
    fetchSystemVulnByProject()
      .then(d => setVulnByProjectAll(d)).catch(() => setVulnByProjectAll([])).finally(() => setVulnAllLoading(false))
  }, [])

  // Re-fetch all project-filterable insights whenever the project selection changes
  useEffect(() => {
    const projectsParam = selectedProjects.size > 0 ? [...selectedProjects] : undefined

    setActivityLoading(true)
    fetchSystemActivity(365, projectsParam)
      .then(a => setActivity(a)).catch(() => setActivity([])).finally(() => setActivityLoading(false))

    setTopReposLoading(true)
    fetchSystemTopRepos(10, 'pushes', projectsParam)
      .then(d => setTopRepos(d)).catch(() => setTopRepos([])).finally(() => setTopReposLoading(false))

    setOpMixLoading(true)
    fetchSystemOperationMix(30, projectsParam)
      .then(d => setOperationMix(d)).catch(() => setOperationMix([])).finally(() => setOpMixLoading(false))

    setPlatformsLoading(true)
    fetchSystemImagePlatforms(projectsParam)
      .then(d => setPlatforms(d)).catch(() => setPlatforms([])).finally(() => setPlatformsLoading(false))

    setCoverageLoading(true)
    fetchSystemScanCoverage(projectsParam)
      .then(d => setScanCoverage(d)).catch(() => setScanCoverage({ total: 0, scanned: 0, by_project: [] })).finally(() => setCoverageLoading(false))

    setVulnLoading(true)
    fetchSystemVulnByProject(projectsParam)
      .then(d => setVulnByProject(d)).catch(() => setVulnByProject([])).finally(() => setVulnLoading(false))

    setImageStatsLoading(true)
    fetchSystemImageStats(projectsParam)
      .then(d => setImageStats(d)).catch(() => setImageStats(undefined)).finally(() => setImageStatsLoading(false))

    setSecretLoading(true)
    fetchSystemSecuritySecrets(undefined, projectsParam)
      .then(d => setSecretSummary(d)).catch(() => setSecretSummary([])).finally(() => setSecretLoading(false))

    setMisconfigLoading(true)
    fetchSystemSecurityMisconfigs(undefined, projectsParam)
      .then(d => setMisconfigSummary(d)).catch(() => setMisconfigSummary([])).finally(() => setMisconfigLoading(false))
  }, [selectedProjects]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (projects.length === 0) return
    const missing = projects.filter(p => !summaries.has(p.name))
    if (missing.length === 0) return
    setSummaryLoading(prev => { const n = new Set(prev); missing.forEach(p => n.add(p.name)); return n })
    missing.forEach(p => {
      getProjectSummary(p.name)
        .then(s => setSummaries(prev => new Map(prev).set(p.name, s)))
        .catch(() => {})
        .finally(() => setSummaryLoading(prev => { const n = new Set(prev); n.delete(p.name); return n }))
    })
  }, [projects]) // eslint-disable-line react-hooks/exhaustive-deps

  const visibleProjects = useMemo(() =>
    selectedProjects.size === 0
      ? projects
      : projects.filter(p => selectedProjects.has(p.name)),
    [projects, selectedProjects],
  )

  const filteredStats = useMemo(() => {
    if (selectedProjects.size === 0) {
      return {
        repos:    stats?.repository_count ?? null,
        storage:  stats ? stats.storage_bytes : null,
        users:    stats?.user_count ?? null,
        projects: stats?.project_count ?? null,
      }
    }
    const rows = visibleProjects.map(p => summaries.get(p.name))
    if (rows.some(r => r === undefined)) return null
    return {
      repos:    rows.reduce((a, r) => a + (r?.repo_count  ?? 0), 0),
      storage:  rows.reduce((a, r) => a + (r?.storage_bytes ?? 0), 0),
      users:    null,
      projects: visibleProjects.length,
    }
  }, [selectedProjects, visibleProjects, summaries, stats])

  // aggregate vuln counts from the per-project data
  const vulnCounts = useMemo<VulnCounts>(() => {
    if (!vulnByProject) return { critical: 0, high: 0, medium: 0, low: 0 }
    return vulnByProject.reduce(
      (acc, r) => ({
        critical: acc.critical + r.critical,
        high:     acc.high     + r.high,
        medium:   acc.medium   + r.medium,
        low:      acc.low      + r.low,
      }),
      { critical: 0, high: 0, medium: 0, low: 0 },
    )
  }, [vulnByProject])

  const totalSecrets = useMemo(
    () => (secretSummary ?? []).reduce((a, r) => a + r.total, 0),
    [secretSummary],
  )

  const totalMisconfigFails = useMemo(
    () => (misconfigSummary ?? []).reduce((a, r) => a + r.fail, 0),
    [misconfigSummary],
  )

  const secretCoverage = useMemo(() => ({
    total: secretSummary?.length ?? 0,
    scanned: (secretSummary ?? []).filter(r => r.scan_status === 'finished').length,
  }), [secretSummary])

  const misconfigCoverage = useMemo(() => ({
    total: misconfigSummary?.length ?? 0,
    scanned: (misconfigSummary ?? []).filter(r => r.scan_status === 'finished').length,
  }), [misconfigSummary])

  // Derived chart data
  const storageBars = useMemo<HBarRow[]>(() =>
    (storageByProject ?? []).slice(0, 10).map(r => ({
      label: r.project,
      value: r.storage_bytes,
    })),
    [storageByProject],
  )

  const topRepoBars = useMemo<HBarRow[]>(() =>
    (topRepos ?? []).map(r => ({
      label: r.name,
      sublabel: r.project,
      value: r.push_count,
      value2: r.pull_count,
    })),
    [topRepos],
  )

  const operationSlices = useMemo<DonutSlice[]>(() =>
    (operationMix ?? []).map(r => ({
      label: r.operation,
      value: r.count,
      color: OPERATION_CHART_COLORS[r.operation],
    })),
    [operationMix],
  )

  const platformSlices = useMemo<DonutSlice[]>(() =>
    (platforms ?? []).map(r => ({
      label: r.label,
      value: r.count,
    })),
    [platforms],
  )

  const isFiltered = selectedProjects.size > 0
  const selectedNames = [...selectedProjects]

  const projectRows = visibleProjects.map(p => ({
    project: p,
    summary: summaries.get(p.name) ?? null,
    loading: summaryLoading.has(p.name),
  }))

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <GaugeIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>System</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Dashboard</span>
        <div className='ml-auto flex items-center gap-2'>
          <ProjectFilter
            projects={projects}
            selected={selectedProjects}
            onChange={setSelectedProjects}
          />
        </div>
      </header>

      <main className='flex-1 space-y-6 px-6 py-6'>

        {/* Top stat cards */}
        <div className='grid grid-cols-2 gap-3 sm:grid-cols-4'>
          <StatCard
            icon={FolderOpenIcon}
            label='Projects'
            value={isFiltered ? visibleProjects.length : (stats?.project_count ?? '—')}
            sub={isFiltered ? 'selected' : 'total projects'}
            loading={isFiltered ? false : statsLoading}
          />
          <StatCard
            icon={PackageIcon}
            label='Repositories'
            value={filteredStats?.repos ?? '—'}
            sub={isFiltered ? 'in selected' : 'total repos'}
            loading={isFiltered ? visibleProjects.some(p => summaryLoading.has(p.name)) : statsLoading}
          />
          <StatCard
            icon={UsersIcon}
            label='Users'
            value={stats?.user_count ?? '—'}
            sub='registered users'
            href='/admin/users'
            loading={statsLoading}
          />
          <StatCard
            icon={HardDriveIcon}
            label='Storage'
            value={filteredStats?.storage != null ? formatBytes(filteredStats.storage) : '—'}
            sub={isFiltered ? 'in selected' : 'total used'}
            loading={isFiltered ? visibleProjects.some(p => summaryLoading.has(p.name)) : statsLoading}
          />
        </div>

        {/* Avg image size + scan coverage strip */}
        <div className='grid grid-cols-2 gap-3 sm:grid-cols-4'>
          <StatCard
            icon={ImageIcon}
            label='Avg Image Size'
            value={imageStats ? formatBytes(imageStats.avg_bytes) : '—'}
            sub='average tag size'
            loading={imageStatsLoading}
          />
          <StatCard
            icon={TagIcon}
            label='Total Tags'
            value={imageStats?.total_tags ?? (stats ? '—' : '—')}
            sub='across all projects'
            loading={imageStatsLoading}
          />
          <StatCard
            icon={HardDriveIcon}
            label='Largest Tag'
            value={imageStats ? formatBytes(imageStats.max_bytes) : '—'}
            sub='max single tag size'
            loading={imageStatsLoading}
          />
          <StatCard
            icon={ShieldAlertIcon}
            label='Scanned'
            value={scanCoverage ? `${scanCoverage.total > 0 ? Math.round((scanCoverage.scanned / scanCoverage.total) * 100) : 0}%` : '—'}
            sub='tags with completed scan'
            loading={coverageLoading}
          />
        </div>

        {/* Security posture strip */}
        <div className='grid grid-cols-3 gap-3'>
          <StatCard
            icon={ShieldAlertIcon}
            label='Critical vulnerabilities'
            value={vulnLoading ? '—' : vulnCounts.critical}
            sub='critical CVEs fleet-wide'
            href='/admin/security'
            loading={vulnLoading}
          />
          <StatCard
            icon={KeySquareIcon}
            label='Secrets detected'
            value={secretLoading ? '—' : totalSecrets}
            sub='total secrets found'
            href='/admin/security'
            loading={secretLoading}
          />
          <StatCard
            icon={WrenchIcon}
            label='Misconfig failures'
            value={misconfigLoading ? '—' : totalMisconfigFails}
            sub='total FAIL findings'
            href='/admin/security'
            loading={misconfigLoading}
          />
        </div>

        {/* Activity chart + Vuln venn */}
        <div className='flex flex-col gap-4 sm:gap-6 xl:flex-row'>
          <RegistryActivityChart data={activity} loading={activityLoading} />
          <RegistryVulnVenn counts={vulnCounts} loading={vulnLoading} className='xl:w-[340px] xl:shrink-0' />
        </div>

        {/* Insight row 1: Storage by project + Top repos by pulls */}
        <div className='grid gap-4 xl:grid-cols-2'>
          <RegistryHorizontalBarChart
            title='Storage by Project'
            subtitle='Top 10 projects by disk usage'
            primaryLabel='Storage'
            data={storageBars}
            loading={storageLoading}
            formatValue={formatBytes}
          />
          <RegistryHorizontalBarChart
            title='Top Repositories'
            subtitle='By push count (pulls in secondary)'
            primaryLabel='Pushes'
            secondaryLabel='Pulls'
            data={topRepoBars}
            loading={topReposLoading}
          />
        </div>

        {/* Insight row 2: Operation mix donut + Platform donut + Scan coverage ring */}
        <div className='grid gap-4 sm:grid-cols-2 xl:grid-cols-3'>
          <RegistryDonutChart
            title='Operation Mix'
            subtitle='Last 30 days'
            data={operationSlices}
            loading={opMixLoading}
          />
          <RegistryDonutChart
            title='Image Platforms'
            subtitle='OS / architecture distribution'
            data={platformSlices}
            loading={platformsLoading}
          />
          <RegistryScanCoverage
            total={scanCoverage?.total}
            scanned={scanCoverage?.scanned}
            secretTotal={secretSummary !== undefined ? secretCoverage.total : undefined}
            secretScanned={secretCoverage.scanned}
            misconfigTotal={misconfigSummary !== undefined ? misconfigCoverage.total : undefined}
            misconfigScanned={misconfigCoverage.scanned}
            loading={coverageLoading || secretLoading || misconfigLoading}
          />
        </div>

        {/* Insight row 3: Vuln density scatter per project (always all projects) */}
        <RegistryVulnScatter
          data={vulnByProjectAll}
          loading={vulnAllLoading}
        />

        {/* Per-project breakdown */}
        <BreakdownTable rows={projectRows} />

        {/* Audit log */}
        <AuditLogPanel logs={logs} loading={logsLoading} projectNames={selectedNames} />

      </main>
    </>
  )
}
