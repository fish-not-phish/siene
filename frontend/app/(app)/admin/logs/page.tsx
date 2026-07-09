'use client'

import { useEffect, useState, useCallback, useRef } from 'react'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Tabs, TabsContent, TabsList, TabsTrigger,
} from '@/components/ui/tabs'
import {
  ScrollTextIcon, SearchIcon, RefreshCwIcon, CheckCircle2Icon, XCircleIcon,
  XIcon, CheckCircleIcon, AlertCircleIcon, Trash2Icon, DatabaseIcon,
  ShieldIcon, RepeatIcon, DownloadIcon, FileTextIcon, FileJsonIcon,
} from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { fetchAuditLogs, type AuditLog, type AuditLogFilters } from '@/services/registry'
import { describeLog } from '@/lib/auditLogDescription'
import { useProjects } from '@/providers/ProjectsContext'
import { DatePickerFilter } from '@/components/shadcn-studio/blocks/date-picker-filter'
import { baseUrl } from '@/constants/constants'

// ── Types ─────────────────────────────────────────────────────────────────────

interface GCJob {
  id: number
  status: 'pending' | 'running' | 'success' | 'error'
  triggered_by: string
  started_at: string
  finished_at: string | null
  orphans_deleted: number
  retention_deleted: number
  audit_deleted: number
  errors: number
  blob_gc_ok: boolean | null
  blob_gc_output: string
  error: string
}

interface SyncJob {
  id: number
  status: 'pending' | 'running' | 'success' | 'error'
  started_at: string
  finished_at: string | null
  repos_created: number
  tags_created: number
  error: string
}

interface ReplicationJob {
  id: number
  status: 'pending' | 'running' | 'success' | 'partial' | 'error'
  rule_name: string
  started_at: string
  finished_at: string | null
  copied: number
  errors: number
  log: string
}

interface TrivyUpdateJob {
  id: number
  status: 'pending' | 'running' | 'success' | 'error'
  triggered_by: string
  started_at: string
  finished_at: string | null
  error: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const OPERATIONS = ['all', 'push', 'pull', 'delete', 'create', 'update', 'login', 'scan_started', 'scan_finished', 'scan_error']

const opLabels: Record<string, string> = {
  all:           'All',
  push:          'Push',
  pull:          'Pull',
  delete:        'Delete',
  create:        'Create',
  update:        'Update',
  login:         'Login',
  scan_started:  'Scan started',
  scan_finished: 'Scan finished',
  scan_error:    'Scan error',
}

const opColors: Record<string, string> = {
  push:          'bg-blue-600/10 text-blue-600 dark:bg-blue-400/10 dark:text-blue-400',
  pull:          'bg-green-600/10 text-green-600 dark:bg-green-400/10 dark:text-green-400',
  delete:        'bg-destructive/10 text-destructive',
  create:        'bg-purple-600/10 text-purple-600 dark:bg-purple-400/10 dark:text-purple-400',
  update:        'bg-orange-600/10 text-orange-600 dark:bg-orange-400/10 dark:text-orange-400',
  login:         'bg-muted text-muted-foreground',
  scan_started:  'bg-sky-600/10 text-sky-600 dark:bg-sky-400/10 dark:text-sky-400',
  scan_finished: 'bg-teal-600/10 text-teal-600 dark:bg-teal-400/10 dark:text-teal-400',
  scan_error:    'bg-destructive/10 text-destructive',
}

const statusColors: Record<string, string> = {
  success: 'text-green-600',
  error:   'text-destructive',
  partial: 'text-orange-500',
  running: 'text-blue-500',
  pending: 'text-muted-foreground',
}

function StatusIcon({ status }: { status: string }) {
  if (status === 'success') return <CheckCircleIcon className='size-3.5 text-green-600 shrink-0' />
  if (status === 'error')   return <AlertCircleIcon className='size-3.5 text-destructive shrink-0' />
  if (status === 'partial') return <AlertCircleIcon className='size-3.5 text-orange-500 shrink-0' />
  return <RefreshCwIcon className={`size-3.5 shrink-0 text-muted-foreground ${status === 'running' ? 'animate-spin' : ''}`} />
}

function fmtTime(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function duration(start: string, end: string | null) {
  if (!end) return null
  const s = Math.round((new Date(end).getTime() - new Date(start).getTime()) / 1000)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className='flex flex-col items-center justify-center gap-3 py-20 text-center text-muted-foreground'>
      <ScrollTextIcon className='size-10 opacity-30' />
      <p className='text-sm'>{label}</p>
    </div>
  )
}

function LoadingRows() {
  return (
    <div className='space-y-px'>
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className='h-12 w-full rounded-none first:rounded-t-md last:rounded-b-md' />
      ))}
    </div>
  )
}

const EMPTY: AuditLogFilters = { operation: '', projectName: '', dateFrom: '', dateTo: '', q: '' }
function hasFilters(f: AuditLogFilters) {
  return !!(f.operation || f.projectName || f.dateFrom || f.dateTo || f.q)
}

// ── Audit tab ─────────────────────────────────────────────────────────────────

function AuditTab() {
  const { projects } = useProjects()
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState<AuditLogFilters>(EMPTY)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const load = useCallback((f: AuditLogFilters) => {
    setLoading(true)
    fetchAuditLogs(f)
      .then((d) => setLogs(Array.isArray(d) ? d : []))
      .catch(() => setLogs([]))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load(EMPTY) }, [load])

  const setImm = (patch: Partial<AuditLogFilters>) => {
    const next = { ...filters, ...patch }; setFilters(next); load(next)
  }
  const setDeb = (patch: Partial<AuditLogFilters>) => {
    const next = { ...filters, ...patch }; setFilters(next)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => load(next), 350)
  }
  const clear = () => { setFilters(EMPTY); load(EMPTY) }
  const active = hasFilters(filters)

  const exportLogs = (format: 'csv' | 'json') => {
    const p = new URLSearchParams({ format })
    if (filters.operation)   p.set('operation', filters.operation)
    if (filters.projectName) p.set('project_name', filters.projectName)
    if (filters.dateFrom)    p.set('date_from', filters.dateFrom)
    if (filters.dateTo)      p.set('date_to', filters.dateTo)
    if (filters.q)           p.set('q', filters.q)
    window.location.href = `${baseUrl}registry/system/audit-logs/export?${p}`
  }

  return (
    <div className='space-y-4'>
      <div className='flex flex-wrap items-center gap-2'>
        <Select value={filters.operation || 'all'} onValueChange={(v) => setImm({ operation: v === 'all' ? '' : v })}>
          <SelectTrigger className='h-8 w-32 text-sm'><SelectValue placeholder='Operation' /></SelectTrigger>
          <SelectContent>{OPERATIONS.map((op) => <SelectItem key={op} value={op}>{opLabels[op] ?? op}</SelectItem>)}</SelectContent>
        </Select>
        <Select value={filters.projectName || 'all'} onValueChange={(v) => setImm({ projectName: v === 'all' ? '' : v })}>
          <SelectTrigger className='h-8 w-36 text-sm'><SelectValue placeholder='All projects' /></SelectTrigger>
          <SelectContent>
            <SelectItem value='all'>All projects</SelectItem>
            {projects.map((p) => <SelectItem key={p.name} value={p.name}>{p.name}</SelectItem>)}
          </SelectContent>
        </Select>
        <DatePickerFilter label='From' value={filters.dateFrom ?? ''} max={filters.dateTo || undefined} onChange={(v) => setImm({ dateFrom: v })} />
        <DatePickerFilter label='To'   value={filters.dateTo  ?? ''} min={filters.dateFrom || undefined} onChange={(v) => setImm({ dateTo: v })} />
        <div className='relative'>
          <SearchIcon className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
          <Input placeholder='Search user or resource…' className='h-8 w-52 pl-8 text-sm' value={filters.q ?? ''} onChange={(e) => setDeb({ q: e.target.value })} />
        </div>
        {active && <Button size='sm' variant='ghost' onClick={clear} className='h-8 gap-1 text-xs'><XIcon className='size-3' />Clear</Button>}
        <div className='ml-auto flex items-center gap-2'>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size='sm' variant='outline' className='h-8 gap-1.5'>
                <DownloadIcon className='size-3.5' />
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align='end'>
              <DropdownMenuItem onClick={() => exportLogs('csv')} className='gap-2'>
                <FileTextIcon className='size-3.5' />
                Download CSV
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => exportLogs('json')} className='gap-2'>
                <FileJsonIcon className='size-3.5' />
                Download JSON
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button size='sm' variant='outline' onClick={() => load(filters)} className='h-8'><RefreshCwIcon className='size-3.5' /></Button>
        </div>
      </div>

      {loading ? <LoadingRows /> : logs.length === 0 ? (
        <EmptyState label={active ? 'No entries match the current filters.' : 'No audit log entries yet.'} />
      ) : (
        <div className='rounded-md border divide-y'>
          {logs.map((log) => (
            <div key={log.id} className='flex items-start gap-4 px-4 py-3 hover:bg-muted/30 transition-colors'>
              <div className='mt-0.5 shrink-0'>
                {log.result
                  ? <CheckCircle2Icon className='size-4 text-green-600 dark:text-green-400' />
                  : <XCircleIcon className='size-4 text-destructive' />}
              </div>
              <div className='flex-1 min-w-0'>
                <div className='flex flex-wrap items-center gap-x-2 gap-y-0.5'>
                  <span className='text-sm font-semibold'>{log.username}</span>
                  <span className={`inline-flex rounded-full px-2 py-0.5 text-[11px] font-medium ${opColors[log.operation] ?? 'bg-muted text-muted-foreground'}`}>{opLabels[log.operation] ?? log.operation}</span>
                  {log.project_name && <span className='rounded-full border px-2 py-0.5 text-[11px] text-muted-foreground font-mono'>{log.project_name}</span>}
                </div>
                <p className='text-sm text-muted-foreground mt-0.5'>{describeLog(log)}</p>
              </div>
              <time className='shrink-0 text-xs text-muted-foreground tabular-nums mt-0.5'>{fmtTime(log.timestamp)}</time>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── GC Jobs tab ───────────────────────────────────────────────────────────────

function GCTab() {
  const [jobs, setJobs] = useState<GCJob[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    fetch(`${baseUrl}registry/system/gc/jobs?limit=100`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : [])
      .then(setJobs).catch(() => {}).finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div className='space-y-4'>
      <div className='flex justify-end'><Button size='sm' variant='outline' onClick={load}><RefreshCwIcon className='size-3.5' /></Button></div>
      {loading ? <LoadingRows /> : jobs.length === 0 ? <EmptyState label='No GC runs yet.' /> : (
        <div className='rounded-md border divide-y text-sm'>
          {jobs.map((job) => (
            <div key={job.id} className='flex items-start gap-3 px-4 py-3 hover:bg-muted/30'>
              <StatusIcon status={job.status} />
              <div className='flex-1 min-w-0'>
                <div className='flex flex-wrap items-center gap-2'>
                  <span className={`font-medium capitalize ${statusColors[job.status]}`}>{job.status}</span>
                  <Badge variant='outline' className='text-xs capitalize'>{job.triggered_by}</Badge>
                  {duration(job.started_at, job.finished_at) && (
                    <span className='text-xs text-muted-foreground'>{duration(job.started_at, job.finished_at)}</span>
                  )}
                </div>
                {job.status === 'success' && (
                  <p className='text-xs text-muted-foreground mt-0.5'>
                    {job.orphans_deleted > 0 && <>{job.orphans_deleted} orphan{job.orphans_deleted !== 1 ? 's' : ''} · </>}
                    {job.retention_deleted > 0 && <>{job.retention_deleted} retention · </>}
                    {job.audit_deleted > 0 && <>{job.audit_deleted} audit rows · </>}
                    blob GC {job.blob_gc_ok ? 'ok' : 'failed'}
                  </p>
                )}
                {job.error && <p className='text-xs text-destructive mt-0.5 truncate'>{job.error}</p>}
              </div>
              <time className='shrink-0 text-xs text-muted-foreground tabular-nums'>{fmtTime(job.started_at)}</time>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Catalog Sync tab ──────────────────────────────────────────────────────────

function SyncTab() {
  const [jobs, setJobs] = useState<SyncJob[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    fetch(`${baseUrl}registry/system/sync/jobs?limit=100`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : [])
      .then(setJobs).catch(() => {}).finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div className='space-y-4'>
      <div className='flex justify-end'><Button size='sm' variant='outline' onClick={load}><RefreshCwIcon className='size-3.5' /></Button></div>
      {loading ? <LoadingRows /> : jobs.length === 0 ? <EmptyState label='No catalog sync runs yet.' /> : (
        <div className='rounded-md border divide-y text-sm'>
          {jobs.map((job) => (
            <div key={job.id} className='flex items-start gap-3 px-4 py-3 hover:bg-muted/30'>
              <StatusIcon status={job.status} />
              <div className='flex-1 min-w-0'>
                <div className='flex flex-wrap items-center gap-2'>
                  <span className={`font-medium capitalize ${statusColors[job.status]}`}>{job.status}</span>
                  {duration(job.started_at, job.finished_at) && (
                    <span className='text-xs text-muted-foreground'>{duration(job.started_at, job.finished_at)}</span>
                  )}
                </div>
                {job.status === 'success' && (
                  <p className='text-xs text-muted-foreground mt-0.5'>
                    {job.repos_created} repo{job.repos_created !== 1 ? 's' : ''}, {job.tags_created} tag{job.tags_created !== 1 ? 's' : ''} added
                  </p>
                )}
                {job.error && <p className='text-xs text-destructive mt-0.5 truncate'>{job.error}</p>}
              </div>
              <time className='shrink-0 text-xs text-muted-foreground tabular-nums'>{fmtTime(job.started_at)}</time>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Replications tab ──────────────────────────────────────────────────────────

function ReplicationsTab() {
  const [jobs, setJobs] = useState<ReplicationJob[]>([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState<number | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    fetch(`${baseUrl}registry/system/replications/all-jobs?limit=100`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : [])
      .then(setJobs).catch(() => {}).finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div className='space-y-4'>
      <div className='flex justify-end'><Button size='sm' variant='outline' onClick={load}><RefreshCwIcon className='size-3.5' /></Button></div>
      {loading ? <LoadingRows /> : jobs.length === 0 ? <EmptyState label='No replication jobs yet.' /> : (
        <div className='rounded-md border divide-y text-sm'>
          {jobs.map((job) => (
            <div key={job.id}>
              <div
                className='flex items-start gap-3 px-4 py-3 hover:bg-muted/30 cursor-pointer'
                onClick={() => setExpanded(expanded === job.id ? null : job.id)}
              >
                <StatusIcon status={job.status} />
                <div className='flex-1 min-w-0'>
                  <div className='flex flex-wrap items-center gap-2'>
                    <span className='font-medium font-mono'>{job.rule_name}</span>
                    <span className={`capitalize ${statusColors[job.status]}`}>{job.status}</span>
                    {duration(job.started_at, job.finished_at) && (
                      <span className='text-xs text-muted-foreground'>{duration(job.started_at, job.finished_at)}</span>
                    )}
                  </div>
                  <p className='text-xs text-muted-foreground mt-0.5'>
                    {job.copied} copied · {job.errors} error{job.errors !== 1 ? 's' : ''}
                    {job.log && ' · click to view log'}
                  </p>
                </div>
                <time className='shrink-0 text-xs text-muted-foreground tabular-nums'>{fmtTime(job.started_at)}</time>
              </div>
              {expanded === job.id && job.log && (
                <pre className='px-4 pb-3 text-xs text-muted-foreground font-mono whitespace-pre-wrap bg-muted/30 border-t max-h-64 overflow-y-auto'>
                  {job.log}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Trivy DB tab ──────────────────────────────────────────────────────────────

function TrivyTab() {
  const [jobs, setJobs] = useState<TrivyUpdateJob[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    fetch(`${baseUrl}registry/system/trivy/jobs?limit=100`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : [])
      .then(setJobs).catch(() => {}).finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div className='space-y-4'>
      <div className='flex justify-end'><Button size='sm' variant='outline' onClick={load}><RefreshCwIcon className='size-3.5' /></Button></div>
      {loading ? <LoadingRows /> : jobs.length === 0 ? <EmptyState label='No Trivy DB update runs yet.' /> : (
        <div className='rounded-md border divide-y text-sm'>
          {jobs.map((job) => (
            <div key={job.id} className='flex items-start gap-3 px-4 py-3 hover:bg-muted/30'>
              <StatusIcon status={job.status} />
              <div className='flex-1 min-w-0'>
                <div className='flex flex-wrap items-center gap-2'>
                  <span className={`font-medium capitalize ${statusColors[job.status]}`}>{job.status}</span>
                  <Badge variant='outline' className='text-xs capitalize'>{job.triggered_by}</Badge>
                  {duration(job.started_at, job.finished_at) && (
                    <span className='text-xs text-muted-foreground'>{duration(job.started_at, job.finished_at)}</span>
                  )}
                </div>
                {job.error && <p className='text-xs text-destructive mt-0.5'>{job.error}</p>}
              </div>
              <time className='shrink-0 text-xs text-muted-foreground tabular-nums'>{fmtTime(job.started_at)}</time>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AdminLogsPage() {
  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <ScrollTextIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>System</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Logs</span>
      </header>

      <main className='flex-1 px-6 py-6'>
        <Tabs defaultValue='audit'>
          <TabsList className='mb-6'>
            <TabsTrigger value='audit'        className='gap-1.5'><ScrollTextIcon className='size-3.5' />Audit</TabsTrigger>
            <TabsTrigger value='gc'           className='gap-1.5'><Trash2Icon className='size-3.5' />GC</TabsTrigger>
            <TabsTrigger value='sync'         className='gap-1.5'><DatabaseIcon className='size-3.5' />Catalog Sync</TabsTrigger>
            <TabsTrigger value='replications' className='gap-1.5'><RepeatIcon className='size-3.5' />Replications</TabsTrigger>
            <TabsTrigger value='trivy'        className='gap-1.5'><ShieldIcon className='size-3.5' />Trivy DB</TabsTrigger>
          </TabsList>

          <TabsContent value='audit'>        <AuditTab /> </TabsContent>
          <TabsContent value='gc'>          <GCTab />   </TabsContent>
          <TabsContent value='sync'>        <SyncTab /> </TabsContent>
          <TabsContent value='replications'><ReplicationsTab /> </TabsContent>
          <TabsContent value='trivy'>       <TrivyTab /></TabsContent>
        </Tabs>
      </main>
    </>
  )
}
