'use client'

import { useEffect, useRef, useState, useCallback } from 'react'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { useAuthContext } from '@/store/AuthContext'
import { baseUrl } from '@/constants/constants'
import { WrenchIcon, Trash2Icon, RefreshCwIcon, CheckIcon, ClockIcon, PlayIcon, HeartPulseIcon, ShieldIcon, XCircleIcon, CheckCircleIcon, AlertCircleIcon, HistoryIcon, FlaskConicalIcon, InfoIcon } from 'lucide-react'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Badge } from '@/components/ui/badge'

interface GCConfig {
  gc_enabled: boolean
  gc_schedule_type: 'hourly' | 'every_n_hours' | 'daily' | 'weekly' | 'monthly'
  gc_interval_hours: number
  gc_schedule_time: string       // HH:MM
  gc_schedule_day_of_week: number  // 0=Mon … 6=Sun
  gc_schedule_day_of_month: number // 1–28
  gc_last_run_at: string | null
}

interface TrivyConfig {
  trivy_db_update_enabled: boolean
  trivy_db_update_interval_hours: number
  trivy_db_last_updated_at: string | null
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

interface GcDryRunTag {
  project: string
  repo: string
  tag: string
  reason: string
  rule_pattern: string | null
}

interface GcDryRunResult {
  orphan_tags: GcDryRunTag[]
  retention_tags: GcDryRunTag[]
  scans_to_prune: number
  audit_logs_to_prune: number
  job_logs_to_prune: number
  total_tags_to_delete: number
  errors: string[]
}

type GCScheduleType = 'hourly' | 'every_n_hours' | 'daily' | 'weekly' | 'monthly'

const SCHEDULE_TYPE_OPTIONS: { value: GCScheduleType; label: string }[] = [
  { value: 'hourly',       label: 'Every hour' },
  { value: 'every_n_hours', label: 'Every N hours' },
  { value: 'daily',        label: 'Daily' },
  { value: 'weekly',       label: 'Weekly' },
  { value: 'monthly',      label: 'Monthly' },
]

const N_HOURS_OPTIONS = [2,3,4,6,8,12,18].map((n) => ({
  value: String(n),
  label: `Every ${n} hours`,
}))

const DAY_OF_WEEK_OPTIONS = [
  { value: '0', label: 'Monday' },
  { value: '1', label: 'Tuesday' },
  { value: '2', label: 'Wednesday' },
  { value: '3', label: 'Thursday' },
  { value: '4', label: 'Friday' },
  { value: '5', label: 'Saturday' },
  { value: '6', label: 'Sunday' },
]

const DAY_OF_MONTH_OPTIONS = Array.from({ length: 28 }, (_, i) => ({
  value: String(i + 1),
  label: String(i + 1),
}))



function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export default function AdminJobsPage() {
  const { user } = useAuthContext()
  const [gcConfig, setGcConfig] = useState<GCConfig | null>(null)
  const [gcLoading, setGcLoading] = useState(true)
  const [gcSaving, setGcSaving] = useState(false)

  // Local editable state — kept in sync with server, only saved on explicit action
  const [gcEnabled, setGcEnabled] = useState(false)
  const [gcScheduleType, setGcScheduleType] = useState<GCScheduleType>('daily')
  const [gcIntervalHours, setGcIntervalHours] = useState('6')
  const [gcScheduleTime, setGcScheduleTime] = useState('02:00')
  const [gcDayOfWeek, setGcDayOfWeek] = useState('0')
  const [gcDayOfMonth, setGcDayOfMonth] = useState('1')

  const [gcJobs, setGcJobs] = useState<GCJob[]>([])
  const [gcJobsLoading, setGcJobsLoading] = useState(true)
  const gcPollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const [syncJob, setSyncJob] = useState<SyncJob | null>(null)
  const [syncJobLoading, setSyncJobLoading] = useState(true)
  const syncPollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const [resetRunning, setResetRunning] = useState(false)
  const [resetDone, setResetDone] = useState(false)
  const [resetMessage, setResetMessage] = useState<string | null>(null)

  const [dryRunOpen, setDryRunOpen] = useState(false)
  const [dryRunLoading, setDryRunLoading] = useState(false)
  const [dryRunResult, setDryRunResult] = useState<GcDryRunResult | null>(null)
  const [dryRunError, setDryRunError] = useState<string | null>(null)

  const [trivyConfig, setTrivyConfig] = useState<TrivyConfig | null>(null)
  const [trivyLoading, setTrivyLoading] = useState(true)
  const [trivySaving, setTrivySaving] = useState(false)
  const [trivyEnabled, setTrivyEnabled] = useState(false)
  const [trivyInterval, setTrivyInterval] = useState('12')
  const [trivyRunning, setTrivyRunning] = useState(false)
  const [trivyDone, setTrivyDone] = useState(false)

  const isTrivyDirty = trivyConfig !== null && (
    trivyEnabled !== trivyConfig.trivy_db_update_enabled ||
    trivyInterval !== String(trivyConfig.trivy_db_update_interval_hours)
  )

  // Track whether local form state differs from saved config
  const isDirty = gcConfig !== null && (
    gcEnabled !== gcConfig.gc_enabled ||
    gcScheduleType !== gcConfig.gc_schedule_type ||
    gcIntervalHours !== String(gcConfig.gc_interval_hours) ||
    gcScheduleTime !== gcConfig.gc_schedule_time ||
    gcDayOfWeek !== String(gcConfig.gc_schedule_day_of_week) ||
    gcDayOfMonth !== String(gcConfig.gc_schedule_day_of_month)
  )

  const loadGcConfig = () => {
    setGcLoading(true)
    fetch(`${baseUrl}registry/system/gc/config`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : null)
      .then((data: GCConfig | null) => {
        if (data) {
          setGcConfig(data)
          setGcEnabled(data.gc_enabled)
          setGcScheduleType(data.gc_schedule_type)
          setGcIntervalHours(String(data.gc_interval_hours))
          setGcScheduleTime(data.gc_schedule_time)
          setGcDayOfWeek(String(data.gc_schedule_day_of_week))
          setGcDayOfMonth(String(data.gc_schedule_day_of_month))
        }
      })
      .catch(() => {})
      .finally(() => setGcLoading(false))
  }

  const loadGcJobs = useCallback(() => {
    fetch(`${baseUrl}registry/system/gc/jobs?limit=10`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : [])
      .then((data: GCJob[]) => setGcJobs(data))
      .catch(() => {})
      .finally(() => setGcJobsLoading(false))
  }, [])

  const stopGcPoll = () => {
    if (gcPollRef.current !== null) {
      clearInterval(gcPollRef.current)
      gcPollRef.current = null
    }
  }

  const startGcPoll = (jobId: number) => {
    stopGcPoll()
    gcPollRef.current = setInterval(async () => {
      const r = await fetch(`${baseUrl}registry/system/gc/jobs?limit=10`, { credentials: 'include' })
      if (!r.ok) return
      const data: GCJob[] = await r.json()
      setGcJobs(data)
      const job = data.find((j) => j.id === jobId)
      if (!job || job.status === 'success' || job.status === 'error') {
        stopGcPoll()
        loadGcConfig()
      }
    }, 2000)
  }

  const loadLatestSyncJob = () => {
    fetch(`${baseUrl}registry/system/registry/sync/latest`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : null)
      .then((data: SyncJob | null) => { if (data) setSyncJob(data) })
      .catch(() => {})
      .finally(() => setSyncJobLoading(false))
  }

  const stopSyncPoll = () => {
    if (syncPollRef.current !== null) {
      clearInterval(syncPollRef.current)
      syncPollRef.current = null
    }
  }

  const startSyncPoll = (jobId: number) => {
    stopSyncPoll()
    syncPollRef.current = setInterval(async () => {
      const r = await fetch(`${baseUrl}registry/system/registry/sync/latest`, { credentials: 'include' })
      if (!r.ok) return
      const data: SyncJob = await r.json()
      if (data.id === jobId) {
        setSyncJob(data)
        if (data.status === 'success' || data.status === 'error') {
          stopSyncPoll()
        }
      }
    }, 2000)
  }

  // Clean up polls on unmount
  useEffect(() => () => { stopSyncPoll(); stopGcPoll() }, [])

  useEffect(() => { loadGcConfig(); loadTrivyConfig(); loadLatestSyncJob(); loadGcJobs() }, [loadGcJobs])

  const saveGcConfig = async () => {
    setGcSaving(true)
    const res = await fetch(`${baseUrl}registry/system/gc/config`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': user.csrfToken ?? '' },
      body: JSON.stringify({
        gc_enabled: gcEnabled,
        gc_schedule_type: gcScheduleType,
        gc_interval_hours: parseInt(gcIntervalHours, 10),
        gc_schedule_time: gcScheduleTime,
        gc_schedule_day_of_week: parseInt(gcDayOfWeek, 10),
        gc_schedule_day_of_month: parseInt(gcDayOfMonth, 10),
      }),
    })
    if (res.ok) {
      const data: GCConfig = await res.json()
      setGcConfig(data)
      setGcEnabled(data.gc_enabled)
      setGcScheduleType(data.gc_schedule_type)
      setGcIntervalHours(String(data.gc_interval_hours))
      setGcScheduleTime(data.gc_schedule_time)
      setGcDayOfWeek(String(data.gc_schedule_day_of_week))
      setGcDayOfMonth(String(data.gc_schedule_day_of_month))
    }
    setGcSaving(false)
  }

  const runGc = async () => {
    const res = await fetch(`${baseUrl}registry/system/gc`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRFToken': user.csrfToken ?? '' },
    })
    if (res.ok) {
      const job: GCJob = await res.json()
      setGcJobs((prev) => [job, ...prev.slice(0, 9)])
      startGcPoll(job.id)
    }
  }

  const runDryRun = async () => {
    setDryRunLoading(true)
    setDryRunError(null)
    setDryRunResult(null)
    setDryRunOpen(true)
    try {
      const res = await fetch(`${baseUrl}registry/system/gc/dry-run`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'X-CSRFToken': user.csrfToken ?? '' },
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        setDryRunError(body?.detail || body?.message || `Server error (HTTP ${res.status})`)
      } else {
        setDryRunResult(await res.json())
      }
    } catch {
      setDryRunError('Request failed')
    } finally {
      setDryRunLoading(false)
    }
  }

  const latestGcJob = gcJobs[0] ?? null
  const gcRunning = latestGcJob?.status === 'pending' || latestGcJob?.status === 'running'

  const runSync = async () => {
    const res = await fetch(`${baseUrl}registry/system/registry/sync`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRFToken': user.csrfToken ?? '' },
    })
    if (!res.ok) return
    const job: SyncJob = await res.json()
    setSyncJob(job)
    startSyncPoll(job.id)
  }

  const loadTrivyConfig = () => {
    setTrivyLoading(true)
    fetch(`${baseUrl}registry/system/trivy/config`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : null)
      .then((data: TrivyConfig | null) => {
        if (data) {
          setTrivyConfig(data)
          setTrivyEnabled(data.trivy_db_update_enabled)
          setTrivyInterval(String(data.trivy_db_update_interval_hours))
        }
      })
      .catch(() => {})
      .finally(() => setTrivyLoading(false))
  }

  const saveTrivyConfig = async () => {
    setTrivySaving(true)
    const res = await fetch(`${baseUrl}registry/system/trivy/config`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': user.csrfToken ?? '' },
      body: JSON.stringify({
        trivy_db_update_enabled: trivyEnabled,
        trivy_db_update_interval_hours: parseInt(trivyInterval, 10),
      }),
    })
    if (res.ok) {
      const data: TrivyConfig = await res.json()
      setTrivyConfig(data)
      setTrivyEnabled(data.trivy_db_update_enabled)
      setTrivyInterval(String(data.trivy_db_update_interval_hours))
    }
    setTrivySaving(false)
  }

  const runTrivyUpdate = async () => {
    setTrivyRunning(true)
    setTrivyDone(false)
    await fetch(`${baseUrl}registry/system/trivy/update`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRFToken': user.csrfToken ?? '' },
    })
    setTrivyRunning(false)
    setTrivyDone(true)
    setTimeout(() => setTrivyDone(false), 4000)
  }

  const runResetStale = async () => {
    setResetRunning(true)
    setResetDone(false)
    setResetMessage(null)
    const res = await fetch(`${baseUrl}registry/system/workers/reset-stale`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRFToken': user.csrfToken ?? '' },
    })
    setResetRunning(false)
    if (res.ok) {
      const data = await res.json()
      setResetMessage(data.message ?? null)
      setResetDone(true)
      setTimeout(() => { setResetDone(false); setResetMessage(null) }, 8000)
    }
  }

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <WrenchIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>System</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Jobs & GC</span>
      </header>

      <main className='flex-1 px-6 py-6 space-y-4 max-w-2xl mx-auto w-full'>

        {/* ── Garbage Collection ── */}
        <Card>
          <CardHeader>
            <div className='flex items-start gap-3'>
              <div className='rounded-md border p-2 text-muted-foreground mt-0.5'>
                <Trash2Icon className='size-4' />
              </div>
              <div className='flex-1'>
                <CardTitle className='text-base'>Garbage Collection</CardTitle>
                <CardDescription className='mt-1'>
                  Removes unreferenced blobs from registry storage. Can run automatically on a
                  schedule, manually, or both.
                </CardDescription>
              </div>
            </div>
          </CardHeader>

          <CardContent className='space-y-5'>
            {gcLoading ? (
              <div className='space-y-3'>
                <Skeleton className='h-8 w-full rounded-md' />
                <Skeleton className='h-8 w-2/3 rounded-md' />
              </div>
            ) : (
              <>
                {/* Enable auto-run toggle */}
                <div className='flex items-center justify-between rounded-lg border px-4 py-3'>
                  <div className='space-y-0.5'>
                    <Label htmlFor='gc-enabled' className='text-sm font-medium cursor-pointer'>
                      Automatic garbage collection
                    </Label>
                    <p className='text-xs text-muted-foreground'>
                      Run GC automatically on a recurring schedule.
                    </p>
                  </div>
                  <Switch
                    id='gc-enabled'
                    checked={gcEnabled}
                    onCheckedChange={setGcEnabled}
                  />
                </div>

                {/* Schedule type + detail — only visible when enabled */}
                <div className={`space-y-3 transition-opacity duration-150 ${gcEnabled ? 'opacity-100' : 'opacity-40 pointer-events-none'}`}>
                  <div className='space-y-1.5'>
                    <Label htmlFor='gc-schedule-type' className='text-sm font-medium flex items-center gap-1.5'>
                      <ClockIcon className='size-3.5 text-muted-foreground' />
                      Run frequency
                    </Label>
                    <Select
                      value={gcScheduleType}
                      onValueChange={(v) => setGcScheduleType(v as GCScheduleType)}
                      disabled={!gcEnabled}
                    >
                      <SelectTrigger id='gc-schedule-type' className='w-52'>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SCHEDULE_TYPE_OPTIONS.map((opt) => (
                          <SelectItem key={opt.value} value={opt.value}>
                            {opt.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  {/* N-hours interval */}
                  {gcScheduleType === 'every_n_hours' && (
                    <div className='space-y-1.5'>
                      <Label htmlFor='gc-interval-hours' className='text-sm font-medium'>Interval</Label>
                      <Select value={gcIntervalHours} onValueChange={setGcIntervalHours} disabled={!gcEnabled}>
                        <SelectTrigger id='gc-interval-hours' className='w-52'>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {N_HOURS_OPTIONS.map((opt) => (
                            <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  )}

                  {/* Time of day — daily / weekly / monthly */}
                  {(gcScheduleType === 'daily' || gcScheduleType === 'weekly' || gcScheduleType === 'monthly') && (
                    <div className='space-y-1.5'>
                      <Label htmlFor='gc-schedule-time' className='text-sm font-medium'>Time (server local time)</Label>
                      <Input
                        id='gc-schedule-time'
                        type='time'
                        value={gcScheduleTime}
                        onChange={(e) => setGcScheduleTime(e.target.value)}
                        disabled={!gcEnabled}
                        className='w-36'
                      />
                    </div>
                  )}

                  {/* Day of week — weekly */}
                  {gcScheduleType === 'weekly' && (
                    <div className='space-y-1.5'>
                      <Label htmlFor='gc-day-of-week' className='text-sm font-medium'>Day of week</Label>
                      <Select value={gcDayOfWeek} onValueChange={setGcDayOfWeek} disabled={!gcEnabled}>
                        <SelectTrigger id='gc-day-of-week' className='w-52'>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {DAY_OF_WEEK_OPTIONS.map((opt) => (
                            <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  )}

                  {/* Day of month — monthly */}
                  {gcScheduleType === 'monthly' && (
                    <div className='space-y-1.5'>
                      <Label htmlFor='gc-day-of-month' className='text-sm font-medium'>Day of month</Label>
                      <Select value={gcDayOfMonth} onValueChange={setGcDayOfMonth} disabled={!gcEnabled}>
                        <SelectTrigger id='gc-day-of-month' className='w-52'>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {DAY_OF_MONTH_OPTIONS.map((opt) => (
                            <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  )}
                </div>

                {/* Run history */}
                <div className='space-y-1.5'>
                  <p className='text-xs font-medium flex items-center gap-1.5 text-muted-foreground'>
                    <HistoryIcon className='size-3.5' /> Recent runs
                  </p>
                  {gcJobsLoading ? (
                    <Skeleton className='h-16 w-full rounded-md' />
                  ) : gcJobs.length === 0 ? (
                    <p className='text-xs text-muted-foreground'>Never run.</p>
                  ) : (
                    <div className='rounded-md border divide-y text-xs'>
                      {gcJobs.slice(0, 5).map((job) => (
                        <div key={job.id} className='flex items-center gap-3 px-3 py-2'>
                          {job.status === 'success' && <CheckCircleIcon className='size-3.5 shrink-0 text-green-600' />}
                          {job.status === 'error'   && <AlertCircleIcon className='size-3.5 shrink-0 text-destructive' />}
                          {(job.status === 'pending' || job.status === 'running') && (
                            <RefreshCwIcon className='size-3.5 shrink-0 animate-spin text-muted-foreground' />
                          )}
                          <span className='text-muted-foreground shrink-0 w-20'>
                            {job.finished_at ? timeAgo(job.finished_at) : job.status === 'running' ? 'Running…' : 'Queued…'}
                          </span>
                          <span className='text-muted-foreground capitalize shrink-0'>{job.triggered_by}</span>
                          {job.status === 'success' && (
                            <span className='text-muted-foreground ml-auto'>
                              {job.orphans_deleted > 0 && <>{job.orphans_deleted} orphan{job.orphans_deleted !== 1 ? 's' : ''} · </>}
                              {job.retention_deleted > 0 && <>{job.retention_deleted} retained · </>}
                              {job.audit_deleted > 0 && <>{job.audit_deleted} audit rows · </>}
                              {job.orphans_deleted === 0 && job.retention_deleted === 0 && job.audit_deleted === 0 && <>nothing deleted · </>}
                              blob GC {job.blob_gc_ok ? 'ok' : 'failed'}
                            </span>
                          )}
                          {job.status === 'error' && (
                            <span className='text-destructive ml-auto truncate max-w-48'>{job.error || 'Unknown error'}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
          </CardContent>

          <CardFooter className='flex items-center justify-between gap-3'>
            {/* Save schedule settings */}
            <Button
              size='sm'
              variant='outline'
              onClick={saveGcConfig}
              disabled={gcLoading || gcSaving || !isDirty}
            >
              {gcSaving ? (
                <><RefreshCwIcon className='size-3.5 animate-spin' /> Saving…</>
              ) : (
                'Save schedule'
              )}
            </Button>

            <div className='flex items-center gap-2'>
              {/* Dry run */}
              <Button
                size='sm'
                variant='outline'
                onClick={runDryRun}
                disabled={dryRunLoading || gcLoading}
              >
                {dryRunLoading ? (
                  <><RefreshCwIcon className='size-3.5 animate-spin' /> Simulating…</>
                ) : (
                  <><FlaskConicalIcon className='size-3.5' /> Dry run</>
                )}
              </Button>

              {/* Manual run */}
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button
                    size='sm'
                    variant='destructive'
                    disabled={gcRunning || gcLoading}
                  >
                    {gcRunning ? (
                      <><RefreshCwIcon className='size-3.5 animate-spin' /> Running…</>
                    ) : (
                      <><PlayIcon className='size-3.5' /> Run now</>
                    )}
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Run garbage collection now?</AlertDialogTitle>
                    <AlertDialogDescription>
                      This will scan the registry for unreferenced blobs and delete them. The
                      registry may be briefly unavailable during the process.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                      className='bg-destructive text-destructive-foreground hover:bg-destructive/90'
                      onClick={runGc}
                    >
                      Run GC
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </div>
          </CardFooter>
        </Card>

        {/* ── Registry Catalog Sync ── */}
        <Card>
          <CardHeader>
            <div className='flex items-start gap-3'>
              <div className='rounded-md border p-2 text-muted-foreground mt-0.5'>
                <RefreshCwIcon className='size-4' />
              </div>
              <div className='flex-1'>
                <CardTitle className='text-base'>Registry Catalog Sync</CardTitle>
                <CardDescription className='mt-1'>
                  Re-synchronizes the database with the registry catalog. Use this if the UI is
                  out of sync with the actual registry contents.
                </CardDescription>
              </div>
            </div>
          </CardHeader>

          <CardContent>
            {syncJobLoading ? (
              <Skeleton className='h-4 w-48 rounded' />
            ) : syncJob ? (
              <div className='space-y-1'>
                {(syncJob.status === 'pending' || syncJob.status === 'running') && (
                  <p className='text-xs text-muted-foreground flex items-center gap-1.5'>
                    <RefreshCwIcon className='size-3 animate-spin' />
                    {syncJob.status === 'pending' ? 'Queued…' : 'Syncing…'}
                  </p>
                )}
                {syncJob.status === 'success' && (
                  <p className='text-xs text-muted-foreground'>
                    Last run:{' '}
                    <span className='font-medium text-foreground'>{timeAgo(syncJob.started_at)}</span>
                    {' '}&mdash;{' '}
                    <span className='text-green-600 font-medium'>Success</span>
                    {' '}&mdash;{' '}
                    {syncJob.repos_created} repo{syncJob.repos_created !== 1 ? 's' : ''},{' '}
                    {syncJob.tags_created} tag{syncJob.tags_created !== 1 ? 's' : ''} added
                  </p>
                )}
                {syncJob.status === 'error' && (
                  <div className='space-y-1'>
                    <p className='text-xs text-muted-foreground'>
                      Last run:{' '}
                      <span className='font-medium text-foreground'>{timeAgo(syncJob.started_at)}</span>
                      {' '}&mdash;{' '}
                      <span className='text-destructive font-medium flex-inline items-center gap-1'>
                        <XCircleIcon className='size-3 inline mr-0.5' />Failed
                      </span>
                    </p>
                    {syncJob.error && (
                      <p className='rounded border bg-muted/50 px-3 py-1.5 font-mono text-xs text-destructive'>
                        {syncJob.error}
                      </p>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <p className='text-xs text-muted-foreground'>Never run.</p>
            )}
          </CardContent>

          <CardFooter>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button size='sm' disabled={syncJob?.status === 'pending' || syncJob?.status === 'running'}>
                  {syncJob?.status === 'pending' || syncJob?.status === 'running' ? (
                    <><RefreshCwIcon className='size-3.5 animate-spin' /> Running…</>
                  ) : (
                    <><PlayIcon className='size-3.5' /> Sync now</>
                  )}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Sync registry catalog?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This will scan the registry and update the database to match. New repositories
                    and tags will be added. Stale entries are not removed — use Garbage Collection for that.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={runSync}>Sync Now</AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </CardFooter>
        </Card>

        {/* ── Trivy Vulnerability DB ── */}
        <Card>
          <CardHeader>
            <div className='flex items-start gap-3'>
              <div className='rounded-md border p-2 text-muted-foreground mt-0.5'>
                <ShieldIcon className='size-4' />
              </div>
              <div className='flex-1'>
                <CardTitle className='text-base'>Trivy Vulnerability Database</CardTitle>
                <CardDescription className='mt-1'>
                  Keeps the Trivy CVE database up to date. Without periodic updates, scans will
                  report against an increasingly stale vulnerability database.
                </CardDescription>
              </div>
            </div>
          </CardHeader>

          <CardContent className='space-y-5'>
            {trivyLoading ? (
              <div className='space-y-3'>
                <Skeleton className='h-8 w-full rounded-md' />
                <Skeleton className='h-8 w-2/3 rounded-md' />
              </div>
            ) : (
              <>
                {/* Enable auto-update toggle */}
                <div className='flex items-center justify-between rounded-lg border px-4 py-3'>
                  <div className='space-y-0.5'>
                    <Label htmlFor='trivy-enabled' className='text-sm font-medium cursor-pointer'>
                      Automatic DB updates
                    </Label>
                    <p className='text-xs text-muted-foreground'>
                      Automatically download a fresh CVE database on a recurring schedule.
                    </p>
                  </div>
                  <Switch
                    id='trivy-enabled'
                    checked={trivyEnabled}
                    onCheckedChange={setTrivyEnabled}
                  />
                </div>

                {/* Interval selector */}
                <div className={`space-y-1.5 transition-opacity duration-150 ${trivyEnabled ? 'opacity-100' : 'opacity-40 pointer-events-none'}`}>
                  <Label htmlFor='trivy-interval' className='text-sm font-medium flex items-center gap-1.5'>
                    <ClockIcon className='size-3.5 text-muted-foreground' />
                    Update frequency
                  </Label>
                  <Select value={trivyInterval} onValueChange={setTrivyInterval} disabled={!trivyEnabled}>
                    <SelectTrigger id='trivy-interval' className='w-52'>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value='6'>Every 6 hours</SelectItem>
                      <SelectItem value='12'>Every 12 hours</SelectItem>
                      <SelectItem value='24'>Every day</SelectItem>
                      <SelectItem value='48'>Every 2 days</SelectItem>
                      <SelectItem value='168'>Every week</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* Last updated info */}
                {trivyConfig?.trivy_db_last_updated_at ? (
                  <p className='text-xs text-muted-foreground'>
                    Last updated:{' '}
                    <span className='font-medium text-foreground'>
                      {timeAgo(trivyConfig.trivy_db_last_updated_at)}
                    </span>{' '}
                    &mdash;{' '}
                    {new Date(trivyConfig.trivy_db_last_updated_at).toLocaleString()}
                  </p>
                ) : (
                  <p className='text-xs text-muted-foreground'>Never updated via this interface.</p>
                )}
              </>
            )}
          </CardContent>

          <CardFooter className='flex items-center justify-between gap-3'>
            <Button
              size='sm'
              variant='outline'
              onClick={saveTrivyConfig}
              disabled={trivyLoading || trivySaving || !isTrivyDirty}
            >
              {trivySaving ? (
                <><RefreshCwIcon className='size-3.5 animate-spin' /> Saving…</>
              ) : (
                'Save schedule'
              )}
            </Button>

            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button size='sm' disabled={trivyRunning || trivyLoading}>
                  {trivyDone ? (
                    <><CheckIcon className='size-3.5' /> Queued</>
                  ) : trivyRunning ? (
                    <><RefreshCwIcon className='size-3.5 animate-spin' /> Updating…</>
                  ) : (
                    <><PlayIcon className='size-3.5' /> Update now</>
                  )}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Update Trivy vulnerability database?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This will download the latest CVE database from the Trivy DB source. The update
                    runs in the background and may take a minute or two to complete.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={runTrivyUpdate}>Update now</AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </CardFooter>
        </Card>

        {/* ── Worker Queue Health ── */}
        <Card>
          <CardHeader>
            <div className='flex items-start gap-3'>
              <div className='rounded-md border p-2 text-muted-foreground mt-0.5'>
                <HeartPulseIcon className='size-4' />
              </div>
              <div className='flex-1'>
                <CardTitle className='text-base'>Worker Queue Health</CardTitle>
                <CardDescription className='mt-1'>
                  Resets scan and SBOM jobs stuck in &ldquo;pending&rdquo; or &ldquo;running&rdquo; back to
                  &ldquo;error&rdquo; so they can be re-triggered. Also flushes any orphaned messages from the
                  legacy default Celery queue.
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          {resetMessage && (
            <CardContent>
              <p className='rounded-md border bg-muted/50 px-4 py-2.5 font-mono text-xs text-foreground'>
                {resetMessage}
              </p>
            </CardContent>
          )}
          <CardFooter>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button size='sm' variant='outline' disabled={resetRunning}>
                  {resetDone ? (
                    <><CheckIcon className='size-3.5' /> Done</>
                  ) : resetRunning ? (
                    <><RefreshCwIcon className='size-3.5 animate-spin' /> Resetting…</>
                  ) : (
                    <><HeartPulseIcon className='size-3.5' /> Reset stale jobs</>
                  )}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Reset stale worker jobs?</AlertDialogTitle>
                  <AlertDialogDescription>
                    Any vulnerability, secret, misconfig, or SBOM scan stuck in &ldquo;pending&rdquo; or
                    &ldquo;running&rdquo; will be marked as errored so it can be re-triggered manually.
                    Orphaned messages in the legacy Celery queue will also be flushed.
                    Jobs currently being processed by a worker will be interrupted.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={runResetStale}>Reset stale jobs</AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </CardFooter>
        </Card>

      </main>

      {/* ── GC Dry Run results ── */}
      <Sheet open={dryRunOpen} onOpenChange={setDryRunOpen}>
        <SheetContent className='w-full sm:max-w-xl overflow-y-auto'>
          <SheetHeader className='mb-4'>
            <SheetTitle className='flex items-center gap-2'>
              <FlaskConicalIcon className='size-4' />
              GC Dry Run
            </SheetTitle>
            <SheetDescription>
              What would be deleted if garbage collection ran right now.
              Blob GC (unreferenced layer storage) cannot be simulated — it requires the{' '}
              <code className='font-mono text-xs'>registry garbage-collect</code> binary.
            </SheetDescription>
          </SheetHeader>

          {dryRunLoading && (
            <div className='space-y-3'>
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className='flex items-center gap-3'>
                  <RefreshCwIcon className='size-4 animate-spin text-muted-foreground shrink-0' />
                  <div className='h-4 flex-1 rounded bg-muted animate-pulse' />
                </div>
              ))}
              <p className='text-xs text-muted-foreground'>Checking registry… this may take a few seconds.</p>
            </div>
          )}

          {dryRunError && (
            <div className='rounded-md border border-destructive/40 bg-destructive/10 px-4 py-3'>
              <p className='text-sm text-destructive'>{dryRunError}</p>
            </div>
          )}

          {dryRunResult && !dryRunLoading && (
            <div className='space-y-5'>
              {/* Summary strip */}
              <div className='grid grid-cols-2 gap-3 sm:grid-cols-4'>
                {[
                  { label: 'Tags to delete', value: dryRunResult.total_tags_to_delete, destructive: dryRunResult.total_tags_to_delete > 0 },
                  { label: 'Scans to prune', value: dryRunResult.scans_to_prune, destructive: false },
                  { label: 'Audit rows', value: dryRunResult.audit_logs_to_prune, destructive: false },
                  { label: 'Job log rows', value: dryRunResult.job_logs_to_prune, destructive: false },
                ].map(({ label, value, destructive }) => (
                  <div key={label} className='rounded-lg border px-3 py-2.5 text-center'>
                    <p className={`text-xl font-semibold tabular-nums ${destructive && value > 0 ? 'text-destructive' : ''}`}>{value}</p>
                    <p className='text-xs text-muted-foreground mt-0.5'>{label}</p>
                  </div>
                ))}
              </div>

              {/* Errors from orphan check */}
              {dryRunResult.errors.length > 0 && (
                <div className='space-y-1.5'>
                  <p className='text-xs font-medium flex items-center gap-1.5 text-muted-foreground'>
                    <AlertCircleIcon className='size-3.5 text-destructive' /> Registry check errors
                  </p>
                  <div className='rounded-md border bg-muted/50 px-3 py-2 space-y-1'>
                    {dryRunResult.errors.map((e, i) => (
                      <p key={i} className='font-mono text-xs text-destructive'>{e}</p>
                    ))}
                  </div>
                </div>
              )}

              {/* Orphaned tags */}
              <div className='space-y-1.5'>
                <p className='text-xs font-medium flex items-center gap-1.5 text-muted-foreground'>
                  <Trash2Icon className='size-3.5' />
                  Orphaned tags
                  <Badge variant='secondary' className='ml-auto font-mono'>{dryRunResult.orphan_tags.length}</Badge>
                </p>
                {dryRunResult.orphan_tags.length === 0 ? (
                  <p className='text-xs text-muted-foreground flex items-center gap-1.5'>
                    <CheckCircleIcon className='size-3.5 text-green-600' /> None — all tags have live manifests.
                  </p>
                ) : (
                  <div className='rounded-md border divide-y text-xs max-h-52 overflow-y-auto'>
                    {dryRunResult.orphan_tags.map((t, i) => (
                      <div key={i} className='flex items-center gap-2 px-3 py-1.5 font-mono'>
                        <span className='text-muted-foreground shrink-0'>{t.project}/</span>
                        <span className='shrink-0'>{t.repo}</span>
                        <span className='text-muted-foreground'>:</span>
                        <span className='font-medium'>{t.tag}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Retention tags */}
              <div className='space-y-1.5'>
                <p className='text-xs font-medium flex items-center gap-1.5 text-muted-foreground'>
                  <ClockIcon className='size-3.5' />
                  Retention policy tags
                  <Badge variant='secondary' className='ml-auto font-mono'>{dryRunResult.retention_tags.length}</Badge>
                </p>
                {dryRunResult.retention_tags.length === 0 ? (
                  <p className='text-xs text-muted-foreground flex items-center gap-1.5'>
                    <CheckCircleIcon className='size-3.5 text-green-600' /> None — all tags satisfy retention rules.
                  </p>
                ) : (
                  <div className='rounded-md border divide-y text-xs max-h-52 overflow-y-auto'>
                    {dryRunResult.retention_tags.map((t, i) => (
                      <div key={i} className='flex items-center gap-2 px-3 py-1.5'>
                        <span className='font-mono shrink-0 text-muted-foreground'>{t.project}/{t.repo}:{t.tag}</span>
                        {t.rule_pattern && (
                          <span className='ml-auto shrink-0 rounded bg-muted px-1.5 py-0.5 font-mono text-muted-foreground'>
                            rule: {t.rule_pattern}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Scan / log pruning summary */}
              <div className='rounded-lg border px-4 py-3 space-y-1.5 text-xs text-muted-foreground'>
                <p className='flex items-center gap-1.5'>
                  <InfoIcon className='size-3.5 shrink-0' />
                  <span className='font-medium text-foreground'>{dryRunResult.scans_to_prune}</span> stale scan history rows would be pruned
                  <span className='text-xs'>(keeps last 5 finished + 1 error per tag)</span>
                </p>
                <p className='flex items-center gap-1.5'>
                  <InfoIcon className='size-3.5 shrink-0' />
                  <span className='font-medium text-foreground'>{dryRunResult.audit_logs_to_prune}</span> audit log rows older than {dryRunResult.audit_logs_to_prune > 0 ? 'retention window' : 'retention window (none)'} would be deleted
                </p>
                <p className='flex items-center gap-1.5'>
                  <InfoIcon className='size-3.5 shrink-0' />
                  <span className='font-medium text-foreground'>{dryRunResult.job_logs_to_prune}</span> job log rows would be pruned
                </p>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </>
  )
}
