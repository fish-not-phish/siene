'use client'

import { useState, useEffect, useCallback, useMemo } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import {
  Sheet, SheetContent, SheetDescription, SheetFooter,
  SheetHeader, SheetTitle,
} from '@/components/ui/sheet'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { cn } from '@/lib/utils'
import {
  ArrowUpIcon, ArrowDownIcon, Globe2Icon, InfoIcon,
  FolderIcon, BoxIcon, TagIcon, ClockIcon,
} from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { baseUrl } from '@/constants/constants'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface RemoteRegistry {
  id: number
  name: string
  registry_type: string
  endpoint: string
}

export interface ReplicationRuleData {
  name: string
  description: string
  remote_id: number
  direction: 'push' | 'pull'
  // filters
  source_filter: string
  tag_filter: string
  label_filter: string
  resource_type: string
  // destination
  destination_namespace: string
  flatten_mode: string
  // trigger
  trigger: string
  schedule: string
  // behaviour
  bandwidth_limit_kb: number
  override_existing: boolean
  single_active: boolean
  delete_remote_on_local_delete: boolean
  enabled: boolean
}

export interface ReplicationRule extends ReplicationRuleData {
  id: number
  remote_name: string
  last_run_at: string | null
  last_run_status: string
  created_at: string
  updated_at: string
}

interface ReplicationRuleSheetProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  remotes: RemoteRegistry[]
  existing?: ReplicationRule
  onSave: (data: ReplicationRuleData) => Promise<void>
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function SectionHeader({ title, description }: { title: string; description?: string }) {
  return (
    <div className='mb-3'>
      <p className='text-sm font-semibold'>{title}</p>
      {description && <p className='text-xs text-muted-foreground mt-0.5'>{description}</p>}
    </div>
  )
}

function FieldTip({ tip }: { tip: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <InfoIcon className='size-3.5 text-muted-foreground cursor-help shrink-0' />
      </TooltipTrigger>
      <TooltipContent side='top' className='max-w-56 text-xs'>{tip}</TooltipContent>
    </Tooltip>
  )
}

function OptionRow({
  checked, onCheckedChange, label, description,
}: {
  checked: boolean
  onCheckedChange: (v: boolean) => void
  label: string
  description: string
}) {
  return (
    <div className='flex items-start justify-between gap-4 py-3'>
      <div className='flex-1 min-w-0'>
        <p className='text-sm font-medium leading-none'>{label}</p>
        <p className='text-xs text-muted-foreground mt-1'>{description}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onCheckedChange} className='shrink-0 mt-0.5' />
    </div>
  )
}

// ── Schedule picker ───────────────────────────────────────────────────────────

type SchedulePreset =
  | 'every_1h'
  | 'every_2h'
  | 'every_6h'
  | 'every_12h'
  | 'daily'
  | 'weekly'

const PRESET_LABELS: Record<SchedulePreset, string> = {
  every_1h:  'Every hour',
  every_2h:  'Every 2 hours',
  every_6h:  'Every 6 hours',
  every_12h: 'Every 12 hours',
  daily:     'Daily at…',
  weekly:    'Weekly on…',
}

const DAYS_OF_WEEK = [
  'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday',
]

/** Build a cron expression from the picker state */
function buildCron(
  preset: SchedulePreset,
  hour: string,
  minute: string,
  dayOfWeek: string,
): string {
  const h = hour.padStart(2, '0')
  const m = minute.padStart(2, '0')
  switch (preset) {
    case 'every_1h':  return '0 * * * *'
    case 'every_2h':  return '0 */2 * * *'
    case 'every_6h':  return '0 */6 * * *'
    case 'every_12h': return '0 */12 * * *'
    case 'daily':     return `${m} ${h} * * *`
    case 'weekly':    return `${m} ${h} * * ${dayOfWeek}`
  }
}

/** Parse a stored cron back into picker state. Returns null if unrecognised. */
function parseCron(cron: string): {
  preset: SchedulePreset
  hour: string
  minute: string
  dayOfWeek: string
} | null {
  if (!cron) return null
  const parts = cron.trim().split(/\s+/)
  if (parts.length !== 5) return null
  const [min, hr, , , dow] = parts

  if (cron === '0 * * * *')    return { preset: 'every_1h',  hour: '0', minute: '0', dayOfWeek: '0' }
  if (cron === '0 */2 * * *')  return { preset: 'every_2h',  hour: '0', minute: '0', dayOfWeek: '0' }
  if (cron === '0 */6 * * *')  return { preset: 'every_6h',  hour: '0', minute: '0', dayOfWeek: '0' }
  if (cron === '0 */12 * * *') return { preset: 'every_12h', hour: '0', minute: '0', dayOfWeek: '0' }

  // daily: "MM HH * * *"
  if (/^\d+$/.test(min) && /^\d+$/.test(hr) && parts[2] === '*' && parts[3] === '*' && dow === '*')
    return { preset: 'daily', hour: hr, minute: min, dayOfWeek: '0' }

  // weekly: "MM HH * * D"
  if (/^\d+$/.test(min) && /^\d+$/.test(hr) && parts[2] === '*' && parts[3] === '*' && /^[0-6]$/.test(dow))
    return { preset: 'weekly', hour: hr, minute: min, dayOfWeek: dow }

  return null
}

/** Human-readable description of when the next run will occur */
function describeNextRun(cron: string): string {
  const parsed = parseCron(cron)
  if (!parsed) return ''
  const { preset, hour, minute, dayOfWeek } = parsed

  const pad = (n: string) => n.padStart(2, '0')
  const timeStr = `${pad(hour)}:${pad(minute)} UTC`

  switch (preset) {
    case 'every_1h':  return 'Runs at the top of every hour'
    case 'every_2h':  return 'Runs every 2 hours'
    case 'every_6h':  return 'Runs every 6 hours'
    case 'every_12h': return 'Runs every 12 hours'
    case 'daily':     return `Runs every day at ${timeStr}`
    case 'weekly':    return `Runs every ${DAYS_OF_WEEK[parseInt(dayOfWeek)]} at ${timeStr}`
  }
}

function SchedulePicker({
  value,
  onChange,
}: {
  value: string
  onChange: (cron: string) => void
}) {
  const parsed = useMemo(() => parseCron(value), [value])

  const [preset, setPreset] = useState<SchedulePreset>(parsed?.preset ?? 'daily')
  const [hour, setHour] = useState(parsed?.hour ?? '2')
  const [minute, setMinute] = useState(parsed?.minute ?? '0')
  const [dayOfWeek, setDayOfWeek] = useState(parsed?.dayOfWeek ?? '1') // Monday

  // Sync outward whenever picker state changes
  useEffect(() => {
    onChange(buildCron(preset, hour, minute, dayOfWeek))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preset, hour, minute, dayOfWeek])

  // When opened with an existing cron, re-hydrate
  useEffect(() => {
    if (parsed) {
      setPreset(parsed.preset)
      setHour(parsed.hour)
      setMinute(parsed.minute)
      setDayOfWeek(parsed.dayOfWeek)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const showTimePicker = preset === 'daily' || preset === 'weekly'
  const showDayPicker  = preset === 'weekly'
  const nextRunDesc    = describeNextRun(buildCron(preset, hour, minute, dayOfWeek))

  return (
    <div className='mt-3 space-y-3'>
      {/* Preset selector */}
      <div className='space-y-1.5'>
        <Label>Frequency</Label>
        <Select value={preset} onValueChange={(v) => setPreset(v as SchedulePreset)}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {(Object.entries(PRESET_LABELS) as [SchedulePreset, string][]).map(([k, label]) => (
              <SelectItem key={k} value={k}>{label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Day picker (weekly only) */}
      {showDayPicker && (
        <div className='space-y-1.5'>
          <Label>Day of week</Label>
          <Select value={dayOfWeek} onValueChange={setDayOfWeek}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {DAYS_OF_WEEK.map((d, i) => (
                <SelectItem key={i} value={String(i)}>{d}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      {/* Time picker (daily + weekly) */}
      {showTimePicker && (
        <div className='space-y-1.5'>
          <div className='flex items-center gap-1.5'>
            <Label>Time (UTC)</Label>
            <FieldTip tip='All times are in UTC.' />
          </div>
          <div className='flex items-center gap-2'>
            <Select value={hour} onValueChange={setHour}>
              <SelectTrigger className='w-24'>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Array.from({ length: 24 }, (_, i) => (
                  <SelectItem key={i} value={String(i)}>
                    {String(i).padStart(2, '0')}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <span className='text-sm text-muted-foreground font-mono'>:</span>
            <Select value={minute} onValueChange={setMinute}>
              <SelectTrigger className='w-24'>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {['0', '15', '30', '45'].map((m) => (
                  <SelectItem key={m} value={m}>
                    {m.padStart(2, '0')}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      )}

      {/* Next-run preview */}
      {nextRunDesc && (
        <div className='flex items-center gap-2 rounded-md border border-dashed px-3 py-2 text-xs text-muted-foreground'>
          <ClockIcon className='size-3.5 shrink-0' />
          <span>{nextRunDesc}</span>
        </div>
      )}
    </div>
  )
}

// A small inline "no remotes" prompt
function NoRemotesPrompt() {
  return (
    <div className='flex items-center gap-2 rounded-md border border-dashed px-3 py-2.5 text-sm text-muted-foreground'>
      <Globe2Icon className='size-4 shrink-0' />
      <span>
        Please{' '}
        <a href='/admin/registries' className='underline underline-offset-2'>
          add a remote registry
        </a>{' '}
        first.
      </span>
    </div>
  )
}

const DEFAULT: ReplicationRuleData = {
  name: '',
  description: '',
  remote_id: 0,
  direction: 'push',
  source_filter: '',
  tag_filter: '',
  label_filter: '',
  resource_type: 'all',
  destination_namespace: '',
  flatten_mode: 'flatten_1',
  trigger: 'manual',
  schedule: '',
  bandwidth_limit_kb: -1,
  override_existing: false,
  single_active: false,
  delete_remote_on_local_delete: false,
  enabled: true,
}

// Sentinel value used in the repo dropdown to mean "create a new repo"
const CREATE_NEW = '__create_new__'
// Sentinel value used in the repo dropdown to mean "all repos (glob)"
const ALL_REPOS = '__all__'

// ── Sheet ─────────────────────────────────────────────────────────────────────

export function ReplicationRuleSheet({
  open, onOpenChange, remotes, existing, onSave,
}: ReplicationRuleSheetProps) {
  const [form, setForm] = useState<ReplicationRuleData>(DEFAULT)
  const [saving, setSaving] = useState(false)

  // Local projects + repos + labels for pickers
  const [localProjects, setLocalProjects] = useState<string[]>([])
  const [localRepos, setLocalRepos] = useState<string[]>([])   // repo names in selected project
  const [loadingRepos, setLoadingRepos] = useState(false)
  const [localLabels, setLocalLabels] = useState<string[]>([]) // label names in dst project

  // Derived UI state for the repo pickers
  // Push source
  const [srcProject, setSrcProject] = useState('')      // project name
  const [srcRepoSel, setSrcRepoSel] = useState(ALL_REPOS) // dropdown value
  const [srcGlob, setSrcGlob] = useState('')            // custom glob text

  // Pull destination
  const [dstProject, setDstProject] = useState('')
  const [dstRepoSel, setDstRepoSel] = useState('')      // existing repo name or CREATE_NEW
  const [dstNewRepo, setDstNewRepo] = useState('')      // text input when CREATE_NEW

  // Fetch all local projects on open
  useEffect(() => {
    if (!open) return
    fetch(`${baseUrl}registry/projects`, { credentials: 'include' })
      .then((r) => r.json())
      .then((data) => setLocalProjects((data.items ?? data).map((p: { name: string }) => p.name)))
      .catch(() => setLocalProjects([]))
  }, [open])

  // Fetch repos whenever the relevant project changes
  const fetchRepos = useCallback((projectName: string) => {
    if (!projectName) { setLocalRepos([]); return }
    setLoadingRepos(true)
    fetch(`${baseUrl}registry/projects/${encodeURIComponent(projectName)}/repositories`, {
      credentials: 'include',
    })
      .then((r) => r.json())
      .then((data) => setLocalRepos((data.items ?? data).map((r: { name: string }) => r.name)))
      .catch(() => setLocalRepos([]))
      .finally(() => setLoadingRepos(false))
  }, [])

  useEffect(() => {
    if (form.direction === 'push') fetchRepos(srcProject)
  }, [srcProject, form.direction, fetchRepos])

  useEffect(() => {
    if (form.direction === 'pull') fetchRepos(dstProject)
  }, [dstProject, form.direction, fetchRepos])

  const fetchLabels = useCallback((projectName: string) => {
    if (!projectName) { setLocalLabels([]); return }
    fetch(`${baseUrl}registry/projects/${encodeURIComponent(projectName)}/labels`, {
      credentials: 'include',
    })
      .then((r) => r.json())
      .then((data) => setLocalLabels((data.items ?? data).map((l: { name: string }) => l.name)))
      .catch(() => setLocalLabels([]))
  }, [])

  useEffect(() => {
    if (form.direction === 'pull') fetchLabels(dstProject)
    else setLocalLabels([])
  }, [dstProject, form.direction, fetchLabels])

  // Populate form when editing
  useEffect(() => {
    if (existing) {
      setForm({
        name: existing.name,
        description: existing.description,
        remote_id: existing.remote_id,
        direction: existing.direction,
        source_filter: existing.source_filter,
        tag_filter: existing.tag_filter,
        label_filter: existing.label_filter,
        resource_type: existing.resource_type,
        destination_namespace: existing.destination_namespace,
        flatten_mode: existing.flatten_mode,
        trigger: existing.trigger,
        schedule: existing.schedule,
        bandwidth_limit_kb: existing.bandwidth_limit_kb,
        override_existing: existing.override_existing,
        single_active: existing.single_active,
        delete_remote_on_local_delete: existing.delete_remote_on_local_delete,
        enabled: existing.enabled,
      })

      // Re-hydrate picker state from the stored filter strings
      if (existing.direction === 'push') {
        const parts = existing.source_filter.split('/')
        const proj = parts[0] ?? ''
        setSrcProject(proj)
        const remainder = parts.slice(1).join('/')
        if (!remainder || remainder === '**') {
          setSrcRepoSel(ALL_REPOS)
          setSrcGlob('')
        } else if (!remainder.includes('*')) {
          setSrcRepoSel(remainder)
          setSrcGlob('')
        } else {
          setSrcRepoSel('__glob__')
          setSrcGlob(remainder)
        }
      } else {
        const ns = existing.destination_namespace
        const parts = ns.split('/')
        const proj = parts[0] ?? ''
        const repo = parts.slice(1).join('/') ?? ''
        setDstProject(proj)
        setDstRepoSel(repo || '')
        setDstNewRepo('')
      }
    } else {
      setForm(DEFAULT)
      setSrcProject('')
      setSrcRepoSel(ALL_REPOS)
      setSrcGlob('')
      setDstProject('')
      setDstRepoSel('')
      setDstNewRepo('')
    }
  }, [existing, open])

  const set = <K extends keyof ReplicationRuleData>(k: K, v: ReplicationRuleData[K]) =>
    setForm((f) => ({ ...f, [k]: v }))

  // Keep source_filter in sync with push picker state
  useEffect(() => {
    if (form.direction !== 'push') return
    if (!srcProject) { set('source_filter', ''); return }
    if (srcRepoSel === ALL_REPOS) {
      set('source_filter', `${srcProject}/**`)
    } else if (srcRepoSel === '__glob__') {
      set('source_filter', srcGlob ? `${srcProject}/${srcGlob}` : srcProject)
    } else {
      set('source_filter', srcRepoSel ? `${srcProject}/${srcRepoSel}` : srcProject)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [srcProject, srcRepoSel, srcGlob, form.direction])

  // Keep destination_namespace in sync with pull picker state
  useEffect(() => {
    if (form.direction !== 'pull') return
    if (!dstProject) { set('destination_namespace', ''); return }
    const repoName = dstRepoSel === CREATE_NEW ? dstNewRepo.trim() : dstRepoSel
    set('destination_namespace', repoName ? `${dstProject}/${repoName}` : dstProject)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dstProject, dstRepoSel, dstNewRepo, form.direction])

  const selectedRemote = remotes.find((r) => r.id === form.remote_id)
  const isEdit = !!existing

  const canSave =
    form.name.trim() !== '' &&
    form.remote_id !== 0 &&
    (form.trigger !== 'scheduled' || form.schedule.trim() !== '') &&
    (form.direction !== 'push' || !!srcProject) &&
    (form.direction !== 'pull' || (!!dstProject && (dstRepoSel !== CREATE_NEW || !!dstNewRepo.trim())))

  const handleSave = async () => {
    if (!canSave) return
    setSaving(true)
    try {
      await onSave(form)
      onOpenChange(false)
    } finally {
      setSaving(false)
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side='right'
        className='flex flex-col w-full sm:max-w-xl overflow-hidden p-0'
      >
        <SheetHeader className='px-6 py-4 border-b shrink-0'>
          <SheetTitle>{isEdit ? 'Edit replication rule' : 'New replication rule'}</SheetTitle>
          <SheetDescription>
            Define how images are synced between this registry and a remote endpoint.
          </SheetDescription>
        </SheetHeader>

        {/* Scrollable body */}
        <div className='flex-1 overflow-y-auto px-6 py-5 space-y-6'>

          {/* ── Basic info ───────────────────────────────────────── */}
          <div className='space-y-3'>
            <div className='space-y-1.5'>
              <Label htmlFor='rule-name'>Rule name</Label>
              <Input
                id='rule-name'
                value={form.name}
                onChange={(e) => set('name', e.target.value)}
                placeholder='sync-to-production'
                autoFocus
              />
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='rule-desc'>
                Description <span className='text-muted-foreground font-normal'>(optional)</span>
              </Label>
              <Input
                id='rule-desc'
                value={form.description}
                onChange={(e) => set('description', e.target.value)}
                placeholder='Nightly sync of release images to prod ECR'
              />
            </div>
          </div>

          <Separator />

          {/* ── Replication mode ─────────────────────────────────── */}
          <div>
            <SectionHeader
              title='Replication mode'
              description='Choose the direction images flow between this registry and the remote.'
            />
            <RadioGroup
              value={form.direction}
              onValueChange={(v) => {
                set('direction', v as 'push' | 'pull')
                // Reset filter/namespace when switching modes
                set('source_filter', '')
                set('destination_namespace', '')
                set('label_filter', '')
                setSrcProject(''); setSrcRepoSel(ALL_REPOS); setSrcGlob('')
                setDstProject(''); setDstRepoSel(''); setDstNewRepo('')
                // on_push is only valid for push rules — reset to manual if switching to pull
                if (v === 'pull' && form.trigger === 'on_push') set('trigger', 'manual')
              }}
              className='grid grid-cols-2 gap-3'
            >
              {([
                {
                  value: 'push', icon: ArrowUpIcon, label: 'Push',
                  desc: 'Send images from this registry to a remote.',
                },
                {
                  value: 'pull', icon: ArrowDownIcon, label: 'Pull',
                  desc: 'Fetch images from a remote into this registry.',
                },
              ] as const).map(({ value, icon: Icon, label, desc }) => (
                <label
                  key={value}
                  className={cn(
                    'flex cursor-pointer flex-col gap-2 rounded-lg border p-4 transition-colors',
                    form.direction === value
                      ? 'border-primary bg-primary/5'
                      : 'hover:bg-muted/50',
                  )}
                >
                  <div className='flex items-center gap-2'>
                    <RadioGroupItem value={value} id={`dir-${value}`} />
                    <Icon className='size-4 text-muted-foreground' />
                    <span className='text-sm font-medium'>{label}</span>
                  </div>
                  <p className='text-xs text-muted-foreground pl-6'>{desc}</p>
                </label>
              ))}
            </RadioGroup>
          </div>

          <Separator />

          {/* ── Source ───────────────────────────────────────────── */}
          {form.direction === 'push' ? (
            <PushSourceSection
              localProjects={localProjects}
              localRepos={localRepos}
              loadingRepos={loadingRepos}
              srcProject={srcProject}
              setSrcProject={setSrcProject}
              srcRepoSel={srcRepoSel}
              setSrcRepoSel={setSrcRepoSel}
              srcGlob={srcGlob}
              setSrcGlob={setSrcGlob}
              tagFilter={form.tag_filter}
              setTagFilter={(v) => set('tag_filter', v)}
            />
          ) : (
            <PullSourceSection
              remotes={remotes}
              remoteId={form.remote_id}
              setRemoteId={(v) => set('remote_id', v)}
              selectedRemote={selectedRemote}
              sourceFilter={form.source_filter}
              setSourceFilter={(v) => set('source_filter', v)}
              tagFilter={form.tag_filter}
              setTagFilter={(v) => set('tag_filter', v)}
            />
          )}

          <Separator />

          {/* ── Destination ──────────────────────────────────────── */}
          {form.direction === 'push' ? (
            <PushDestinationSection
              remotes={remotes}
              remoteId={form.remote_id}
              setRemoteId={(v) => set('remote_id', v)}
              selectedRemote={selectedRemote}
              destinationNamespace={form.destination_namespace}
              setDestinationNamespace={(v) => set('destination_namespace', v)}
              flattenMode={form.flatten_mode}
              setFlattenMode={(v) => set('flatten_mode', v)}
              exampleSrcRepo={
                srcProject
                  ? srcRepoSel === ALL_REPOS
                    ? `${srcProject}/my-image`
                    : srcRepoSel === '__glob__'
                      ? `${srcProject}/${srcGlob || 'my-image'}`
                      : `${srcProject}/${srcRepoSel}`
                  : ''
              }
            />
          ) : (
            <PullDestinationSection
              localProjects={localProjects}
              localRepos={localRepos}
              loadingRepos={loadingRepos}
              dstProject={dstProject}
              setDstProject={setDstProject}
              dstRepoSel={dstRepoSel}
              setDstRepoSel={setDstRepoSel}
              dstNewRepo={dstNewRepo}
              setDstNewRepo={setDstNewRepo}
            />
          )}

          <Separator />

          {/* ── Auto-label (pull only) ───────────────────────────── */}
          {form.direction === 'pull' && (
            <>
              <AutoLabelSection
                localLabels={localLabels}
                labelFilter={form.label_filter}
                setLabelFilter={(v) => set('label_filter', v)}
                dstProject={dstProject}
              />
              <Separator />
            </>
          )}

          {/* ── Trigger mode ─────────────────────────────────────── */}
          <div>
            <SectionHeader
              title='Trigger'
              description='When should this rule execute?'
            />
            <RadioGroup
              value={form.trigger}
              onValueChange={(v) => {
                set('trigger', v)
                if (v !== 'scheduled') set('schedule', '')
              }}
              className='space-y-2'
            >
              {([
                { value: 'manual',    label: 'Manual',    desc: 'Only run when triggered via the UI or API.' },
                { value: 'on_push',  label: 'On push',   desc: 'Run automatically when an image is pushed to this registry.' },
                { value: 'scheduled', label: 'Scheduled', desc: 'Run automatically on a repeating schedule.' },
              ] as const)
              .filter(({ value }) => form.direction !== 'pull' || value !== 'on_push')
              .map(({ value, label, desc }) => (
                <label
                  key={value}
                  className={cn(
                    'flex cursor-pointer items-start gap-3 rounded-lg border px-4 py-3 transition-colors',
                    form.trigger === value ? 'border-primary bg-primary/5' : 'hover:bg-muted/50',
                  )}
                >
                  <RadioGroupItem value={value} id={`trig-${value}`} className='mt-0.5' />
                  <div>
                    <p className='text-sm font-medium'>{label}</p>
                    <p className='text-xs text-muted-foreground mt-0.5'>{desc}</p>
                  </div>
                </label>
              ))}
            </RadioGroup>

            {form.trigger === 'scheduled' && (
              <SchedulePicker
                value={form.schedule}
                onChange={(v) => set('schedule', v)}
              />
            )}
          </div>

          <Separator />

          {/* ── Options ──────────────────────────────────────────── */}
          <div>
            <SectionHeader title='Options' />
            <div className='divide-y'>
              <OptionRow
                checked={form.override_existing}
                onCheckedChange={(v) => set('override_existing', v)}
                label='Override existing'
                description='Re-copy artifacts whose digest has changed at the source.'
              />
              <OptionRow
                checked={form.enabled}
                onCheckedChange={(v) => set('enabled', v)}
                label='Rule enabled'
                description='Disabled rules will not run automatically or manually.'
              />
            </div>
          </div>

        </div>

        {/* ── Footer ───────────────────────────────────────────── */}
        <SheetFooter className='px-6 py-4 border-t shrink-0 gap-2 sm:gap-2'>
          <Button variant='outline' onClick={() => onOpenChange(false)} className='flex-1'>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={!canSave || saving} className='flex-1'>
            {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Create rule'}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

// ── Auto-label section (pull only) ───────────────────────────────────────────

function AutoLabelSection({
  localLabels, labelFilter, setLabelFilter, dstProject,
}: {
  localLabels: string[]
  labelFilter: string
  setLabelFilter: (v: string) => void
  dstProject: string
}) {
  const selected = labelFilter ? labelFilter.split(',').map((s) => s.trim()).filter(Boolean) : []

  const toggle = (name: string) => {
    const next = selected.includes(name)
      ? selected.filter((s) => s !== name)
      : [...selected, name]
    setLabelFilter(next.join(','))
  }

  return (
    <div>
      <SectionHeader
        title='Auto-label pulled images'
        description='Labels selected here will be automatically applied to every image pulled by this rule.'
      />
      {!dstProject ? (
        <p className='text-xs text-muted-foreground'>Select a destination project first.</p>
      ) : localLabels.length === 0 ? (
        <p className='text-xs text-muted-foreground'>
          No labels in project <span className='font-mono'>{dstProject}</span>.{' '}
          <a href={`/projects/${dstProject}/labels`} className='underline underline-offset-2'>
            Create labels
          </a>{' '}
          to use this feature.
        </p>
      ) : (
        <div className='flex flex-wrap gap-2'>
          {localLabels.map((name) => {
            const active = selected.includes(name)
            return (
              <button
                key={name}
                type='button'
                onClick={() => toggle(name)}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors',
                  active
                    ? 'border-primary bg-primary text-primary-foreground'
                    : 'border-border bg-background hover:bg-muted',
                )}
              >
                <TagIcon className='size-3' />
                {name}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Push: Source section ──────────────────────────────────────────────────────

function PushSourceSection({
  localProjects, localRepos, loadingRepos,
  srcProject, setSrcProject,
  srcRepoSel, setSrcRepoSel,
  srcGlob, setSrcGlob,
  tagFilter, setTagFilter,
}: {
  localProjects: string[]
  localRepos: string[]
  loadingRepos: boolean
  srcProject: string
  setSrcProject: (v: string) => void
  srcRepoSel: string
  setSrcRepoSel: (v: string) => void
  srcGlob: string
  setSrcGlob: (v: string) => void
  tagFilter: string
  setTagFilter: (v: string) => void
}) {
  return (
    <div>
      <SectionHeader
        title='Source'
        description='Which images in this registry should be pushed to the remote?'
      />
      <div className='space-y-3'>
        {/* Project picker */}
        <div className='space-y-1.5'>
          <div className='flex items-center gap-1.5'>
            <FolderIcon className='size-3.5 text-muted-foreground' />
            <Label>Project</Label>
          </div>
          {localProjects.length === 0 ? (
            <p className='text-xs text-muted-foreground'>No projects found.</p>
          ) : (
            <Select value={srcProject} onValueChange={(v) => { setSrcProject(v); setSrcRepoSel(ALL_REPOS) }}>
              <SelectTrigger>
                <SelectValue placeholder='Select project…' />
              </SelectTrigger>
              <SelectContent>
                {localProjects.map((p) => (
                  <SelectItem key={p} value={p}>{p}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>

        {/* Repo picker — only shown after a project is selected */}
        {srcProject && (
          <div className='space-y-1.5'>
            <div className='flex items-center gap-1.5'>
              <BoxIcon className='size-3.5 text-muted-foreground' />
              <Label>Repository</Label>
            </div>
            <Select
              value={srcRepoSel}
              onValueChange={setSrcRepoSel}
              disabled={loadingRepos}
            >
              <SelectTrigger>
                <SelectValue placeholder={loadingRepos ? 'Loading…' : 'Select repository…'} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL_REPOS}>All repositories in project</SelectItem>
                {localRepos.map((r) => (
                  <SelectItem key={r} value={r}>{r}</SelectItem>
                ))}
                <SelectItem value='__glob__'>Match by glob pattern…</SelectItem>
              </SelectContent>
            </Select>
            {srcRepoSel === '__glob__' && (
              <Input
                value={srcGlob}
                onChange={(e) => setSrcGlob(e.target.value)}
                placeholder={`e.g. ${srcProject}/my-app-*`}
                className='font-mono text-sm'
                autoFocus
              />
            )}
            {srcRepoSel && srcRepoSel !== ALL_REPOS && srcRepoSel !== '__glob__' && (
              <p className='text-xs text-muted-foreground font-mono'>
                Will push: <span className='text-foreground'>{srcProject}/{srcRepoSel}</span>
              </p>
            )}
            {srcRepoSel === ALL_REPOS && (
              <p className='text-xs text-muted-foreground font-mono'>
                Will push: <span className='text-foreground'>{srcProject}/**</span>
              </p>
            )}
          </div>
        )}

        {/* Tag filter */}
        <div className='space-y-1.5'>
          <div className='flex items-center gap-1.5'>
            <Label htmlFor='push-tag-filter'>Tag filter</Label>
            <FieldTip tip='Glob pattern matched against image tags. Leave blank to replicate all tags.' />
          </div>
          <Input
            id='push-tag-filter'
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)}
            placeholder='All tags (leave blank) or v*, latest, release-*'
            className='font-mono text-sm'
          />
        </div>
      </div>
    </div>
  )
}

// ── Push: Destination section ─────────────────────────────────────────────────

// Mirrors the backend flatten_mode logic in tasks.py
function applyFlatten(srcRepo: string, flattenMode: string): string {
  const parts = srcRepo.split('/')
  if (flattenMode === 'flatten_all') return parts[parts.length - 1]
  if (flattenMode === 'flatten_1') return parts.length > 1 ? parts.slice(1).join('/') : parts[0]
  return srcRepo // 'none'
}

function PushDestinationSection({
  remotes, remoteId, setRemoteId, selectedRemote,
  destinationNamespace, setDestinationNamespace,
  flattenMode, setFlattenMode,
  exampleSrcRepo,
}: {
  remotes: RemoteRegistry[]
  remoteId: number
  setRemoteId: (v: number) => void
  selectedRemote: RemoteRegistry | undefined
  destinationNamespace: string
  setDestinationNamespace: (v: string) => void
  flattenMode: string
  setFlattenMode: (v: string) => void
  exampleSrcRepo: string
}) {
  // Compute the live destination path preview using the same logic as the backend
  const previewDst = exampleSrcRepo
    ? (() => {
        const flattened = applyFlatten(exampleSrcRepo, flattenMode)
        return destinationNamespace.trim()
          ? `${destinationNamespace.trim()}/${flattened}`
          : flattened
      })()
    : null

  return (
    <div>
      <SectionHeader
        title='Destination'
        description='The remote registry and path to push images into.'
      />
      <div className='space-y-3'>
        <div className='space-y-1.5'>
          <Label>Remote registry</Label>
          {remotes.length === 0 ? <NoRemotesPrompt /> : (
            <Select
              value={remoteId ? String(remoteId) : ''}
              onValueChange={(v) => setRemoteId(parseInt(v))}
            >
              <SelectTrigger>
                <SelectValue placeholder='Select a registry…' />
              </SelectTrigger>
              <SelectContent>
                {remotes.map((r) => (
                  <SelectItem key={r.id} value={String(r.id)}>
                    <span className='font-medium'>{r.name}</span>
                    <span className='ml-2 text-xs text-muted-foreground'>{r.endpoint}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          {selectedRemote && (
            <p className='text-xs text-muted-foreground font-mono'>{selectedRemote.endpoint}</p>
          )}
        </div>

        <div className='space-y-1.5'>
          <div className='flex items-center gap-1.5'>
            <Label htmlFor='push-dest-ns'>Destination namespace override</Label>
            <FieldTip tip='Prefix all pushed repositories with this namespace on the remote. Leave blank to use the source path.' />
          </div>
          <Input
            id='push-dest-ns'
            value={destinationNamespace}
            onChange={(e) => setDestinationNamespace(e.target.value)}
            placeholder='Leave blank to mirror source path'
            className='font-mono text-sm'
          />
        </div>

        <div className='space-y-1.5'>
          <div className='flex items-center gap-1.5'>
            <Label>Path flattening</Label>
            <FieldTip tip='Controls how the source repository path is shortened before being placed at the destination.' />
          </div>
          <Select value={flattenMode} onValueChange={setFlattenMode}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value='none'>No flattening — keep full source path</SelectItem>
              <SelectItem value='flatten_1'>Flatten 1 level — strip project prefix</SelectItem>
              <SelectItem value='flatten_all'>Flatten all — repository name only</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Live path preview */}
        {previewDst && (
          <div className='rounded-md border border-dashed px-3 py-2.5 space-y-1'>
            <p className='text-xs text-muted-foreground font-medium'>Path preview</p>
            <div className='flex items-center gap-2 text-xs font-mono flex-wrap'>
              <span className='text-muted-foreground'>{exampleSrcRepo}:tag</span>
              <span className='text-muted-foreground'>→</span>
              <span className='text-foreground font-semibold'>{previewDst}:tag</span>
              {selectedRemote && (
                <span className='text-muted-foreground'>{`on ${selectedRemote.endpoint}`}</span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Pull: Source section ──────────────────────────────────────────────────────

function PullSourceSection({
  remotes, remoteId, setRemoteId, selectedRemote,
  sourceFilter, setSourceFilter,
  tagFilter, setTagFilter,
}: {
  remotes: RemoteRegistry[]
  remoteId: number
  setRemoteId: (v: number) => void
  selectedRemote: RemoteRegistry | undefined
  sourceFilter: string
  setSourceFilter: (v: string) => void
  tagFilter: string
  setTagFilter: (v: string) => void
}) {
  const noCatalog = selectedRemote && [
    'ecr', 'docker-hub', 'gcr', 'acr-azure', 'acr-alibaba', 'tcr', 'swr',
  ].includes(selectedRemote.registry_type)

  return (
    <div>
      <SectionHeader
        title='Source'
        description='The remote registry and repository to pull images from.'
      />
      <div className='space-y-3'>
        <div className='space-y-1.5'>
          <Label>Remote registry</Label>
          {remotes.length === 0 ? <NoRemotesPrompt /> : (
            <Select
              value={remoteId ? String(remoteId) : ''}
              onValueChange={(v) => setRemoteId(parseInt(v))}
            >
              <SelectTrigger>
                <SelectValue placeholder='Select a registry…' />
              </SelectTrigger>
              <SelectContent>
                {remotes.map((r) => (
                  <SelectItem key={r.id} value={String(r.id)}>
                    <span className='font-medium'>{r.name}</span>
                    <span className='ml-2 text-xs text-muted-foreground'>{r.endpoint}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          {selectedRemote && (
            <p className='text-xs text-muted-foreground font-mono'>{selectedRemote.endpoint}</p>
          )}
        </div>

        <div className='space-y-1.5'>
          <div className='flex items-center gap-1.5'>
            <Label htmlFor='pull-src-repo'>Repository name</Label>
            <FieldTip tip='The repository path on the remote registry to pull from, e.g. myorg/my-app' />
          </div>
          <Input
            id='pull-src-repo'
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            placeholder='myorg/my-app'
            className='font-mono text-sm'
          />
          {noCatalog && sourceFilter.includes('*') && (
            <p className='text-xs text-amber-600 dark:text-amber-400'>
              This registry does not support catalog browsing — wildcards will not work.
              Use an exact repository name.
            </p>
          )}
          {noCatalog && !sourceFilter.includes('*') && (
            <p className='text-xs text-muted-foreground'>
              This registry does not support catalog browsing. Enter the exact repository name.
            </p>
          )}
        </div>

        <div className='space-y-1.5'>
          <div className='flex items-center gap-1.5'>
            <Label htmlFor='pull-tag-filter'>Tag filter</Label>
            <FieldTip tip='Glob pattern matched against image tags. Leave blank to pull all tags.' />
          </div>
          <Input
            id='pull-tag-filter'
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)}
            placeholder='All tags (leave blank) or v*, latest'
            className='font-mono text-sm'
          />
        </div>
      </div>
    </div>
  )
}

// ── Pull: Destination section ─────────────────────────────────────────────────

function PullDestinationSection({
  localProjects, localRepos, loadingRepos,
  dstProject, setDstProject,
  dstRepoSel, setDstRepoSel,
  dstNewRepo, setDstNewRepo,
}: {
  localProjects: string[]
  localRepos: string[]
  loadingRepos: boolean
  dstProject: string
  setDstProject: (v: string) => void
  dstRepoSel: string
  setDstRepoSel: (v: string) => void
  dstNewRepo: string
  setDstNewRepo: (v: string) => void
}) {
  const effectiveRepo = dstRepoSel === CREATE_NEW ? dstNewRepo.trim() : dstRepoSel

  return (
    <div>
      <SectionHeader
        title='Destination'
        description='Where in this registry should the pulled images be stored?'
      />
      <div className='space-y-3'>
        {/* Project picker */}
        <div className='space-y-1.5'>
          <div className='flex items-center gap-1.5'>
            <FolderIcon className='size-3.5 text-muted-foreground' />
            <Label>Project</Label>
          </div>
          {localProjects.length === 0 ? (
            <p className='text-xs text-muted-foreground'>No projects found.</p>
          ) : (
            <Select value={dstProject} onValueChange={(v) => { setDstProject(v); setDstRepoSel(''); setDstNewRepo('') }}>
              <SelectTrigger>
                <SelectValue placeholder='Select project…' />
              </SelectTrigger>
              <SelectContent>
                {localProjects.map((p) => (
                  <SelectItem key={p} value={p}>{p}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>

        {/* Repo picker */}
        {dstProject && (
          <div className='space-y-1.5'>
            <div className='flex items-center gap-1.5'>
              <BoxIcon className='size-3.5 text-muted-foreground' />
              <Label>Repository</Label>
            </div>
            <Select
              value={dstRepoSel}
              onValueChange={setDstRepoSel}
              disabled={loadingRepos}
            >
              <SelectTrigger>
                <SelectValue placeholder={loadingRepos ? 'Loading…' : 'Select or create repository…'} />
              </SelectTrigger>
              <SelectContent>
                {localRepos.map((r) => (
                  <SelectItem key={r} value={r}>{r}</SelectItem>
                ))}
                <SelectItem value={CREATE_NEW}>+ Create new repository…</SelectItem>
              </SelectContent>
            </Select>

            {dstRepoSel === CREATE_NEW && (
              <Input
                value={dstNewRepo}
                onChange={(e) => setDstNewRepo(e.target.value)}
                placeholder='my-new-repo'
                className='font-mono text-sm'
                autoFocus
              />
            )}

            {dstProject && effectiveRepo && (
              <p className='text-xs text-muted-foreground font-mono'>
                Images will be stored in:{' '}
                <span className='text-foreground'>{dstProject}/{effectiveRepo}</span>
                {dstRepoSel === CREATE_NEW && (
                  <span className='ml-1 text-blue-500'>(will be created on first pull)</span>
                )}
              </p>
            )}
          </div>
        )}

      </div>
    </div>
  )
}
