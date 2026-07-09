'use client'

import { useEffect, useState, useCallback } from 'react'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { useAuthContext } from '@/store/AuthContext'
import { baseUrl } from '@/constants/constants'
import {
  ArrowLeftRightIcon, PlusIcon, Trash2Icon, PlayIcon,
  RefreshCwIcon, CheckIcon, ArrowUpIcon, ArrowDownIcon,
  PencilIcon, ClockIcon, ZapIcon, CalendarIcon, FilterIcon,
  ScrollTextIcon,
} from 'lucide-react'
import {
  ReplicationRuleSheet,
  type ReplicationRule,
  type ReplicationRuleData,
  type RemoteRegistry,
} from '@/components/shadcn-studio/blocks/replications/replication-rule-sheet'
import {
  ReplicationJobDialog,
} from '@/components/shadcn-studio/blocks/replications/replication-job-dialog'

// ── Helpers ───────────────────────────────────────────────────────────────────

function timeAgo(iso: string) {
  const d = Date.now() - new Date(iso).getTime()
  const m = Math.floor(d / 60_000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

const triggerIcon = {
  manual:    <ClockIcon className='size-3' />,
  on_push:   <ZapIcon className='size-3' />,
  scheduled: <CalendarIcon className='size-3' />,
} as const

const triggerLabel = {
  manual:    'Manual',
  on_push:   'On push',
  scheduled: 'Scheduled',
} as const

const statusColor: Record<string, string> = {
  success:  'text-green-600 dark:text-green-400',
  failed:   'text-destructive',
  running:  'text-blue-600 dark:text-blue-400',
  '':       'text-muted-foreground',
}

// ── Rule card ─────────────────────────────────────────────────────────────────

function RuleCard({
  rule, executing, executedDone,
  onExecute, onToggleEnabled, onEdit, onDelete, onViewLogs,
}: {
  rule: ReplicationRule
  executing: number | null
  executedDone: Set<number>
  onExecute: (id: number) => void
  onToggleEnabled: (id: number, enabled: boolean) => void
  onEdit: (rule: ReplicationRule) => void
  onDelete: (rule: ReplicationRule) => void
  onViewLogs: (rule: ReplicationRule) => void
}) {
  const filters = [
    rule.source_filter && `name: ${rule.source_filter}`,
    rule.tag_filter    && `tag: ${rule.tag_filter}`,
    rule.label_filter  && `label: ${rule.label_filter}`,
    rule.resource_type !== 'all' && `type: ${rule.resource_type}`,
  ].filter(Boolean)

  const trig = rule.trigger as keyof typeof triggerLabel

  return (
    <div className={`rounded-lg border bg-card transition-opacity ${!rule.enabled ? 'opacity-60' : ''}`}>
      <div className='flex items-start gap-4 p-4'>
        {/* Direction icon */}
        <div className={`mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md border ${
          rule.direction === 'push' ? 'bg-blue-600/10 text-blue-600 dark:bg-blue-400/10 dark:text-blue-400'
                                    : 'bg-purple-600/10 text-purple-600 dark:bg-purple-400/10 dark:text-purple-400'
        }`}>
          {rule.direction === 'push'
            ? <ArrowUpIcon className='size-4' />
            : <ArrowDownIcon className='size-4' />}
        </div>

        {/* Main content */}
        <div className='flex-1 min-w-0 space-y-1.5'>
          <div className='flex flex-wrap items-center gap-2'>
            <span className='font-semibold text-sm'>{rule.name}</span>
            {!rule.enabled && (
              <Badge variant='secondary' className='text-xs'>Disabled</Badge>
            )}
          </div>
          {rule.description && (
            <p className='text-xs text-muted-foreground'>{rule.description}</p>
          )}

          <div className='flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground'>
            {/* Remote */}
            <span className='font-medium text-foreground'>{rule.remote_name}</span>

            {/* Trigger */}
            <span className='flex items-center gap-1'>
              {triggerIcon[trig] ?? <ClockIcon className='size-3' />}
              {triggerLabel[trig] ?? rule.trigger}
              {rule.trigger === 'scheduled' && rule.schedule && (
                <code className='ml-1 font-mono text-[10px] bg-muted px-1 py-0.5 rounded'>{rule.schedule}</code>
              )}
            </span>

            {/* Last run */}
            {rule.last_run_at && (
              <span className={`flex items-center gap-1 ${statusColor[rule.last_run_status] ?? statusColor['']}`}>
                {rule.last_run_status === 'success' && <CheckIcon className='size-3' />}
                Last run {timeAgo(rule.last_run_at)}
                {rule.last_run_status && ` · ${rule.last_run_status}`}
              </span>
            )}

            {/* Bandwidth */}
            {rule.bandwidth_limit_kb !== -1 && (
              <span>{rule.bandwidth_limit_kb} Kbps</span>
            )}
          </div>

          {/* Filters */}
          {filters.length > 0 && (
            <div className='flex flex-wrap items-center gap-1.5 pt-0.5'>
              <FilterIcon className='size-3 text-muted-foreground shrink-0' />
              {filters.map((f, i) => (
                <code key={i} className='text-[10px] font-mono bg-muted px-1.5 py-0.5 rounded'>{f}</code>
              ))}
            </div>
          )}
        </div>

        {/* Actions */}
        <div className='flex items-center gap-1 shrink-0'>
          {/* Enable toggle */}
          <Switch
            checked={rule.enabled}
            onCheckedChange={(v) => onToggleEnabled(rule.id, v)}
            className='scale-75'
          />

          {/* Run now */}
          <Button
            size='icon' variant='ghost' className='size-7 text-muted-foreground'
            title='Run now' disabled={executing === rule.id || !rule.enabled}
            onClick={() => onExecute(rule.id)}
          >
            {executedDone.has(rule.id) ? (
              <CheckIcon className='size-3.5 text-green-500' />
            ) : executing === rule.id ? (
              <RefreshCwIcon className='size-3.5 animate-spin' />
            ) : (
              <PlayIcon className='size-3.5' />
            )}
          </Button>

          {/* Logs */}
          <Button
            size='icon' variant='ghost' className='size-7 text-muted-foreground'
            title='View logs' onClick={() => onViewLogs(rule)}
          >
            <ScrollTextIcon className='size-3.5' />
          </Button>

          {/* Edit */}
          <Button
            size='icon' variant='ghost' className='size-7 text-muted-foreground'
            title='Edit' onClick={() => onEdit(rule)}
          >
            <PencilIcon className='size-3.5' />
          </Button>

          {/* Delete */}
          <Button
            size='icon' variant='ghost' className='size-7 text-muted-foreground hover:text-destructive'
            title='Delete' onClick={() => onDelete(rule)}
          >
            <Trash2Icon className='size-3.5' />
          </Button>
        </div>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ReplicationsPage() {
  const { user } = useAuthContext()
  const [rules,        setRules]        = useState<ReplicationRule[]>([])
  const [remotes,      setRemotes]      = useState<RemoteRegistry[]>([])
  const [loading,      setLoading]      = useState(true)
  const [executing,    setExecuting]    = useState<number | null>(null)
  const [executedDone, setExecutedDone] = useState<Set<number>>(new Set())
  const [sheetOpen,    setSheetOpen]    = useState(false)
  const [editTarget,   setEditTarget]   = useState<ReplicationRule | undefined>()
  const [deleteTarget, setDeleteTarget] = useState<ReplicationRule | null>(null)
  const [logsTarget,   setLogsTarget]   = useState<ReplicationRule | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([
      fetch(`${baseUrl}registry/system/replications`, { credentials: 'include' }).then((r) => r.json()),
      fetch(`${baseUrl}registry/system/remote-registries`, { credentials: 'include' }).then((r) => r.json()),
    ])
      .then(([r, reg]) => {
        setRules(Array.isArray(r) ? r : [])
        setRemotes(Array.isArray(reg) ? reg : [])
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const headers = { 'Content-Type': 'application/json', 'X-CSRFToken': user.csrfToken ?? '' }

  const create = async (data: ReplicationRuleData) => {
    await fetch(`${baseUrl}registry/system/replications`, {
      method: 'POST', credentials: 'include', headers, body: JSON.stringify(data),
    })
    load()
  }

  const update = async (id: number, data: ReplicationRuleData) => {
    await fetch(`${baseUrl}registry/system/replications/${id}`, {
      method: 'PATCH', credentials: 'include', headers, body: JSON.stringify(data),
    })
    load()
  }

  const toggleEnabled = async (id: number, enabled: boolean) => {
    await fetch(`${baseUrl}registry/system/replications/${id}`, {
      method: 'PATCH', credentials: 'include', headers,
      body: JSON.stringify({ enabled }),
    })
    load()
  }

  const remove = async (id: number) => {
    await fetch(`${baseUrl}registry/system/replications/${id}`, {
      method: 'DELETE', credentials: 'include', headers,
    })
    load()
  }

  const execute = async (id: number) => {
    setExecuting(id)
    await fetch(`${baseUrl}registry/system/replications/${id}/execute`, {
      method: 'POST', credentials: 'include', headers,
    })
    setExecuting(null)
    setExecutedDone((p) => new Set([...p, id]))
    setTimeout(() => setExecutedDone((p) => { const n = new Set(p); n.delete(id); return n }), 4000)
    load()
  }

  const openNew = () => { setEditTarget(undefined); setSheetOpen(true) }
  const openEdit = (rule: ReplicationRule) => { setEditTarget(rule); setSheetOpen(true) }

  const handleSave = async (data: ReplicationRuleData) => {
    if (editTarget) {
      await update(editTarget.id, data)
    } else {
      await create(data)
    }
  }

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <ArrowLeftRightIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>System</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Replications</span>
        <div className='ml-auto flex items-center gap-2'>
          <Button size='sm' variant='outline' onClick={load}>
            <RefreshCwIcon className='size-3.5' />
          </Button>
          <Button size='sm' onClick={openNew} disabled={remotes.length === 0}>
            <PlusIcon className='size-3.5' />New rule
          </Button>
        </div>
      </header>

      <main className='flex-1 px-6 py-6 space-y-4'>
        {/* No-registries warning */}
        {remotes.length === 0 && !loading && (
          <div className='rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm text-amber-700 dark:text-amber-400'>
            No remote registries configured.{' '}
            <a href='/admin/registries' className='underline underline-offset-2'>Add one</a>{' '}
            before creating replication rules.
          </div>
        )}

        {loading ? (
          <div className='space-y-3'>
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className='h-24 w-full rounded-lg' />
            ))}
          </div>
        ) : rules.length === 0 ? (
          <div className='flex flex-col items-center gap-3 py-24 text-center text-muted-foreground'>
            <ArrowLeftRightIcon className='size-10 opacity-30' />
            <p className='text-sm'>No replication rules yet.</p>
            <p className='text-xs'>Create one to sync images with a remote registry.</p>
            {remotes.length > 0 && (
              <Button size='sm' variant='outline' onClick={openNew}>
                <PlusIcon className='size-3.5' />New rule
              </Button>
            )}
          </div>
        ) : (
          <div className='space-y-3'>
            {rules.map((rule) => (
              <RuleCard
                key={rule.id}
                rule={rule}
                executing={executing}
                executedDone={executedDone}
                onExecute={execute}
                onToggleEnabled={toggleEnabled}
                onEdit={openEdit}
                onDelete={setDeleteTarget}
                onViewLogs={setLogsTarget}
              />
            ))}
          </div>
        )}
      </main>

      {/* Create / Edit sheet */}
      <ReplicationRuleSheet
        open={sheetOpen}
        onOpenChange={setSheetOpen}
        remotes={remotes}
        existing={editTarget}
        onSave={handleSave}
      />

      {/* Job logs dialog */}
      {logsTarget && (
        <ReplicationJobDialog
          open={!!logsTarget}
          onOpenChange={(v) => { if (!v) setLogsTarget(null) }}
          rule={logsTarget}
        />
      )}

      {/* Delete confirm */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete replication rule?</AlertDialogTitle>
            <AlertDialogDescription>
              <strong>{deleteTarget?.name}</strong> will be permanently removed. Any in-progress replication will be interrupted.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className='bg-destructive text-destructive-foreground hover:bg-destructive/90'
              onClick={async () => {
                if (deleteTarget) await remove(deleteTarget.id)
                setDeleteTarget(null)
              }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
