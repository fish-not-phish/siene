'use client'

import { useEffect, useRef, useState } from 'react'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { RefreshCwIcon, ClockIcon, CheckIcon, XIcon, AlertTriangleIcon } from 'lucide-react'
import { baseUrl } from '@/constants/constants'
import type { ReplicationRule } from './replication-rule-sheet'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ReplicationJob {
  id: number
  rule_id: number
  status: 'pending' | 'running' | 'success' | 'partial' | 'error'
  started_at: string
  finished_at: string | null
  copied: number
  errors: number
  log: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDuration(start: string, end: string | null) {
  const ms = (end ? new Date(end).getTime() : Date.now()) - new Date(start).getTime()
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

const statusIcon = {
  pending: <ClockIcon className='size-3' />,
  running: <RefreshCwIcon className='size-3 animate-spin' />,
  success: <CheckIcon className='size-3' />,
  partial: <AlertTriangleIcon className='size-3' />,
  error:   <XIcon className='size-3' />,
}

const statusVariant: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  pending: 'secondary',
  running: 'secondary',
  success: 'default',
  partial: 'outline',
  error:   'destructive',
}

const statusClass: Record<string, string> = {
  success: 'bg-green-600 hover:bg-green-600 text-white',
  partial: 'border-amber-500 text-amber-600 dark:text-amber-400',
  running: 'text-blue-600 dark:text-blue-400',
}

// ── Job row ───────────────────────────────────────────────────────────────────

function JobRow({
  job, selected, onClick,
}: {
  job: ReplicationJob
  selected: boolean
  onClick: () => void
}) {
  const isRunning = job.status === 'running'
  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-3 py-2.5 rounded-md transition-colors text-sm ${
        selected ? 'bg-muted' : 'hover:bg-muted/50'
      }`}
    >
      <div className='flex items-center justify-between gap-2'>
        <span className='text-xs text-muted-foreground'>{formatTime(job.started_at)}</span>
        <Badge
          variant={statusVariant[job.status] ?? 'secondary'}
          className={`text-[10px] px-1.5 py-0 h-4 gap-0.5 ${statusClass[job.status] ?? ''}`}
        >
          {statusIcon[job.status]}
          {job.status}
        </Badge>
      </div>
      <div className='flex items-center gap-3 mt-1 text-xs text-muted-foreground'>
        <span className='text-green-600 dark:text-green-400'>{job.copied} copied</span>
        {job.errors > 0 && <span className='text-destructive'>{job.errors} errors</span>}
        <span className='ml-auto'>{formatDuration(job.started_at, job.finished_at)}{isRunning ? '…' : ''}</span>
      </div>
    </button>
  )
}

// ── Log viewer ────────────────────────────────────────────────────────────────

function LogViewer({ job }: { job: ReplicationJob }) {
  const bottomRef = useRef<HTMLDivElement>(null)
  const isRunning = job.status === 'running'

  useEffect(() => {
    if (isRunning) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [job.log, isRunning])

  const lines = job.log.split('\n').filter(Boolean)

  return (
    <ScrollArea className='h-full rounded-md border bg-black/95 dark:bg-black font-mono text-xs'>
      <div className='p-3 space-y-0.5'>
        {lines.length === 0 ? (
          <span className='text-muted-foreground'>No output yet…</span>
        ) : (
          lines.map((line, i) => {
            const isError = line.includes('ERROR') || line.includes('error')
            const isOk = line.includes('OK') || line.includes('Done')
            const isWarn = line.includes('WARNING') || line.includes('WARN')
            return (
              <div
                key={i}
                className={
                  isError ? 'text-red-400' :
                  isOk    ? 'text-green-400' :
                  isWarn  ? 'text-amber-400' :
                            'text-zinc-300'
                }
              >
                {line}
              </div>
            )
          })
        )}
        {isRunning && (
          <div className='text-blue-400 animate-pulse'>▌</div>
        )}
        <div ref={bottomRef} />
      </div>
    </ScrollArea>
  )
}

// ── Dialog ────────────────────────────────────────────────────────────────────

interface ReplicationJobDialogProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  rule: ReplicationRule
}

export function ReplicationJobDialog({ open, onOpenChange, rule }: ReplicationJobDialogProps) {
  const [jobs, setJobs]           = useState<ReplicationJob[]>([])
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [loading, setLoading]     = useState(true)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const selectedJob = jobs.find((j) => j.id === selectedId) ?? jobs[0] ?? null

  const fetchJobs = async () => {
    try {
      const res = await fetch(`${baseUrl}registry/system/replications/${rule.id}/jobs`, {
        credentials: 'include',
      })
      if (!res.ok) return
      const data: ReplicationJob[] = await res.json()
      setJobs(data)
      // Auto-select latest if nothing selected yet
      setSelectedId((prev) => prev ?? (data[0]?.id ?? null))
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  const fetchSelected = async () => {
    if (!selectedId) return
    try {
      const res = await fetch(
        `${baseUrl}registry/system/replications/${rule.id}/jobs/${selectedId}`,
        { credentials: 'include' },
      )
      if (!res.ok) return
      const data: ReplicationJob = await res.json()
      setJobs((prev) => prev.map((j) => (j.id === data.id ? data : j)))
    } catch {
      // ignore
    }
  }

  // Poll while dialog is open and selected job is running
  useEffect(() => {
    if (!open) return
    fetchJobs()
  }, [open, rule.id])

  useEffect(() => {
    if (!open) {
      if (pollRef.current) clearInterval(pollRef.current)
      return
    }
    pollRef.current = setInterval(() => {
      const isRunning = jobs.find((j) => j.id === selectedId)?.status === 'running'
        || (selectedJob === null && jobs.some((j) => j.status === 'running'))
      if (isRunning) {
        fetchSelected()
      }
    }, 2000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [open, selectedId, jobs])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className='sm:max-w-6xl h-[80vh] flex flex-col p-0 gap-0'>
        <DialogHeader className='px-6 pt-5 pb-4 shrink-0'>
          <DialogTitle className='flex items-center gap-2'>
            Replication logs
            <span className='text-muted-foreground font-normal text-sm'>— {rule.name}</span>
          </DialogTitle>
          <DialogDescription>
            Execution history for this rule. Logs update in real-time while a job is running.
          </DialogDescription>
        </DialogHeader>

        <Separator />

        <div className='flex flex-1 min-h-0'>
          {/* Job list sidebar */}
          <div className='w-52 shrink-0 border-r flex flex-col'>
            <div className='px-3 py-2 text-xs font-medium text-muted-foreground uppercase tracking-wide border-b'>
              Executions
            </div>
            <ScrollArea className='flex-1'>
              <div className='p-2 space-y-1'>
                {loading ? (
                  <div className='text-xs text-muted-foreground px-2 py-4 text-center'>Loading…</div>
                ) : jobs.length === 0 ? (
                  <div className='text-xs text-muted-foreground px-2 py-4 text-center'>No executions yet</div>
                ) : (
                  jobs.map((job) => (
                    <JobRow
                      key={job.id}
                      job={job}
                      selected={job.id === (selectedId ?? jobs[0]?.id)}
                      onClick={() => setSelectedId(job.id)}
                    />
                  ))
                )}
              </div>
            </ScrollArea>
          </div>

          {/* Log panel */}
          <div className='flex-1 flex flex-col min-w-0 p-4 gap-3'>
            {selectedJob ? (
              <>
                {/* Job summary bar */}
                <div className='flex items-center gap-3 text-xs shrink-0'>
                  <Badge
                    variant={statusVariant[selectedJob.status] ?? 'secondary'}
                    className={`gap-1 ${statusClass[selectedJob.status] ?? ''}`}
                  >
                    {statusIcon[selectedJob.status]}
                    {selectedJob.status}
                  </Badge>
                  <span className='text-muted-foreground'>
                    Started {formatTime(selectedJob.started_at)}
                  </span>
                  {selectedJob.finished_at && (
                    <span className='text-muted-foreground'>
                      · {formatDuration(selectedJob.started_at, selectedJob.finished_at)}
                    </span>
                  )}
                  <span className='ml-auto text-green-600 dark:text-green-400'>
                    {selectedJob.copied} copied
                  </span>
                  {selectedJob.errors > 0 && (
                    <span className='text-destructive'>{selectedJob.errors} errors</span>
                  )}
                  {selectedJob.status === 'running' && (
                    <Button
                      size='icon' variant='ghost' className='size-6'
                      onClick={fetchSelected}
                    >
                      <RefreshCwIcon className='size-3' />
                    </Button>
                  )}
                </div>
                <LogViewer job={selectedJob} />
              </>
            ) : (
              <div className='flex items-center justify-center flex-1 text-sm text-muted-foreground'>
                Select an execution to view its log
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
