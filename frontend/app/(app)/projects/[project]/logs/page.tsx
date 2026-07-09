'use client'

import { useEffect, useState, useCallback, useRef } from 'react'
import { useParams } from 'next/navigation'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { ScrollTextIcon, SearchIcon, RefreshCwIcon, CheckCircle2Icon, XCircleIcon, XIcon, DownloadIcon, FileTextIcon, FileJsonIcon } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { fetchProjectAuditLogs, type AuditLog, type AuditLogFilters } from '@/services/registry'
import { describeLog } from '@/lib/auditLogDescription'
import { DatePickerFilter } from '@/components/shadcn-studio/blocks/date-picker-filter'
import { baseUrl } from '@/constants/constants'

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

function fmtTime(iso: string) {
  const d = new Date(iso)
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

const EMPTY: AuditLogFilters = { operation: '', dateFrom: '', dateTo: '', q: '' }

function hasFilters(f: AuditLogFilters) {
  return !!(f.operation || f.dateFrom || f.dateTo || f.q)
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ProjectLogsPage() {
  const { project } = useParams<{ project: string }>()

  const [logs, setLogs] = useState<AuditLog[]>([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState<AuditLogFilters>(EMPTY)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const load = useCallback((f: AuditLogFilters) => {
    setLoading(true)
    fetchProjectAuditLogs(project, f)
      .then((d) => setLogs(Array.isArray(d) ? d : []))
      .catch(() => setLogs([]))
      .finally(() => setLoading(false))
  }, [project])

  useEffect(() => { load(EMPTY) }, [load])

  const setImmediate = (patch: Partial<AuditLogFilters>) => {
    const next = { ...filters, ...patch }
    setFilters(next)
    load(next)
  }

  const setDebounced = (patch: Partial<AuditLogFilters>) => {
    const next = { ...filters, ...patch }
    setFilters(next)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => load(next), 350)
  }

  const clearFilters = () => {
    setFilters(EMPTY)
    load(EMPTY)
  }

  const exportLogs = (format: 'csv' | 'json') => {
    const p = new URLSearchParams({ format })
    if (filters.operation) p.set('operation', filters.operation)
    if (filters.dateFrom)  p.set('date_from', filters.dateFrom)
    if (filters.dateTo)    p.set('date_to', filters.dateTo)
    if (filters.q)         p.set('q', filters.q)
    window.location.href = `${baseUrl}registry/projects/${project}/audit-logs/export?${p}`
  }

  const active = hasFilters(filters)

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <ScrollTextIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>{project}</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Audit Logs</span>
        <div className='ml-auto flex items-center gap-2'>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size='sm' variant='outline' className='gap-1.5'>
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
          <Button size='sm' variant='outline' onClick={() => load(filters)}>
            <RefreshCwIcon className='size-3.5' />
          </Button>
        </div>
      </header>

      <main className='flex-1 px-6 py-6 space-y-4'>

        {/* Filter bar */}
        <div className='flex flex-wrap items-center gap-2'>
          {/* Operation */}
          <Select
            value={filters.operation || 'all'}
            onValueChange={(v) => setImmediate({ operation: v === 'all' ? '' : v })}
          >
            <SelectTrigger className='h-8 w-32 text-sm'>
              <SelectValue placeholder='Operation' />
            </SelectTrigger>
            <SelectContent>
              {OPERATIONS.map((op) => (
                <SelectItem key={op} value={op}>{opLabels[op] ?? op}</SelectItem>
              ))}
            </SelectContent>
          </Select>

          {/* Date from */}
          <DatePickerFilter
            label='From'
            value={filters.dateFrom ?? ''}
            max={filters.dateTo || undefined}
            onChange={(v) => setImmediate({ dateFrom: v })}
          />

          {/* Date to */}
          <DatePickerFilter
            label='To'
            value={filters.dateTo ?? ''}
            min={filters.dateFrom || undefined}
            onChange={(v) => setImmediate({ dateTo: v })}
          />

          {/* Search */}
          <div className='relative'>
            <SearchIcon className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
            <Input
              placeholder='Search user or resource…'
              className='h-8 w-52 pl-8 text-sm'
              value={filters.q ?? ''}
              onChange={(e) => setDebounced({ q: e.target.value })}
            />
          </div>

          {/* Clear */}
          {active && (
            <Button size='sm' variant='ghost' onClick={clearFilters} className='h-8 gap-1 text-xs'>
              <XIcon className='size-3' />
              Clear
            </Button>
          )}
        </div>

        {/* Results */}
        {loading ? (
          <div className='space-y-px'>
            {Array.from({ length: 8 }).map((_, i) => (
              <Skeleton key={i} className='h-14 w-full rounded-none first:rounded-t-md last:rounded-b-md' />
            ))}
          </div>
        ) : logs.length === 0 ? (
          <div className='flex flex-col items-center justify-center gap-3 py-24 text-center text-muted-foreground'>
            <ScrollTextIcon className='size-10 opacity-30' />
            <p className='text-sm'>
              {active
                ? 'No entries match the current filters.'
                : 'No audit log entries for this project yet.'}
            </p>
            {active && (
              <Button variant='outline' size='sm' onClick={clearFilters}>Clear filters</Button>
            )}
          </div>
        ) : (
          <div className='rounded-md border divide-y'>
            {logs.map((log) => (
              <div key={log.id} className='flex items-start gap-4 px-4 py-3 hover:bg-muted/30 transition-colors'>
                <div className='mt-0.5 shrink-0'>
                  {log.result
                    ? <CheckCircle2Icon className='size-4 text-green-600 dark:text-green-400' />
                    : <XCircleIcon className='size-4 text-destructive' />
                  }
                </div>
                <div className='flex-1 min-w-0'>
                  <div className='flex flex-wrap items-center gap-x-2 gap-y-0.5'>
                    <span className='text-sm font-semibold'>{log.username}</span>
                    <span className={`inline-flex rounded-full px-2 py-0.5 text-[11px] font-medium ${opColors[log.operation] ?? 'bg-muted text-muted-foreground'}`}>
                      {opLabels[log.operation] ?? log.operation}
                    </span>
                  </div>
                  <p className='text-sm text-muted-foreground mt-0.5'>{describeLog(log)}</p>
                </div>
                <time className='shrink-0 text-xs text-muted-foreground tabular-nums mt-0.5'>
                  {fmtTime(log.timestamp)}
                </time>
              </div>
            ))}
          </div>
        )}
      </main>
    </>
  )
}
