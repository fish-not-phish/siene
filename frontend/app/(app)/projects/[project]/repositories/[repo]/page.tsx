'use client'

import { useParams, useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { baseUrl, registryHost as registryHostConst } from '@/constants/constants'
import {
  BoxesIcon, TagIcon, RefreshCwIcon, ShieldAlertIcon, Trash2Icon,
  ShieldCheckIcon, ShieldXIcon, ShieldQuestionIcon, CopyIcon,
  ChevronLeftIcon, ChevronRightIcon, SearchIcon, AlertTriangleIcon,
  TerminalIcon, KeySquareIcon, WrenchIcon, PackageIcon, CheckCircle2Icon,
  ClockIcon, LoaderIcon, XCircleIcon, MinusIcon,
} from 'lucide-react'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { useAuthContext } from '@/store/AuthContext'
import { fetchProjectPolicy, type ProjectPolicy } from '@/services/registry'

const PAGE_SIZE = 20

interface TagLabel { id: number; name: string; color: string }
interface Tag {
  id: number; name: string; digest: string; size_bytes: number
  os: string; architecture: string; pushed_by_username: string | null
  pushed_at: string; last_activity_at: string | null; scan_status: string | null
  secret_scan_status: string | null; misconfig_scan_status: string | null
  sbom_status: string | null; labels: TagLabel[]
  cosign_status: string; notation_status: string
  is_index: boolean; platform: string
}
interface QuotaData { quota_gb: number | null; used_bytes: number; quota_bytes: number | null }

function formatBytes(bytes: number) {
  if (bytes === 0) return '—'
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function ScanStatusIcon({ status }: { status: string | null }) {
  if (!status)               return <MinusIcon        className='size-3 opacity-40' />
  if (status === 'finished') return <CheckCircle2Icon className='size-3' />
  if (status === 'running')  return <LoaderIcon       className='size-3 animate-spin' />
  if (status === 'pending')  return <ClockIcon        className='size-3' />
  return <XCircleIcon className='size-3' />
}

function ScanBadge({ vuln, secret, misconfig, sbom }: {
  vuln: string | null; secret: string | null; misconfig: string | null; sbom: string | null
}) {
  const statuses = [vuln, secret, misconfig, sbom]
  const hasAny    = statuses.some(Boolean)
  const anyError  = statuses.some(s => s === 'error')
  const anyActive = statuses.some(s => s === 'running' || s === 'pending')
  const allDone   = statuses.every(s => s === 'finished')

  // Overall badge colour
  const badgeCls = !hasAny
    ? 'bg-muted text-muted-foreground'
    : anyError
    ? 'bg-destructive/10 text-destructive'
    : anyActive
    ? 'bg-blue-600/10 text-blue-600 dark:bg-blue-400/10 dark:text-blue-400'
    : allDone
    ? 'bg-green-600/10 text-green-600 dark:bg-green-400/10 dark:text-green-400'
    : 'bg-yellow-600/10 text-yellow-600 dark:bg-yellow-400/10 dark:text-yellow-400'

  const label = !hasAny ? 'none' : anyError ? 'error' : anyActive ? (statuses.some(s => s === 'running') ? 'running' : 'pending') : allDone ? 'finished' : 'partial'

  const rows: { icon: React.ReactNode; name: string; status: string | null }[] = [
    { icon: <ShieldAlertIcon className='size-3' />, name: 'Vulnerabilities', status: vuln },
    { icon: <KeySquareIcon   className='size-3' />, name: 'Secrets',         status: secret },
    { icon: <WrenchIcon      className='size-3' />, name: 'Misconfig',       status: misconfig },
    { icon: <PackageIcon     className='size-3' />, name: 'SBOM',            status: sbom },
  ]

  return (
    <TooltipProvider delayDuration={100}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className={`inline-flex cursor-default items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${badgeCls}`}>
            <ShieldAlertIcon className='size-3' />
            {label}
          </span>
        </TooltipTrigger>
        {/* TooltipContent uses bg-foreground/text-background — an inverted surface.
            Status colours use opacity so they stay legible on both light and dark themes. */}
        <TooltipContent side='left' className='p-2 min-w-[175px] space-y-1'>
          {rows.map(({ icon, name, status }) => {
            // green-400 / red-400 / amber-400 sit in the middle of the palette —
            // visible on both the dark inverted surface (light mode) and the
            // light inverted surface (dark mode) without needing dark: variants.
            const statusCls = status === 'finished'
              ? 'text-green-400'
              : status === 'error'
              ? 'text-red-400'
              : status === 'running' || status === 'pending'
              ? 'text-amber-400'
              : 'text-red-400'   // null / never run = red (incomplete)
            return (
              <div key={name} className='flex items-center justify-between gap-4'>
                <span className='flex items-center gap-1.5 text-background/80'>
                  {icon}{name}
                </span>
                <span className={`flex items-center gap-1 font-medium ${statusCls}`}>
                  <ScanStatusIcon status={status} />
                  {status ?? 'none'}
                </span>
              </div>
            )
          })}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

function SignatureBadge({ cosign }: { cosign: string }) {
  if (!cosign || cosign === 'unknown')
    return <span className='inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-muted text-muted-foreground'><ShieldQuestionIcon className='size-3' />Unknown</span>
  if (cosign === 'signed')
    return <span className='inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-emerald-600/10 text-emerald-600 dark:bg-emerald-400/10 dark:text-emerald-400'><ShieldCheckIcon className='size-3' />Signed</span>
  return <span className='inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-muted text-muted-foreground'><ShieldXIcon className='size-3' />Not signed</span>
}

function StaleBadge({ lastActivityAt, pushedAt, activeDays }: { lastActivityAt: string | null; pushedAt: string; activeDays: number }) {
  // Use last_activity_at when available; fall back to pushed_at for tags that
  // predate the last_activity_at field or whose push webhook didn't fire.
  const activityTs = lastActivityAt ?? pushedAt
  const isStale = (Date.now() - new Date(activityTs).getTime()) > activeDays * 86400000
  if (!isStale) return null
  return (
    <TooltipProvider delayDuration={100}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className='inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-muted text-muted-foreground'>
            <ClockIcon className='size-3' />
            Stale
          </span>
        </TooltipTrigger>
        <TooltipContent side='top'>
          <p className='text-xs'>
            No activity for over {activeDays} days — last seen {new Date(activityTs).toLocaleDateString()}
          </p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

function QuotaBar({ quota }: { quota: QuotaData }) {
  if (!quota.quota_bytes) return null
  const pct = Math.min(100, Math.round((quota.used_bytes / quota.quota_bytes) * 100))
  const warn = pct >= 80
  const crit = pct >= 95
  return (
    <div className={`flex items-center gap-2 rounded-md border px-3 py-2 text-xs ${crit ? 'border-destructive/50 bg-destructive/5' : warn ? 'border-yellow-500/50 bg-yellow-500/5' : 'bg-muted/40'}`}>
      {(warn || crit) && <AlertTriangleIcon className={`size-3.5 shrink-0 ${crit ? 'text-destructive' : 'text-yellow-500'}`} />}
      <span className={crit ? 'text-destructive' : warn ? 'text-yellow-600 dark:text-yellow-400' : 'text-muted-foreground'}>
        {formatBytes(quota.used_bytes)} of {formatBytes(quota.quota_bytes)} used ({pct}%)
      </span>
      <div className='flex-1 h-1.5 rounded-full bg-muted overflow-hidden'>
        <div
          className={`h-full rounded-full transition-all ${crit ? 'bg-destructive' : warn ? 'bg-yellow-500' : 'bg-primary'}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}

function PushCommand({ registryHost, project, repo }: { registryHost: string; project: string; repo: string }) {
  const [copied, setCopied] = useState<string | null>(null)

  const copy = (key: string, text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(null), 1500)
  }

  const imagePath = `${registryHost}/${project}/${repo}`

  const lines: { key: string; comment: string; cmd: string }[] = [
    { key: 'tag',  comment: '# Tag your local image',       cmd: `docker tag <local-image> ${imagePath}:<tag>` },
    { key: 'push', comment: '# Push to the registry',       cmd: `docker push ${imagePath}:<tag>` },
    { key: 'pull', comment: '# Pull from the registry',     cmd: `docker pull ${imagePath}:<tag>` },
  ]

  return (
    <div className='rounded-md border bg-muted/30 px-4 py-3 space-y-1.5'>
      <div className='flex items-center gap-1.5 text-xs font-medium text-muted-foreground mb-2'>
        <TerminalIcon className='size-3.5' />
        Quick reference
      </div>
      {lines.map(({ key, comment, cmd }) => (
        <div key={key} className='flex items-center gap-2 font-mono text-xs'>
          <span className='text-muted-foreground/60 select-none w-48 shrink-0 hidden sm:block'>{comment}</span>
          <code className='flex-1 rounded bg-background border px-2.5 py-1 text-foreground overflow-x-auto whitespace-nowrap'>
            {cmd}
          </code>
          <button
            type='button'
            onClick={() => copy(key, cmd)}
            className='shrink-0 text-muted-foreground hover:text-foreground transition-colors'
            aria-label={`Copy ${key} command`}
          >
            <CopyIcon className={`size-3.5 transition-colors ${copied === key ? 'text-green-500' : ''}`} />
          </button>
        </div>
      ))}
    </div>
  )
}

export default function RepoTagsPage() {
  const { project, repo } = useParams<{ project: string; repo: string }>()
  const router = useRouter()
  const { user } = useAuthContext()

  const [tags, setTags] = useState<Tag[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0)
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')

  // Single delete
  const [deleteTarget, setDeleteTarget] = useState<Tag | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  // Bulk delete
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false)
  const [bulkDeleting, setBulkDeleting] = useState(false)

  // Copy/retag dialog
  const [copySource, setCopySource] = useState<Tag | null>(null)
  const [newTagName, setNewTagName] = useState('')
  const [destRepo, setDestRepo] = useState('')
  const [copying, setCopying] = useState(false)
  const [copyError, setCopyError] = useState('')

  // Quota
  const [quota, setQuota] = useState<QuotaData | null>(null)

  // Policy — needed to determine staleness window
  const [policy, setPolicy] = useState<ProjectPolicy | null>(null)

  const registryHost = registryHostConst || (() => {
    try {
      const url = new URL(baseUrl)
      return url.port ? `${url.hostname}:${url.port}` : url.hostname
    } catch {
      return typeof window !== 'undefined' ? window.location.hostname : 'localhost'
    }
  })()

  const load = (p = page, q = search) => {
    setLoading(true)
    const params = new URLSearchParams({
      limit: String(PAGE_SIZE),
      offset: String(p * PAGE_SIZE),
    })
    if (q) params.set('search', q)
    fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags?${params}`, {
      credentials: 'include',
    })
      .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() })
      .then((data) => {
        setTags(Array.isArray(data.items) ? data.items : [])
        setTotal(typeof data.total === 'number' ? data.total : 0)
      })
      .catch(() => { setTags([]); setTotal(0) })
      .finally(() => setLoading(false))
  }

  const loadQuota = () => {
    fetch(`${baseUrl}registry/projects/${project}/quota`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : null)
      .then((d) => setQuota(d))
      .catch(() => {})
  }

  useEffect(() => {
    setPage(0)
    setSelected(new Set())
    load(0, search)
    loadQuota()
    fetchProjectPolicy(project).then(setPolicy).catch(() => {})
  }, [project, repo])

  const goToPage = (p: number) => {
    setPage(p)
    setSelected(new Set())
    load(p, search)
  }

  const applySearch = () => {
    setSearch(searchInput)
    setPage(0)
    setSelected(new Set())
    load(0, searchInput)
  }

  // ── Single delete ────────────────────────────────────────────────────────
  const confirmDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    setDeleteError(null)
    try {
      const res = await fetch(
        `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${deleteTarget.name}`,
        { method: 'DELETE', credentials: 'include', headers: { 'X-CSRFToken': user.csrfToken ?? '' } }
      )
      if (!res.ok) {
        const msg = await res.text().catch(() => `HTTP ${res.status}`)
        setDeleteError(msg || `Delete failed (HTTP ${res.status})`)
        return
      }
      setDeleteTarget(null)
      load()
      loadQuota()
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Delete failed')
    } finally {
      setDeleting(false)
    }
  }

  // ── Bulk delete ──────────────────────────────────────────────────────────
  const confirmBulkDelete = async () => {
    setBulkDeleting(true)
    const names = tags.filter(t => selected.has(t.id)).map(t => t.name)
    await Promise.allSettled(names.map(name =>
      fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${name}`, {
        method: 'DELETE', credentials: 'include', headers: { 'X-CSRFToken': user.csrfToken ?? '' },
      })
    ))
    setBulkDeleting(false)
    setBulkDeleteOpen(false)
    setSelected(new Set())
    load()
    loadQuota()
  }

  const toggleSelect = (id: number) =>
    setSelected(prev => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s })
  const allSelected = tags.length > 0 && tags.every(t => selected.has(t.id))
  const toggleAll = () =>
    setSelected(allSelected ? new Set() : new Set(tags.map(t => t.id)))

  // ── Copy/retag ───────────────────────────────────────────────────────────
  const confirmCopy = async () => {
    if (!copySource || !newTagName.trim()) return
    setCopying(true)
    setCopyError('')
    const params = new URLSearchParams({ new_tag: newTagName.trim() })
    if (destRepo.trim()) params.set('dest_repo', destRepo.trim())
    const res = await fetch(
      `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${copySource.name}/copy?${params}`,
      { method: 'POST', credentials: 'include', headers: { 'X-CSRFToken': user.csrfToken ?? '' } }
    )
    setCopying(false)
    if (res.ok) {
      setCopySource(null)
      setNewTagName('')
      setDestRepo('')
      load()
    } else {
      const body = await res.json().catch(() => ({}))
      setCopyError(body?.detail || body?.message || 'Copy failed')
    }
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <BoxesIcon className='size-4 text-muted-foreground' />
        <Link href={`/projects/${project}/repositories`} className='text-sm hover:underline'>{project}</Link>
        <span className='text-muted-foreground'>/</span>
        <span className='font-semibold text-sm'>{repo}</span>
        <div className='ml-auto flex items-center gap-2'>
          {selected.size > 0 && (
            <Button size='sm' variant='destructive' onClick={() => setBulkDeleteOpen(true)}>
              <Trash2Icon className='size-3.5' />
              Delete {selected.size}
            </Button>
          )}
          <Button size='sm' variant='outline' onClick={() => load()}>
            <RefreshCwIcon className='size-3.5' />
          </Button>
        </div>
      </header>

      <main className='flex-1 px-6 py-6 space-y-4'>

        {/* Quota bar */}
        {quota && <QuotaBar quota={quota} />}

        {/* Push command */}
        <PushCommand registryHost={registryHost} project={project} repo={repo} />

        {/* Search */}
        <div className='flex items-center gap-2'>
          <div className='relative'>
            <SearchIcon className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
            <Input
              placeholder='Search tags…'
              value={searchInput}
              onChange={e => setSearchInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') applySearch() }}
              className='h-8 w-52 pl-8 text-xs'
            />
          </div>
          <Button size='sm' variant='outline' className='h-8' onClick={applySearch}>Search</Button>
          {search && (
            <Button size='sm' variant='ghost' className='h-8 text-xs text-muted-foreground' onClick={() => { setSearchInput(''); setSearch(''); load(0, '') }}>
              Clear
            </Button>
          )}
          <span className='ml-auto text-xs text-muted-foreground'>{total} tag{total !== 1 ? 's' : ''}</span>
        </div>

        {loading ? (
          <div className='space-y-2'>
            {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className='h-12 w-full rounded-md' />)}
          </div>
        ) : tags.length === 0 ? (
          <div className='flex flex-col items-center justify-center gap-3 py-24 text-center text-muted-foreground'>
            <TagIcon className='size-10 opacity-30' />
            <p className='text-sm'>{search ? 'No tags match your search.' : 'No tags yet.'}</p>
            {!search && (
              <p className='text-xs'>
                Push an image to{' '}
                <code className='rounded bg-muted px-1 text-foreground'>
                  {registryHost}/{project}/{repo}:&lt;tag&gt;
                </code>
              </p>
            )}
          </div>
        ) : (
          <>
            <div className='rounded-md border'>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className='w-10'>
                      <Checkbox checked={allSelected} onCheckedChange={toggleAll} aria-label='Select all' />
                    </TableHead>
                    <TableHead>Tag</TableHead>
                    <TableHead>Digest</TableHead>
                    <TableHead className='w-28'>Size</TableHead>
                    <TableHead className='w-32'>OS / Arch</TableHead>
                    <TableHead className='w-28'>Scan</TableHead>
                    <TableHead className='w-28'>Signature</TableHead>
                    <TableHead className='w-36'>Pushed</TableHead>
                    <TableHead>Labels</TableHead>
                    <TableHead className='w-20' />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tags.map((tag) => (
                    <TableRow key={tag.id} className='group' data-selected={selected.has(tag.id)}>
                      <TableCell>
                        <Checkbox
                          checked={selected.has(tag.id)}
                          onCheckedChange={() => toggleSelect(tag.id)}
                          aria-label={`Select ${tag.name}`}
                        />
                      </TableCell>
                      <TableCell>
                        <div className='flex items-center gap-2 flex-wrap'>
                          <Link href={`/projects/${project}/repositories/${repo}/${tag.name}`} className='font-mono text-sm font-medium hover:underline'>
                            {tag.name}
                          </Link>
                          {tag.is_index && (
                            <span className='inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-blue-600/10 text-blue-600 dark:bg-blue-400/10 dark:text-blue-400'>
                              <BoxesIcon className='size-3' />
                              Multi-arch
                            </span>
                          )}
                          {policy?.vuln_rescan_active_only && (
                            <StaleBadge
                              lastActivityAt={tag.last_activity_at}
                              pushedAt={tag.pushed_at}
                              activeDays={policy.vuln_rescan_active_days}
                            />
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <code className='rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground'>
                          {tag.digest.slice(0, 19)}…
                        </code>
                      </TableCell>
                      <TableCell className='text-sm text-muted-foreground'>{formatBytes(tag.size_bytes)}</TableCell>
                      <TableCell className='text-sm text-muted-foreground'>
                        {tag.is_index
                          ? <span className='text-muted-foreground/60 text-xs italic'>index</span>
                          : tag.os && tag.architecture ? `${tag.os}/${tag.architecture}` : '—'}
                      </TableCell>
                      <TableCell><ScanBadge vuln={tag.scan_status} secret={tag.secret_scan_status} misconfig={tag.misconfig_scan_status} sbom={tag.sbom_status} /></TableCell>
                      <TableCell><SignatureBadge cosign={tag.cosign_status} /></TableCell>
                      <TableCell className='text-sm text-muted-foreground'>
                        {new Date(tag.pushed_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        <div className='flex flex-wrap gap-1'>
                          {(tag.labels ?? []).map((label) => (
                            <span key={label.id} className='inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium'
                              style={{ backgroundColor: `${label.color}22`, color: label.color, border: `1px solid ${label.color}55` }}>
                              {label.name}
                            </span>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className='text-right'>
                        <div className='flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity'>
                          <Button size='icon' variant='ghost' className='size-7 text-muted-foreground hover:text-foreground'
                            title='Copy / retag' onClick={() => { setCopySource(tag); setNewTagName(''); setDestRepo(''); setCopyError('') }}>
                            <CopyIcon className='size-3.5' />
                          </Button>
                          <Button size='icon' variant='ghost' className='size-7 text-muted-foreground hover:text-destructive'
                            title='Delete' onClick={() => setDeleteTarget(tag)}>
                            <Trash2Icon className='size-3.5' />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className='flex items-center justify-between text-xs text-muted-foreground'>
                <span>
                  {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
                </span>
                <div className='flex items-center gap-1'>
                  <Button size='icon' variant='outline' className='size-7' disabled={page === 0} onClick={() => goToPage(page - 1)}>
                    <ChevronLeftIcon className='size-3.5' />
                  </Button>
                  {Array.from({ length: totalPages }, (_, i) => i).filter(i => Math.abs(i - page) <= 2).map(i => (
                    <Button key={i} size='sm' variant={i === page ? 'default' : 'outline'} className='size-7 text-xs' onClick={() => goToPage(i)}>
                      {i + 1}
                    </Button>
                  ))}
                  <Button size='icon' variant='outline' className='size-7' disabled={page >= totalPages - 1} onClick={() => goToPage(page + 1)}>
                    <ChevronRightIcon className='size-3.5' />
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </main>

      {/* Single delete dialog */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) { setDeleteTarget(null); setDeleteError(null) } }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete tag?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete tag{' '}
              <span className='font-mono font-semibold text-foreground'>{deleteTarget?.name}</span>{' '}
              from <span className='font-mono font-semibold text-foreground'>{repo}</span>. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {deleteError && (
            <p className='text-sm text-destructive px-1'>{deleteError}</p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={confirmDelete} disabled={deleting} className='bg-destructive text-destructive-foreground hover:bg-destructive/90'>
              {deleting ? 'Deleting…' : 'Delete tag'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Bulk delete dialog */}
      <AlertDialog open={bulkDeleteOpen} onOpenChange={setBulkDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {selected.size} tag{selected.size !== 1 ? 's' : ''}?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete the selected tags from{' '}
              <span className='font-mono font-semibold text-foreground'>{repo}</span>. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={bulkDeleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={confirmBulkDelete} disabled={bulkDeleting} className='bg-destructive text-destructive-foreground hover:bg-destructive/90'>
              {bulkDeleting ? 'Deleting…' : `Delete ${selected.size} tag${selected.size !== 1 ? 's' : ''}`}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Copy/retag dialog */}
      <Dialog open={!!copySource} onOpenChange={(o) => { if (!o) { setCopySource(null); setCopyError('') } }}>
        <DialogContent className='sm:max-w-md'>
          <DialogHeader>
            <DialogTitle>Copy / retag</DialogTitle>
            <DialogDescription>
              Push the manifest of{' '}
              <span className='font-mono font-semibold text-foreground'>{copySource?.name}</span>{' '}
              under a new tag name. No image data is transferred.
            </DialogDescription>
          </DialogHeader>
          <div className='space-y-3 py-2'>
            <div className='space-y-1.5'>
              <Label htmlFor='new-tag' className='text-sm'>New tag name</Label>
              <Input
                id='new-tag'
                placeholder='e.g. latest, v2.0.0'
                value={newTagName}
                onChange={e => setNewTagName(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') confirmCopy() }}
                className='font-mono'
              />
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='dest-repo' className='text-sm'>Destination repository <span className='text-muted-foreground font-normal'>(optional)</span></Label>
              <Input
                id='dest-repo'
                placeholder={`default: ${repo}`}
                value={destRepo}
                onChange={e => setDestRepo(e.target.value)}
                className='font-mono'
              />
              <p className='text-xs text-muted-foreground'>Leave blank to copy within the same repository.</p>
            </div>
            {copyError && <p className='text-xs text-destructive'>{copyError}</p>}
          </div>
          <DialogFooter>
            <Button variant='outline' onClick={() => { setCopySource(null); setCopyError('') }}>Cancel</Button>
            <Button disabled={copying || !newTagName.trim()} onClick={confirmCopy}>
              {copying ? <><RefreshCwIcon className='size-3.5 animate-spin' /> Copying…</> : 'Copy tag'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
