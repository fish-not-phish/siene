'use client'

import { useParams, useRouter } from 'next/navigation'
import { Fragment, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { useAuthContext } from '@/store/AuthContext'
import { baseUrl, registryHost as registryHostConst } from '@/constants/constants'
import {
  BoxesIcon,
  TagIcon,
  CopyIcon,
  ChevronDownIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  ScanIcon,
  RefreshCwIcon,
  LayersIcon,
  PackageIcon,
  FileTextIcon,
  Trash2Icon,
  TagsIcon,
  PlusIcon,
  XIcon,
  KeyRoundIcon,
  ShieldXIcon,
  ShieldQuestionIcon,
  DownloadIcon,
  KeySquareIcon,
  WrenchIcon,
  SearchIcon,
  ClockIcon,
} from 'lucide-react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label as FormLabel } from '@/components/ui/label'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import type { Label, SignatureStatus, AllowlistEntry, SecretAllowlistEntry, MisconfigAllowlistEntry, ProjectPolicy } from '@/services/registry'
import {
  fetchAllowlist, createAllowlistEntry, deleteAllowlistEntry,
  fetchSecretAllowlist, createSecretAllowlistEntry, deleteSecretAllowlistEntry,
  fetchProjectSecretAllowlist, deleteProjectSecretAllowlistEntry,
  fetchMisconfigAllowlist, createMisconfigAllowlistEntry, deleteMisconfigAllowlistEntry,
  fetchProjectMisconfigAllowlist, deleteProjectMisconfigAllowlistEntry,
  fetchProjectPolicy,
} from '@/services/registry'

interface PlatformChild {
  id: number
  name: string
  platform: string
  digest: string
  os: string
  architecture: string
  size_bytes: number
  scan_status: string | null
  secret_scan_status: string | null
  misconfig_scan_status: string | null
  sbom_status: string | null
}

interface TagDetail {
  id: number
  name: string
  digest: string
  size_bytes: number
  os: string
  architecture: string
  pushed_by_username: string | null
  pushed_at: string
  last_activity_at: string | null
  scan_status: string | null
  manifest: Record<string, unknown>
  image_config: Record<string, unknown>
  // Multi-arch fields
  is_index: boolean
  platform: string
  index_manifest: Record<string, unknown>
  platform_children: PlatformChild[]
}

interface Layer {
  mediaType: string
  size: number
  digest: string
}

interface HistoryEntry {
  created?: string
  created_by?: string
  comment?: string
  empty_layer?: boolean
}

interface LayerRow {
  index: number          // display index (1-based, counts only non-empty layers)
  historyIndex: number   // position in full history array
  command: string        // cleaned-up created_by string
  isEmpty: boolean       // true = metadata-only step, no blob
  digest?: string
  size?: number
  mediaType?: string
}

interface VulnFinding {
  vulnerability_id: string
  pkg_name: string
  installed_version: string
  fixed_version: string
  severity: string
  title: string
  description: string
  references: string[]
  cwe_ids: string[]
  cvss_v3_score: number | null
  cvss_v3_vector: string
  cvss_v2_score: number | null
  published_date: string
  last_modified_date: string
  data_source: string
  pkg_path: string
  target: string
  class: string
  pkg_type: string
  suppressed?: boolean
}

interface ScanReport {
  status: string
  summary: Record<string, number>
  started_at: string | null
  finished_at: string | null
  report: VulnFinding[]
}

interface SecretFinding {
  rule_id: string
  category: string
  severity: string
  title: string
  target: string
  match: string
  start_line: number | null
  end_line: number | null
  suppressed?: boolean
}

interface SecretScanReport {
  status: string
  total: number
  started_at: string | null
  finished_at: string | null
  report: SecretFinding[]
}

interface MisconfigFinding {
  id: string
  avd_id: string
  type: string
  title: string
  description: string
  message: string
  resolution: string
  severity: string
  status: string
  references: string[]
  target: string
  class: string
  result_type: string
  suppressed?: boolean
}

interface MisconfigScanReport {
  status: string
  summary: Record<string, number>
  started_at: string | null
  finished_at: string | null
  report: MisconfigFinding[]
}

interface SBOMPackage {
  name: string
  versionInfo: string
  licenseConcluded: string
  licenseInfoFromFiles?: string[]
  supplier: string
  SPDXID: string
  packageType?: string
  externalRefs?: { referenceCategory: string; referenceType: string; referenceLocator: string }[]
}

interface SBOMReport {
  status: string
  created_at: string | null
  finished_at: string | null
  report: {
    packages?: SBOMPackage[]
    spdxVersion?: string
    name?: string
    creationInfo?: { created?: string; creators?: string[] }
  }
}

function formatBytes(bytes: number) {
  if (!bytes || bytes === 0) return '—'
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-600/10 text-red-600 dark:bg-red-400/10 dark:text-red-400',
  high: 'bg-orange-600/10 text-orange-600 dark:bg-orange-400/10 dark:text-orange-400',
  medium: 'bg-yellow-600/10 text-yellow-600 dark:bg-yellow-400/10 dark:text-yellow-400',
  low: 'bg-blue-600/10 text-blue-600 dark:bg-blue-400/10 dark:text-blue-400',
  negligible: 'bg-muted text-muted-foreground',
  unknown: 'bg-muted text-muted-foreground',
}

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  negligible: 4,
  unknown: 5,
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <Button size='icon' variant='ghost' className='size-6 shrink-0' onClick={copy}>
      <CopyIcon className={`size-3 ${copied ? 'text-green-500' : 'text-muted-foreground'}`} />
    </Button>
  )
}

// ── Export helpers ─────────────────────────────────────────────────────────────

function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function csvRow(cells: (string | number | null | undefined)[]): string {
  return cells.map(c => {
    const s = c == null ? '' : String(c)
    // Escape double-quotes and wrap in quotes if the cell contains commas, newlines, or quotes
    if (s.includes(',') || s.includes('\n') || s.includes('"')) {
      return `"${s.replace(/"/g, '""')}"`
    }
    return s
  }).join(',')
}

function exportVulnsCsv(findings: VulnFinding[], filename: string) {
  const header = csvRow(['CVE / ID', 'Severity', 'Package', 'Installed Version', 'Fixed Version', 'CVSS v3', 'Title', 'Target', 'Suppressed'])
  const rows = findings.map(f => csvRow([
    f.vulnerability_id,
    f.severity,
    f.pkg_name,
    f.installed_version,
    f.fixed_version || '',
    f.cvss_v3_score ?? '',
    f.title || '',
    f.target || '',
    f.suppressed ? 'yes' : 'no',
  ]))
  downloadBlob([header, ...rows].join('\n'), filename, 'text/csv')
}

function exportSecretsCsv(findings: SecretFinding[], filename: string) {
  const header = csvRow(['Rule ID', 'Severity', 'Title', 'Target', 'Start Line', 'End Line', 'Suppressed'])
  const rows = findings.map(f => csvRow([
    f.rule_id,
    f.severity,
    f.title || '',
    f.target || '',
    f.start_line ?? '',
    f.end_line ?? '',
    f.suppressed ? 'yes' : 'no',
  ]))
  downloadBlob([header, ...rows].join('\n'), filename, 'text/csv')
}

function exportMisconfigsCsv(findings: MisconfigFinding[], filename: string) {
  const header = csvRow(['ID', 'Severity', 'Status', 'Title', 'Type', 'Suppressed'])
  const rows = findings.map(f => csvRow([
    f.avd_id || f.id,
    f.severity,
    f.status,
    f.title || '',
    f.type || '',
    f.suppressed ? 'yes' : 'no',
  ]))
  downloadBlob([header, ...rows].join('\n'), filename, 'text/csv')
}

function ExportMenu({ onCsv, onJson, disabled }: { onCsv: () => void; onJson: () => void; disabled?: boolean }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size='sm' variant='outline' disabled={disabled}>
          <DownloadIcon className='size-3.5' />
          Export
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align='end'>
        <DropdownMenuItem onClick={onCsv}>
          Export CSV
        </DropdownMenuItem>
        <DropdownMenuItem onClick={onJson}>
          Export JSON
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function ExpandableTable({
  headers,
  rows,
}: {
  headers: string[]
  rows: { cells: React.ReactNode[]; detail: React.ReactNode }[]
}) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const toggle = (i: number) =>
    setExpanded(prev => { const s = new Set(prev); s.has(i) ? s.delete(i) : s.add(i); return s })
  const cols = headers.length + 1

  return (
    <div className='mt-3 rounded-md border text-xs overflow-x-auto'>
      <table className='w-full'>
        <thead>
          <tr className='border-b bg-muted/50'>
            <th className='w-7 px-2 py-2' />
            {headers.map(h => (
              <th key={h} className='px-3 py-2 text-left font-medium whitespace-nowrap'>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <Fragment key={i}>
              <tr
                className='border-b last:border-0 cursor-pointer hover:bg-muted/30 transition-colors'
                onClick={() => toggle(i)}
              >
                <td className='px-2 py-1.5 text-muted-foreground'>
                  <ChevronDownIcon className={`size-3.5 transition-transform duration-150 ${expanded.has(i) ? 'rotate-180' : ''}`} />
                </td>
                {row.cells.map((cell, ci) => (
                  <td key={ci} className='px-3 py-1.5'>{cell}</td>
                ))}
              </tr>
              {expanded.has(i) && (
                <tr className='border-b last:border-0 bg-muted/20'>
                  <td colSpan={cols} className='px-4 py-3'>
                    {row.detail}
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SecretDetail({ f }: { f: SecretFinding }) {
  return (
    <div className='space-y-1 text-xs'>
      {(f.title || f.category) && <p className='font-medium text-foreground'>{f.title || f.category}</p>}
      <div className='flex flex-wrap gap-x-6 gap-y-1 text-muted-foreground'>
        {f.target && <span><span className='font-medium text-foreground'>File:</span> <span className='font-mono'>{f.target}</span></span>}
        {f.start_line != null && (
          <span>
            <span className='font-medium text-foreground'>Line:</span>{' '}
            {f.start_line}{f.end_line != null && f.end_line !== f.start_line ? `–${f.end_line}` : ''}
          </span>
        )}
      </div>
    </div>
  )
}

function SecretTable({
  findings,
  suppressedIds,
  secretAllowlist,
  projectSecretAllowlist,
  allowlistsReady,
  project,
  repo,
  tagName,
  csrfToken,
  onAllowlistChange,
}: {
  findings: SecretFinding[]
  suppressedIds: Set<string>
  secretAllowlist: SecretAllowlistEntry[]
  projectSecretAllowlist: SecretAllowlistEntry[]
  allowlistsReady: boolean
  project: string
  repo: string
  tagName: string
  csrfToken: string
  onAllowlistChange: () => void
}) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [addingId, setAddingId] = useState<string | null>(null)
  const [removingId, setRemovingId] = useState<string | null>(null)
  const [reasonDraft, setReasonDraft] = useState('')
  const toggle = (i: number) =>
    setExpanded(prev => { const s = new Set(prev); s.has(i) ? s.delete(i) : s.add(i); return s })

  const suppress = async (ruleId: string) => {
    setAddingId(ruleId)
    try {
      await createSecretAllowlistEntry(project, repo, tagName, { rule_id: ruleId, reason: reasonDraft || undefined }, csrfToken)
      setReasonDraft('')
      onAllowlistChange()
    } catch { /* duplicate = already suppressed */ }
    setAddingId(null)
  }

  const unsuppress = async (ruleId: string) => {
    const lower = ruleId.toLowerCase()
    setRemovingId(lower)
    try {
      const tagEntry = secretAllowlist.find(e => e.rule_id.toLowerCase() === lower)
      if (tagEntry) {
        await deleteSecretAllowlistEntry(project, repo, tagName, tagEntry.id, csrfToken)
        onAllowlistChange()
        return
      }
      const projectEntry = projectSecretAllowlist.find(e => e.rule_id.toLowerCase() === lower)
      if (projectEntry) {
        await deleteProjectSecretAllowlistEntry(project, projectEntry.id, csrfToken)
        onAllowlistChange()
      }
    } finally {
      setRemovingId(null)
    }
  }

  return (
    <div className='mt-3 rounded-md border text-xs overflow-x-auto'>
      <table className='w-full'>
        <thead>
          <tr className='border-b bg-muted/50'>
            <th className='w-7 px-2 py-2' />
            <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>Rule</th>
            <th className='px-3 py-2 text-left font-medium'>Severity</th>
            <th className='sticky right-0 w-8 px-2 py-2 bg-muted/50 shadow-[-1px_0_0_0_hsl(var(--border))]' />
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => {
            const isSuppressed = !!f.suppressed || suppressedIds.has((f.rule_id ?? '').toLowerCase())
            return (
              <Fragment key={i}>
                <tr className={`border-b last:border-0 cursor-pointer hover:bg-muted/30 transition-colors ${isSuppressed ? 'opacity-50' : ''}`} onClick={() => toggle(i)}>
                  <td className='px-2 py-1.5 text-muted-foreground'>
                    <ChevronDownIcon className={`size-3.5 transition-transform duration-150 ${expanded.has(i) ? 'rotate-180' : ''}`} />
                  </td>
                   <td className='px-3 py-1.5 font-mono break-all'>
                    {f.rule_id}
                    {isSuppressed && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>suppressed</span>}
                  </td>
                  <td className='px-3 py-1.5'>
                    <span className={`rounded-full px-1.5 py-0.5 font-medium capitalize ${severityColors[f.severity?.toLowerCase()] ?? 'bg-muted text-muted-foreground'}`}>{f.severity}</span>
                  </td>
                  <td className='sticky right-0 px-2 py-1.5 bg-background shadow-[-1px_0_0_0_hsl(var(--border))]' onClick={e => e.stopPropagation()}>
                    {isSuppressed ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button type='button'
                            onClick={() => unsuppress(f.rule_id ?? '')}
                            disabled={!allowlistsReady || removingId === (f.rule_id ?? '').toLowerCase()}
                            className='text-muted-foreground hover:text-destructive transition-colors disabled:opacity-40 disabled:cursor-not-allowed'>
                            {removingId === (f.rule_id ?? '').toLowerCase()
                              ? <RefreshCwIcon className='size-3.5 animate-spin' />
                              : <XIcon className='size-3.5' />}
                          </button>
                        </TooltipTrigger>
                        <TooltipContent side='left'>Remove from allowlist</TooltipContent>
                      </Tooltip>
                    ) : (
                      <Tooltip>
                         <Popover onOpenChange={(open) => { if (open) setReasonDraft('') }}>
                           <TooltipTrigger asChild>
                             <PopoverTrigger asChild>
                               <button type='button' className='text-muted-foreground hover:text-foreground transition-colors'>
                                 <PlusIcon className='size-3.5' />
                               </button>
                             </PopoverTrigger>
                           </TooltipTrigger>
                           <TooltipContent side='left'>Add to allowlist</TooltipContent>
                           <PopoverContent className='w-64 p-3 space-y-3' align='end'>
                             <p className='text-xs font-medium'>Suppress {f.rule_id}</p>
                             <input
                               type='text'
                               placeholder='Reason (optional)'
                               value={reasonDraft}
                               onChange={e => setReasonDraft(e.target.value)}
                              className='w-full h-7 rounded-md border bg-background px-2 text-xs outline-none focus:ring-1 focus:ring-ring'
                            />
                            <Button
                              size='sm'
                              className='w-full h-7 text-xs'
                              disabled={addingId === f.rule_id}
                              onClick={() => suppress(f.rule_id ?? '')}
                            >
                              {addingId === f.rule_id ? <RefreshCwIcon className='size-3 animate-spin' /> : 'Suppress'}
                            </Button>
                          </PopoverContent>
                        </Popover>
                      </Tooltip>
                    )}
                  </td>
                </tr>
                {expanded.has(i) && (
                  <tr className='border-b last:border-0 bg-muted/20'>
                    <td colSpan={5} className='px-4 py-3'>
                      <SecretDetail f={f} />
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function MisconfigTable({
  findings,
  suppressedIds,
  misconfigAllowlist,
  projectMisconfigAllowlist,
  allowlistsReady,
  project,
  repo,
  tagName,
  csrfToken,
  onAllowlistChange,
}: {
  findings: MisconfigFinding[]
  suppressedIds: Set<string>
  misconfigAllowlist: MisconfigAllowlistEntry[]
  projectMisconfigAllowlist: MisconfigAllowlistEntry[]
  allowlistsReady: boolean
  project: string
  repo: string
  tagName: string
  csrfToken: string
  onAllowlistChange: () => void
}) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [addingId, setAddingId] = useState<string | null>(null)
  const [removingId, setRemovingId] = useState<string | null>(null)
  const [reasonDraft, setReasonDraft] = useState('')
  const toggle = (i: number) =>
    setExpanded(prev => { const s = new Set(prev); s.has(i) ? s.delete(i) : s.add(i); return s })

  const suppress = async (checkId: string) => {
    setAddingId(checkId)
    try {
      await createMisconfigAllowlistEntry(project, repo, tagName, { check_id: checkId, reason: reasonDraft || undefined }, csrfToken)
      setReasonDraft('')
      onAllowlistChange()
    } catch { /* duplicate */ }
    setAddingId(null)
  }

  const unsuppress = async (checkId: string) => {
    const lower = checkId.toLowerCase()
    setRemovingId(lower)
    try {
      const tagEntry = misconfigAllowlist.find(e => e.check_id.toLowerCase() === lower)
      if (tagEntry) {
        await deleteMisconfigAllowlistEntry(project, repo, tagName, tagEntry.id, csrfToken)
        onAllowlistChange()
        return
      }
      const projectEntry = projectMisconfigAllowlist.find(e => e.check_id.toLowerCase() === lower)
      if (projectEntry) {
        await deleteProjectMisconfigAllowlistEntry(project, projectEntry.id, csrfToken)
        onAllowlistChange()
      }
    } finally {
      setRemovingId(null)
    }
  }

  return (
    <div className='mt-3 rounded-md border text-xs overflow-x-auto'>
      <table className='w-full'>
        <thead>
          <tr className='border-b bg-muted/50'>
            <th className='w-7 px-2 py-2' />
            <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>ID</th>
            <th className='px-3 py-2 text-left font-medium'>Severity</th>
            <th className='sticky right-0 w-8 px-2 py-2 bg-muted/50 shadow-[-1px_0_0_0_hsl(var(--border))]' />
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => {
            const checkId = (f.avd_id || f.id || '').toUpperCase()
            const isSuppressed = !!f.suppressed || suppressedIds.has(checkId.toLowerCase())
            return (
              <Fragment key={i}>
                <tr className={`border-b last:border-0 cursor-pointer hover:bg-muted/30 transition-colors ${isSuppressed ? 'opacity-50' : ''}`} onClick={() => toggle(i)}>
                  <td className='px-2 py-1.5 text-muted-foreground'>
                    <ChevronDownIcon className={`size-3.5 transition-transform duration-150 ${expanded.has(i) ? 'rotate-180' : ''}`} />
                  </td>
                  <td className='px-3 py-1.5 font-mono break-all'>
                    {f.avd_id || f.id}
                    {isSuppressed && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>suppressed</span>}
                  </td>
                  <td className='px-3 py-1.5'>
                    <span className={`rounded-full px-1.5 py-0.5 font-medium capitalize ${severityColors[f.severity?.toLowerCase()] ?? 'bg-muted text-muted-foreground'}`}>{f.severity}</span>
                  </td>
                  <td className='sticky right-0 px-2 py-1.5 bg-background shadow-[-1px_0_0_0_hsl(var(--border))]' onClick={e => e.stopPropagation()}>
                    {isSuppressed ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button type='button'
                            onClick={() => unsuppress(checkId)}
                            disabled={!allowlistsReady || removingId === checkId.toLowerCase()}
                            className='text-muted-foreground hover:text-destructive transition-colors disabled:opacity-40 disabled:cursor-not-allowed'>
                            {removingId === checkId.toLowerCase()
                              ? <RefreshCwIcon className='size-3.5 animate-spin' />
                              : <XIcon className='size-3.5' />}
                          </button>
                        </TooltipTrigger>
                        <TooltipContent side='left'>Remove from allowlist</TooltipContent>
                      </Tooltip>
                    ) : (
                      <Tooltip>
                         <Popover onOpenChange={(open) => { if (open) setReasonDraft('') }}>
                           <TooltipTrigger asChild>
                             <PopoverTrigger asChild>
                               <button type='button' className='text-muted-foreground hover:text-foreground transition-colors'>
                                 <PlusIcon className='size-3.5' />
                               </button>
                             </PopoverTrigger>
                           </TooltipTrigger>
                           <TooltipContent side='left'>Add to allowlist</TooltipContent>
                           <PopoverContent className='w-64 p-3 space-y-3' align='end'>
                             <p className='text-xs font-medium'>Suppress {f.avd_id || f.id}</p>
                             <input
                               type='text'
                               placeholder='Reason (optional)'
                               value={reasonDraft}
                               onChange={e => setReasonDraft(e.target.value)}
                              className='w-full h-7 rounded-md border bg-background px-2 text-xs outline-none focus:ring-1 focus:ring-ring'
                            />
                            <Button
                              size='sm'
                              className='w-full h-7 text-xs'
                              disabled={addingId === checkId}
                              onClick={() => suppress(checkId)}
                            >
                              {addingId === checkId ? <RefreshCwIcon className='size-3 animate-spin' /> : 'Suppress'}
                            </Button>
                          </PopoverContent>
                        </Popover>
                      </Tooltip>
                    )}
                  </td>
                </tr>
                {expanded.has(i) && (
                  <tr className='border-b last:border-0 bg-muted/20'>
                    <td colSpan={5} className='px-4 py-3'>
                      <div className='space-y-1.5 text-xs'>
                        {f.title && <p className='font-medium text-foreground'>{f.title}</p>}
                        {f.description && <p className='text-muted-foreground leading-relaxed'>{f.description}</p>}
                        <div className='flex flex-wrap gap-x-6 gap-y-1 text-muted-foreground'>
                          {f.status && <span><span className='font-medium text-foreground'>Status: </span><span className={`rounded-full px-1.5 py-0.5 font-medium ${f.status === 'FAIL' ? severityColors['high'] : severityColors['medium']}`}>{f.status}</span></span>}
                          {f.type && <span><span className='font-medium text-foreground'>Type: </span>{f.type}</span>}
                          {f.class && <span><span className='font-medium text-foreground'>Class: </span>{f.class}</span>}
                        </div>
                        {f.message && <pre className='rounded bg-muted px-3 py-2 font-mono text-xs text-muted-foreground overflow-x-auto whitespace-pre-wrap break-all'>{f.message}</pre>}
                        {f.resolution && <p><span className='font-medium text-foreground'>Resolution: </span><span className='text-muted-foreground'>{f.resolution}</span></p>}
                        {(f.references ?? []).length > 0 && (
                          <div className='flex flex-wrap gap-x-3 gap-y-0.5'>
                            <span className='font-medium text-foreground'>References: </span>
                            {(f.references ?? []).slice(0, 4).map((ref, ri) => (
                              <a key={ri} href={ref} target='_blank' rel='noopener noreferrer' className='text-blue-600 dark:text-blue-400 hover:underline truncate max-w-[320px]' title={ref}>
                                {ref.replace(/^https?:\/\//, '').split('/')[0]}
                              </a>
                            ))}
                            {(f.references ?? []).length > 4 && <span className='text-muted-foreground'>+{(f.references ?? []).length - 4} more</span>}
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

const MISCONFIG_STATUSES = ['FAIL', 'WARN', 'PASS'] as const
const MISCONFIG_STATUS_COLORS: Record<string, string> = {
  FAIL: severityColors['high'],
  WARN: severityColors['medium'],
  PASS: 'bg-green-600/10 text-green-600 dark:bg-green-400/10 dark:text-green-400',
}

function MisconfigTabContent({
  scan,
  misconfigAllowlist,
  projectMisconfigAllowlist,
  allowlistsReady,
  project,
  repo,
  tagName,
  csrfToken,
  onMisconfigAllowlistChange,
}: {
  scan: MisconfigScanReport
  misconfigAllowlist: MisconfigAllowlistEntry[]
  projectMisconfigAllowlist: MisconfigAllowlistEntry[]
  allowlistsReady: boolean
  project: string
  repo: string
  tagName: string
  csrfToken: string
  onMisconfigAllowlistChange: () => void
}) {
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [sevFilter, setSevFilter] = useState<string>('all')
  const [search, setSearch] = useState('')
  const [showSuppressed, setShowSuppressed] = useState(false)

  // suppressedIds covers both tag-scoped and project-wide entries.
  // Used as an optimistic fallback alongside the backend-annotated f.suppressed field.
  const suppressedIds = new Set([
    ...misconfigAllowlist.filter(e => !e.is_expired).map(e => e.check_id.toLowerCase()),
    ...projectMisconfigAllowlist.filter(e => !e.is_expired).map(e => e.check_id.toLowerCase()),
  ])

  const sorted = [...scan.report].sort(
    (a, b) => (severityOrder[a.severity?.toLowerCase()] ?? 6) - (severityOrder[b.severity?.toLowerCase()] ?? 6)
  )

  // Filter using backend-annotated suppressed field (reliable on initial load)
  const activeSorted = sorted.filter(f => showSuppressed || !f.suppressed)
  const suppressedCount = sorted.filter(f => f.suppressed).length

  // Severity counts derived from active (unsuppressed) findings
  const sevCounts = SEVERITIES.reduce<Record<string, number>>((acc, sev) => {
    acc[sev] = activeSorted.filter(f => f.severity?.toLowerCase() === sev).length
    return acc
  }, {})

  const filtered = activeSorted.filter(f => {
    if (statusFilter !== 'all' && f.status !== statusFilter) return false
    if (sevFilter !== 'all' && f.severity?.toLowerCase() !== sevFilter) return false
    if (search) {
      const q = search.toLowerCase()
      if (
        !(f.avd_id || f.id).toLowerCase().includes(q) &&
        !(f.title ?? '').toLowerCase().includes(q)
      ) return false
    }
    return true
  })

  const hasFilter = statusFilter !== 'all' || sevFilter !== 'all' || search !== ''

  return (
    <div className='space-y-3'>
      {/* Status badges — clickable filter, use backend-adjusted summary counts */}
      <div className='flex flex-wrap gap-2'>
        {MISCONFIG_STATUSES.map(s => {
          const count = scan.summary[s] ?? 0
          if (count === 0) return null
          const active = statusFilter === s
          return (
            <button
              key={s}
              type='button'
              onClick={() => setStatusFilter(active ? 'all' : s)}
              className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium transition-opacity cursor-pointer hover:opacity-80 ${
                MISCONFIG_STATUS_COLORS[s]
              } ${!active && statusFilter !== 'all' ? 'opacity-40' : 'opacity-100'}`}
            >
              {s === 'PASS' ? <ShieldCheckIcon className='size-3' /> : <ShieldAlertIcon className='size-3' />}
              {s}: {count}
            </button>
          )
        })}
        {Object.values(scan.summary).every(v => v === 0) && (
          <span className='inline-flex items-center gap-1 rounded-full bg-green-600/10 px-2.5 py-0.5 text-xs font-medium text-green-600 dark:bg-green-400/10 dark:text-green-400'>
            <ShieldCheckIcon className='size-3' />
            No misconfigurations found
          </span>
        )}
      </div>

      {/* Severity badges — clickable filter */}
      {activeSorted.length > 0 && SEVERITIES.some(sev => sevCounts[sev] > 0) && (
        <div className='flex flex-wrap gap-2'>
          {SEVERITIES.map(sev => {
            const count = sevCounts[sev]
            if (count === 0) return null
            const active = sevFilter === sev
            return (
              <button
                key={sev}
                type='button'
                onClick={() => setSevFilter(active ? 'all' : sev)}
                className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium transition-opacity cursor-pointer hover:opacity-80 ${
                  severityColors[sev] ?? 'bg-muted text-muted-foreground'
                } ${!active && sevFilter !== 'all' ? 'opacity-40' : 'opacity-100'}`}
              >
                <ShieldAlertIcon className='size-3' />
                {sev.charAt(0).toUpperCase() + sev.slice(1)}: {count}
              </button>
            )
          })}
        </div>
      )}

      {/* Filter bar */}
      {scan.report.length > 0 && (
        <div className='flex items-center gap-2'>
          <div className='relative'>
            <SearchIcon className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
            <input
              type='search'
              placeholder='ID or title…'
              value={search}
              onChange={e => setSearch(e.target.value)}
              className='h-8 w-64 rounded-md border bg-background pl-8 pr-3 text-xs outline-none focus:ring-1 focus:ring-ring'
            />
          </div>
          {hasFilter && (
            <button type='button'
              onClick={() => { setStatusFilter('all'); setSevFilter('all'); setSearch('') }}
              className='text-xs text-muted-foreground hover:text-foreground transition-colors'>
              Clear filters
            </button>
          )}
          {suppressedCount > 0 && (
            <button type='button' onClick={() => setShowSuppressed(v => !v)}
              className='text-xs text-muted-foreground hover:text-foreground transition-colors ml-2'>
              {showSuppressed ? 'Hide' : 'Show'} {suppressedCount} suppressed
            </button>
          )}
          <span className='ml-auto text-xs text-muted-foreground'>
            {filtered.length === scan.report.length
              ? `${scan.report.length} finding${scan.report.length !== 1 ? 's' : ''}`
              : `${filtered.length} of ${scan.report.length} findings`}
          </span>
        </div>
      )}

      {filtered.length === 0 && hasFilter ? (
        <p className='text-sm text-muted-foreground py-4 text-center'>No findings match the current filters.</p>
      ) : filtered.length > 0 ? (
        <MisconfigTable
          findings={filtered}
          suppressedIds={suppressedIds}
          misconfigAllowlist={misconfigAllowlist}
          projectMisconfigAllowlist={projectMisconfigAllowlist}
          allowlistsReady={allowlistsReady}
          project={project}
          repo={repo}
          tagName={tagName}
          csrfToken={csrfToken}
          onAllowlistChange={onMisconfigAllowlistChange}
        />
      ) : null}

      <MisconfigImageAllowlistSection
        misconfigAllowlist={misconfigAllowlist}
        scanReport={scan.report}
        project={project}
        repo={repo}
        tagName={tagName}
        csrfToken={csrfToken}
        onAllowlistChange={onMisconfigAllowlistChange}
      />
      <ProjectMisconfigAllowlistSection
        projectMisconfigAllowlist={projectMisconfigAllowlist}
        scanReport={scan.report}
        project={project}
        csrfToken={csrfToken}
        onAllowlistChange={onMisconfigAllowlistChange}
      />
    </div>
  )
}

function MisconfigImageAllowlistSection({
  misconfigAllowlist,
  scanReport,
  project,
  repo,
  tagName,
  csrfToken,
  onAllowlistChange,
}: {
  misconfigAllowlist: MisconfigAllowlistEntry[]
  scanReport: MisconfigFinding[]
  project: string
  repo: string
  tagName: string
  csrfToken: string
  onAllowlistChange: () => void
}) {
  const [newCheckId, setNewCheckId] = useState('')
  const [newReason, setNewReason] = useState('')
  const [adding, setAdding] = useState(false)

  const addEntry = async () => {
    if (!newCheckId.trim()) return
    setAdding(true)
    try {
      await createMisconfigAllowlistEntry(project, repo, tagName, { check_id: newCheckId.trim(), reason: newReason.trim() || undefined }, csrfToken)
      setNewCheckId('')
      setNewReason('')
      onAllowlistChange()
    } catch { /* ignore */ }
    setAdding(false)
  }

  const removeEntry = async (id: number) => {
    await deleteMisconfigAllowlistEntry(project, repo, tagName, id, csrfToken)
    onAllowlistChange()
  }

  return (
    <div className='mt-4 space-y-2'>
      <div className='flex items-center gap-2'>
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Misconfig suppressions</p>
        {misconfigAllowlist.length > 0 && (
          <span className='rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>{misconfigAllowlist.length}</span>
        )}
      </div>
      <p className='text-xs text-muted-foreground'>Suppressed checks are hidden from the count and findings table for this image.</p>
      <div className='flex gap-2'>
        <input type='text' placeholder='AVD-DS-0002 or DS002'
          value={newCheckId} onChange={e => setNewCheckId(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') addEntry() }}
          className='h-7 w-48 rounded-md border bg-background px-2 font-mono text-xs outline-none focus:ring-1 focus:ring-ring' />
        <input type='text' placeholder='Reason (optional)'
          value={newReason} onChange={e => setNewReason(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') addEntry() }}
          className='h-7 flex-1 rounded-md border bg-background px-2 text-xs outline-none focus:ring-1 focus:ring-ring' />
        <Button size='sm' variant='outline' className='h-7 text-xs px-2' disabled={adding || !newCheckId.trim()} onClick={addEntry}>
          {adding ? <RefreshCwIcon className='size-3 animate-spin' /> : <PlusIcon className='size-3' />}
        </Button>
      </div>
      {misconfigAllowlist.length === 0 ? (
        <p className='text-xs text-muted-foreground italic'>No suppressions for this image.</p>
      ) : (
        <div className='rounded-md border text-xs overflow-x-auto'>
          <table className='w-full'>
            <thead>
              <tr className='border-b bg-muted/50'>
                <th className='px-3 py-1.5 text-left font-medium whitespace-nowrap'>Check ID</th>
                <th className='px-3 py-1.5 text-left font-medium'>Finding</th>
                <th className='px-3 py-1.5 text-left font-medium'>Reason</th>
                <th className='px-3 py-1.5 text-left font-medium whitespace-nowrap'>Added by</th>
                <th className='w-8 px-2 py-1.5' />
              </tr>
            </thead>
            <tbody>
              {misconfigAllowlist.map(entry => {
                const finding = scanReport.find(f =>
                  (f.avd_id || f.id || '').toUpperCase() === entry.check_id.toUpperCase()
                )
                return (
                  <tr key={entry.id} className={`border-b last:border-0 ${entry.is_expired ? 'opacity-40' : ''}`}>
                    <td className='px-3 py-1.5 font-mono whitespace-nowrap'>
                      {entry.check_id}
                      {entry.is_expired && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>expired</span>}
                    </td>
                    <td className='px-3 py-1.5'>
                      {finding ? (
                        <div className='flex items-center gap-2'>
                          <span className={`shrink-0 rounded-full px-1.5 py-0.5 font-medium capitalize ${severityColors[finding.severity?.toLowerCase()] ?? 'bg-muted text-muted-foreground'}`}>
                            {finding.severity}
                          </span>
                          <span className='text-muted-foreground truncate max-w-[240px]' title={finding.title || finding.description}>
                            {finding.title || finding.description || '—'}
                          </span>
                        </div>
                      ) : (
                        <span className='text-muted-foreground italic'>not in current scan</span>
                      )}
                    </td>
                    <td className='px-3 py-1.5 text-muted-foreground'>{entry.reason || '—'}</td>
                    <td className='px-3 py-1.5 text-muted-foreground whitespace-nowrap'>{entry.added_by_username ?? '—'}</td>
                    <td className='px-2 py-1.5'>
                      <button type='button' onClick={() => removeEntry(entry.id)}
                        className='text-muted-foreground hover:text-destructive transition-colors' title='Remove'>
                        <XIcon className='size-3.5' />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function ProjectMisconfigAllowlistSection({
  projectMisconfigAllowlist,
  scanReport,
  project,
  csrfToken,
  onAllowlistChange,
}: {
  projectMisconfigAllowlist: MisconfigAllowlistEntry[]
  scanReport: MisconfigFinding[]
  project: string
  csrfToken: string
  onAllowlistChange: () => void
}) {
  const removeEntry = async (id: number) => {
    await deleteProjectMisconfigAllowlistEntry(project, id, csrfToken)
    onAllowlistChange()
  }

  if (projectMisconfigAllowlist.length === 0) return null

  return (
    <div className='mt-4 space-y-2'>
      <div className='flex items-center gap-2'>
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Project-wide suppressions</p>
        <span className='rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>{projectMisconfigAllowlist.length}</span>
      </div>
      <p className='text-xs text-muted-foreground'>
        These suppressions apply to all images in the project. Removing them affects every image, not just this one.
      </p>
      <div className='rounded-md border text-xs overflow-x-auto'>
        <table className='w-full'>
          <thead>
            <tr className='border-b bg-muted/50'>
              <th className='px-3 py-1.5 text-left font-medium whitespace-nowrap'>Check ID</th>
              <th className='px-3 py-1.5 text-left font-medium'>Finding</th>
              <th className='px-3 py-1.5 text-left font-medium'>Reason</th>
              <th className='px-3 py-1.5 text-left font-medium whitespace-nowrap'>Added by</th>
              <th className='w-8 px-2 py-1.5' />
            </tr>
          </thead>
          <tbody>
            {projectMisconfigAllowlist.map(entry => {
              const finding = scanReport.find(f =>
                (f.avd_id || f.id || '').toUpperCase() === entry.check_id.toUpperCase()
              )
              return (
                <tr key={entry.id} className={`border-b last:border-0 ${entry.is_expired ? 'opacity-40' : ''}`}>
                  <td className='px-3 py-1.5 font-mono whitespace-nowrap'>
                    {entry.check_id}
                    {entry.is_expired && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>expired</span>}
                  </td>
                  <td className='px-3 py-1.5'>
                    {finding ? (
                      <div className='flex items-center gap-2'>
                        <span className={`shrink-0 rounded-full px-1.5 py-0.5 font-medium capitalize ${severityColors[finding.severity?.toLowerCase()] ?? 'bg-muted text-muted-foreground'}`}>
                          {finding.severity}
                        </span>
                        <span className='text-muted-foreground truncate max-w-[240px]' title={finding.title || finding.description}>
                          {finding.title || finding.description || '—'}
                        </span>
                      </div>
                    ) : (
                      <span className='text-muted-foreground italic'>not in current scan</span>
                    )}
                  </td>
                  <td className='px-3 py-1.5 text-muted-foreground'>{entry.reason || '—'}</td>
                  <td className='px-3 py-1.5 text-muted-foreground whitespace-nowrap'>{entry.added_by_username ?? '—'}</td>
                  <td className='px-2 py-1.5'>
                    <button type='button' onClick={() => removeEntry(entry.id)}
                      className='text-muted-foreground hover:text-destructive transition-colors' title='Remove project-wide suppression'>
                      <XIcon className='size-3.5' />
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function SecretTabContent({
  scan,
  secretAllowlist,
  projectSecretAllowlist,
  allowlistsReady,
  project,
  repo,
  tagName,
  csrfToken,
  onSecretAllowlistChange,
}: {
  scan: SecretScanReport
  secretAllowlist: SecretAllowlistEntry[]
  projectSecretAllowlist: SecretAllowlistEntry[]
  allowlistsReady: boolean
  project: string
  repo: string
  tagName: string
  csrfToken: string
  onSecretAllowlistChange: () => void
}) {
  const [search, setSearch] = useState('')
  const [showSuppressed, setShowSuppressed] = useState(false)

  // suppressedIds covers both tag-scoped and project-wide entries.
  // Used as an optimistic fallback: if f.suppressed is already true from the backend,
  // the row shows suppressed immediately; this set covers the gap between an inline
  // suppress action and the next scan report reload completing.
  const suppressedIds = new Set([
    ...secretAllowlist.filter(e => !e.is_expired).map(e => e.rule_id.toLowerCase()),
    ...projectSecretAllowlist.filter(e => !e.is_expired).map(e => e.rule_id.toLowerCase()),
  ])

  const allFiltered = scan.report.filter(f => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      (f.rule_id ?? '').toLowerCase().includes(q) ||
      (f.title ?? '').toLowerCase().includes(q) ||
      (f.target ?? '').toLowerCase().includes(q)
    )
  })

  // Filter using backend-annotated suppressed field (reliable on initial load)
  const filtered = allFiltered.filter(f => showSuppressed || !f.suppressed)
  const suppressedCount = allFiltered.filter(f => f.suppressed).length
  const hasFilter = search !== ''

  const activeTotal = scan.total  // already subtracted by the backend

  return (
    <div className='space-y-3'>
      {/* Count badge */}
      {activeTotal === 0 ? (
        <span className='inline-flex items-center gap-1 rounded-full bg-green-600/10 px-2.5 py-0.5 text-xs font-medium text-green-600 dark:bg-green-400/10 dark:text-green-400'>
          <ShieldCheckIcon className='size-3' />
          No secrets found
        </span>
      ) : (
        <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ${severityColors['critical']}`}>
          <KeySquareIcon className='size-3' />
          {activeTotal} secret{activeTotal !== 1 ? 's' : ''} found
        </span>
      )}

      {/* Search bar */}
      {scan.report.length > 0 && (
        <div className='flex items-center gap-2'>
          <div className='relative'>
            <SearchIcon className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
            <input
              type='search'
              placeholder='Rule ID, title, or target…'
              value={search}
              onChange={e => setSearch(e.target.value)}
              className='h-8 w-64 rounded-md border bg-background pl-8 pr-3 text-xs outline-none focus:ring-1 focus:ring-ring'
            />
          </div>
          {hasFilter && (
            <button type='button' onClick={() => setSearch('')}
              className='text-xs text-muted-foreground hover:text-foreground transition-colors'>
              Clear
            </button>
          )}
          {suppressedCount > 0 && (
            <button type='button' onClick={() => setShowSuppressed(v => !v)}
              className='text-xs text-muted-foreground hover:text-foreground transition-colors ml-2'>
              {showSuppressed ? 'Hide' : 'Show'} {suppressedCount} suppressed
            </button>
          )}
          <span className='ml-auto text-xs text-muted-foreground'>
            {filtered.length === scan.report.length
              ? `${scan.report.length} finding${scan.report.length !== 1 ? 's' : ''}`
              : `${filtered.length} of ${scan.report.length} findings`}
          </span>
        </div>
      )}

      {filtered.length === 0 && hasFilter ? (
        <p className='text-sm text-muted-foreground py-4 text-center'>No findings match the current search.</p>
      ) : filtered.length > 0 ? (
        <SecretTable
          findings={filtered}
          suppressedIds={suppressedIds}
          secretAllowlist={secretAllowlist}
          projectSecretAllowlist={projectSecretAllowlist}
          allowlistsReady={allowlistsReady}
          project={project}
          repo={repo}
          tagName={tagName}
          csrfToken={csrfToken}
          onAllowlistChange={onSecretAllowlistChange}
        />
      ) : null}

      <SecretImageAllowlistSection
        secretAllowlist={secretAllowlist}
        scanReport={scan.report}
        project={project}
        repo={repo}
        tagName={tagName}
        csrfToken={csrfToken}
        onAllowlistChange={onSecretAllowlistChange}
      />
      <ProjectSecretAllowlistSection
        projectSecretAllowlist={projectSecretAllowlist}
        scanReport={scan.report}
        project={project}
        csrfToken={csrfToken}
        onAllowlistChange={onSecretAllowlistChange}
      />
    </div>
  )
}

function SecretImageAllowlistSection({
  secretAllowlist,
  scanReport,
  project,
  repo,
  tagName,
  csrfToken,
  onAllowlistChange,
}: {
  secretAllowlist: SecretAllowlistEntry[]
  scanReport: SecretFinding[]
  project: string
  repo: string
  tagName: string
  csrfToken: string
  onAllowlistChange: () => void
}) {
  const [newRuleId, setNewRuleId] = useState('')
  const [newReason, setNewReason] = useState('')
  const [adding, setAdding] = useState(false)

  const addEntry = async () => {
    if (!newRuleId.trim()) return
    setAdding(true)
    try {
      await createSecretAllowlistEntry(project, repo, tagName, { rule_id: newRuleId.trim(), reason: newReason.trim() || undefined }, csrfToken)
      setNewRuleId('')
      setNewReason('')
      onAllowlistChange()
    } catch { /* ignore */ }
    setAdding(false)
  }

  const removeEntry = async (id: number) => {
    await deleteSecretAllowlistEntry(project, repo, tagName, id, csrfToken)
    onAllowlistChange()
  }

  return (
    <div className='mt-4 space-y-2'>
      <div className='flex items-center gap-2'>
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Secret suppressions</p>
        {secretAllowlist.length > 0 && (
          <span className='rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>{secretAllowlist.length}</span>
        )}
      </div>
      <p className='text-xs text-muted-foreground'>Suppressed rules are hidden from the count and findings table for this image.</p>
      <div className='flex gap-2'>
        <input type='text' placeholder='rule_id, e.g. aws-access-key-id'
          value={newRuleId} onChange={e => setNewRuleId(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') addEntry() }}
          className='h-7 w-56 rounded-md border bg-background px-2 font-mono text-xs outline-none focus:ring-1 focus:ring-ring' />
        <input type='text' placeholder='Reason (optional)'
          value={newReason} onChange={e => setNewReason(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') addEntry() }}
          className='h-7 flex-1 rounded-md border bg-background px-2 text-xs outline-none focus:ring-1 focus:ring-ring' />
        <Button size='sm' variant='outline' className='h-7 text-xs px-2' disabled={adding || !newRuleId.trim()} onClick={addEntry}>
          {adding ? <RefreshCwIcon className='size-3 animate-spin' /> : <PlusIcon className='size-3' />}
        </Button>
      </div>
      {secretAllowlist.length === 0 ? (
        <p className='text-xs text-muted-foreground italic'>No suppressions for this image.</p>
      ) : (
        <div className='rounded-md border text-xs overflow-x-auto'>
          <table className='w-full'>
            <thead>
              <tr className='border-b bg-muted/50'>
                <th className='px-3 py-1.5 text-left font-medium whitespace-nowrap'>Rule ID</th>
                <th className='px-3 py-1.5 text-left font-medium'>Finding</th>
                <th className='px-3 py-1.5 text-left font-medium'>Reason</th>
                <th className='px-3 py-1.5 text-left font-medium whitespace-nowrap'>Added by</th>
                <th className='w-8 px-2 py-1.5' />
              </tr>
            </thead>
            <tbody>
              {secretAllowlist.map(entry => {
                const finding = scanReport.find(f => f.rule_id.toLowerCase() === entry.rule_id.toLowerCase())
                return (
                  <tr key={entry.id} className={`border-b last:border-0 ${entry.is_expired ? 'opacity-40' : ''}`}>
                    <td className='px-3 py-1.5 font-mono whitespace-nowrap'>
                      {entry.rule_id}
                      {entry.is_expired && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>expired</span>}
                    </td>
                    <td className='px-3 py-1.5'>
                      {finding ? (
                        <div className='flex items-center gap-2'>
                          <span className={`shrink-0 rounded-full px-1.5 py-0.5 font-medium capitalize ${severityColors[finding.severity?.toLowerCase()] ?? 'bg-muted text-muted-foreground'}`}>
                            {finding.severity}
                          </span>
                          <span className='text-muted-foreground truncate max-w-[240px]' title={finding.title || finding.target}>
                            {finding.title || finding.target || '—'}
                          </span>
                        </div>
                      ) : (
                        <span className='text-muted-foreground italic'>not in current scan</span>
                      )}
                    </td>
                    <td className='px-3 py-1.5 text-muted-foreground'>{entry.reason || '—'}</td>
                    <td className='px-3 py-1.5 text-muted-foreground whitespace-nowrap'>{entry.added_by_username ?? '—'}</td>
                    <td className='px-2 py-1.5'>
                      <button type='button' onClick={() => removeEntry(entry.id)}
                        className='text-muted-foreground hover:text-destructive transition-colors' title='Remove'>
                        <XIcon className='size-3.5' />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function ProjectSecretAllowlistSection({
  projectSecretAllowlist,
  scanReport,
  project,
  csrfToken,
  onAllowlistChange,
}: {
  projectSecretAllowlist: SecretAllowlistEntry[]
  scanReport: SecretFinding[]
  project: string
  csrfToken: string
  onAllowlistChange: () => void
}) {
  const removeEntry = async (id: number) => {
    await deleteProjectSecretAllowlistEntry(project, id, csrfToken)
    onAllowlistChange()
  }

  if (projectSecretAllowlist.length === 0) return null

  return (
    <div className='mt-4 space-y-2'>
      <div className='flex items-center gap-2'>
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Project-wide suppressions</p>
        <span className='rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>{projectSecretAllowlist.length}</span>
      </div>
      <p className='text-xs text-muted-foreground'>
        These suppressions apply to all images in the project. Removing them affects every image, not just this one.
      </p>
      <div className='rounded-md border text-xs overflow-x-auto'>
        <table className='w-full'>
          <thead>
            <tr className='border-b bg-muted/50'>
              <th className='px-3 py-1.5 text-left font-medium whitespace-nowrap'>Rule ID</th>
              <th className='px-3 py-1.5 text-left font-medium'>Finding</th>
              <th className='px-3 py-1.5 text-left font-medium'>Reason</th>
              <th className='px-3 py-1.5 text-left font-medium whitespace-nowrap'>Added by</th>
              <th className='w-8 px-2 py-1.5' />
            </tr>
          </thead>
          <tbody>
            {projectSecretAllowlist.map(entry => {
              const finding = scanReport.find(f => f.rule_id.toLowerCase() === entry.rule_id.toLowerCase())
              return (
                <tr key={entry.id} className={`border-b last:border-0 ${entry.is_expired ? 'opacity-40' : ''}`}>
                  <td className='px-3 py-1.5 font-mono whitespace-nowrap'>
                    {entry.rule_id}
                    {entry.is_expired && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>expired</span>}
                  </td>
                  <td className='px-3 py-1.5'>
                    {finding ? (
                      <div className='flex items-center gap-2'>
                        <span className={`shrink-0 rounded-full px-1.5 py-0.5 font-medium capitalize ${severityColors[finding.severity?.toLowerCase()] ?? 'bg-muted text-muted-foreground'}`}>
                          {finding.severity}
                        </span>
                        <span className='text-muted-foreground truncate max-w-[240px]' title={finding.title || finding.target}>
                          {finding.title || finding.target || '—'}
                        </span>
                      </div>
                    ) : (
                      <span className='text-muted-foreground italic'>not in current scan</span>
                    )}
                  </td>
                  <td className='px-3 py-1.5 text-muted-foreground'>{entry.reason || '—'}</td>
                  <td className='px-3 py-1.5 text-muted-foreground whitespace-nowrap'>{entry.added_by_username ?? '—'}</td>
                  <td className='px-2 py-1.5'>
                    <button type='button' onClick={() => removeEntry(entry.id)}
                      className='text-muted-foreground hover:text-destructive transition-colors' title='Remove project-wide suppression'>
                      <XIcon className='size-3.5' />
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function VulnDetail({ cve }: { cve: VulnFinding }) {
  const refs = cve.references ?? []
  const cwes = cve.cwe_ids ?? []
  return (
    <div className='space-y-2 text-xs'>
      {cve.title && <p className='font-medium text-foreground'>{cve.title}</p>}
      {cve.description && <p className='text-muted-foreground leading-relaxed'>{cve.description}</p>}
      <div className='flex flex-wrap gap-x-6 gap-y-1'>
        {cve.cvss_v3_score != null ? (
          <span>
            <span className='font-medium text-foreground'>CVSS v3: </span>
            <span className={`font-medium ${
              cve.cvss_v3_score >= 9 ? 'text-red-600 dark:text-red-400'
              : cve.cvss_v3_score >= 7 ? 'text-orange-600 dark:text-orange-400'
              : cve.cvss_v3_score >= 4 ? 'text-yellow-600 dark:text-yellow-400'
              : 'text-foreground'
            }`}>{cve.cvss_v3_score.toFixed(1)}</span>
            {cve.cvss_v3_vector && <span className='font-mono ml-1 text-muted-foreground'>{cve.cvss_v3_vector}</span>}
          </span>
        ) : cve.cvss_v2_score != null ? (
          <span><span className='font-medium text-foreground'>CVSS v2: </span><span className='text-muted-foreground'>{cve.cvss_v2_score.toFixed(1)}</span></span>
        ) : (
          <span className='text-muted-foreground'>No CVSS score available</span>
        )}
        {cve.target && <span><span className='font-medium text-foreground'>Target: </span><span className='font-mono text-muted-foreground'>{cve.target}</span></span>}
        {cve.pkg_type && <span><span className='font-medium text-foreground'>Type: </span><span className='text-muted-foreground'>{cve.pkg_type}</span></span>}
        {cve.data_source && <span><span className='font-medium text-foreground'>Source: </span><span className='text-muted-foreground'>{cve.data_source}</span></span>}
        {cve.published_date && <span><span className='font-medium text-foreground'>Published: </span><span className='text-muted-foreground'>{new Date(cve.published_date).toLocaleDateString()}</span></span>}
        {cve.last_modified_date && <span><span className='font-medium text-foreground'>Modified: </span><span className='text-muted-foreground'>{new Date(cve.last_modified_date).toLocaleDateString()}</span></span>}
      </div>
      {cwes.length > 0 && (
        <div className='flex flex-wrap gap-1'>
          {cwes.map(cwe => (
            <span key={cwe} className='rounded bg-muted px-1.5 py-0.5 font-mono text-muted-foreground'>{cwe}</span>
          ))}
        </div>
      )}
      {refs.length > 0 && (
        <div className='flex flex-wrap gap-x-3 gap-y-0.5'>
          <span className='font-medium text-foreground'>References: </span>
          {refs.slice(0, 5).map((ref, ri) => (
            <a key={ri} href={ref} target='_blank' rel='noopener noreferrer'
              className='text-blue-600 dark:text-blue-400 hover:underline truncate max-w-[320px]' title={ref}>
              {ref.replace(/^https?:\/\//, '').split('/')[0]}
            </a>
          ))}
          {refs.length > 5 && <span className='text-muted-foreground'>+{refs.length - 5} more</span>}
        </div>
      )}
    </div>
  )
}

function VulnTable({
  vulns,
  allowlist,
  tagId,
  projectName,
  csrfToken,
  onAllowlistChange,
}: {
  vulns: VulnFinding[]
  allowlist: AllowlistEntry[]
  tagId: number
  projectName: string
  csrfToken: string
  onAllowlistChange: () => void
}) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [addingId, setAddingId] = useState<string | null>(null)
  const [reasonDraft, setReasonDraft] = useState('')
  const [scopeTag, setScopeTag] = useState(false)

  const toggle = (i: number) =>
    setExpanded(prev => { const s = new Set(prev); s.has(i) ? s.delete(i) : s.add(i); return s })

  const suppress = async (cveId: string) => {
    setAddingId(cveId)
    try {
      await createAllowlistEntry(projectName, {
        cve_id: cveId,
        reason: reasonDraft,
        tag_id: scopeTag ? tagId : null,
      }, csrfToken)
      setReasonDraft('')
      setScopeTag(false)
      onAllowlistChange()
    } catch { /* ignore */ }
    setAddingId(null)
  }

  const unsuppress = async (cveId: string) => {
    const lower = cveId.toLowerCase()
    // Prefer tag-specific entry; fall back to project-wide.
    // This matches SecretTable/MisconfigTable behaviour and ensures the
    // project-wide suppression is only removed when there is no tag-specific
    // entry to remove first.
    const tagEntry     = allowlist.find(e => e.cve_id.toLowerCase() === lower && e.tag_id === tagId)
    const projectEntry = allowlist.find(e => e.cve_id.toLowerCase() === lower && e.tag_id === null)
    const entry = tagEntry ?? projectEntry
    if (!entry) return
    await deleteAllowlistEntry(projectName, entry.id, csrfToken)
    onAllowlistChange()
  }

  return (
    <div className='mt-3 rounded-md border text-xs overflow-x-auto'>
      <table className='w-full'>
        <thead>
          <tr className='border-b bg-muted/50'>
            <th className='w-7 px-2 py-2' />
            <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>CVE / ID</th>
            <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>Package</th>
            <th className='px-3 py-2 text-left font-medium whitespace-nowrap'>Installed → Fixed</th>
            <th className='px-3 py-2 text-left font-medium'>Severity</th>
            <th className='sticky right-0 w-8 px-2 py-2 bg-muted/50 shadow-[-1px_0_0_0_hsl(var(--border))]' />
          </tr>
        </thead>
        <tbody>
          {vulns.map((cve, i) => {
            const isSuppressed = !!cve.suppressed
            const isAdding = addingId === cve.vulnerability_id
            return (
              <Fragment key={cve.vulnerability_id + i}>
                <tr
                  className={`border-b last:border-0 cursor-pointer hover:bg-muted/30 transition-colors ${isSuppressed ? 'opacity-50' : ''}`}
                  onClick={() => toggle(i)}
                >
                  <td className='px-2 py-1.5 text-muted-foreground'>
                    <ChevronDownIcon className={`size-3.5 transition-transform duration-150 ${expanded.has(i) ? 'rotate-180' : ''}`} />
                  </td>
                  <td className='px-3 py-1.5 font-mono break-all'>
                    {cve.vulnerability_id}
                    {isSuppressed && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>suppressed</span>}
                  </td>
                  <td className='px-3 py-1.5 break-all'>
                    {cve.pkg_name}
                    {cve.pkg_path && cve.pkg_path !== cve.pkg_name && (
                      <span className='ml-1 text-muted-foreground font-mono' title={cve.pkg_path}>
                        ({cve.pkg_path.split('/').pop()})
                      </span>
                    )}
                  </td>
                  <td className='px-3 py-1.5 font-mono break-all'>
                    <span className='text-muted-foreground'>{cve.installed_version}</span>
                    {cve.fixed_version
                      ? <> <span className='text-muted-foreground'>→</span> <span className='text-green-600 dark:text-green-400'>{cve.fixed_version}</span></>
                      : <span className='text-muted-foreground'> → no fix</span>}
                  </td>
                  <td className='px-3 py-1.5'>
                    <span className={`rounded-full px-1.5 py-0.5 font-medium capitalize ${severityColors[cve.severity] ?? 'bg-muted text-muted-foreground'}`}>
                      {cve.severity}
                    </span>
                  </td>
                  <td className='sticky right-0 px-2 py-1.5 bg-background shadow-[-1px_0_0_0_hsl(var(--border))]' onClick={e => e.stopPropagation()}>
                    {isSuppressed ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            type='button'
                            onClick={() => unsuppress(cve.vulnerability_id)}
                            className='text-muted-foreground hover:text-destructive transition-colors'
                          >
                            <XIcon className='size-3.5' />
                          </button>
                        </TooltipTrigger>
                        <TooltipContent side='left'>Remove from allowlist</TooltipContent>
                      </Tooltip>
                     ) : (
                      <Tooltip>
                         <Popover onOpenChange={(open) => { if (open) { setReasonDraft(''); setScopeTag(false) } }}>
                           <TooltipTrigger asChild>
                             <PopoverTrigger asChild>
                               <button
                                 type='button'
                                 className='text-muted-foreground hover:text-foreground transition-colors'
                               >
                                 <PlusIcon className='size-3.5' />
                               </button>
                             </PopoverTrigger>
                           </TooltipTrigger>
                           <TooltipContent side='left'>Add to allowlist</TooltipContent>
                         <PopoverContent className='w-72 p-3 space-y-3' align='end'>
                           <p className='text-xs font-medium'>Suppress {cve.vulnerability_id}</p>
                           <input
                             type='text'
                             placeholder='Reason (optional)'
                             value={reasonDraft}
                             onChange={e => setReasonDraft(e.target.value)}
                            className='w-full h-7 rounded-md border bg-background px-2 text-xs outline-none focus:ring-1 focus:ring-ring'
                          />
                          <div className='flex items-center gap-2'>
                            <input
                              id={`scope-tag-${i}`}
                              type='checkbox'
                              checked={scopeTag}
                              onChange={e => setScopeTag(e.target.checked)}
                              className='rounded'
                            />
                            <label htmlFor={`scope-tag-${i}`} className='text-xs text-muted-foreground cursor-pointer'>
                              This image only (tag-specific)
                            </label>
                          </div>
                          <Button
                            size='sm'
                            className='w-full h-7 text-xs'
                            disabled={isAdding}
                            onClick={() => suppress(cve.vulnerability_id)}
                          >
                            {isAdding ? <RefreshCwIcon className='size-3 animate-spin' /> : 'Suppress'}
                          </Button>
                        </PopoverContent>
                        </Popover>
                      </Tooltip>
                    )}
                  </td>
                </tr>
                {expanded.has(i) && (
                  <tr className='border-b last:border-0 bg-muted/20'>
                    <td colSpan={6} className='px-4 py-3'>
                      <VulnDetail cve={cve} />
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown']

function VulnTabContent({
  scan,
  allowlist,
  tagId,
  projectName,
  csrfToken,
  onAllowlistChange,
}: {
  scan: ScanReport
  allowlist: AllowlistEntry[]
  tagId: number
  projectName: string
  csrfToken: string
  onAllowlistChange: () => void
}) {
  const [sevFilter, setSevFilter] = useState<string>('all')
  const [cveSearch, setCveSearch] = useState('')
  const [showSuppressed, setShowSuppressed] = useState(false)
  const [fixableOnly, setFixableOnly] = useState(false)

  const sorted = [...scan.report].sort(
    (a, b) => (severityOrder[a.severity] ?? 6) - (severityOrder[b.severity] ?? 6)
  )

  const suppressedCount = sorted.filter(c => c.suppressed).length
  const fixableCount = sorted.filter(c => !c.suppressed && !!c.fixed_version).length

  const filtered = sorted.filter(cve => {
    if (!showSuppressed && cve.suppressed) return false
    if (fixableOnly && !cve.fixed_version) return false
    if (sevFilter !== 'all' && cve.severity !== sevFilter) return false
    if (cveSearch) {
      const q = cveSearch.toLowerCase()
      if (
        !cve.vulnerability_id.toLowerCase().includes(q) &&
        !cve.pkg_name.toLowerCase().includes(q) &&
        !(cve.title ?? '').toLowerCase().includes(q)
      ) return false
    }
    return true
  })

  const hasFilter = sevFilter !== 'all' || cveSearch !== '' || fixableOnly
  const activeCounts = sorted.filter(c => !c.suppressed)

  return (
    <div className='space-y-3'>
      {/* Summary badges — clickable as severity filter */}
      <div className='flex flex-wrap gap-2'>
        {SEVERITIES.map(sev => {
          const count = activeCounts.filter(c => c.severity === sev).length
          if (count === 0) return null
          const active = sevFilter === sev
          return (
            <button
              key={sev}
              type='button'
              onClick={() => setSevFilter(active ? 'all' : sev)}
              className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium transition-opacity ${
                severityColors[sev] ?? 'bg-muted text-muted-foreground'
              } ${!active && sevFilter !== 'all' ? 'opacity-40' : 'opacity-100'} cursor-pointer hover:opacity-80`}
            >
              <ShieldAlertIcon className='size-3' />
              {sev}: {count}
            </button>
          )
        })}
        {suppressedCount > 0 && (
          <button
            type='button'
            onClick={() => setShowSuppressed(s => !s)}
            className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium transition-opacity cursor-pointer hover:opacity-80 bg-muted text-muted-foreground ${showSuppressed ? 'ring-1 ring-ring' : ''}`}
          >
            <XIcon className='size-3' />
            {suppressedCount} suppressed
          </button>
        )}
        {activeCounts.length === 0 && suppressedCount === 0 && (
          <span className='inline-flex items-center gap-1 rounded-full bg-green-600/10 px-2.5 py-0.5 text-xs font-medium text-green-600 dark:bg-green-400/10 dark:text-green-400'>
            <ShieldCheckIcon className='size-3' />
            No vulnerabilities found
          </span>
        )}
        {activeCounts.length === 0 && suppressedCount > 0 && (
          <span className='inline-flex items-center gap-1 rounded-full bg-green-600/10 px-2.5 py-0.5 text-xs font-medium text-green-600 dark:bg-green-400/10 dark:text-green-400'>
            <ShieldCheckIcon className='size-3' />
            All vulnerabilities suppressed
          </span>
        )}
      </div>

      {/* Filter bar */}
      {scan.report.length > 0 && (
        <div className='flex items-center gap-2'>
          <div className='relative'>
            <SearchIcon className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
            <input
              type='search'
              placeholder='CVE ID, package, or title…'
              value={cveSearch}
              onChange={e => setCveSearch(e.target.value)}
              className='h-8 w-64 rounded-md border bg-background pl-8 pr-3 text-xs outline-none focus:ring-1 focus:ring-ring'
            />
          </div>
          {fixableCount > 0 && (
            <button
              type='button'
              onClick={() => setFixableOnly(v => !v)}
              className={`inline-flex items-center gap-1 rounded-md border px-2 h-8 text-xs transition-colors ${
                fixableOnly
                  ? 'border-green-600/40 bg-green-600/10 text-green-600 dark:border-green-400/40 dark:bg-green-400/10 dark:text-green-400'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <ShieldCheckIcon className='size-3.5' />
              {fixableOnly ? `${fixableCount} fixable` : `${fixableCount} fixable`}
            </button>
          )}
          {hasFilter && (
            <button
              type='button'
              onClick={() => { setSevFilter('all'); setCveSearch(''); setFixableOnly(false) }}
              className='text-xs text-muted-foreground hover:text-foreground transition-colors'
            >
              Clear filters
            </button>
          )}
          <span className='ml-auto text-xs text-muted-foreground'>
            {filtered.length === scan.report.length
              ? `${scan.report.length} CVE${scan.report.length !== 1 ? 's' : ''}`
              : `${filtered.length} of ${scan.report.length} CVEs`}
          </span>
        </div>
      )}

      {/* Table or empty state */}
      {filtered.length === 0 && hasFilter ? (
        <p className='text-sm text-muted-foreground py-4 text-center'>No CVEs match the current filters.</p>
      ) : filtered.length > 0 ? (
        <VulnTable
          vulns={filtered}
          allowlist={allowlist}
          tagId={tagId}
          projectName={projectName}
          csrfToken={csrfToken}
          onAllowlistChange={onAllowlistChange}
        />
      ) : null}

      {/* Image-specific suppressions */}
      <ImageAllowlistSection
        allowlist={allowlist}
        scanReport={scan.report}
        tagId={tagId}
        projectName={projectName}
        csrfToken={csrfToken}
        onAllowlistChange={onAllowlistChange}
      />
    </div>
  )
}

function ImageAllowlistSection({
  allowlist,
  scanReport,
  tagId,
  projectName,
  csrfToken,
  onAllowlistChange,
}: {
  allowlist: AllowlistEntry[]
  scanReport: VulnFinding[]
  tagId: number
  projectName: string
  csrfToken: string
  onAllowlistChange: () => void
}) {
  const [newCveId, setNewCveId] = useState('')
  const [newReason, setNewReason] = useState('')
  const [adding, setAdding] = useState(false)

  const tagEntries = allowlist.filter(e => e.tag_id === tagId)

  const addEntry = async () => {
    if (!newCveId.trim()) return
    setAdding(true)
    try {
      await createAllowlistEntry(projectName, {
        cve_id: newCveId.trim(),
        reason: newReason.trim() || undefined,
        tag_id: tagId,
      }, csrfToken)
      setNewCveId('')
      setNewReason('')
      onAllowlistChange()
    } catch { /* ignore */ }
    setAdding(false)
  }

  const removeEntry = async (id: number) => {
    await deleteAllowlistEntry(projectName, id, csrfToken)
    onAllowlistChange()
  }

  return (
    <div className='mt-4 space-y-2'>
      <div className='flex items-center gap-2'>
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Image-specific suppressions</p>
        {tagEntries.length > 0 && (
          <span className='rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>{tagEntries.length}</span>
        )}
      </div>
      <p className='text-xs text-muted-foreground'>
        These suppressions apply only to this image. Use the project settings page to manage project-wide suppressions.
      </p>

      {/* Quick-add row */}
      <div className='flex gap-2'>
        <input
          type='text'
          placeholder='CVE-2024-1234 or AVD-GO-0001'
          value={newCveId}
          onChange={e => setNewCveId(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') addEntry() }}
          className='h-7 w-48 rounded-md border bg-background px-2 font-mono text-xs outline-none focus:ring-1 focus:ring-ring'
        />
        <input
          type='text'
          placeholder='Reason (optional)'
          value={newReason}
          onChange={e => setNewReason(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') addEntry() }}
          className='h-7 flex-1 rounded-md border bg-background px-2 text-xs outline-none focus:ring-1 focus:ring-ring'
        />
        <Button size='sm' variant='outline' className='h-7 text-xs px-2' disabled={adding || !newCveId.trim()} onClick={addEntry}>
          {adding ? <RefreshCwIcon className='size-3 animate-spin' /> : <PlusIcon className='size-3' />}
        </Button>
      </div>

      {tagEntries.length === 0 ? (
        <p className='text-xs text-muted-foreground italic'>No image-specific suppressions.</p>
      ) : (
        <div className='rounded-md border text-xs overflow-x-auto'>
          <table className='w-full'>
            <thead>
              <tr className='border-b bg-muted/50'>
                <th className='px-3 py-1.5 text-left font-medium whitespace-nowrap'>CVE / ID</th>
                <th className='px-3 py-1.5 text-left font-medium'>Finding</th>
                <th className='px-3 py-1.5 text-left font-medium'>Reason</th>
                <th className='px-3 py-1.5 text-left font-medium whitespace-nowrap'>Added by</th>
                <th className='w-8 px-2 py-1.5' />
              </tr>
            </thead>
            <tbody>
              {tagEntries.map(entry => {
                const finding = scanReport.find(f => f.vulnerability_id.toLowerCase() === entry.cve_id.toLowerCase())
                return (
                  <tr key={entry.id} className={`border-b last:border-0 ${entry.is_expired ? 'opacity-40' : ''}`}>
                    <td className='px-3 py-1.5 font-mono whitespace-nowrap'>
                      {entry.cve_id}
                      {entry.is_expired && <span className='ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground'>expired</span>}
                    </td>
                    <td className='px-3 py-1.5'>
                      {finding ? (
                        <div className='flex items-center gap-2'>
                          <span className={`shrink-0 rounded-full px-1.5 py-0.5 font-medium capitalize ${severityColors[finding.severity] ?? 'bg-muted text-muted-foreground'}`}>
                            {finding.severity}
                          </span>
                          <span className='text-muted-foreground truncate max-w-[240px]' title={finding.title ?? finding.pkg_name}>
                            {finding.title || finding.pkg_name}
                          </span>
                        </div>
                      ) : (
                        <span className='text-muted-foreground italic'>not in current scan</span>
                      )}
                    </td>
                    <td className='px-3 py-1.5 text-muted-foreground'>{entry.reason || '—'}</td>
                    <td className='px-3 py-1.5 text-muted-foreground whitespace-nowrap'>{entry.added_by_username ?? '—'}</td>
                    <td className='px-2 py-1.5'>
                      <button
                        type='button'
                        onClick={() => removeEntry(entry.id)}
                        className='text-muted-foreground hover:text-destructive transition-colors'
                        title='Remove'
                      >
                        <XIcon className='size-3.5' />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default function TagDetailPage() {
  const { project, repo, tag } = useParams<{ project: string; repo: string; tag: string }>()
  const router = useRouter()
  const { user } = useAuthContext()
  const [detail, setDetail] = useState<TagDetail | null>(null)
  const [scan, setScan] = useState<ScanReport | null>(null)
  const [secretScan, setSecretScan] = useState<SecretScanReport | null>(null)
  const [misconfigScan, setMisconfigScan] = useState<MisconfigScanReport | null>(null)
  const [sbom, setSbom] = useState<SBOMReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [secretScanning, setSecretScanning] = useState(false)
  const [misconfigScanning, setMisconfigScanning] = useState(false)
  const [generatingSbom, setGeneratingSbom] = useState(false)
  const [sbomFilter, setSbomFilter] = useState('')
  const [sbomTypeFilter, setSbomTypeFilter] = useState('all')
  const scanPollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const secretScanPollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const misconfigScanPollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const sbomPollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  // Copy/retag
  const [showCopyDialog, setShowCopyDialog] = useState(false)
  const [newTagName, setNewTagName] = useState('')
  const [destRepo, setDestRepo] = useState('')
  const [copying, setCopying] = useState(false)
  const [copyError, setCopyError] = useState('')
  // Labels
  const [tagLabels, setTagLabels] = useState<Label[]>([])
  const [projectLabels, setProjectLabels] = useState<Label[]>([])
  const [labelPopoverOpen, setLabelPopoverOpen] = useState(false)
  const [savingLabels, setSavingLabels] = useState(false)
  // Signatures
  const [sigStatus, setSigStatus] = useState<SignatureStatus | null>(null)
  const [verifying, setVerifying] = useState(false)
  // Policy — for staleness display
  const [policy, setPolicy] = useState<ProjectPolicy | null>(null)
  // CVE Allowlist
  const [allowlist, setAllowlist] = useState<AllowlistEntry[]>([])
  const loadAllowlist = () => {
    fetchAllowlist(project).then(setAllowlist).catch(() => {})
  }
  // Reload vuln scan report so suppressed flags are refreshed after allowlist changes
  const reloadVulnScan = () => {
    fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/scan/report`, { credentials: 'include' })
      .then(r => r.ok ? r.json() : null).then(d => { if (d) setScan(d) }).catch(() => {})
  }
  const onVulnAllowlistChanged = () => { loadAllowlist(); reloadVulnScan() }
  // Secret Allowlist (tag-scoped)
  const [secretAllowlist, setSecretAllowlist] = useState<SecretAllowlistEntry[]>([])
  const [secretAllowlistReady, setSecretAllowlistReady] = useState(false)
  const loadSecretAllowlist = () => {
    fetchSecretAllowlist(project, repo, tag).then(d => { setSecretAllowlist(d); setSecretAllowlistReady(true) }).catch(() => {})
  }
  // Secret Allowlist (project-wide)
  const [projectSecretAllowlist, setProjectSecretAllowlist] = useState<SecretAllowlistEntry[]>([])
  const [projectSecretAllowlistReady, setProjectSecretAllowlistReady] = useState(false)
  const loadProjectSecretAllowlist = () => {
    fetchProjectSecretAllowlist(project).then(d => { setProjectSecretAllowlist(d); setProjectSecretAllowlistReady(true) }).catch(() => {})
  }
  const secretAllowlistsReady = secretAllowlistReady && projectSecretAllowlistReady
  // Reload secret scan report so suppressed flags are refreshed after allowlist changes
  const reloadSecretScan = () => {
    fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/secret-scan/report`, { credentials: 'include' })
      .then(r => r.ok ? r.json() : null).then(d => { if (d) setSecretScan(d) }).catch(() => {})
  }
  const onSecretAllowlistChanged = () => { loadSecretAllowlist(); loadProjectSecretAllowlist(); reloadSecretScan() }

  // Misconfig Allowlist (tag-scoped)
  const [misconfigAllowlist, setMisconfigAllowlist] = useState<MisconfigAllowlistEntry[]>([])
  const [misconfigAllowlistReady, setMisconfigAllowlistReady] = useState(false)
  const loadMisconfigAllowlist = () => {
    fetchMisconfigAllowlist(project, repo, tag).then(d => { setMisconfigAllowlist(d); setMisconfigAllowlistReady(true) }).catch(() => {})
  }
  // Misconfig Allowlist (project-wide)
  const [projectMisconfigAllowlist, setProjectMisconfigAllowlist] = useState<MisconfigAllowlistEntry[]>([])
  const [projectMisconfigAllowlistReady, setProjectMisconfigAllowlistReady] = useState(false)
  const loadProjectMisconfigAllowlist = () => {
    fetchProjectMisconfigAllowlist(project).then(d => { setProjectMisconfigAllowlist(d); setProjectMisconfigAllowlistReady(true) }).catch(() => {})
  }
  const misconfigAllowlistsReady = misconfigAllowlistReady && projectMisconfigAllowlistReady
  // Reload misconfig scan report so suppressed flags are refreshed after allowlist changes
  const reloadMisconfigScan = () => {
    fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/misconfig-scan/report`, { credentials: 'include' })
      .then(r => r.ok ? r.json() : null).then(d => { if (d) setMisconfigScan(d) }).catch(() => {})
  }
  const onMisconfigAllowlistChanged = () => { loadMisconfigAllowlist(); loadProjectMisconfigAllowlist(); reloadMisconfigScan() }

  const registryHost = registryHostConst || (() => {
    try {
      const url = new URL(baseUrl)
      return url.port ? `${url.hostname}:${url.port}` : url.hostname
    } catch {
      return typeof window !== 'undefined' ? window.location.hostname : 'localhost'
    }
  })()
  const pullCommand = `docker pull ${registryHost}/${project}/${repo}:${tag}`

  const startScanPoll = () => {
    if (scanPollRef.current) return
    scanPollRef.current = setInterval(async () => {
      const r = await fetch(
        `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/scan/report`,
        { credentials: 'include' }
      )
      if (r.ok) {
        const data: ScanReport = await r.json()
        setScan(data)
        if (data.status !== 'pending' && data.status !== 'running') {
          clearInterval(scanPollRef.current!)
          scanPollRef.current = null
          setScanning(false)
        }
      }
    }, 3000)
  }

  const startSecretScanPoll = () => {
    if (secretScanPollRef.current) return
    secretScanPollRef.current = setInterval(async () => {
      const r = await fetch(
        `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/secret-scan/report`,
        { credentials: 'include' }
      )
      if (r.ok) {
        const data: SecretScanReport = await r.json()
        setSecretScan(data)
        if (data.status !== 'pending' && data.status !== 'running') {
          clearInterval(secretScanPollRef.current!)
          secretScanPollRef.current = null
          setSecretScanning(false)
        }
      }
    }, 3000)
  }

  const startMisconfigScanPoll = () => {
    if (misconfigScanPollRef.current) return
    misconfigScanPollRef.current = setInterval(async () => {
      const r = await fetch(
        `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/misconfig-scan/report`,
        { credentials: 'include' }
      )
      if (r.ok) {
        const data: MisconfigScanReport = await r.json()
        setMisconfigScan(data)
        if (data.status !== 'pending' && data.status !== 'running') {
          clearInterval(misconfigScanPollRef.current!)
          misconfigScanPollRef.current = null
          setMisconfigScanning(false)
        }
      }
    }, 3000)
  }

  const startSbomPoll = () => {
    if (sbomPollRef.current) return
    sbomPollRef.current = setInterval(async () => {
      const r = await fetch(
        `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/sbom`,
        { credentials: 'include' }
      )
      if (r.ok) {
        const data: SBOMReport = await r.json()
        setSbom(data)
        if (data.status !== 'pending' && data.status !== 'running') {
          clearInterval(sbomPollRef.current!)
          sbomPollRef.current = null
          setGeneratingSbom(false)
        }
      }
    }, 3000)
  }

  useEffect(() => {
    return () => {
      if (scanPollRef.current) clearInterval(scanPollRef.current)
      if (secretScanPollRef.current) clearInterval(secretScanPollRef.current)
      if (misconfigScanPollRef.current) clearInterval(misconfigScanPollRef.current)
      if (sbomPollRef.current) clearInterval(sbomPollRef.current)
    }
  }, [])

  useEffect(() => {
    setLoading(true)
    Promise.all([
      fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}`, {
        credentials: 'include',
      }).then((r) => (r.ok ? r.json() : null)),
      fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/scan/report`, {
        credentials: 'include',
      }).then((r) => (r.ok ? r.json() : null)),
      fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/secret-scan/report`, {
        credentials: 'include',
      }).then((r) => (r.ok ? r.json() : null)),
      fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/misconfig-scan/report`, {
        credentials: 'include',
      }).then((r) => (r.ok ? r.json() : null)),
      fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/sbom`, {
        credentials: 'include',
      }).then((r) => (r.ok ? r.json() : null)),
      fetch(`${baseUrl}registry/projects/${project}/labels`, {
        credentials: 'include',
      }).then((r) => (r.ok ? r.json() : [])),
      fetch(`${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/signature`, {
        credentials: 'include',
      }).then((r) => (r.ok ? r.json() : null)),
    ])
      .then(([tagData, scanData, secretScanData, misconfigScanData, sbomData, projectLabelData, sigData]) => {
        setDetail(tagData)
        setScan(scanData)
        setSecretScan(secretScanData)
        setMisconfigScan(misconfigScanData)
        setSbom(sbomData)
        setProjectLabels(Array.isArray(projectLabelData) ? projectLabelData : [])
        setTagLabels(Array.isArray(tagData?.labels) ? tagData.labels : [])
        setSigStatus(sigData)
        // Resume polling if any scan was already in-progress when we loaded
        if (scanData?.status === 'pending' || scanData?.status === 'running') {
          setScanning(true)
          startScanPoll()
        }
        if (secretScanData?.status === 'pending' || secretScanData?.status === 'running') {
          setSecretScanning(true)
          startSecretScanPoll()
        }
        if (misconfigScanData?.status === 'pending' || misconfigScanData?.status === 'running') {
          setMisconfigScanning(true)
          startMisconfigScanPoll()
        }
        if (sbomData?.status === 'pending' || sbomData?.status === 'running') {
          setGeneratingSbom(true)
          startSbomPoll()
        }
      })
      .finally(() => setLoading(false))
    fetchProjectPolicy(project).then(setPolicy).catch(() => {})
    loadAllowlist()
    loadSecretAllowlist()
    loadProjectSecretAllowlist()
    loadMisconfigAllowlist()
    loadProjectMisconfigAllowlist()
  }, [project, repo, tag])

  const triggerVerify = async () => {
    setVerifying(true)
    await fetch(
      `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/signature/verify`,
      { method: 'POST', credentials: 'include', headers: { 'X-CSRFToken': user.csrfToken ?? '' } }
    )
    // Poll for result after a short delay
    setTimeout(async () => {
      const r = await fetch(
        `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/signature`,
        { credentials: 'include' }
      )
      if (r.ok) setSigStatus(await r.json())
      setVerifying(false)
    }, 3000)
  }

  const toggleLabel = async (label: Label) => {
    const alreadySet = tagLabels.some((l) => l.id === label.id)
    const nextIds = alreadySet
      ? tagLabels.filter((l) => l.id !== label.id).map((l) => l.id)
      : [...tagLabels.map((l) => l.id), label.id]
    setSavingLabels(true)
    try {
      const res = await fetch(
        `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/labels`,
        {
          method: 'PUT',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': user.csrfToken ?? '' },
          body: JSON.stringify({ label_ids: nextIds }),
        }
      )
      if (res.ok) setTagLabels(await res.json())
    } finally {
      setSavingLabels(false)
    }
  }

  const triggerScan = async () => {
    setScanning(true)
    const r = await fetch(
      `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/scan`,
      {
        method: 'POST',
        credentials: 'include',
        headers: { 'X-CSRFToken': user.csrfToken ?? '' },
      }
    )
    if (!r.ok) { setScanning(false); return }
    // Immediately set pending so UI shows spinner, then poll until done
    setScan((prev) => prev ? { ...prev, status: 'pending' } : { status: 'pending', summary: {}, report: [], started_at: null, finished_at: null })
    startScanPoll()
  }

  const triggerSecretScan = async () => {
    setSecretScanning(true)
    const r = await fetch(
      `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/secret-scan`,
      {
        method: 'POST',
        credentials: 'include',
        headers: { 'X-CSRFToken': user.csrfToken ?? '' },
      }
    )
    if (!r.ok) { setSecretScanning(false); return }
    setSecretScan((prev) => prev ? { ...prev, status: 'pending' } : { status: 'pending', total: 0, report: [], started_at: null, finished_at: null })
    startSecretScanPoll()
  }

  const triggerMisconfigScan = async () => {
    setMisconfigScanning(true)
    const r = await fetch(
      `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/misconfig-scan`,
      {
        method: 'POST',
        credentials: 'include',
        headers: { 'X-CSRFToken': user.csrfToken ?? '' },
      }
    )
    if (!r.ok) { setMisconfigScanning(false); return }
    setMisconfigScan((prev) => prev ? { ...prev, status: 'pending' } : { status: 'pending', summary: {}, report: [], started_at: null, finished_at: null })
    startMisconfigScanPoll()
  }

  const triggerSbom = async () => {
    setGeneratingSbom(true)
    const r = await fetch(
      `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/sbom`,
      {
        method: 'POST',
        credentials: 'include',
        headers: { 'X-CSRFToken': user.csrfToken ?? '' },
      }
    )
    if (!r.ok) { setGeneratingSbom(false); return }
    setSbom((prev) => prev ? { ...prev, status: 'pending' } : { status: 'pending', created_at: null, finished_at: null, report: {} })
    startSbomPoll()
  }

  const handleDelete = async () => {
    setDeleting(true)
    setDeleteError(null)
    try {
      const res = await fetch(
        `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}`,
        {
          method: 'DELETE',
          credentials: 'include',
          headers: { 'X-CSRFToken': user.csrfToken ?? '' },
        }
      )
      if (!res.ok) {
        const msg = await res.text().catch(() => `HTTP ${res.status}`)
        setDeleteError(msg || `Delete failed (HTTP ${res.status})`)
        return
      }
      router.push(`/projects/${project}/repositories/${repo}`)
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Delete failed')
    } finally {
      setDeleting(false)
    }
  }

  const confirmCopy = async () => {
    if (!newTagName.trim()) return
    setCopying(true)
    setCopyError('')
    const params = new URLSearchParams({ new_tag: newTagName.trim() })
    if (destRepo.trim()) params.set('dest_repo', destRepo.trim())
    try {
      const res = await fetch(
        `${baseUrl}registry/projects/${project}/repositories/${repo}/tags/${tag}/copy?${params}`,
        { method: 'POST', credentials: 'include', headers: { 'X-CSRFToken': user.csrfToken ?? '' } }
      )
      if (res.ok) {
        setShowCopyDialog(false)
        setNewTagName('')
        setDestRepo('')
      } else {
        const body = await res.json().catch(() => ({}))
        setCopyError(body?.detail || body?.message || 'Copy failed')
      }
    } catch {
      setCopyError('Copy failed')
    } finally {
      setCopying(false)
    }
  }

  // Parse layers from manifest
  const layers: Layer[] = (() => {
    if (!detail?.manifest) return []
    const m = detail.manifest as Record<string, unknown>
    const arr = (m.layers ?? m.Layers) as Layer[] | undefined
    return Array.isArray(arr) ? arr : []
  })()

  // Build merged layer+history rows (like Docker Hub)
  // history[] from image_config maps 1:1 to layers[] skipping empty_layer entries
  const layerRows: LayerRow[] = (() => {
    const history = (detail?.image_config?.history as HistoryEntry[] | undefined) ?? []
    if (history.length === 0) {
      // No history — fall back to plain layer list
      return layers.map((l, i) => ({
        index: i + 1,
        historyIndex: i,
        command: l.digest,
        isEmpty: false,
        digest: l.digest,
        size: l.size,
        mediaType: l.mediaType,
      }))
    }
    const rows: LayerRow[] = []
    let layerIdx = 0
    history.forEach((h, hi) => {
      const isEmpty = h.empty_layer === true
      const layer = !isEmpty ? layers[layerIdx] : undefined
      if (!isEmpty) layerIdx++
      // Strip the shell prefix Docker adds: "/bin/sh -c #(nop) " or "/bin/sh -c "
      let cmd = h.created_by ?? h.comment ?? ''
      cmd = cmd.replace(/^\/bin\/sh -c #\(nop\)\s+/, '')
      cmd = cmd.replace(/^\/bin\/sh -c\s+/, 'RUN ')
      rows.push({
        index: isEmpty ? 0 : layerIdx,
        historyIndex: hi,
        command: cmd || '—',
        isEmpty,
        digest: layer?.digest,
        size: layer?.size,
        mediaType: layer?.mediaType,
      })
    })
    return rows
  })()

  const sbomPackages = sbom?.report?.packages ?? []

  // Derive ecosystem/type from PURL for each package
  const getPkgType = (pkg: SBOMPackage) => {
    const purl = pkg.externalRefs?.find(r => r.referenceType === 'purl')?.referenceLocator ?? ''
    return purl ? (purl.split(':')[1]?.split('/')[0] ?? '') : ''
  }

  const sbomTypes = Array.from(new Set(sbomPackages.map(getPkgType).filter(Boolean))).sort()

  const filteredPackages = sbomPackages.filter(p => {
    if (sbomFilter) {
      const q = sbomFilter.toLowerCase()
      if (
        !p.name.toLowerCase().includes(q) &&
        !(p.versionInfo ?? '').toLowerCase().includes(q) &&
        !(p.licenseConcluded ?? '').toLowerCase().includes(q)
      ) return false
    }
    if (sbomTypeFilter !== 'all' && getPkgType(p) !== sbomTypeFilter) return false
    return true
  })



  const downloadSbom = () => {
    if (!sbom?.report) return
    const blob = new Blob([JSON.stringify(sbom.report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sbom-${project}-${repo}-${tag}.spdx.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  if (loading) {
    return (
      <>
        <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
          <SidebarTrigger />
          <Separator orientation='vertical' className='h-4!' />
          <Skeleton className='h-4 w-64' />
        </header>
        <main className='flex-1 px-6 py-6 space-y-4'>
          <Skeleton className='h-12 w-full rounded-md' />
          <Skeleton className='h-8 w-64 rounded-md' />
          <Skeleton className='h-48 w-full rounded-md' />
        </main>
      </>
    )
  }

  if (!detail) {
    return (
      <>
        <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
          <SidebarTrigger />
        </header>
        <main className='flex-1 flex items-center justify-center py-24'>
          <p className='text-muted-foreground text-sm'>Tag not found.</p>
        </main>
      </>
    )
  }

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <BoxesIcon className='size-4 text-muted-foreground' />
        <Link href={`/projects/${project}/repositories`} className='text-sm hover:underline'>
          {project}
        </Link>
        <span className='text-muted-foreground'>/</span>
        <Link href={`/projects/${project}/repositories/${repo}`} className='text-sm hover:underline'>
          {repo}
        </Link>
        <span className='text-muted-foreground'>/</span>
        <TagIcon className='size-3.5 text-muted-foreground' />
        <span className='font-semibold text-sm'>{tag}</span>
        {detail?.is_index && (
          <span className='inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-blue-600/10 text-blue-600 dark:bg-blue-400/10 dark:text-blue-400'>
            <LayersIcon className='size-3' />
            Multi-arch
          </span>
        )}
        {detail?.platform && !detail.is_index && (
          <span className='inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-muted text-muted-foreground'>
            <LayersIcon className='size-3' />
            {detail.platform}
          </span>
        )}
        {policy?.vuln_rescan_active_only && detail && (() => {
          // Fall back to pushed_at when last_activity_at is null (tags that predate
          // the last_activity_at field or whose push webhook didn't fire).
          const activityTs = detail.last_activity_at ?? detail.pushed_at
          const activityMs = Date.now() - new Date(activityTs).getTime()
          const isStale = activityMs > (policy.vuln_rescan_active_days * 86400000)
          return isStale ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className='inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium bg-muted text-muted-foreground'>
                  <ClockIcon className='size-3' />
                  Stale
                </span>
              </TooltipTrigger>
              <TooltipContent side='bottom'>
                <p className='text-xs'>
                  No activity for over {policy.vuln_rescan_active_days} days — last seen {new Date(activityTs).toLocaleDateString()}
                </p>
              </TooltipContent>
            </Tooltip>
          ) : null
        })()}
        <div className='ml-auto flex items-center gap-2'>
          <Button
            size='sm'
            variant='outline'
            className='gap-1.5'
            onClick={() => { setNewTagName(''); setDestRepo(''); setCopyError(''); setShowCopyDialog(true) }}
          >
            <CopyIcon className='size-3.5' />
            Copy tag
          </Button>
          <Button
            size='sm'
            variant='outline'
            className='gap-1.5 text-destructive border-destructive/30 hover:bg-destructive/10 hover:text-destructive'
            onClick={() => setShowDeleteDialog(true)}
          >
            <Trash2Icon className='size-3.5' />
            Delete tag
          </Button>
        </div>
      </header>

      <main className='flex-1 px-6 py-6 space-y-4 max-w-7xl mx-auto w-full'>
        {/* Pull command */}
        <div className='flex items-center gap-2 rounded-md border bg-muted/50 px-4 py-3'>
          <code className='flex-1 font-mono text-sm text-foreground truncate'>{pullCommand}</code>
          <CopyButton text={pullCommand} />
        </div>

        {/* Metadata */}
        <Card>
          <CardHeader className='pb-2'>
            <CardTitle className='text-base'>Metadata</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableBody>
                <TableRow>
                  <TableCell className='text-sm text-muted-foreground w-40'>Digest</TableCell>
                  <TableCell>
                    <div className='flex items-center gap-1'>
                      <code className='font-mono text-xs'>{detail.digest}</code>
                      <CopyButton text={detail.digest} />
                    </div>
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className='text-sm text-muted-foreground'>Size</TableCell>
                  <TableCell className='text-sm'>{formatBytes(detail.size_bytes)}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className='text-sm text-muted-foreground'>OS / Arch</TableCell>
                  <TableCell className='text-sm'>
                    {detail.is_index ? (
                      <span className='inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium bg-blue-600/10 text-blue-600 dark:bg-blue-400/10 dark:text-blue-400'>
                        <LayersIcon className='size-3' />
                        Multi-arch ({detail.platform_children.length} platform{detail.platform_children.length !== 1 ? 's' : ''})
                      </span>
                    ) : detail.os && detail.architecture ? (
                      `${detail.os} / ${detail.architecture}`
                    ) : '—'}
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className='text-sm text-muted-foreground'>Pushed by</TableCell>
                  <TableCell className='text-sm'>{detail.pushed_by_username ?? '—'}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className='text-sm text-muted-foreground'>Pushed at</TableCell>
                  <TableCell className='text-sm'>{new Date(detail.pushed_at).toLocaleString()}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className='text-sm text-muted-foreground'>Last activity</TableCell>
                  <TableCell className='text-sm'>
                    {detail.last_activity_at
                      ? new Date(detail.last_activity_at).toLocaleString()
                      : <span className='text-muted-foreground italic'>No recorded activity</span>}
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Platform children (multi-arch index tags only) */}
        {detail.is_index && detail.platform_children.length > 0 && (
          <Card>
            <CardHeader className='pb-2'>
              <CardTitle className='text-base flex items-center gap-2'>
                <LayersIcon className='size-4 text-muted-foreground' />
                Platforms
              </CardTitle>
              <CardDescription>
                Per-platform images in this multi-arch manifest. Click a platform to view its scan results.
              </CardDescription>
            </CardHeader>
            <CardContent className='p-0'>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className='pl-6'>Platform</TableHead>
                    <TableHead>OS / Arch</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>Vuln</TableHead>
                    <TableHead>Secrets</TableHead>
                    <TableHead>Misconfig</TableHead>
                    <TableHead>SBOM</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {detail.platform_children.map((child) => {
                    const childTagName = child.name.split('@')[1] ? child.name : child.name
                    const childUrl = `/projects/${project}/repositories/${repo}/${encodeURIComponent(child.name)}`
                    const scanBadge = (status: string | null) => {
                      if (!status) return <span className='text-xs text-muted-foreground'>—</span>
                      const cls = status === 'finished' ? 'text-green-600 dark:text-green-400'
                        : status === 'error' ? 'text-destructive'
                        : status === 'running' || status === 'pending' ? 'text-amber-500'
                        : 'text-muted-foreground'
                      return <span className={`text-xs font-medium ${cls}`}>{status}</span>
                    }
                    return (
                      <TableRow key={child.id} className='cursor-pointer hover:bg-muted/50' onClick={() => window.location.href = childUrl}>
                        <TableCell className='pl-6'>
                          <code className='font-mono text-xs'>{child.platform}</code>
                        </TableCell>
                        <TableCell className='text-sm'>{child.os}/{child.architecture}</TableCell>
                        <TableCell className='text-sm'>{child.size_bytes > 0 ? `${(child.size_bytes / 1024 / 1024).toFixed(1)} MB` : '—'}</TableCell>
                        <TableCell>{scanBadge(child.scan_status)}</TableCell>
                        <TableCell>{scanBadge(child.secret_scan_status)}</TableCell>
                        <TableCell>{scanBadge(child.misconfig_scan_status)}</TableCell>
                        <TableCell>{scanBadge(child.sbom_status)}</TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}

        {/* Labels */}
        <Card>
          <CardHeader className='flex flex-row items-center gap-3 space-y-0 pb-3'>
            <div>
              <CardTitle className='text-base flex items-center gap-2'>
                <TagsIcon className='size-4 text-muted-foreground' />
                Labels
              </CardTitle>
              <CardDescription>
                {tagLabels.length === 0 ? 'No labels applied' : `${tagLabels.length} label${tagLabels.length !== 1 ? 's' : ''} applied`}
              </CardDescription>
            </div>
            <div className='ml-auto'>
              <Popover open={labelPopoverOpen} onOpenChange={setLabelPopoverOpen}>
                <PopoverTrigger asChild>
                  <Button size='sm' variant='outline' className='gap-1.5' disabled={savingLabels}>
                    <PlusIcon className='size-3.5' />
                    Manage labels
                  </Button>
                </PopoverTrigger>
                <PopoverContent className='w-64 p-2' align='end'>
                  {projectLabels.length === 0 ? (
                    <p className='px-2 py-3 text-xs text-muted-foreground text-center'>
                      No labels defined for this project.{' '}
                      <a href={`/projects/${project}/labels`} className='underline'>Create labels</a> first.
                    </p>
                  ) : (
                    <div className='space-y-0.5'>
                      {projectLabels.map((label) => {
                        const active = tagLabels.some((l) => l.id === label.id)
                        return (
                          <button
                            key={label.id}
                            onClick={() => toggleLabel(label)}
                            disabled={savingLabels}
                            className='flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-muted disabled:opacity-50'
                          >
                            <span
                              className='size-3 shrink-0 rounded-full border-2'
                              style={{
                                backgroundColor: active ? label.color : 'transparent',
                                borderColor: label.color,
                              }}
                            />
                            <span className='flex-1 truncate text-left'>{label.name}</span>
                            {active && <span className='text-[10px] text-muted-foreground'>applied</span>}
                          </button>
                        )
                      })}
                    </div>
                  )}
                </PopoverContent>
              </Popover>
            </div>
          </CardHeader>
          <CardContent>
            {tagLabels.length === 0 ? (
              <p className='text-sm text-muted-foreground'>No labels applied to this tag.</p>
            ) : (
              <div className='flex flex-wrap gap-2'>
                {tagLabels.map((label) => (
                  <span
                    key={label.id}
                    className='inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium'
                    style={{ backgroundColor: `${label.color}22`, color: label.color, border: `1px solid ${label.color}55` }}
                  >
                    {label.name}
                    <button
                      onClick={() => toggleLabel(label)}
                      disabled={savingLabels}
                      className='ml-0.5 rounded-full opacity-60 hover:opacity-100 disabled:opacity-30 transition-opacity'
                    >
                      <XIcon className='size-3' />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Tabs: Vulnerabilities / Layers / SBOM / Manifest */}
        <Tabs defaultValue='vulnerabilities'>
          <TabsList>
            <TabsTrigger value='vulnerabilities' className='gap-1.5'>
              <ShieldAlertIcon className='size-3.5' />
              Vulnerabilities
            </TabsTrigger>
            <TabsTrigger value='secrets' className='gap-1.5'>
              <KeySquareIcon className='size-3.5' />
              Secrets
              {secretScan?.status === 'finished' && secretScan.total > 0 && (
                <Badge variant='destructive' className='ml-1 px-1.5 text-xs'>{secretScan.total}</Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value='misconfigs' className='gap-1.5'>
              <WrenchIcon className='size-3.5' />
              Misconfigs
              {misconfigScan?.status === 'finished' && (misconfigScan.summary['FAIL'] ?? 0) > 0 && (
                <Badge variant='destructive' className='ml-1 px-1.5 text-xs'>{misconfigScan.summary['FAIL']}</Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value='layers' className='gap-1.5'>
              <LayersIcon className='size-3.5' />
              Layers
              {layers.length > 0 && (
                <Badge variant='secondary' className='ml-1 px-1.5 text-xs'>{layers.length}</Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value='sbom' className='gap-1.5'>
              <PackageIcon className='size-3.5' />
              SBOM
              {sbomPackages.length > 0 && (
                <Badge variant='secondary' className='ml-1 px-1.5 text-xs'>{sbomPackages.length}</Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value='signatures' className='gap-1.5'>
              <KeyRoundIcon className='size-3.5' />
              Signatures
            </TabsTrigger>
            <TabsTrigger value='manifest' className='gap-1.5'>
              <FileTextIcon className='size-3.5' />
              Manifest
            </TabsTrigger>
          </TabsList>

          {/* ── Vulnerabilities ── */}
          <TabsContent value='vulnerabilities'>
            {detail.is_index ? (
              <Card>
                <CardContent className='pt-6'>
                  <div className='flex items-start gap-3 text-sm text-muted-foreground'>
                    <LayersIcon className='size-4 mt-0.5 shrink-0 text-blue-500' />
                    <div>
                      <p className='font-medium text-foreground mb-1'>Multi-arch image — scans run per platform</p>
                      <p>This tag is a manifest index pointing to {detail.platform_children.length} platform image{detail.platform_children.length !== 1 ? 's' : ''}. Vulnerability scans are run independently for each platform. Click a platform in the Platforms table above to view its scan results.</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ) : (
            <Card>
              <CardHeader className='flex flex-row items-center gap-3 space-y-0 pb-3'>
                <div>
                  <CardTitle className='text-base'>Vulnerability Scan</CardTitle>
                  <CardDescription>
                    {scan
                      ? scan.status === 'pending' ? 'Queued — waiting for worker'
                      : scan.status === 'running' ? 'Scanning now…'
                      : `Last scanned: ${scan.finished_at ? new Date(scan.finished_at).toLocaleString() : '—'}`
                      : 'No scan results yet'}
                  </CardDescription>
                </div>
                 <div className='ml-auto flex items-center gap-2'>
                   <ExportMenu
                     disabled={!scan || scan.status !== 'finished' || !scan.report?.length}
                     onCsv={() => exportVulnsCsv(scan!.report, `${project}-${repo}-${tag}-vulns.csv`)}
                     onJson={() => downloadBlob(JSON.stringify(scan!.report, null, 2), `${project}-${repo}-${tag}-vulns.json`, 'application/json')}
                   />
                   <Button size='sm' variant='outline' onClick={triggerScan} disabled={scanning}>
                     {scanning ? (
                       <RefreshCwIcon className='size-3.5 animate-spin' />
                     ) : (
                       <ScanIcon className='size-3.5' />
                     )}
                     {scanning ? (scan?.status === 'pending' ? 'In queue…' : 'Scanning…') : 'Scan now'}
                   </Button>
                 </div>
              </CardHeader>
              <CardContent>
                {!scan ? (
                  <p className='text-sm text-muted-foreground'>
                    Click "Scan now" to queue a vulnerability scan for this image.
                  </p>
                ) : scan.status === 'pending' ? (
                  <div className='flex items-center gap-2 text-sm text-muted-foreground'>
                    <RefreshCwIcon className='size-4 animate-spin' />
                    In queue — waiting for the scan worker to pick this up…
                  </div>
                ) : scan.status === 'running' ? (
                  <div className='flex items-center gap-2 text-sm text-muted-foreground'>
                    <RefreshCwIcon className='size-4 animate-spin' />
                    Scanning…
                  </div>
                ) : scan.status === 'error' ? (
                  <p className='text-sm text-destructive'>Scan failed. Try again.</p>
                ) : (
                  <VulnTabContent
                    scan={scan}
                    allowlist={allowlist}
                    tagId={detail?.id ?? 0}
                    projectName={project}
                    csrfToken={user.csrfToken ?? ''}
                    onAllowlistChange={onVulnAllowlistChanged}
                  />
                )}
              </CardContent>
            </Card>
            )}
          </TabsContent>

          {/* ── Secrets ── */}
          <TabsContent value='secrets'>
            {detail.is_index ? (
              <Card>
                <CardContent className='pt-6'>
                  <div className='flex items-start gap-3 text-sm text-muted-foreground'>
                    <LayersIcon className='size-4 mt-0.5 shrink-0 text-blue-500' />
                    <div>
                      <p className='font-medium text-foreground mb-1'>Multi-arch image — scans run per platform</p>
                      <p>Secret scans are run independently for each platform. Click a platform in the Platforms table above to view its scan results.</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ) : (
            <Card>
              <CardHeader className='flex flex-row items-center gap-3 space-y-0 pb-3'>
                <div>
                  <CardTitle className='text-base'>Secret Scan</CardTitle>
                  <CardDescription>
                    {secretScan
                      ? secretScan.status === 'pending' ? 'Queued — waiting for worker'
                      : secretScan.status === 'running' ? 'Scanning now…'
                      : `Last scanned: ${secretScan.finished_at ? new Date(secretScan.finished_at).toLocaleString() : '—'}`
                      : 'No secret scan results yet'}
                  </CardDescription>
                </div>
                 <div className='ml-auto flex items-center gap-2'>
                   <ExportMenu
                     disabled={!secretScan || secretScan.status !== 'finished' || !secretScan.report?.length}
                     onCsv={() => exportSecretsCsv(secretScan!.report, `${project}-${repo}-${tag}-secrets.csv`)}
                     onJson={() => downloadBlob(JSON.stringify(secretScan!.report, null, 2), `${project}-${repo}-${tag}-secrets.json`, 'application/json')}
                   />
                   <Button size='sm' variant='outline' onClick={triggerSecretScan} disabled={secretScanning}>
                     {secretScanning ? (
                       <RefreshCwIcon className='size-3.5 animate-spin' />
                     ) : (
                       <KeySquareIcon className='size-3.5' />
                     )}
                     {secretScanning ? (secretScan?.status === 'pending' ? 'In queue…' : 'Scanning…') : 'Scan now'}
                   </Button>
                 </div>
              </CardHeader>
              <CardContent>
                {!secretScan ? (
                  <p className='text-sm text-muted-foreground'>
                    Click "Scan now" to scan this image for hardcoded secrets, credentials, and API keys.
                  </p>
                ) : secretScan.status === 'pending' ? (
                  <div className='flex items-center gap-2 text-sm text-muted-foreground'>
                    <RefreshCwIcon className='size-4 animate-spin' />
                    In queue — waiting for the scan worker to pick this up…
                  </div>
                ) : secretScan.status === 'running' ? (
                  <div className='flex items-center gap-2 text-sm text-muted-foreground'>
                    <RefreshCwIcon className='size-4 animate-spin' />
                    Scanning…
                  </div>
                ) : secretScan.status === 'error' ? (
                  <p className='text-sm text-destructive'>Secret scan failed. Try again.</p>
                ) : (
                  <SecretTabContent
                    scan={secretScan}
                    secretAllowlist={secretAllowlist}
                    projectSecretAllowlist={projectSecretAllowlist}
                    allowlistsReady={secretAllowlistsReady}
                    project={project}
                    repo={repo}
                    tagName={tag}
                    csrfToken={user.csrfToken ?? ''}
                    onSecretAllowlistChange={onSecretAllowlistChanged}
                  />
                )}
              </CardContent>
            </Card>
            )}
          </TabsContent>

          {/* ── Misconfigs ── */}
          <TabsContent value='misconfigs'>
            {detail.is_index ? (
              <Card>
                <CardContent className='pt-6'>
                  <div className='flex items-start gap-3 text-sm text-muted-foreground'>
                    <LayersIcon className='size-4 mt-0.5 shrink-0 text-blue-500' />
                    <div>
                      <p className='font-medium text-foreground mb-1'>Multi-arch image — scans run per platform</p>
                      <p>Misconfiguration scans are run independently for each platform. Click a platform in the Platforms table above to view its scan results.</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ) : (
            <Card>
              <CardHeader className='flex flex-row items-center gap-3 space-y-0 pb-3'>
                <div>
                  <CardTitle className='text-base'>Misconfiguration Scan</CardTitle>
                  <CardDescription>
                    {misconfigScan
                      ? misconfigScan.status === 'pending' ? 'Queued — waiting for worker'
                      : misconfigScan.status === 'running' ? 'Scanning now…'
                      : `Last scanned: ${misconfigScan.finished_at ? new Date(misconfigScan.finished_at).toLocaleString() : '—'}`
                      : 'No misconfiguration scan results yet'}
                  </CardDescription>
                </div>
                 <div className='ml-auto flex items-center gap-2'>
                   <ExportMenu
                     disabled={!misconfigScan || misconfigScan.status !== 'finished' || !misconfigScan.report?.length}
                     onCsv={() => exportMisconfigsCsv(misconfigScan!.report, `${project}-${repo}-${tag}-misconfigs.csv`)}
                     onJson={() => downloadBlob(JSON.stringify(misconfigScan!.report, null, 2), `${project}-${repo}-${tag}-misconfigs.json`, 'application/json')}
                   />
                   <Button size='sm' variant='outline' onClick={triggerMisconfigScan} disabled={misconfigScanning}>
                     {misconfigScanning ? (
                       <RefreshCwIcon className='size-3.5 animate-spin' />
                     ) : (
                       <WrenchIcon className='size-3.5' />
                     )}
                     {misconfigScanning ? (misconfigScan?.status === 'pending' ? 'In queue…' : 'Scanning…') : 'Scan now'}
                   </Button>
                 </div>
              </CardHeader>
              <CardContent>
                {!misconfigScan ? (
                  <p className='text-sm text-muted-foreground'>
                    Click "Scan now" to check this image for Dockerfile and runtime misconfigurations.
                  </p>
                ) : misconfigScan.status === 'pending' ? (
                  <div className='flex items-center gap-2 text-sm text-muted-foreground'>
                    <RefreshCwIcon className='size-4 animate-spin' />
                    In queue — waiting for the scan worker to pick this up…
                  </div>
                ) : misconfigScan.status === 'running' ? (
                  <div className='flex items-center gap-2 text-sm text-muted-foreground'>
                    <RefreshCwIcon className='size-4 animate-spin' />
                    Scanning…
                  </div>
                ) : misconfigScan.status === 'error' ? (
                  <p className='text-sm text-destructive'>Misconfiguration scan failed. Try again.</p>
                ) : (
                  <MisconfigTabContent
                    scan={misconfigScan}
                    misconfigAllowlist={misconfigAllowlist}
                    projectMisconfigAllowlist={projectMisconfigAllowlist}
                    allowlistsReady={misconfigAllowlistsReady}
                    project={project}
                    repo={repo}
                    tagName={tag}
                    csrfToken={user.csrfToken ?? ''}
                    onMisconfigAllowlistChange={onMisconfigAllowlistChanged}
                  />
                )}
              </CardContent>
            </Card>
            )}
          </TabsContent>

          {/* ── Layers ── */}
          <TabsContent value='layers'>
            <Card>
              <CardHeader className='pb-2'>
                <CardTitle className='text-base'>Image Layers</CardTitle>
                <CardDescription>
                  {layers.length > 0
                    ? `${layers.length} layer${layers.length !== 1 ? 's' : ''} · ${formatBytes(layers.reduce((a, l) => a + (l.size ?? 0), 0))} total`
                    : 'No layer data available — push the image again to populate layers'}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {layerRows.length === 0 ? (
                  <p className='text-sm text-muted-foreground'>No layers found in manifest.</p>
                ) : (
                  <div className='rounded-md border text-sm divide-y'>
                    {layerRows.map((row) => (
                      <div
                        key={row.historyIndex}
                        className={`flex flex-col gap-1 px-4 py-3 ${row.isEmpty ? 'bg-muted/30' : ''}`}
                      >
                        {/* Command line */}
                        <div className='flex items-start gap-3'>
                          <span className='mt-0.5 shrink-0 w-6 text-right text-xs tabular-nums text-muted-foreground'>
                            {row.isEmpty ? '' : row.index}
                          </span>
                          <code className='flex-1 break-all font-mono text-xs leading-relaxed'>
                            {row.command}
                          </code>
                          {!row.isEmpty && row.size !== undefined && (
                            <span className='shrink-0 text-xs text-muted-foreground tabular-nums'>
                              {formatBytes(row.size)}
                            </span>
                          )}
                          {row.isEmpty && (
                            <span className='shrink-0 text-xs text-muted-foreground italic'>
                              no layer
                            </span>
                          )}
                        </div>
                        {/* Digest (only for real layers) */}
                        {!row.isEmpty && row.digest && (
                          <div className='flex items-center gap-1 pl-9'>
                            <code className='font-mono text-xs text-muted-foreground/70'>
                              {row.digest}
                            </code>
                            <CopyButton text={row.digest} />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ── SBOM ── */}
          <TabsContent value='sbom'>
            <Card>
              <CardHeader className='flex flex-row items-center gap-3 space-y-0 pb-3'>
                <div>
                  <CardTitle className='text-base'>Software Bill of Materials</CardTitle>
                  <CardDescription>
                    {sbom?.status === 'finished' && sbom.finished_at
                      ? `Generated ${new Date(sbom.finished_at).toLocaleString()} · SPDX ${sbom.report.spdxVersion ?? ''}`
                      : sbom?.status === 'pending'
                      ? 'Queued — waiting for worker'
                      : sbom?.status === 'running'
                      ? 'Generating now…'
                      : sbom?.status === 'error'
                      ? 'SBOM generation failed'
                      : 'No SBOM available'}
                  </CardDescription>
                </div>
                <div className='ml-auto flex items-center gap-2'>
                  {sbomPackages.length > 0 && (
                    <>
                      {sbomTypes.length > 0 && (
                        <Select value={sbomTypeFilter} onValueChange={setSbomTypeFilter}>
                          <SelectTrigger className='h-8 w-32 text-xs'>
                            <SelectValue placeholder='All types' />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value='all'>All types</SelectItem>
                            {sbomTypes.map(t => (
                              <SelectItem key={t} value={t}>{t}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      )}
                      <div className='relative'>
                        <SearchIcon className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
                        <input
                          type='search'
                          placeholder='Filter packages…'
                          value={sbomFilter}
                          onChange={(e) => setSbomFilter(e.target.value)}
                          className='h-8 w-44 rounded-md border bg-background pl-8 pr-3 text-xs outline-none focus:ring-1 focus:ring-ring'
                        />
                      </div>
                      <Button size='sm' variant='outline' onClick={downloadSbom} className='gap-1.5'>
                        <DownloadIcon className='size-3.5' />
                        Export
                      </Button>
                    </>
                  )}
                  <Button
                    size='sm'
                    variant='outline'
                    onClick={triggerSbom}
                    disabled={generatingSbom || sbom?.status === 'pending' || sbom?.status === 'running'}
                    className='gap-1.5'
                  >
                    {generatingSbom || sbom?.status === 'pending' || sbom?.status === 'running'
                      ? <RefreshCwIcon className='size-3.5 animate-spin' />
                      : <PackageIcon className='size-3.5' />
                    }
                    {generatingSbom || sbom?.status === 'pending' || sbom?.status === 'running'
                      ? (sbom?.status === 'pending' ? 'In queue…' : 'Generating…')
                      : sbom?.status === 'finished' ? 'Regenerate' : 'Generate SBOM'
                    }
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {!sbom || sbom.status === 'error' ? (
                  <p className='text-sm text-muted-foreground'>
                    {sbom?.status === 'error'
                      ? 'SBOM generation failed. Click "Generate SBOM" to retry.'
                      : 'No SBOM available. Click "Generate SBOM" to create one.'}
                  </p>
                ) : sbom.status === 'pending' ? (
                  <div className='flex items-center gap-2 text-sm text-muted-foreground'>
                    <RefreshCwIcon className='size-4 animate-spin' />
                    In queue — waiting for the SBOM worker to pick this up…
                  </div>
                ) : sbom.status === 'running' ? (
                  <div className='flex items-center gap-2 text-sm text-muted-foreground'>
                    <RefreshCwIcon className='size-4 animate-spin' />
                    Generating SBOM…
                  </div>
                ) : sbomPackages.length === 0 ? (
                  <p className='text-sm text-muted-foreground'>No packages found in SBOM.</p>
                ) : (
                  <div className='space-y-4'>
                    <p className='text-xs text-muted-foreground'>
                      {filteredPackages.length === sbomPackages.length
                        ? `${sbomPackages.length} packages`
                        : `${filteredPackages.length} of ${sbomPackages.length} packages`}
                    </p>
                    <ExpandableTable
                      headers={['Package', 'Version', 'Type']}
                      rows={filteredPackages.map(pkg => {
                        const purl = pkg.externalRefs?.find(r => r.referenceType === 'purl')?.referenceLocator ?? ''
                        const ecosystem = getPkgType(pkg)
                        const supplier = pkg.supplier && pkg.supplier !== 'NOASSERTION'
                          ? pkg.supplier.replace(/^Organization:\s*/i, '') : null
                        return {
                          cells: [
                            <span className='font-medium' title={pkg.name}>{pkg.name}</span>,
                            <span className='font-mono text-muted-foreground whitespace-nowrap'>
                              {pkg.versionInfo && pkg.versionInfo !== 'UNKNOWN' ? pkg.versionInfo : '—'}
                            </span>,
                            <span className='text-muted-foreground'>{ecosystem || '—'}</span>,
                          ] as React.ReactNode[],
                          detail: (
                            <div className='flex flex-wrap gap-x-8 gap-y-1 text-muted-foreground'>
                              {supplier && <span><span className='font-medium text-foreground'>Supplier:</span> {supplier}</span>}
                              {purl && <span><span className='font-medium text-foreground'>PURL:</span> <span className='font-mono break-all'>{purl}</span></span>}
                              {pkg.SPDXID && <span><span className='font-medium text-foreground'>SPDX ID:</span> <span className='font-mono'>{pkg.SPDXID}</span></span>}
                            </div>
                          ),
                        }
                      })}
                    />
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ── Signatures ── */}
          <TabsContent value='signatures'>
            <Card>
              <CardHeader className='flex flex-row items-center gap-3 space-y-0 pb-3'>
                <div>
                  <CardTitle className='text-base'>Image Signatures</CardTitle>
                  <CardDescription>
                    {sigStatus?.checked_at
                      ? `Last checked: ${new Date(sigStatus.checked_at).toLocaleString()}`
                      : 'Not yet checked'}
                  </CardDescription>
                </div>
                <div className='ml-auto'>
                  <Button size='sm' variant='outline' onClick={triggerVerify} disabled={verifying}>
                    {verifying
                      ? <RefreshCwIcon className='size-3.5 animate-spin' />
                      : <KeyRoundIcon className='size-3.5' />
                    }
                    {verifying ? 'Checking…' : 'Verify now'}
                  </Button>
                </div>
              </CardHeader>
              <CardContent className='space-y-4'>
                {/* Cosign */}
                <div className='rounded-lg border p-4 space-y-2'>
                  <div className='flex items-center justify-between'>
                    <div className='flex items-center gap-2'>
                      <span className='text-sm font-medium'>Cosign</span>
                      <span className='text-xs text-muted-foreground'>(Sigstore)</span>
                    </div>
                    {!sigStatus || sigStatus.cosign === 'unknown' ? (
                      <span className='inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium bg-muted text-muted-foreground'>
                        <ShieldQuestionIcon className='size-3' /> Unknown
                      </span>
                    ) : sigStatus.cosign === 'signed' ? (
                      <span className='inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium bg-emerald-600/10 text-emerald-600 dark:bg-emerald-400/10 dark:text-emerald-400'>
                        <ShieldCheckIcon className='size-3' /> Signed
                      </span>
                    ) : sigStatus.cosign === 'not_signed' ? (
                      <span className='inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium bg-muted text-muted-foreground'>
                        <ShieldXIcon className='size-3' /> Not signed
                      </span>
                    ) : sigStatus.cosign === 'not_available' ? (
                      <span className='inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium bg-muted text-muted-foreground'>
                        Not available
                      </span>
                    ) : (
                      <span className='inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium bg-red-600/10 text-red-600 dark:bg-red-400/10 dark:text-red-400'>
                        <ShieldXIcon className='size-3' /> Verification failed
                      </span>
                    )}
                  </div>
                  {sigStatus?.cosign_output && (
                    <pre className='max-h-40 overflow-auto rounded-md border bg-muted/50 p-3 font-mono text-xs text-muted-foreground whitespace-pre-wrap'>
                      {sigStatus.cosign_output}
                    </pre>
                  )}
                  {!sigStatus?.cosign_output && (
                    <p className='text-xs text-muted-foreground'>
                      Click "Verify now" to check for a cosign signature artifact in the registry.
                    </p>
                  )}
                </div>

                {/* Notation */}
                <div className='rounded-lg border p-4 space-y-2'>
                  <div className='flex items-center justify-between'>
                    <div className='flex items-center gap-2'>
                      <span className='text-sm font-medium'>Notation</span>
                      <span className='text-xs text-muted-foreground'>(CNCF)</span>
                    </div>
                    <span className='inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium bg-muted text-muted-foreground'>
                      Not available
                    </span>
                  </div>
                  <p className='text-xs text-muted-foreground'>
                    The <code className='rounded bg-muted px-1'>notation</code> binary is not installed in this deployment.
                    Add it to the backend Dockerfile to enable Notation signature verification.
                  </p>
                </div>

                {/* How to sign */}
                <div className='rounded-lg border bg-muted/30 p-4 space-y-2'>
                  <p className='text-xs font-medium'>How to sign this image with cosign</p>
                  <pre className='font-mono text-xs text-muted-foreground whitespace-pre-wrap'>{
`# Generate a key pair (once)
cosign generate-key-pair

# Sign the image
cosign sign --key cosign.key \\
  --allow-insecure-registry \\
  ${registryHost}/${project}/${repo}:${tag}

# Verify manually
cosign verify --key cosign.pub \\
  --allow-insecure-registry \\
  --insecure-ignore-tlog \\
  ${registryHost}/${project}/${repo}:${tag}`
                  }</pre>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* ── Manifest ── */}
          <TabsContent value='manifest'>
            <Card>
              <CardHeader className='pb-2'>
                <CardTitle className='text-base'>Raw Manifest</CardTitle>
                {detail.is_index && (
                  <CardDescription>
                    OCI index / manifest list — lists all platform manifests. Each platform has its own manifest accessible via the Platforms table.
                  </CardDescription>
                )}
              </CardHeader>
              <CardContent>
                <pre className='max-h-96 overflow-auto rounded-md border bg-muted/50 p-4 font-mono text-xs'>
                  {JSON.stringify(detail.is_index ? detail.index_manifest : detail.manifest, null, 2)}
                </pre>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Copy/retag dialog */}
      <Dialog open={showCopyDialog} onOpenChange={(o) => { if (!o) { setShowCopyDialog(false); setCopyError('') } }}>
        <DialogContent className='sm:max-w-md'>
          <DialogHeader>
            <DialogTitle>Copy / retag</DialogTitle>
            <DialogDescription>
              Push the manifest of{' '}
              <span className='font-mono font-semibold text-foreground'>{tag}</span>{' '}
              under a new tag name. No image data is transferred.
            </DialogDescription>
          </DialogHeader>
          <div className='space-y-3 py-2'>
            <div className='space-y-1.5'>
              <FormLabel htmlFor='copy-new-tag' className='text-sm'>New tag name</FormLabel>
              <Input
                id='copy-new-tag'
                placeholder='e.g. latest, v2.0.0'
                value={newTagName}
                onChange={(e) => setNewTagName(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') confirmCopy() }}
                className='font-mono'
                autoFocus
              />
            </div>
            <div className='space-y-1.5'>
              <FormLabel htmlFor='copy-dest-repo' className='text-sm'>
                Destination repository{' '}
                <span className='text-muted-foreground font-normal'>(optional)</span>
              </FormLabel>
              <Input
                id='copy-dest-repo'
                placeholder={`default: ${repo}`}
                value={destRepo}
                onChange={(e) => setDestRepo(e.target.value)}
                className='font-mono'
              />
              <p className='text-xs text-muted-foreground'>Leave blank to copy within the same repository.</p>
            </div>
            {copyError && <p className='text-xs text-destructive'>{copyError}</p>}
          </div>
          <DialogFooter>
            <Button variant='outline' onClick={() => { setShowCopyDialog(false); setCopyError('') }}>Cancel</Button>
            <Button disabled={copying || !newTagName.trim()} onClick={confirmCopy}>
              {copying ? <><RefreshCwIcon className='size-3.5 animate-spin' />Copying…</> : 'Copy tag'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={showDeleteDialog} onOpenChange={(o) => { if (!o) { setShowDeleteDialog(false); setDeleteError(null) } }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete tag?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete tag{' '}
              <span className='font-mono font-semibold text-foreground'>{tag}</span>{' '}
              from{' '}
              <span className='font-mono font-semibold text-foreground'>{repo}</span>.
              The image manifest will be removed from the registry and cannot be recovered.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {deleteError && (
            <p className='text-sm text-destructive px-1'>{deleteError}</p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={deleting}
              className='bg-destructive text-destructive-foreground hover:bg-destructive/90'
            >
              {deleting ? 'Deleting…' : 'Delete tag'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
