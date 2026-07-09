'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  ShieldAlertIcon, SearchIcon, RefreshCwIcon, ShieldCheckIcon,
  KeySquareIcon, WrenchIcon,
} from 'lucide-react'
import { fetchProjectSecurity, type VulnSummary } from '@/services/registry'
import { baseUrl } from '@/constants/constants'

interface SecretSummary {
  tag_id: number
  tag_name: string
  repository: string
  project: string
  scan_status: string
  total: number
  scanned_at: string | null
}

interface MisconfigSummary {
  tag_id: number
  tag_name: string
  repository: string
  project: string
  scan_status: string
  fail: number
  warn: number
  pass_count: number
  scanned_at: string | null
}

const SEV_OPTIONS = [
  { value: 'all',      label: 'All severities' },
  { value: 'critical', label: 'Critical only' },
  { value: 'high',     label: 'High or above' },
]

const sevBadge = (count: number, cls: string) =>
  count > 0 ? (
    <span className={`inline-flex items-center rounded-full px-1.5 py-0.5 text-xs font-medium ${cls}`}>
      {count}
    </span>
  ) : (
    <span className='text-xs text-muted-foreground'>—</span>
  )

export default function ProjectSecurityPage() {
  const { project } = useParams<{ project: string }>()

  const [vulns, setVulns]             = useState<VulnSummary[]>([])
  const [secrets, setSecrets]         = useState<SecretSummary[]>([])
  const [misconfigs, setMisconfigs]   = useState<MisconfigSummary[]>([])
  const [loadingVulns, setLoadingVulns]         = useState(true)
  const [loadingSecrets, setLoadingSecrets]     = useState(true)
  const [loadingMisconfigs, setLoadingMisconfigs] = useState(true)
  const [search, setSearch]           = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')

  const loadVulns = () => {
    setLoadingVulns(true)
    fetchProjectSecurity(project, severityFilter)
      .then(d => setVulns(Array.isArray(d) ? d : []))
      .catch(() => setVulns([]))
      .finally(() => setLoadingVulns(false))
  }

  const loadSecrets = () => {
    setLoadingSecrets(true)
    fetch(`${baseUrl}registry/projects/${project}/security/secrets`, { credentials: 'include' })
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() })
      .then(d => setSecrets(Array.isArray(d) ? d : []))
      .catch(() => setSecrets([]))
      .finally(() => setLoadingSecrets(false))
  }

  const loadMisconfigs = () => {
    setLoadingMisconfigs(true)
    fetch(`${baseUrl}registry/projects/${project}/security/misconfigs`, { credentials: 'include' })
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() })
      .then(d => setMisconfigs(Array.isArray(d) ? d : []))
      .catch(() => setMisconfigs([]))
      .finally(() => setLoadingMisconfigs(false))
  }

  useEffect(() => { loadVulns() }, [project, severityFilter])
  useEffect(() => { loadSecrets() }, [project])
  useEffect(() => { loadMisconfigs() }, [project])

  const q = search.toLowerCase()
  const filteredVulns      = vulns.filter(v => v.tag_name.toLowerCase().includes(q) || v.repository.toLowerCase().includes(q))
  const filteredSecrets    = secrets.filter(v => v.tag_name.toLowerCase().includes(q) || v.repository.toLowerCase().includes(q))
  const filteredMisconfigs = misconfigs.filter(v => v.tag_name.toLowerCase().includes(q) || v.repository.toLowerCase().includes(q))

  const totalCritical = filteredVulns.reduce((s, v) => s + v.critical, 0)
  const totalHigh     = filteredVulns.reduce((s, v) => s + v.high, 0)
  const totalSecrets  = filteredSecrets.reduce((s, v) => s + v.total, 0)
  const totalFail     = filteredMisconfigs.reduce((s, v) => s + v.fail, 0)

  const imageLink = (v: { repository: string; tag_name: string }) =>
    `/projects/${project}/repositories/${v.repository}/${v.tag_name}`

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <ShieldAlertIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>{project}</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Security</span>
        <div className='ml-auto flex items-center gap-2'>
          <div className='relative'>
            <SearchIcon className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
            <Input
              placeholder='Search…'
              className='h-8 w-40 pl-8 text-sm'
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <Button size='sm' variant='outline' onClick={() => { loadVulns(); loadSecrets(); loadMisconfigs() }}>
            <RefreshCwIcon className='size-3.5' />
          </Button>
        </div>
      </header>

      <main className='flex-1 px-6 py-6 space-y-4 max-w-7xl mx-auto w-full'>
        {/* Summary strip */}
        <div className='flex flex-wrap items-center gap-4 rounded-lg border px-4 py-3 text-sm'>
          {totalCritical > 0 && (
            <span className='flex items-center gap-1.5 font-medium text-red-600 dark:text-red-400'>
              <ShieldAlertIcon className='size-4' />{totalCritical} Critical vulns
            </span>
          )}
          {totalHigh > 0 && (
            <span className='font-medium text-orange-600 dark:text-orange-400'>{totalHigh} High vulns</span>
          )}
          {totalSecrets > 0 && (
            <span className='flex items-center gap-1.5 font-medium text-red-600 dark:text-red-400'>
              <KeySquareIcon className='size-4' />{totalSecrets} Secret{totalSecrets !== 1 ? 's' : ''}
            </span>
          )}
          {totalFail > 0 && (
            <span className='flex items-center gap-1.5 font-medium text-orange-600 dark:text-orange-400'>
              <WrenchIcon className='size-4' />{totalFail} Misconfig FAIL{totalFail !== 1 ? 's' : ''}
            </span>
          )}
          {totalCritical === 0 && totalHigh === 0 && totalSecrets === 0 && totalFail === 0 && !loadingVulns && !loadingSecrets && !loadingMisconfigs && (
            <span className='flex items-center gap-1.5 text-green-600 dark:text-green-400'>
              <ShieldCheckIcon className='size-4' />No critical issues found
            </span>
          )}
        </div>

        <Tabs defaultValue='vulnerabilities'>
          <TabsList>
            <TabsTrigger value='vulnerabilities' className='gap-1.5'>
              <ShieldAlertIcon className='size-3.5' />
              Vulnerabilities
              {!loadingVulns && vulns.length > 0 && (
                <span className='ml-1 rounded-full bg-muted px-1.5 py-0.5 text-xs'>{vulns.length}</span>
              )}
            </TabsTrigger>
            <TabsTrigger value='secrets' className='gap-1.5'>
              <KeySquareIcon className='size-3.5' />
              Secrets
              {!loadingSecrets && secrets.length > 0 && (
                <span className='ml-1 rounded-full bg-muted px-1.5 py-0.5 text-xs'>{secrets.length}</span>
              )}
            </TabsTrigger>
            <TabsTrigger value='misconfigs' className='gap-1.5'>
              <WrenchIcon className='size-3.5' />
              Misconfigs
              {!loadingMisconfigs && misconfigs.length > 0 && (
                <span className='ml-1 rounded-full bg-muted px-1.5 py-0.5 text-xs'>{misconfigs.length}</span>
              )}
            </TabsTrigger>
          </TabsList>

          {/* ── Vulnerabilities ── */}
          <TabsContent value='vulnerabilities' className='mt-4 space-y-3'>
            <div className='flex items-center gap-2'>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className='h-8 w-36 text-sm'><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SEV_OPTIONS.map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            {loadingVulns ? (
              <div className='space-y-2'>{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className='h-12 w-full rounded-md' />)}</div>
            ) : filteredVulns.length === 0 ? (
              <div className='flex flex-col items-center gap-3 py-20 text-center text-muted-foreground'>
                <ShieldCheckIcon className='size-10 opacity-30' />
                <p className='text-sm'>{vulns.length === 0 ? 'No vulnerability scans yet.' : 'No results match the current filters.'}</p>
              </div>
            ) : (
              <div className='rounded-md border'>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Image</TableHead>
                      <TableHead className='w-20 text-center'>Critical</TableHead>
                      <TableHead className='w-20 text-center'>High</TableHead>
                      <TableHead className='w-20 text-center'>Medium</TableHead>
                      <TableHead className='w-20 text-center'>Low</TableHead>
                      <TableHead className='w-36'>Scanned</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredVulns.map(v => (
                      <TableRow key={v.tag_id}>
                        <TableCell>
                          <Link href={imageLink(v)} className='font-mono text-sm hover:underline'>{v.repository}:{v.tag_name}</Link>
                        </TableCell>
                        <TableCell className='text-center'>{sevBadge(v.critical, 'bg-red-600/10 text-red-600 dark:bg-red-400/10 dark:text-red-400')}</TableCell>
                        <TableCell className='text-center'>{sevBadge(v.high, 'bg-orange-600/10 text-orange-600 dark:bg-orange-400/10 dark:text-orange-400')}</TableCell>
                        <TableCell className='text-center'>{sevBadge(v.medium, 'bg-yellow-600/10 text-yellow-600 dark:bg-yellow-400/10 dark:text-yellow-400')}</TableCell>
                        <TableCell className='text-center'>{sevBadge(v.low, 'bg-blue-600/10 text-blue-600 dark:bg-blue-400/10 dark:text-blue-400')}</TableCell>
                        <TableCell className='text-xs text-muted-foreground'>{v.scanned_at ? new Date(v.scanned_at).toLocaleString() : '—'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>

          {/* ── Secrets ── */}
          <TabsContent value='secrets' className='mt-4'>
            {loadingSecrets ? (
              <div className='space-y-2'>{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className='h-12 w-full rounded-md' />)}</div>
            ) : filteredSecrets.length === 0 ? (
              <div className='flex flex-col items-center gap-3 py-20 text-center text-muted-foreground'>
                <ShieldCheckIcon className='size-10 opacity-30' />
                <p className='text-sm'>{secrets.length === 0 ? 'No secret scans yet.' : 'No results match the current search.'}</p>
              </div>
            ) : (
              <div className='rounded-md border'>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Image</TableHead>
                      <TableHead className='w-28 text-center'>Secrets found</TableHead>
                      <TableHead className='w-36'>Scanned</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredSecrets.map(v => (
                      <TableRow key={v.tag_id}>
                        <TableCell>
                          <Link href={`${imageLink(v)}?tab=secrets`} className='font-mono text-sm hover:underline'>{v.repository}:{v.tag_name}</Link>
                        </TableCell>
                        <TableCell className='text-center'>
                          {v.total > 0
                            ? <span className='inline-flex items-center rounded-full px-1.5 py-0.5 text-xs font-medium bg-red-600/10 text-red-600 dark:bg-red-400/10 dark:text-red-400'>{v.total}</span>
                            : <span className='inline-flex items-center gap-1 rounded-full bg-green-600/10 px-1.5 py-0.5 text-xs font-medium text-green-600 dark:bg-green-400/10 dark:text-green-400'><ShieldCheckIcon className='size-3' />Clean</span>
                          }
                        </TableCell>
                        <TableCell className='text-xs text-muted-foreground'>{v.scanned_at ? new Date(v.scanned_at).toLocaleString() : '—'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>

          {/* ── Misconfigs ── */}
          <TabsContent value='misconfigs' className='mt-4'>
            {loadingMisconfigs ? (
              <div className='space-y-2'>{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className='h-12 w-full rounded-md' />)}</div>
            ) : filteredMisconfigs.length === 0 ? (
              <div className='flex flex-col items-center gap-3 py-20 text-center text-muted-foreground'>
                <ShieldCheckIcon className='size-10 opacity-30' />
                <p className='text-sm'>{misconfigs.length === 0 ? 'No misconfiguration scans yet.' : 'No results match the current search.'}</p>
              </div>
            ) : (
              <div className='rounded-md border'>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Image</TableHead>
                      <TableHead className='w-20 text-center'>FAIL</TableHead>
                      <TableHead className='w-36'>Scanned</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredMisconfigs.map(v => (
                      <TableRow key={v.tag_id}>
                        <TableCell>
                          <Link href={`${imageLink(v)}?tab=misconfigs`} className='font-mono text-sm hover:underline'>{v.repository}:{v.tag_name}</Link>
                        </TableCell>
                        <TableCell className='text-center'>{sevBadge(v.fail, 'bg-orange-600/10 text-orange-600 dark:bg-orange-400/10 dark:text-orange-400')}</TableCell>
                        <TableCell className='text-xs text-muted-foreground'>{v.scanned_at ? new Date(v.scanned_at).toLocaleString() : '—'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>
        </Tabs>
      </main>
    </>
  )
}
