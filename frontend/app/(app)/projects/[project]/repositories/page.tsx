'use client'

import { useParams, useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { baseUrl, registryHost as registryHostConst } from '@/constants/constants'
import { BoxesIcon, SearchIcon, RefreshCwIcon, Trash2Icon, CopyIcon } from 'lucide-react'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
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
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { useAuthContext } from '@/store/AuthContext'

function relativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 2) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  if (days < 30) return `${days}d ago`
  const months = Math.floor(days / 30)
  if (months < 12) return `${months}mo ago`
  return `${Math.floor(months / 12)}y ago`
}

interface Repository {
  id: number
  name: string
  full_name: string
  description: string
  pull_count: number
  push_count: number
  tag_count: number
  updated_at: string
}

export default function RepositoriesPage() {
  const { project } = useParams<{ project: string }>()
  const router = useRouter()
  const { user } = useAuthContext()
  const [repos, setRepos] = useState<Repository[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<Repository | null>(null)
  const [deleting, setDeleting] = useState(false)

  const registryHost = registryHostConst || (() => {
    try {
      const url = new URL(baseUrl)
      return url.port ? `${url.hostname}:${url.port}` : url.hostname
    } catch {
      return typeof window !== 'undefined' ? window.location.hostname : 'localhost'
    }
  })()

  const load = () => {
    setLoading(true)
    fetch(`${baseUrl}registry/projects/${project}/repositories`, { credentials: 'include' })
      .then((r) => r.json())
      .then((data) => setRepos(Array.isArray(data) ? data : []))
      .catch(() => setRepos([]))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [project])

  const filtered = repos.filter((r) =>
    r.name.toLowerCase().includes(search.toLowerCase())
  )

  const confirmDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await fetch(
        `${baseUrl}registry/projects/${project}/repositories/${deleteTarget.name}`,
        {
          method: 'DELETE',
          credentials: 'include',
          headers: { 'X-CSRFToken': user.csrfToken ?? '' },
        }
      )
      setDeleteTarget(null)
      load()
    } finally {
      setDeleting(false)
    }
  }

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <BoxesIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>{project}</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Repositories</span>
        <div className='ml-auto flex items-center gap-2'>
          <div className='relative'>
            <SearchIcon className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
            <Input
              placeholder='Search repositories…'
              className='h-8 w-48 pl-8 text-sm'
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <Button size='sm' variant='outline' onClick={load}>
            <RefreshCwIcon className='size-3.5' />
          </Button>
        </div>
      </header>

      <main className='flex-1 px-6 py-6'>
        {loading ? (
          <div className='space-y-2'>
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className='h-12 w-full rounded-md' />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className='flex flex-col items-center justify-center gap-3 py-24 text-center text-muted-foreground'>
            <BoxesIcon className='size-10 opacity-30' />
            <p className='text-sm'>
              {search ? 'No repositories match your search.' : 'No repositories yet.'}
            </p>
            {!search && (
              <p className='text-xs'>
                Push an image to{' '}
                <code className='rounded bg-muted px-1 text-foreground'>
                  {registryHost}/{project}/&lt;repo&gt;:&lt;tag&gt;
                </code>{' '}
                to get started.
              </p>
            )}
          </div>
        ) : (
          <div className='rounded-md border'>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className='w-20 text-right'>Tags</TableHead>
                  <TableHead className='w-24 text-right'>Pulls</TableHead>
                  <TableHead className='w-24 text-right'>Pushes</TableHead>
                  <TableHead className='w-36'>Last Push</TableHead>
                  <TableHead className='w-12' />
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((repo) => {
                  const pullPath = `${registryHost}/${project}/${repo.name}`
                  return (
                    <TableRow key={repo.id} className='cursor-pointer hover:bg-muted/50 group'>
                      <TableCell>
                        <div className='flex items-center gap-1.5'>
                          <a
                            href={`/projects/${project}/repositories/${repo.name}`}
                            className='font-medium hover:underline'
                          >
                            {repo.name}
                          </a>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <button
                                type='button'
                                onClick={(e) => {
                                  e.preventDefault()
                                  e.stopPropagation()
                                  navigator.clipboard.writeText(`${pullPath}:<tag>`)
                                }}
                                className='opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-foreground'
                                aria-label='Copy pull path'
                              >
                                <CopyIcon className='size-3' />
                              </button>
                            </TooltipTrigger>
                            <TooltipContent side='right' className='font-mono text-xs'>
                              {pullPath}:&lt;tag&gt;
                            </TooltipContent>
                          </Tooltip>
                        </div>
                        {repo.description && (
                          <p className='text-xs text-muted-foreground mt-0.5'>{repo.description}</p>
                        )}
                      </TableCell>
                      <TableCell className='text-right'>
                        <Badge variant='secondary'>{repo.tag_count}</Badge>
                      </TableCell>
                      <TableCell className='text-right text-sm text-muted-foreground'>
                        {repo.pull_count.toLocaleString()}
                      </TableCell>
                      <TableCell className='text-right text-sm text-muted-foreground'>
                        {repo.push_count.toLocaleString()}
                      </TableCell>
                      <TableCell className='text-sm text-muted-foreground'>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span>{relativeTime(repo.updated_at)}</span>
                          </TooltipTrigger>
                          <TooltipContent side='left' className='text-xs'>
                            {new Date(repo.updated_at).toLocaleString()}
                          </TooltipContent>
                        </Tooltip>
                      </TableCell>
                      <TableCell className='text-right'>
                        <Button
                          size='icon'
                          variant='ghost'
                          className='size-7 opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive'
                          onClick={(e) => { e.stopPropagation(); setDeleteTarget(repo) }}
                        >
                          <Trash2Icon className='size-3.5' />
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </main>

      <AlertDialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) setDeleteTarget(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete repository?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete{' '}
              <span className='font-mono font-semibold text-foreground'>{deleteTarget?.name}</span>{' '}
              and all {deleteTarget?.tag_count ?? 0} tag{deleteTarget?.tag_count !== 1 ? 's' : ''} inside it.
              The images will be removed from the registry and cannot be recovered.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              disabled={deleting}
              className='bg-destructive text-destructive-foreground hover:bg-destructive/90'
            >
              {deleting ? 'Deleting…' : 'Delete repository'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
