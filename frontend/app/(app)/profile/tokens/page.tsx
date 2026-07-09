'use client'

import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useAuthContext } from '@/store/AuthContext'
import { baseUrl } from '@/constants/constants'
import { KeyRoundIcon, PlusIcon, CopyIcon, EyeIcon, EyeOffIcon, Trash2Icon, RefreshCwIcon } from 'lucide-react'

interface PAT {
  id: number
  name: string
  prefix: string
  created_at: string
  expires_at: string | null
  last_used_at: string | null
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      size='icon'
      variant='ghost'
      className='size-7 shrink-0'
      onClick={() => {
        navigator.clipboard.writeText(text)
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      }}
    >
      <CopyIcon className={`size-3.5 ${copied ? 'text-green-500' : 'text-muted-foreground'}`} />
    </Button>
  )
}

function CreateTokenDialog({ csrfToken, onCreated }: { csrfToken: string; onCreated: () => void }) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [loading, setLoading] = useState(false)
  const [newToken, setNewToken] = useState<string | null>(null)
  const [showToken, setShowToken] = useState(false)

  const create = async () => {
    if (!name.trim()) return
    setLoading(true)
    const res = await fetch(`${baseUrl}accounts/tokens`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
      body: JSON.stringify({ name, expires_at: expiresAt || null }),
    })
    setLoading(false)
    if (res.status === 201) {
      const data = await res.json()
      setNewToken(data.token)
      onCreated()
    }
  }

  const close = () => {
    setOpen(false)
    setName('')
    setExpiresAt('')
    setNewToken(null)
    setShowToken(false)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) close(); else setOpen(true) }}>
      <DialogTrigger asChild>
        <Button size='sm'>
          <PlusIcon className='size-3.5' />
          New token
        </Button>
      </DialogTrigger>
      <DialogContent className='sm:max-w-md'>
        {newToken ? (
          <>
            <DialogHeader>
              <DialogTitle>Token created</DialogTitle>
              <DialogDescription>
                Copy your token now — it will not be shown again.
              </DialogDescription>
            </DialogHeader>
            <div className='flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2'>
              <code className='flex-1 font-mono text-sm break-all'>
                {showToken ? newToken : '•'.repeat(Math.min(newToken.length, 40))}
              </code>
              <Button
                size='icon'
                variant='ghost'
                className='size-7 shrink-0'
                onClick={() => setShowToken((v) => !v)}
              >
                {showToken
                  ? <EyeOffIcon className='size-3.5 text-muted-foreground' />
                  : <EyeIcon className='size-3.5 text-muted-foreground' />}
              </Button>
              <CopyButton text={newToken} />
            </div>
            <DialogFooter>
              <Button onClick={close}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Create access token</DialogTitle>
              <DialogDescription>
                Tokens authenticate with the registry in place of a password.
              </DialogDescription>
            </DialogHeader>
            <div className='space-y-4 py-2'>
              <div className='space-y-1.5'>
                <Label htmlFor='pat-name'>Token name</Label>
                <Input
                  id='pat-name'
                  placeholder='e.g. CI pipeline'
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && create()}
                  autoFocus
                />
              </div>
              <div className='space-y-1.5'>
                <Label htmlFor='pat-expires'>
                  Expiration <span className='text-muted-foreground font-normal'>(optional)</span>
                </Label>
                <Input
                  id='pat-expires'
                  type='date'
                  value={expiresAt}
                  onChange={(e) => setExpiresAt(e.target.value)}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant='outline' onClick={close}>Cancel</Button>
              <Button onClick={create} disabled={!name.trim() || loading}>
                {loading ? 'Creating…' : 'Create token'}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

function RotateTokenDialog({ token, csrfToken, onRotated }: { token: PAT; csrfToken: string; onRotated: () => void }) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [newToken, setNewToken] = useState<string | null>(null)
  const [showToken, setShowToken] = useState(false)

  const rotate = async () => {
    setLoading(true)
    const res = await fetch(`${baseUrl}accounts/tokens/${token.id}/rotate`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRFToken': csrfToken },
    })
    setLoading(false)
    if (res.ok) {
      const data = await res.json()
      setNewToken(data.token)
    }
  }

  const close = () => {
    setOpen(false)
    setNewToken(null)
    setShowToken(false)
    onRotated()
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) close(); else setOpen(true) }}>
      <DialogTrigger asChild>
        <Button size='icon' variant='ghost' className='size-7 text-muted-foreground hover:text-foreground'>
          <RefreshCwIcon className='size-3.5' />
        </Button>
      </DialogTrigger>
      <DialogContent className='sm:max-w-md'>
        {newToken ? (
          <>
            <DialogHeader>
              <DialogTitle>Token rotated</DialogTitle>
              <DialogDescription>
                Copy your new token now — it will not be shown again. The old token is immediately invalid.
              </DialogDescription>
            </DialogHeader>
            <div className='flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2'>
              <code className='flex-1 font-mono text-sm break-all'>
                {showToken ? newToken : '•'.repeat(Math.min(newToken.length, 40))}
              </code>
              <Button size='icon' variant='ghost' className='size-7 shrink-0' onClick={() => setShowToken((v) => !v)}>
                {showToken
                  ? <EyeOffIcon className='size-3.5 text-muted-foreground' />
                  : <EyeIcon className='size-3.5 text-muted-foreground' />}
              </Button>
              <CopyButton text={newToken} />
            </div>
            <DialogFooter>
              <Button onClick={close}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Rotate token?</DialogTitle>
              <DialogDescription>
                This will immediately invalidate the current secret for{' '}
                <span className='font-semibold text-foreground'>{token.name}</span>{' '}
                and generate a new one. The token name and expiry are preserved.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant='outline' onClick={close}>Cancel</Button>
              <Button onClick={rotate} disabled={loading}>
                {loading ? 'Rotating…' : 'Rotate token'}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

export default function TokensPage() {
  const { user } = useAuthContext()
  const [tokens, setTokens] = useState<PAT[]>([])
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    fetch(`${baseUrl}accounts/tokens`, { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => setTokens(Array.isArray(d) ? d : []))
      .catch(() => setTokens([]))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const revoke = async (id: number) => {
    await fetch(`${baseUrl}accounts/tokens/${id}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: { 'X-CSRFToken': user.csrfToken ?? '' },
    })
    load()
  }

  return (
    <Card>
      <CardHeader className='flex flex-row items-start justify-between gap-4 space-y-0'>
        <div>
          <CardTitle className='text-base'>Personal access tokens</CardTitle>
          <CardDescription className='mt-1'>
            Use a token to authenticate{' '}
            <code className='rounded bg-muted px-1 text-xs'>docker login</code> in place of your
            password.
          </CardDescription>
        </div>
        <CreateTokenDialog csrfToken={user.csrfToken ?? ''} onCreated={load} />
      </CardHeader>

      <CardContent>
        {loading ? (
          <div className='space-y-2'>
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className='h-10 w-full rounded-md' />
            ))}
          </div>
        ) : tokens.length === 0 ? (
          <div className='flex flex-col items-center gap-2 py-10 text-center text-muted-foreground'>
            <KeyRoundIcon className='size-8 opacity-30' />
            <p className='text-sm'>No tokens yet.</p>
            <p className='text-xs'>Create one to enable CLI and CI/CD access.</p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead className='w-24'>Prefix</TableHead>
                <TableHead className='w-28'>Created</TableHead>
                <TableHead className='w-28'>Expires</TableHead>
                <TableHead className='w-28'>Last used</TableHead>
                <TableHead className='w-16' />
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.map((t) => {
                const expired = t.expires_at && new Date(t.expires_at) < new Date()
                return (
                  <TableRow key={t.id}>
                    <TableCell className='font-medium text-sm'>{t.name}</TableCell>
                    <TableCell>
                      <code className='rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground'>
                        {t.prefix}…
                      </code>
                    </TableCell>
                    <TableCell className='text-xs text-muted-foreground'>
                      {new Date(t.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className='text-xs'>
                      {t.expires_at ? (
                        <span className={expired ? 'text-destructive' : 'text-muted-foreground'}>
                          {new Date(t.expires_at).toLocaleDateString()}
                          {expired && ' (expired)'}
                        </span>
                      ) : (
                        <span className='text-muted-foreground'>Never</span>
                      )}
                    </TableCell>
                    <TableCell className='text-xs text-muted-foreground'>
                      {t.last_used_at ? new Date(t.last_used_at).toLocaleDateString() : '—'}
                    </TableCell>
                    <TableCell>
                      <div className='flex items-center gap-1'>
                      <RotateTokenDialog token={t} csrfToken={user.csrfToken ?? ''} onRotated={load} />
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button
                            size='icon'
                            variant='ghost'
                            className='size-7 text-muted-foreground hover:text-destructive'
                          >
                            <Trash2Icon className='size-3.5' />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Revoke token?</AlertDialogTitle>
                            <AlertDialogDescription>
                              <strong>{t.name}</strong> will stop working immediately. This cannot
                              be undone.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              className='bg-destructive text-destructive-foreground hover:bg-destructive/90'
                              onClick={() => revoke(t.id)}
                            >
                              Revoke
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                        </AlertDialog>
                      </div>
                      </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
