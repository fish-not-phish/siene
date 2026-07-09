'use client'

import { useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  PlusIcon,
  EllipsisVerticalIcon,
  BotIcon,
  CopyIcon,
  CheckIcon,
  EyeIcon,
  EyeOffIcon,
  RefreshCwIcon,
  CalendarIcon,
  CheckCircleIcon,
  XCircleIcon,
  LoaderCircleIcon,
} from 'lucide-react'
import { checkUserAvailability } from '@/services/registry'
import { Calendar } from '@/components/ui/calendar'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { format } from 'date-fns'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface RobotRow {
  id: number
  name: string
  description: string
  permissions: string[]
  expires_at: string | null
  disabled: boolean
  created_at: string
}

export interface RobotsListProps {
  robots: RobotRow[]
  loading: boolean
  canManage: boolean
  onCreate: (data: { name: string; description: string; expires_at: string | null }) => Promise<{ secret: string }>
  onRotate: (id: number) => Promise<{ secret: string }>
  onToggle: (id: number, disabled: boolean) => Promise<void>
  onDelete: (id: number) => Promise<void>
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string | null) {
  if (!iso) return 'Never'
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

function isExpired(iso: string | null) {
  if (!iso) return false
  return new Date(iso) < new Date()
}

// ── Secret reveal box ─────────────────────────────────────────────────────────

function SecretBox({ secret }: { secret: string }) {
  const [visible, setVisible] = useState(false)
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(secret)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className='space-y-2'>
      <Label>Robot secret</Label>
      <div className='flex items-center gap-2'>
        <Input
          readOnly
          value={visible ? secret : '•'.repeat(32)}
          className='read-only:bg-muted font-mono text-xs'
        />
        <Button type='button' size='icon' variant='outline' onClick={() => setVisible((v) => !v)}>
          {visible ? <EyeOffIcon className='size-4' /> : <EyeIcon className='size-4' />}
        </Button>
        <Button type='button' size='icon' variant='outline' onClick={copy}>
          {copied ? <CheckIcon className='size-4 text-green-600' /> : <CopyIcon className='size-4' />}
        </Button>
      </div>
      <p className='text-destructive text-xs font-medium'>
        Copy this secret now — it will not be shown again.
      </p>
    </div>
  )
}

// ── Create dialog ─────────────────────────────────────────────────────────────

interface CreateDialogProps {
  onCreate: RobotsListProps['onCreate']
}

function CreateDialog({ onCreate }: CreateDialogProps) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [expiresAt, setExpiresAt] = useState<Date | undefined>(undefined)
  const [saving, setSaving] = useState(false)
  const [createdSecret, setCreatedSecret] = useState<string | null>(null)
  const [nameAvail, setNameAvail] = useState<boolean | 'checking' | null>(null)
  const nameDebounce = useRef<ReturnType<typeof setTimeout> | null>(null)

  const reset = () => {
    setName('')
    setDescription('')
    setExpiresAt(undefined)
    setCreatedSecret(null)
    setNameAvail(null)
  }

  const handleOpenChange = (o: boolean) => {
    setOpen(o)
    if (!o) reset()
  }

  const handleCreate = async () => {
    if (!name.trim()) return
    setSaving(true)
    try {
      const result = await onCreate({
        name: name.trim(),
        description: description.trim(),
        expires_at: expiresAt ? expiresAt.toISOString() : null,
      })
      setCreatedSecret(result.secret)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button className='max-sm:w-full'>
          <PlusIcon />
          New robot account
        </Button>
      </DialogTrigger>
      <DialogContent className='sm:max-w-md'>
        <DialogHeader className='space-y-1'>
          <DialogTitle>
            {createdSecret ? 'Robot account created' : 'New robot account'}
          </DialogTitle>
          <DialogDescription>
            {createdSecret
              ? 'Your robot account is ready. Save the secret before closing.'
              : 'Robot accounts let CI/CD pipelines push and pull images without a user password.'}
          </DialogDescription>
        </DialogHeader>

        {createdSecret ? (
          <>
            <SecretBox secret={createdSecret} />
            <div className='flex justify-end'>
              <DialogClose asChild>
                <Button>Done</Button>
              </DialogClose>
            </div>
          </>
        ) : (
          <>
            <div className='space-y-4'>
              <div className='space-y-2'>
                <Label htmlFor='robot-name'>
                  Name<span className='text-destructive'>*</span>
                </Label>
                <div className='relative'>
                  <Input
                    id='robot-name'
                    value={name}
                    onChange={(e) => {
                      const val = e.target.value
                      setName(val)
                      setNameAvail(null)
                      if (nameDebounce.current) clearTimeout(nameDebounce.current)
                      if (!val.trim()) return
                      setNameAvail('checking')
                      nameDebounce.current = setTimeout(() => {
                        checkUserAvailability({ username: val.trim() })
                          .then((r) => setNameAvail(r.username_available ?? null))
                          .catch(() => setNameAvail(null))
                      }, 400)
                    }}
                    placeholder='e.g. ci-pusher'
                    autoFocus
                    className='pr-8'
                  />
                  <span className='absolute right-2.5 top-1/2 -translate-y-1/2'>
                    {nameAvail === 'checking' && <LoaderCircleIcon className='size-4 animate-spin text-muted-foreground' />}
                    {nameAvail === true && <CheckCircleIcon className='size-4 text-green-500' />}
                    {nameAvail === false && <XCircleIcon className='size-4 text-destructive' />}
                  </span>
                </div>
                {nameAvail === false && (
                  <p className='text-xs text-destructive'>Name is already taken.</p>
                )}
                {nameAvail === true && (
                  <p className='text-xs text-green-600'>Name is available.</p>
                )}
                <p className='text-muted-foreground text-xs'>
                  Used as the username when logging in: <span className='font-mono'>{name || 'robot-name'}</span>
                </p>
              </div>

              <div className='space-y-2'>
                <Label htmlFor='robot-desc'>
                  Description{' '}
                  <span className='font-normal text-muted-foreground'>(optional)</span>
                </Label>
                <Input
                  id='robot-desc'
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder='What this robot is used for'
                />
              </div>

              <div className='space-y-2'>
                <Label>
                  Expiry date{' '}
                  <span className='font-normal text-muted-foreground'>(optional)</span>
                </Label>
                <Popover>
                  <PopoverTrigger asChild>
                    <Button
                      variant='outline'
                      className={`w-full justify-start text-left font-normal ${
                        !expiresAt ? 'text-muted-foreground' : ''
                      }`}
                    >
                      <CalendarIcon className='mr-2 size-4' />
                      {expiresAt ? format(expiresAt, 'yyyy-MM-dd') : 'Select expiry date'}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className='w-auto p-0'>
                    <Calendar
                      mode='single'
                      selected={expiresAt}
                      onSelect={(date) => {
                        if (date) {
                          const today = new Date()
                          today.setHours(0, 0, 0, 0)
                          if (date < today) {
                            setExpiresAt(today)
                          } else {
                            setExpiresAt(date)
                          }
                        }
                      }}
                      disabled={(date) => {
                        const today = new Date()
                        today.setHours(0, 0, 0, 0)
                        return date < today
                      }}
                      initialFocus
                    />
                  </PopoverContent>
                </Popover>
                <p className='text-muted-foreground text-xs'>
                  Leave blank for no expiry.
                </p>
              </div>
            </div>

            <div className='flex flex-col-reverse gap-3 sm:flex-row sm:justify-end'>
              <DialogClose asChild>
                <Button variant='outline'>Cancel</Button>
              </DialogClose>
              <Button onClick={handleCreate} disabled={!name.trim() || saving}>
                {saving ? 'Creating…' : 'Create'}
              </Button>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

// ── Delete confirm dialog ─────────────────────────────────────────────────────

interface DeleteDialogProps {
  robot: RobotRow
  open: boolean
  onOpenChange: (o: boolean) => void
  onConfirm: () => Promise<void>
}

function DeleteDialog({ robot, open, onOpenChange, onConfirm }: DeleteDialogProps) {
  const [deleting, setDeleting] = useState(false)

  const handleDelete = async () => {
    setDeleting(true)
    try {
      await onConfirm()
      onOpenChange(false)
    } finally {
      setDeleting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className='sm:max-w-sm'>
        <DialogHeader className='space-y-2'>
          <DialogTitle>Delete robot account?</DialogTitle>
          <DialogDescription>
            <span className='font-mono font-semibold text-foreground'>{robot.name}</span> will be
            permanently deleted. Any CI/CD pipelines using this account will immediately lose access.
          </DialogDescription>
        </DialogHeader>
        <div className='flex flex-col-reverse gap-3 sm:flex-row sm:justify-end'>
          <DialogClose asChild>
            <Button variant='outline'>Cancel</Button>
          </DialogClose>
          <Button variant='destructive' disabled={deleting} onClick={handleDelete}>
            {deleting ? 'Deleting…' : 'Delete'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ── Rotate secret dialog ──────────────────────────────────────────────────────

interface RotateDialogProps {
  robot: RobotRow
  open: boolean
  onOpenChange: (o: boolean) => void
  onConfirm: () => Promise<{ secret: string }>
}

function RotateDialog({ robot, open, onOpenChange, onConfirm }: RotateDialogProps) {
  const [rotating, setRotating] = useState(false)
  const [newSecret, setNewSecret] = useState<string | null>(null)

  const handleClose = (o: boolean) => {
    if (!o) setNewSecret(null)
    onOpenChange(o)
  }

  const handleRotate = async () => {
    setRotating(true)
    try {
      const result = await onConfirm()
      setNewSecret(result.secret)
    } finally {
      setRotating(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className='sm:max-w-md'>
        <DialogHeader className='space-y-1'>
          <DialogTitle>{newSecret ? 'Secret rotated' : 'Rotate secret?'}</DialogTitle>
          <DialogDescription>
            {newSecret ? (
              'Your new secret is shown below. Save it now — it cannot be retrieved again.'
            ) : (
              <>
                This will immediately invalidate the current secret for{' '}
                <span className='font-mono font-semibold text-foreground'>{robot.name}</span>.
                Any systems using the old secret will lose access until updated.
              </>
            )}
          </DialogDescription>
        </DialogHeader>

        {newSecret ? (
          <>
            <SecretBox secret={newSecret} />
            <div className='flex justify-end'>
              <DialogClose asChild>
                <Button>Done</Button>
              </DialogClose>
            </div>
          </>
        ) : (
          <div className='flex flex-col-reverse gap-3 sm:flex-row sm:justify-end'>
            <DialogClose asChild>
              <Button variant='outline'>Cancel</Button>
            </DialogClose>
            <Button variant='destructive' disabled={rotating} onClick={handleRotate}>
              {rotating ? 'Rotating…' : 'Rotate secret'}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

const RobotsList = ({ robots, loading, canManage, onCreate, onRotate, onToggle, onDelete }: RobotsListProps) => {
  const [deleteTarget, setDeleteTarget] = useState<RobotRow | null>(null)
  const [rotateTarget, setRotateTarget] = useState<RobotRow | null>(null)

  return (
    <section className='py-3'>
      <div className='mx-auto max-w-7xl'>
        {/* Header */}
        <div className='mb-6 flex flex-wrap items-center justify-between gap-4'>
          <div className='space-y-1'>
            <h3 className='font-semibold'>Robot Accounts</h3>
            <p className='text-muted-foreground text-sm'>
              Machine credentials for CI/CD pipelines to push and pull images without a user password.
            </p>
          </div>
          {canManage && <CreateDialog onCreate={onCreate} />}
        </div>

        {/* Rows */}
        {loading ? (
          <div className='space-y-3'>
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className='h-14 w-full rounded-lg' />
            ))}
          </div>
        ) : robots.length === 0 ? (
          <div className='flex flex-col items-center gap-3 py-24 text-center text-muted-foreground'>
            <BotIcon className='size-10 opacity-30' />
            <p className='text-sm'>No robot accounts yet.</p>
            {canManage && (
              <p className='text-xs'>Create one to enable CI/CD push access.</p>
            )}
          </div>
        ) : (
          robots.map((robot, idx) => {
            const expired = isExpired(robot.expires_at)

            return (
              <div key={robot.id}>
                <div className='flex items-center justify-between gap-4 py-1'>
                  {/* Left: icon + info */}
                  <div className='flex min-w-0 items-center gap-3'>
                    <div className={`flex size-9 shrink-0 items-center justify-center rounded-full border ${robot.disabled ? 'opacity-40' : ''}`}>
                      <BotIcon className='size-4 text-muted-foreground' />
                    </div>
                    <div className='min-w-0'>
                      <div className='flex items-center gap-2'>
                        <p className={`font-mono text-sm font-medium ${robot.disabled ? 'text-muted-foreground line-through' : ''}`}>
                          {robot.name}
                        </p>
                        {expired && (
                          <span className='rounded-full bg-destructive/10 px-1.5 py-0.5 text-[10px] font-medium text-destructive'>
                            expired
                          </span>
                        )}
                        {robot.disabled && !expired && (
                          <span className='text-muted-foreground rounded-full border px-1.5 py-0.5 text-[10px]'>
                            disabled
                          </span>
                        )}
                      </div>
                      <p className='truncate text-xs text-muted-foreground'>
                        {robot.description || <span className='italic'>No description</span>}
                        {' · '}
                        Expires {fmtDate(robot.expires_at)}
                        {' · '}
                        Created {fmtDate(robot.created_at)}
                      </p>
                    </div>
                  </div>

                  {/* Right: toggle + menu */}
                  <div className='flex shrink-0 items-center gap-3'>
                    {canManage && (
                      <Switch
                        checked={!robot.disabled}
                        onCheckedChange={(checked) => onToggle(robot.id, !checked)}
                        aria-label={robot.disabled ? 'Enable robot' : 'Disable robot'}
                      />
                    )}
                    {!canManage && (
                      <Switch checked={!robot.disabled} disabled aria-label='Status' />
                    )}

                    {canManage && (
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant='ghost' size='icon' className='rounded-full'>
                            <EllipsisVerticalIcon />
                            <span className='sr-only'>Robot actions</span>
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent className='w-36' align='end'>
                           <DropdownMenuGroup>
                             <DropdownMenuItem onClick={() => setRotateTarget(robot)}>
                               <RefreshCwIcon className='mr-2 size-3.5' />
                               Rotate secret
                             </DropdownMenuItem>
                             <DropdownMenuItem
                               className='text-destructive transition-colors duration-200 hover:bg-destructive/10! hover:text-destructive!'
                               onClick={() => setDeleteTarget(robot)}
                             >
                               Delete
                             </DropdownMenuItem>
                           </DropdownMenuGroup>
                         </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </div>
                </div>

                {idx !== robots.length - 1 && <Separator className='my-2' />}
              </div>
            )
          })
        )}

        {deleteTarget && (
          <DeleteDialog
            robot={deleteTarget}
            open={deleteTarget !== null}
            onOpenChange={(o) => !o && setDeleteTarget(null)}
            onConfirm={() => onDelete(deleteTarget.id)}
          />
        )}

        {rotateTarget && (
          <RotateDialog
            robot={rotateTarget}
            open={rotateTarget !== null}
            onOpenChange={(o) => !o && setRotateTarget(null)}
            onConfirm={() => onRotate(rotateTarget.id)}
          />
        )}
      </div>
    </section>
  )
}

export default RobotsList
