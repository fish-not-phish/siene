'use client'

import { useEffect, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import BadgeCheck from '@/assets/svg/badge-check'
import { SearchIcon, EllipsisVerticalIcon, UserPlusIcon, CheckCircleIcon, XCircleIcon, LoaderCircleIcon } from 'lucide-react'
import { checkUserAvailability } from '@/services/registry'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AdminUserRow {
  id: number
  username: string
  email: string
  is_admin: boolean
  date_joined: string
  last_login: string | null
}

export interface AdminUsersListProps {
  users: AdminUserRow[]
  loading: boolean
  currentUsername: string
  oidcEnabled: boolean
  onDelete: (userId: number) => Promise<void>
  onCreate: (username: string, email: string, password: string) => Promise<void>
  onSetAdmin: (userId: number, isAdmin: boolean) => Promise<void>
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function initials(username: string) {
  return username.slice(0, 2).toUpperCase()
}

function fmtDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

// ── Component ─────────────────────────────────────────────────────────────────

const AdminUsersList = ({
  users,
  loading,
  currentUsername,
  oidcEnabled,
  onDelete,
  onCreate,
  onSetAdmin,
}: AdminUsersListProps) => {
  const [search, setSearch] = useState('')
  const [confirmId, setConfirmId] = useState<number | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [togglingAdminId, setTogglingAdminId] = useState<number | null>(null)

  // Create user dialog state
  const [createOpen, setCreateOpen] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newEmail, setNewEmail] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState<string | null>(null)

  // Availability state: null = unchecked, true = available, false = taken, 'checking' = in-flight
  const [usernameAvail, setUsernameAvail] = useState<boolean | 'checking' | null>(null)
  const [emailAvail, setEmailAvail] = useState<boolean | 'checking' | null>(null)
  const usernameDebounce = useRef<ReturnType<typeof setTimeout> | null>(null)
  const emailDebounce = useRef<ReturnType<typeof setTimeout> | null>(null)

  const filtered = users.filter(
    (u) =>
      u.username.toLowerCase().includes(search.toLowerCase()) ||
      u.email.toLowerCase().includes(search.toLowerCase()),
  )

  const confirmUser = confirmId !== null ? users.find((u) => u.id === confirmId) : null

  const handleDelete = async () => {
    if (confirmId === null) return
    setDeleting(true)
    try {
      await onDelete(confirmId)
      setConfirmId(null)
    } finally {
      setDeleting(false)
    }
  }

  const handleToggleAdmin = async (userId: number, currentIsAdmin: boolean) => {
    setTogglingAdminId(userId)
    try {
      await onSetAdmin(userId, !currentIsAdmin)
    } finally {
      setTogglingAdminId(null)
    }
  }

  const handleCreate = async () => {
    setCreateError(null)
    if (!newUsername.trim()) { setCreateError('Username is required.'); return }
    if (!newEmail.trim()) { setCreateError('Email is required.'); return }
    if (newPassword.length < 8) { setCreateError('Password must be at least 8 characters.'); return }
    setCreating(true)
    try {
      await onCreate(newUsername.trim(), newEmail.trim(), newPassword)
      setCreateOpen(false)
      setNewUsername('')
      setNewEmail('')
      setNewPassword('')
      setUsernameAvail(null)
      setEmailAvail(null)
    } catch (e: unknown) {
      setCreateError(e instanceof Error ? e.message : 'Failed to create user.')
    } finally {
      setCreating(false)
    }
  }

  const createButton = (
    <Button
      size='sm'
      disabled={oidcEnabled}
      onClick={() => !oidcEnabled && setCreateOpen(true)}
      className='gap-1.5'
    >
      <UserPlusIcon className='size-3.5' />
      Create user
    </Button>
  )

  return (
    <TooltipProvider>
      <section className='py-3'>
        <div className='mx-auto max-w-7xl'>
          {/* Header */}
          <div className='mb-6 flex flex-wrap items-center justify-between gap-4'>
            <div className='space-y-1'>
              <h3 className='font-semibold'>Users</h3>
              <p className='text-muted-foreground text-sm'>
                All registered users on this registry instance.
              </p>
            </div>

            <div className='flex items-center gap-2'>
              <div className='relative'>
                <SearchIcon className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
                <Input
                  placeholder='Search users…'
                  className='h-9 w-52 pl-8 text-sm'
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>

              {oidcEnabled ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span tabIndex={0}>{createButton}</span>
                  </TooltipTrigger>
                  <TooltipContent side='bottom'>
                    User creation is managed by your OIDC provider.
                  </TooltipContent>
                </Tooltip>
              ) : (
                createButton
              )}
            </div>
          </div>

          {/* Rows */}
          {loading ? (
            <div className='space-y-3'>
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className='h-12 w-full rounded-lg' />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <p className='text-muted-foreground text-sm'>No users found.</p>
          ) : (
            filtered.map((user, idx) => {
              const isSelf = user.username === currentUsername

              return (
                <div key={user.id}>
                  <div className='flex items-center justify-between gap-3 py-1'>
                    {/* Left: avatar + info */}
                    <div className='flex items-center gap-3'>
                      <div className='relative w-fit'>
                        <Avatar className='size-9'>
                          <AvatarFallback>{initials(user.username)}</AvatarFallback>
                        </Avatar>
                        {user.is_admin && (
                          <span className='absolute -right-1.5 -top-1.5'>
                            <span className='sr-only'>System admin</span>
                            <BadgeCheck className='text-background size-5 fill-sky-500' />
                          </span>
                        )}
                      </div>

                      <div className='flex flex-col items-start'>
                        <div className='flex items-center gap-1.5'>
                          <p className='text-sm font-medium'>{user.username}</p>
                          {isSelf && (
                            <span className='text-muted-foreground rounded-full border px-1.5 py-px text-[10px] leading-tight'>
                              you
                            </span>
                          )}
                        </div>
                        <p className='text-muted-foreground text-xs'>{user.email}</p>
                      </div>
                    </div>

                    {/* Right: dates + actions */}
                    <div className='flex items-center gap-4'>
                      <div className='hidden flex-col items-end sm:flex'>
                        <p className='text-muted-foreground text-xs'>
                          Joined {fmtDate(user.date_joined)}
                        </p>
                        <p className='text-muted-foreground text-xs'>
                          Last login {fmtDate(user.last_login)}
                        </p>
                      </div>

                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button
                            variant='ghost'
                            size='icon'
                            className='rounded-full'
                            disabled={isSelf || togglingAdminId === user.id}
                          >
                            {togglingAdminId === user.id
                              ? <LoaderCircleIcon className='size-4 animate-spin' />
                              : <EllipsisVerticalIcon />
                            }
                            <span className='sr-only'>User actions</span>
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent className='w-44' align='end'>
                          <DropdownMenuGroup>
                            <DropdownMenuItem
                              onClick={() => handleToggleAdmin(user.id, user.is_admin)}
                            >
                              {user.is_admin ? 'Revoke admin' : 'Promote to admin'}
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className='text-destructive transition-colors duration-200 hover:bg-destructive/10! hover:text-destructive!'
                              onClick={() => setConfirmId(user.id)}
                            >
                              Delete user
                            </DropdownMenuItem>
                          </DropdownMenuGroup>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </div>

                  {idx !== filtered.length - 1 && <Separator className='my-2' />}
                </div>
              )
            })
          )}

          {/* Confirm delete dialog */}
          <Dialog open={confirmId !== null} onOpenChange={(o) => !o && setConfirmId(null)}>
            <DialogContent className='sm:max-w-md'>
              <DialogHeader className='space-y-2'>
                <DialogTitle>Delete user?</DialogTitle>
                <p className='text-muted-foreground text-sm'>
                  This will permanently delete{' '}
                  <span className='font-mono font-semibold text-foreground'>
                    {confirmUser?.username}
                  </span>{' '}
                  and all their project memberships. This cannot be undone.
                </p>
              </DialogHeader>
              <div className='flex flex-col-reverse gap-3 sm:flex-row sm:justify-end'>
                <DialogClose asChild>
                  <Button variant='outline'>Cancel</Button>
                </DialogClose>
                <Button variant='destructive' disabled={deleting} onClick={handleDelete}>
                  {deleting ? 'Deleting…' : 'Delete user'}
                </Button>
              </div>
            </DialogContent>
          </Dialog>

          {/* Create user dialog */}
          <Dialog open={createOpen} onOpenChange={(o) => { setCreateOpen(o); if (!o) { setCreateError(null); setUsernameAvail(null); setEmailAvail(null) } }}>
            <DialogContent className='sm:max-w-md'>
              <DialogHeader>
                <DialogTitle>Create user</DialogTitle>
              </DialogHeader>
              <div className='space-y-4 py-2'>
                {createError && (
                  <p className='text-sm text-destructive'>{createError}</p>
                )}
                <div className='space-y-1.5'>
                  <Label htmlFor='new-username'>Username</Label>
                  <div className='relative'>
                    <Input
                      id='new-username'
                      placeholder='jsmith'
                      value={newUsername}
                      onChange={(e) => {
                        const val = e.target.value
                        setNewUsername(val)
                        setUsernameAvail(null)
                        if (usernameDebounce.current) clearTimeout(usernameDebounce.current)
                        if (!val.trim()) return
                        setUsernameAvail('checking')
                        usernameDebounce.current = setTimeout(() => {
                          checkUserAvailability({ username: val.trim() })
                            .then((r) => setUsernameAvail(r.username_available ?? null))
                            .catch(() => setUsernameAvail(null))
                        }, 400)
                      }}
                      autoComplete='off'
                      className='pr-8'
                    />
                    <span className='absolute right-2.5 top-1/2 -translate-y-1/2'>
                      {usernameAvail === 'checking' && <LoaderCircleIcon className='size-4 animate-spin text-muted-foreground' />}
                      {usernameAvail === true && <CheckCircleIcon className='size-4 text-green-500' />}
                      {usernameAvail === false && <XCircleIcon className='size-4 text-destructive' />}
                    </span>
                  </div>
                  {usernameAvail === false && (
                    <p className='text-xs text-destructive'>Username is already taken.</p>
                  )}
                  {usernameAvail === true && (
                    <p className='text-xs text-green-600'>Username is available.</p>
                  )}
                </div>
                <div className='space-y-1.5'>
                  <Label htmlFor='new-email'>Email</Label>
                  <div className='relative'>
                    <Input
                      id='new-email'
                      type='email'
                      placeholder='jsmith@example.com'
                      value={newEmail}
                      onChange={(e) => {
                        const val = e.target.value
                        setNewEmail(val)
                        setEmailAvail(null)
                        if (emailDebounce.current) clearTimeout(emailDebounce.current)
                        if (!val.trim()) return
                        setEmailAvail('checking')
                        emailDebounce.current = setTimeout(() => {
                          checkUserAvailability({ email: val.trim() })
                            .then((r) => setEmailAvail(r.email_available ?? null))
                            .catch(() => setEmailAvail(null))
                        }, 400)
                      }}
                      autoComplete='off'
                      className='pr-8'
                    />
                    <span className='absolute right-2.5 top-1/2 -translate-y-1/2'>
                      {emailAvail === 'checking' && <LoaderCircleIcon className='size-4 animate-spin text-muted-foreground' />}
                      {emailAvail === true && <CheckCircleIcon className='size-4 text-green-500' />}
                      {emailAvail === false && <XCircleIcon className='size-4 text-destructive' />}
                    </span>
                  </div>
                  {emailAvail === false && (
                    <p className='text-xs text-destructive'>Email is already in use.</p>
                  )}
                  {emailAvail === true && (
                    <p className='text-xs text-green-600'>Email is available.</p>
                  )}
                </div>
                <div className='space-y-1.5'>
                  <Label htmlFor='new-password'>Password</Label>
                  <Input
                    id='new-password'
                    type='password'
                    placeholder='Min. 8 characters'
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    autoComplete='new-password'
                  />
                </div>
              </div>
              <div className='flex flex-col-reverse gap-3 sm:flex-row sm:justify-end'>
                <DialogClose asChild>
                  <Button variant='outline'>Cancel</Button>
                </DialogClose>
                <Button disabled={creating} onClick={handleCreate}>
                  {creating ? 'Creating…' : 'Create user'}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </section>
    </TooltipProvider>
  )
}

export default AdminUsersList
