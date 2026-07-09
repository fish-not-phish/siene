'use client'

import { useEffect, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
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
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import BadgeCheck from '@/assets/svg/badge-check'
import { searchUsers, type UserSearchResult } from '@/services/registry'
import { TooltipProvider } from '@/components/ui/tooltip'
import { PlusIcon, ChevronsUpDownIcon, CheckIcon, EllipsisVerticalIcon } from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

export type MemberRole = 'guest' | 'developer' | 'maintainer' | 'admin'

export interface MemberRow {
  id: number
  username: string
  email: string
  role: MemberRole
}

export interface MembersListProps {
  projectSlug: string
  members: MemberRow[]
  loading: boolean
  /** Whether the current user can manage (add/change/remove) members */
  canManage: boolean
  onAdd: (username: string, role: MemberRole) => Promise<void>
  onChangeRole: (memberId: number, role: MemberRole) => Promise<void>
  onRemove: (memberId: number) => Promise<void>
}

// ── Role definitions ──────────────────────────────────────────────────────────

const ROLES: { role: MemberRole; label: string; description: string }[] = [
  {
    role: 'guest',
    label: 'Guest',
    description: 'Read-only access. Can pull images from private repositories.',
  },
  {
    role: 'developer',
    label: 'Developer',
    description: 'Can pull, push, and delete images.',
  },
  {
    role: 'maintainer',
    label: 'Maintainer',
    description: 'All developer permissions plus project settings (webhooks, policies, labels).',
  },
  {
    role: 'admin',
    label: 'Admin',
    description: 'Full project control including managing members. Cannot remove the project owner.',
  },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function initials(username: string) {
  return username.slice(0, 2).toUpperCase()
}

// ── User search combobox ──────────────────────────────────────────────────────

interface UserPickerProps {
  projectSlug: string
  selected: UserSearchResult | null
  onSelect: (u: UserSearchResult | null) => void
}

function UserPicker({ projectSlug, selected, onSelect }: UserPickerProps) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<UserSearchResult[]>([])
  const [searching, setSearching] = useState(false)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    if (!query.trim()) {
      setResults([])
      return
    }
    setSearching(true)
    debounceRef.current = setTimeout(() => {
      searchUsers(query, projectSlug)
        .then(setResults)
        .catch(() => setResults([]))
        .finally(() => setSearching(false))
    }, 250)
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [query, projectSlug])

  // Reset query when popover closes
  useEffect(() => {
    if (!open) setQuery('')
  }, [open])

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant='outline'
          role='combobox'
          aria-expanded={open}
          className='w-full justify-between font-normal'
        >
          {selected ? (
            <span className='flex items-center gap-2'>
              <Avatar className='size-5'>
                <AvatarFallback className='text-[10px]'>{initials(selected.username)}</AvatarFallback>
              </Avatar>
              <span>{selected.username}</span>
              <span className='text-muted-foreground text-xs'>{selected.email}</span>
            </span>
          ) : (
            <span className='text-muted-foreground'>Search by username or email…</span>
          )}
          <ChevronsUpDownIcon className='text-muted-foreground/80 ml-auto size-4 shrink-0' />
        </Button>
      </PopoverTrigger>
      <PopoverContent className='w-(--radix-popper-anchor-width) p-0' align='start'>
        <Command shouldFilter={false}>
          <CommandInput
            placeholder='Search users…'
            value={query}
            onValueChange={setQuery}
          />
          <CommandList>
            {searching ? (
              <div className='py-3 text-center text-sm text-muted-foreground'>Searching…</div>
            ) : query.trim() === '' ? (
              <div className='py-3 text-center text-sm text-muted-foreground'>
                Start typing to search users.
              </div>
            ) : results.length === 0 ? (
              <CommandEmpty>No users found.</CommandEmpty>
            ) : (
              <CommandGroup>
                {results.map((u) => (
                  <CommandItem
                    key={u.id}
                    value={u.username}
                    onSelect={() => {
                      onSelect(selected?.id === u.id ? null : u)
                      setOpen(false)
                    }}
                  >
                    <Avatar className='size-6'>
                      <AvatarFallback className='text-[10px]'>{initials(u.username)}</AvatarFallback>
                    </Avatar>
                    <span className='font-medium'>{u.username}</span>
                    <span className='text-muted-foreground text-xs'>{u.email}</span>
                    {selected?.id === u.id && <CheckIcon className='ml-auto size-4' />}
                  </CommandItem>
                ))}
              </CommandGroup>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

const MembersList = ({
  projectSlug,
  members,
  loading,
  canManage,
  onAdd,
  onChangeRole,
  onRemove,
}: MembersListProps) => {
  const [addOpen, setAddOpen] = useState(false)
  const [selectedUser, setSelectedUser] = useState<UserSearchResult | null>(null)
  const [addRole, setAddRole] = useState<MemberRole>('developer')
  const [adding, setAdding] = useState(false)

  const resetDialog = () => {
    setSelectedUser(null)
    setAddRole('developer')
  }

  const handleAdd = async () => {
    if (!selectedUser) return
    setAdding(true)
    try {
      await onAdd(selectedUser.username, addRole)
      resetDialog()
      setAddOpen(false)
    } finally {
      setAdding(false)
    }
  }

  return (
    <TooltipProvider>
    <section className='py-3'>
      <div className='mx-auto max-w-7xl'>
        {/* Header row */}
        <div className='mb-6 flex flex-wrap items-center justify-between gap-4'>
          <div className='space-y-1'>
            <h3 className='font-semibold'>Members</h3>
            <p className='text-muted-foreground text-sm'>
              Manage team members and their permissions for this project.
            </p>
          </div>

          {canManage && (
            <Dialog
              open={addOpen}
              onOpenChange={(o) => {
                setAddOpen(o)
                if (!o) resetDialog()
              }}
            >
              <DialogTrigger asChild>
                <Button className='max-sm:w-full'>
                  <PlusIcon />
                  Add Member
                </Button>
              </DialogTrigger>
              <DialogContent className='sm:max-w-lg'>
                <DialogHeader>
                  <div className='space-y-1'>
                    <DialogTitle className='text-lg'>Add a member</DialogTitle>
                    <DialogDescription className='text-sm'>
                      Search for a user by username or email to grant them access to this project.
                    </DialogDescription>
                  </div>
                </DialogHeader>

                <div className='mt-4 grid grid-cols-1 gap-4'>
                  <div className='w-full space-y-2'>
                    <Label>
                      User<span className='text-destructive'>*</span>
                    </Label>
                    <UserPicker
                      projectSlug={projectSlug}
                      selected={selectedUser}
                      onSelect={setSelectedUser}
                    />
                  </div>

                  <div className='w-full space-y-2'>
                    <Label htmlFor='member-role'>Role</Label>
                    <Select
                      value={addRole}
                      onValueChange={(v) => setAddRole(v as MemberRole)}
                    >
                      <SelectTrigger id='member-role' className='w-full'>
                        <SelectValue placeholder='Select role…' />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {ROLES.map(({ role, label }) => (
                            <SelectItem key={role} value={role}>
                              {label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className='flex flex-col-reverse gap-4 sm:flex-row sm:justify-end'>
                  <DialogClose asChild>
                    <Button variant='outline'>Cancel</Button>
                  </DialogClose>
                  <Button onClick={handleAdd} disabled={adding || !selectedUser}>
                    {adding ? 'Adding…' : 'Add member'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          )}
        </div>

        {/* Role reference */}
        <div className='mb-6 grid grid-cols-2 gap-2 sm:grid-cols-4'>
          {ROLES.map(({ role, label, description }) => (
            <div key={role} className='rounded-lg border px-3 py-2.5 space-y-1'>
              <p className='text-xs font-semibold capitalize'>{label}</p>
              <p className='text-muted-foreground text-xs leading-snug'>{description}</p>
            </div>
          ))}
        </div>

        {/* Member rows */}
        {loading ? (
          <div className='space-y-3'>
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className='h-12 w-full rounded-lg' />
            ))}
          </div>
        ) : members.length === 0 ? (
          <p className='text-muted-foreground text-sm'>No members yet.</p>
        ) : (
          members.map((member, idx) => {
            const isProjectAdmin = member.role === 'admin'

            return (
              <div key={member.id}>
                <div className='flex items-center justify-between gap-3 py-1'>
                  {/* Left: avatar + name */}
                  <div className='flex items-center gap-3'>
                    <div className='relative w-fit'>
                      <Avatar className='size-9'>
                        <AvatarFallback>{initials(member.username)}</AvatarFallback>
                      </Avatar>
                      {isProjectAdmin && (
                        <span className='absolute -right-1.5 -top-1.5'>
                          <span className='sr-only'>Project admin</span>
                          <BadgeCheck className='text-background size-5 fill-sky-500' />
                        </span>
                      )}
                    </div>
                    <div className='flex flex-col items-start'>
                      <p className='text-sm font-medium'>{member.username}</p>
                      <p className='text-muted-foreground text-xs'>{member.email}</p>
                    </div>
                  </div>

                  {/* Right: role selector + actions */}
                  <div
                    className={`flex items-center gap-2 ${
                      isProjectAdmin && !canManage ? 'cursor-not-allowed opacity-60' : ''
                    }`}
                  >
                    <Select
                      defaultValue={member.role}
                      disabled={!canManage || isProjectAdmin}
                      onValueChange={(v) => onChangeRole(member.id, v as MemberRole)}
                    >
                      <SelectTrigger className='w-32 px-2 py-1 max-sm:w-24'>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value='guest'>Guest</SelectItem>
                          <SelectItem value='developer'>Developer</SelectItem>
                          <SelectItem value='maintainer'>Maintainer</SelectItem>
                          <SelectItem value='admin'>Admin</SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>

                    {canManage && (
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button
                            variant='ghost'
                            size='icon'
                            className='rounded-full'
                            disabled={isProjectAdmin}
                          >
                            <EllipsisVerticalIcon />
                            <span className='sr-only'>Member actions</span>
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent className='w-28' align='end'>
                          <DropdownMenuGroup>
                            <DropdownMenuItem
                              className='text-destructive transition-colors duration-200 hover:bg-destructive/10! hover:text-destructive!'
                              onClick={() => onRemove(member.id)}
                            >
                              Remove
                            </DropdownMenuItem>
                          </DropdownMenuGroup>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </div>
                </div>

                {idx !== members.length - 1 && <Separator className='my-2' />}
              </div>
            )
          })
        )}
      </div>
    </section>
    </TooltipProvider>
  )
}

export default MembersList
