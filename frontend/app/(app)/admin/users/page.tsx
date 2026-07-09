'use client'

import { useEffect, useState } from 'react'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { UsersIcon } from 'lucide-react'
import { toast } from 'sonner'

import { useAuthContext } from '@/store/AuthContext'
import {
  fetchAdminUsers,
  deleteAdminUser,
  createAdminUser,
  patchAdminUser,
  type AdminUser,
} from '@/services/registry'
import { baseUrl } from '@/constants/constants'

import AdminUsersList from '@/components/shadcn-studio/blocks/admin-users/admin-users-list'

export default function AdminUsersPage() {
  const { user: me } = useAuthContext()
  const [users, setUsers] = useState<AdminUser[]>([])
  const [loading, setLoading] = useState(true)
  const [oidcEnabled, setOidcEnabled] = useState(false)

  const load = () => {
    setLoading(true)
    fetchAdminUsers()
      .then((data) => setUsers(Array.isArray(data) ? data : []))
      .catch(() => setUsers([]))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    // Fetch site settings to know if OIDC is enabled
    fetch(`${baseUrl}accounts/site-settings`, { credentials: 'include' })
      .then((r) => r.ok ? r.json() : null)
      .then((data) => { if (data) setOidcEnabled(data.oidc_enabled) })
      .catch(() => {})
  }, [])

  const handleDelete = async (userId: number) => {
    try {
      await deleteAdminUser(userId, me.csrfToken ?? '')
      setUsers((prev) => prev.filter((u) => u.id !== userId))
      toast.success('User deleted.')
    } catch {
      toast.error('Failed to delete user.')
    }
  }

  const handleCreate = async (username: string, email: string, password: string) => {
    const newUser = await createAdminUser({ username, email, password }, me.csrfToken ?? '')
    setUsers((prev) => [...prev, newUser])
    toast.success(`User "${username}" created.`)
  }

  const handleSetAdmin = async (userId: number, isAdmin: boolean) => {
    try {
      const updated = await patchAdminUser(userId, { is_admin: isAdmin }, me.csrfToken ?? '')
      setUsers((prev) => prev.map((u) => (u.id === userId ? updated : u)))
      toast.success(isAdmin ? 'User promoted to admin.' : 'Admin privileges revoked.')
    } catch {
      toast.error('Failed to update user.')
    }
  }

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <UsersIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>System</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Users</span>
      </header>

      <main className='flex-1 px-6 py-6'>
        <AdminUsersList
          users={users}
          loading={loading}
          currentUsername={me.username ?? ''}
          oidcEnabled={oidcEnabled}
          onDelete={handleDelete}
          onCreate={handleCreate}
          onSetAdmin={handleSetAdmin}
        />
      </main>
    </>
  )
}
