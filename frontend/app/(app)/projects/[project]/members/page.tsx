'use client'

import { useParams } from 'next/navigation'
import { useEffect, useState } from 'react'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { UsersIcon } from 'lucide-react'
import { toast } from 'sonner'

import { useAuthContext } from '@/store/AuthContext'
import {
  fetchMembers,
  addMember,
  updateMember,
  removeMember,
  type Member,
} from '@/services/registry'

import MembersList, { type MemberRole } from '@/components/shadcn-studio/blocks/members/members-list'

export default function MembersPage() {
  const { project } = useParams<{ project: string }>()
  const { user } = useAuthContext()

  const [members, setMembers] = useState<Member[]>([])
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    fetchMembers(project)
      .then((data) => setMembers(Array.isArray(data) ? data : []))
      .catch(() => setMembers([]))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [project])

  // canManage: project admins and system admins
  const canManage =
    user.isAdmin ||
    members.some((m) => m.username === user.username && m.role === 'admin')

  const handleAdd = async (username: string, role: MemberRole) => {
    try {
      const m = await addMember(project, { username, role }, user.csrfToken ?? '')
      setMembers((prev) => [...prev, m])
      toast.success(`${username} added as ${role}.`)
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to add member.')
      throw e
    }
  }

  const handleChangeRole = async (memberId: number, role: MemberRole) => {
    try {
      const updated = await updateMember(project, memberId, role, user.csrfToken ?? '')
      setMembers((prev) => prev.map((m) => (m.id === memberId ? updated : m)))
      toast.success('Role updated.')
    } catch {
      toast.error('Failed to update role.')
    }
  }

  const handleRemove = async (memberId: number) => {
    try {
      await removeMember(project, memberId, user.csrfToken ?? '')
      setMembers((prev) => prev.filter((m) => m.id !== memberId))
      toast.success('Member removed.')
    } catch {
      toast.error('Failed to remove member.')
    }
  }

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <UsersIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>{project}</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Members</span>
      </header>

      <main className='flex-1 px-6 py-6'>
        <MembersList
          projectSlug={project}
          members={members}
          loading={loading}
          canManage={canManage}
          onAdd={handleAdd}
          onChangeRole={handleChangeRole}
          onRemove={handleRemove}
        />
      </main>
    </>
  )
}
