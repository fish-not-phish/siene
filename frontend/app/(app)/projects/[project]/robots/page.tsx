'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { BotIcon } from 'lucide-react'
import { toast } from 'sonner'

import { useAuthContext } from '@/store/AuthContext'
import {
  fetchRobots,
  fetchMembers,
  createRobot,
  updateRobot,
  rotateRobot,
  deleteRobot,
  type Robot,
  type Member,
} from '@/services/registry'

import RobotsList, { type RobotRow } from '@/components/shadcn-studio/blocks/robots/robots-list'

export default function RobotsPage() {
  const { project } = useParams<{ project: string }>()
  const { user } = useAuthContext()

  const [robots, setRobots] = useState<Robot[]>([])
  const [members, setMembers] = useState<Member[]>([])
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    Promise.all([
      fetchRobots(project).catch(() => []),
      fetchMembers(project).catch(() => []),
    ]).then(([robotData, memberData]) => {
      setRobots(Array.isArray(robotData) ? robotData : [])
      setMembers(Array.isArray(memberData) ? memberData : [])
    }).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [project])

  // canManage: system admins or project admins
  const canManage =
    user.isAdmin ||
    members.some((m) => m.username === user.username && m.role === 'admin')

  const handleCreate = async (data: { name: string; description: string; expires_at: string | null }) => {
    try {
      const created = await createRobot(project, { ...data, expires_at: data.expires_at ?? undefined }, user.csrfToken ?? '')
      setRobots((prev) => [created, ...prev])
      toast.success(`Robot "${data.name}" created.`)
      return { secret: created.secret }
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to create robot account.')
      throw e
    }
  }

  const handleToggle = async (id: number, disabled: boolean) => {
    try {
      const updated = await updateRobot(project, id, { disabled }, user.csrfToken ?? '')
      setRobots((prev) => prev.map((r) => (r.id === id ? updated : r)))
      toast.success(disabled ? 'Robot disabled.' : 'Robot enabled.')
    } catch {
      toast.error('Failed to update robot.')
    }
  }

  const handleRotate = async (id: number) => {
    try {
      const result = await rotateRobot(project, id, user.csrfToken ?? '')
      toast.success('Secret rotated. Update your systems with the new secret.')
      return result
    } catch {
      toast.error('Failed to rotate secret.')
      throw new Error('Failed to rotate secret.')
    }
  }

  const handleDelete = async (id: number) => {
    try {
      await deleteRobot(project, id, user.csrfToken ?? '')
      setRobots((prev) => prev.filter((r) => r.id !== id))
      toast.success('Robot account deleted.')
    } catch {
      toast.error('Failed to delete robot account.')
    }
  }

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <BotIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>{project}</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Robot Accounts</span>
      </header>

      <main className='flex-1 px-6 py-6'>
        <RobotsList
          robots={robots as RobotRow[]}
          loading={loading}
          canManage={canManage}
          onCreate={handleCreate}
          onRotate={handleRotate}
          onToggle={handleToggle}
          onDelete={handleDelete}
        />
      </main>
    </>
  )
}
