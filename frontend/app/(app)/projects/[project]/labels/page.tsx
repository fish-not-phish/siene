'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { TagIcon } from 'lucide-react'
import { toast } from 'sonner'

import { useAuthContext } from '@/store/AuthContext'
import { baseUrl } from '@/constants/constants'

import LabelsList, { type LabelRow } from '@/components/shadcn-studio/blocks/labels/labels-list'

export default function LabelsPage() {
  const { project } = useParams<{ project: string }>()
  const { user } = useAuthContext()
  const [labels, setLabels] = useState<LabelRow[]>([])
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    fetch(`${baseUrl}registry/projects/${project}/labels`, { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => setLabels(Array.isArray(d) ? d : []))
      .catch(() => setLabels([]))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [project])

  const handleCreate = async (data: { name: string; description: string; color: string }) => {
    const res = await fetch(`${baseUrl}registry/projects/${project}/labels`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': user.csrfToken ?? '' },
      body: JSON.stringify(data),
    })
    if (res.ok) {
      toast.success(`Label "${data.name}" created.`)
      load()
    } else {
      toast.error('Failed to create label.')
      throw new Error('create failed')
    }
  }

  const handleUpdate = async (id: number, data: { name: string; description: string; color: string }) => {
    const res = await fetch(`${baseUrl}registry/projects/${project}/labels/${id}`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': user.csrfToken ?? '' },
      body: JSON.stringify(data),
    })
    if (res.ok) {
      toast.success('Label updated.')
      load()
    } else {
      toast.error('Failed to update label.')
      throw new Error('update failed')
    }
  }

  const handleDelete = async (id: number) => {
    const res = await fetch(`${baseUrl}registry/projects/${project}/labels/${id}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: { 'X-CSRFToken': user.csrfToken ?? '' },
    })
    if (res.ok) {
      toast.success('Label deleted.')
      load()
    } else {
      toast.error('Failed to delete label.')
      throw new Error('delete failed')
    }
  }

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <TagIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>{project}</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Labels</span>
      </header>

      <main className='flex-1 px-6 py-6'>
        <LabelsList
          labels={labels}
          loading={loading}
          onCreate={handleCreate}
          onUpdate={handleUpdate}
          onDelete={handleDelete}
        />
      </main>
    </>
  )
}
