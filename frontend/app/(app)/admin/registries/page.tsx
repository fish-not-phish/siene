'use client'

import { useEffect, useState, useCallback } from 'react'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { Button } from '@/components/ui/button'
import { Globe2Icon, RefreshCwIcon } from 'lucide-react'
import { useAuthContext } from '@/store/AuthContext'
import { baseUrl } from '@/constants/constants'
import { RegistriesList, type RemoteRegistry } from '@/components/shadcn-studio/blocks/registries/registries-list'

export default function RemoteRegistriesPage() {
  const { user } = useAuthContext()
  const [registries, setRegistries] = useState<RemoteRegistry[]>([])
  const [loading,    setLoading]    = useState(true)
  const [pinging,    setPinging]    = useState<number | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    fetch(`${baseUrl}registry/system/remote-registries`, { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => setRegistries(Array.isArray(d) ? d : []))
      .catch(() => setRegistries([]))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const onCreate = async (data: Record<string, unknown>) => {
    await fetch(`${baseUrl}registry/system/remote-registries`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': user.csrfToken ?? '' },
      body: JSON.stringify(data),
    })
    load()
  }

  const onEdit = async (id: number, data: Record<string, unknown>) => {
    await fetch(`${baseUrl}registry/system/remote-registries/${id}`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': user.csrfToken ?? '' },
      body: JSON.stringify(data),
    })
    load()
  }

  const onDelete = async (id: number) => {
    await fetch(`${baseUrl}registry/system/remote-registries/${id}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: { 'X-CSRFToken': user.csrfToken ?? '' },
    })
    load()
  }

  const onPing = async (id: number) => {
    setPinging(id)
    await fetch(`${baseUrl}registry/system/remote-registries/${id}/ping`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRFToken': user.csrfToken ?? '' },
    })
    setPinging(null)
    load()
  }

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <Globe2Icon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>System</span>
        <Separator orientation='vertical' className='h-4!' />
        <span className='text-muted-foreground text-sm'>Remote Registries</span>
        <div className='ml-auto'>
          <Button size='sm' variant='outline' onClick={load}>
            <RefreshCwIcon className='size-3.5' />
          </Button>
        </div>
      </header>

      <main className='flex-1 px-6 py-6 space-y-4'>
        <div>
          <h2 className='text-sm font-semibold'>Registry providers</h2>
          <p className='text-xs text-muted-foreground mt-0.5'>
            Connect external registries to use as replication targets or sources. Registries are system-wide and available to all replication rules.
          </p>
        </div>

        <RegistriesList
          registries={registries}
          loading={loading}
          pinging={pinging}
          onCreate={onCreate}
          onEdit={onEdit}
          onDelete={onDelete}
          onPing={onPing}
        />
      </main>
    </>
  )
}
