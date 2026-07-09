'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { fetchProjects } from '@/services/projects'
import { Spinner } from '@/components/ui/spinner'

export default function ProjectsIndexPage() {
  const router = useRouter()

  useEffect(() => {
    fetchProjects()
      .then((projects) => {
        if (projects.length === 0) router.replace('/onboarding')
        else router.replace(`/projects/${projects[0].name}/repositories`)
      })
      .catch(() => router.replace('/onboarding'))
  }, [router])

  return (
    <div className='flex flex-1 items-center justify-center'>
      <Spinner />
    </div>
  )
}
