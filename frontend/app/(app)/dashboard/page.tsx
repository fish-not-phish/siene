'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { fetchProjects } from '@/services/projects'

export default function DashboardPage() {
  const router = useRouter()

  useEffect(() => {
    fetchProjects()
      .then(projects => {
        if (projects.length === 0) {
          router.replace('/onboarding')
          return
        }
        const last = typeof window !== 'undefined'
          ? localStorage.getItem('registry:lastProject')
          : null
        // Verify the stored project still exists before using it
        const target = last && projects.some(p => p.name === last)
          ? `/projects/${last}`
          : `/projects/${projects[0].name}`
        router.replace(target)
      })
      .catch(() => router.replace('/projects'))
  }, [router])

  return null
}
