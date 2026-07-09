'use client'

import React, { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { usePathname } from 'next/navigation'
import { fetchProjects, type Project } from '@/services/projects'

const LAST_PROJECT_KEY = 'registry:lastProject'

type ProjectsContextProps = {
  projects: Project[]
  loading: boolean
  refresh: () => void
  lastProject: string | null
  setLastProject: (slug: string) => void
}

const ProjectsContext = createContext<ProjectsContextProps | null>(null)

export function ProjectsProvider({ children }: { children: React.ReactNode }) {
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [lastProject, setLastProjectState] = useState<string | null>(() => {
    if (typeof window === 'undefined') return null
    return localStorage.getItem(LAST_PROJECT_KEY)
  })

  const pathname = usePathname()

  // Whenever we're on a project route, persist the slug immediately
  useEffect(() => {
    const match = pathname.match(/^\/projects\/([^/]+)/)
    if (match) {
      const slug = match[1]
      if (slug !== lastProject) {
        setLastProjectState(slug)
        localStorage.setItem(LAST_PROJECT_KEY, slug)
      }
    }
  }, [pathname])

  const setLastProject = useCallback((slug: string) => {
    setLastProjectState(slug)
    localStorage.setItem(LAST_PROJECT_KEY, slug)
  }, [])

  const load = useCallback(() => {
    setLoading(true)
    fetchProjects()
      .then(setProjects)
      .catch(() => setProjects([]))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <ProjectsContext.Provider value={{ projects, loading, refresh: load, lastProject, setLastProject }}>
      {children}
    </ProjectsContext.Provider>
  )
}

export function useProjects() {
  const ctx = useContext(ProjectsContext)
  if (!ctx) throw new Error('useProjects must be used within ProjectsProvider')
  return ctx
}
