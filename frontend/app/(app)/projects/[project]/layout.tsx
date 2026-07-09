'use client'

import { useParams, useRouter } from 'next/navigation'
import { useEffect } from 'react'

// Slugs that are static routes under /projects/ and must never be treated as
// a project name. Any attempt to load /projects/<reserved>/... redirects to
// the canonical static route.
const RESERVED: Record<string, string> = {
  new: '/projects/new',
}

export default function ProjectLayout({ children }: { children: React.ReactNode }) {
  const { project } = useParams<{ project: string }>()
  const router = useRouter()

  useEffect(() => {
    if (project && RESERVED[project]) {
      router.replace(RESERVED[project])
    }
  }, [project, router])

  if (project && RESERVED[project]) {
    return null
  }

  return <>{children}</>
}
