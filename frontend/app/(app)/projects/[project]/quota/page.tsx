'use client'

import { useParams, redirect } from 'next/navigation'
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

/**
 * Storage/quota settings have been merged into the project Settings page.
 * Redirect any direct visits to /projects/[project]/quota → .../settings
 */
export default function QuotaRedirectPage() {
  const { project } = useParams<{ project: string }>()
  const router = useRouter()

  useEffect(() => {
    router.replace(`/projects/${project}/settings`)
  }, [project, router])

  return null
}
