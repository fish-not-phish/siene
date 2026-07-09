'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function Home() {
  const router = useRouter()

  useEffect(() => {
    const last = typeof window !== 'undefined'
      ? localStorage.getItem('registry:lastProject')
      : null
    router.replace(last ? `/projects/${last}` : '/projects')
  }, [router])

  return null
}
