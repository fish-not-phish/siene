'use client'

import { ApiReferenceReact } from '@scalar/api-reference-react'
import '@scalar/api-reference-react/style.css'
import { useEffect, useState } from 'react'
import { baseUrl, baseUrlAccounts } from '@/constants/constants'

export default function DeveloperPage() {
  const openApiUrl = `${baseUrl}v1/openapi.json`
  // Schema paths already include /api/v1/... so the server must be just the origin
  const serverUrl = baseUrlAccounts.replace(/\/$/, '')
  const [spec, setSpec] = useState<Record<string, unknown> | null>(null)

  useEffect(() => {
    fetch(openApiUrl, { credentials: 'include' })
      .then(r => r.json())
      .then(schema => {
        setSpec({ ...schema, servers: [{ url: serverUrl, description: 'Siene API' }] })
      })
  }, [openApiUrl, serverUrl])

  if (!spec) return null

  return (
    <ApiReferenceReact
      configuration={{
        spec: { content: spec },
        withDefaultFonts: false,
      }}
    />
  )
}
