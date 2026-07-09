import { baseUrl } from '@/constants/constants'
import { csrfFetch } from '@/utils/csrfFetch'

export interface Project {
  id: number
  name: string
  display_name: string
  description: string
  public: boolean
  quota_gb: number | null
  owner_username: string | null
  created_at: string
  updated_at: string
}

export async function fetchProjects(): Promise<Project[]> {
  const res = await fetch(`${baseUrl}registry/projects`, {
    credentials: 'include',
  })
  if (!res.ok) throw new Error('Failed to fetch projects')
  return res.json()
}

export async function createProject(
  payload: { name: string; public?: boolean; description?: string },
  csrfToken: string,
): Promise<Project> {
  const res = await csrfFetch(
    `${baseUrl}registry/projects`,
    { method: 'POST', body: JSON.stringify(payload) },
    csrfToken,
  )
  if (res.status === 201) return res.json()
  const data = await res.json().catch(() => ({}))
  throw new Error(data?.detail ?? data?.message ?? 'Failed to create project')
}

export async function checkProjectNameAvailable(name: string): Promise<boolean> {
  const res = await fetch(`${baseUrl}registry/projects/${name}`, {
    credentials: 'include',
  })
  // 404 = available, 200 = taken, anything else treat as unavailable
  return res.status === 404
}
