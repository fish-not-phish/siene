'use client'

import { redirect } from 'next/navigation'
import { useAuthContext } from '@/store/AuthContext'
import { ProjectsProvider } from '@/providers/ProjectsContext'
import { baseUrlAccounts } from '@/constants/constants'

// Full-screen layout: auth-protected, has ProjectsProvider, but no sidebar.
export default function AppNoSidebarLayout({ children }: { children: React.ReactNode }) {
  const { user } = useAuthContext()

  if (user.isLoggedIn === false) {
    redirect(`${baseUrlAccounts}accounts/login/`)
  }

  return (
    <ProjectsProvider>
      <div className='flex min-h-dvh flex-1 flex-col'>
        {children}
      </div>
    </ProjectsProvider>
  )
}
