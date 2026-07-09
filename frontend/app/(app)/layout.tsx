'use client'

import { redirect } from 'next/navigation'
import { useAuthContext } from '@/store/AuthContext'
import { SidebarProvider } from '@/components/ui/sidebar'
import AppSidebar from '@/components/layout/AppSidebar'
import AppFooter from '@/components/shadcn-studio/blocks/app-footer'
import { ProjectsProvider } from '@/providers/ProjectsContext'
import { baseUrlAccounts } from '@/constants/constants'

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { user } = useAuthContext()

  if (user.isLoggedIn === false) {
    redirect(`${baseUrlAccounts}accounts/login/`)
  }

  return (
    <ProjectsProvider>
      <SidebarProvider>
        <AppSidebar />
        <div className='flex min-h-dvh flex-1 flex-col'>
          {children}
          <AppFooter />
        </div>
      </SidebarProvider>
    </ProjectsProvider>
  )
}
