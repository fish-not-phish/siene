'use client'

import { useAuthContext } from '@/store/AuthContext'
import { redirect } from 'next/navigation'
import { baseUrlAccounts } from '@/constants/constants'

// Onboarding gets a clean full-screen layout — no sidebar, no header.
export default function OnboardingLayout({ children }: { children: React.ReactNode }) {
  const { user } = useAuthContext()

  if (user.isLoggedIn === false) {
    redirect(`${baseUrlAccounts}accounts/login/`)
  }

  return <>{children}</>
}
