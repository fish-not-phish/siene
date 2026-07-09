'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { UserIcon, KeyRoundIcon } from 'lucide-react'
import { useAuthContext } from '@/store/AuthContext'

const tabs = [
  { href: '/profile',        label: 'Profile',  icon: UserIcon },
  { href: '/profile/tokens', label: 'Tokens',   icon: KeyRoundIcon },
]

export default function ProfileLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const { user } = useAuthContext()

  const initials = user.username ? user.username.slice(0, 2).toUpperCase() : '?'

  return (
    <>
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <SidebarTrigger />
        <Separator orientation='vertical' className='h-4!' />
        <UserIcon className='size-4 text-muted-foreground' />
        <span className='font-semibold'>Profile</span>
      </header>

      <main className='flex-1 flex flex-col items-center px-4 py-10'>
        <div className='w-full max-w-xl space-y-6'>

          {/* Identity summary */}
          <div className='flex items-center gap-4'>
            <div className='flex size-14 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary font-semibold text-lg select-none'>
              {initials}
            </div>
            <div>
              <p className='font-semibold text-lg leading-tight'>{user.username ?? '—'}</p>
              <p className='text-sm text-muted-foreground'>{user.email ?? '—'}</p>
              {user.isAdmin && (
                <span className='inline-flex rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary mt-1'>
                  Admin
                </span>
              )}
            </div>
          </div>

          {/* Tab nav */}
          <div className='flex gap-1 border-b'>
            {tabs.map(({ href, label, icon: Icon }) => {
              const active = pathname === href
              return (
                <Link
                  key={href}
                  href={href}
                  className={`flex items-center gap-1.5 px-3 pb-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
                    active
                      ? 'border-primary text-foreground'
                      : 'border-transparent text-muted-foreground hover:text-foreground'
                  }`}
                >
                  <Icon className='size-3.5' />
                  {label}
                </Link>
              )
            })}
          </div>

          {/* Page content */}
          {children}

        </div>
      </main>
    </>
  )
}
