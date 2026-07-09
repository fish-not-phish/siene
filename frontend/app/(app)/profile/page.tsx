'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { useAuthContext } from '@/store/AuthContext'
import { baseUrl } from '@/constants/constants'

export default function ProfilePage() {
  const { user } = useAuthContext()

  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [loading, setLoading] = useState(false)

  const changePassword = async () => {
    if (newPw !== confirmPw) {
      setMsg({ ok: false, text: 'New passwords do not match.' })
      return
    }
    if (newPw.length < 8) {
      setMsg({ ok: false, text: 'Password must be at least 8 characters.' })
      return
    }
    setLoading(true)
    setMsg(null)
    const res = await fetch(`${baseUrl}accounts/change-password`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': user.csrfToken ?? '' },
      body: JSON.stringify({ current_password: currentPw, new_password: newPw }),
    })
    const data = await res.json()
    setLoading(false)
    setMsg({ ok: data.success, text: data.message })
    if (data.success) {
      setCurrentPw('')
      setNewPw('')
      setConfirmPw('')
    }
  }

  return (
    <div className='space-y-4'>

      {/* Account details */}
      <Card>
        <CardHeader>
          <CardTitle className='text-base'>Account details</CardTitle>
          <CardDescription>Your identity on this registry.</CardDescription>
        </CardHeader>
        <CardContent className='space-y-3'>
          <div className='space-y-1'>
            <p className='text-xs font-medium text-muted-foreground uppercase tracking-wide'>Username</p>
            <p className='text-sm font-medium'>{user.username ?? '—'}</p>
          </div>
          <div className='space-y-1'>
            <p className='text-xs font-medium text-muted-foreground uppercase tracking-wide'>Email</p>
            <p className='text-sm'>{user.email ?? '—'}</p>
          </div>
          {(user.first_name || user.last_name) && (
            <div className='space-y-1'>
              <p className='text-xs font-medium text-muted-foreground uppercase tracking-wide'>Name</p>
              <p className='text-sm'>{[user.first_name, user.last_name].filter(Boolean).join(' ')}</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Change password */}
      <Card>
        <CardHeader>
          <CardTitle className='text-base'>Change password</CardTitle>
          <CardDescription>Choose a strong password of at least 8 characters.</CardDescription>
        </CardHeader>
        <CardContent className='space-y-3'>
          <div className='space-y-1.5'>
            <Label htmlFor='cur-pw'>Current password</Label>
            <Input
              id='cur-pw'
              type='password'
              value={currentPw}
              onChange={(e) => setCurrentPw(e.target.value)}
              autoComplete='current-password'
            />
          </div>
          <div className='space-y-1.5'>
            <Label htmlFor='new-pw'>New password</Label>
            <Input
              id='new-pw'
              type='password'
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              autoComplete='new-password'
            />
          </div>
          <div className='space-y-1.5'>
            <Label htmlFor='confirm-pw'>Confirm new password</Label>
            <Input
              id='confirm-pw'
              type='password'
              value={confirmPw}
              onChange={(e) => setConfirmPw(e.target.value)}
              autoComplete='new-password'
            />
          </div>
          {msg && (
            <p className={`text-sm ${msg.ok ? 'text-green-600 dark:text-green-400' : 'text-destructive'}`}>
              {msg.text}
            </p>
          )}
        </CardContent>
        <CardFooter>
          <Button
            size='sm'
            onClick={changePassword}
            disabled={loading || !currentPw || !newPw || !confirmPw}
          >
            {loading ? 'Saving…' : 'Update password'}
          </Button>
        </CardFooter>
      </Card>

    </div>
  )
}
