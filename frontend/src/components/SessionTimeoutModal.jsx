import React from 'react'

export default function SessionTimeoutModal({ minutes = 5, onStaySignedIn, onLogout }) {
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl border border-cyan-400/30 bg-slate-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-400/10 text-amber-300">!</div>
          <div>
            <h2 className="text-lg font-semibold text-white">Session expiring soon</h2>
            <p className="text-sm text-slate-400">You have been inactive.</p>
          </div>
        </div>
        <p className="mb-6 text-sm leading-6 text-slate-300">
          Your session will expire in about {minutes} minutes. Stay signed in to continue working, or log out now.
        </p>
        <div className="flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
          <button
            type="button"
            onClick={onLogout}
            className="rounded-lg border border-slate-700 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:bg-slate-800"
          >
            Log out
          </button>
          <button
            type="button"
            onClick={onStaySignedIn}
            className="rounded-lg bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
          >
            Stay signed in
          </button>
        </div>
      </div>
    </div>
  )
}
