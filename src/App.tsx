import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Callback } from './pages/Callback'
import { Session } from './pages/Session'
import { SignIn } from './pages/SignIn'

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<SignIn />} />
        <Route path="/callback" element={<Callback />} />
        <Route path="/session" element={<Session />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
