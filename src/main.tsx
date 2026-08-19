import React from 'react'
import ReactDOM from 'react-dom/client'
import ModernApp from './ModernApp'
import './index.css'
import { AuthProvider } from './components/AuthProvider'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthProvider>
      <ModernApp />
    </AuthProvider>
  </React.StrictMode>,
)
