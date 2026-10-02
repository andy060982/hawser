import { AppLayout } from './components/AppLayout'
import { mockHosts } from './data/mockHosts'
import { SettingsProvider } from './lib/settings'
import { DialogProvider } from './lib/dialogs'

export default function App() {
  // No seeded sessions: real ones are restored from sessions.json on launch.
  return (
    <SettingsProvider>
      <DialogProvider>
        <AppLayout hosts={mockHosts} />
      </DialogProvider>
    </SettingsProvider>
  )
}
