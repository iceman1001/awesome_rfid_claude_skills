# Common Patterns in Production Electron Apps

## 1. Payment/Subscription Integration Patterns

### Stripe

```javascript
// Web-based checkout (most common in Electron)
window.open('https://checkout.stripe.com/...')

// Or via API
const session = await createCheckoutSession({ priceId, customerId })
// Then open session.url in browser

// Webhook listener for payment confirmation
app.on('open-url', (event, url) => {
  if (url.startsWith('myapp://payment-success')) { ... }
})
```

### Paddle

```javascript
// Paddle.js SDK
Paddle.Checkout.open({ product: PRODUCT_ID })

// Or API-based
Paddle.Order.create({ ... })
```

### LemonSqueezy

```javascript
// Typically: create checkout → open URL
const { data } = await lemonSqueezy.createCheckout({ ... })
shell.openExternal(data.attributes.url)
```

## 2. Feature Flag Systems

### PostHog Feature Flags

```javascript
import posthog from 'posthog-js'
posthog.init(API_KEY)
const isEnabled = posthog.isFeatureEnabled('premium-ai-model')
```

### LaunchDarkly

```javascript
import { initialize } from 'launchdarkly-js-client-sdk'
const client = initialize(CLIENT_SIDE_ID, user)
const enabled = await client.variation('pro-feature', false)
```

### Custom/Homegrown

```javascript
// Simple boolean flags
const FEATURES = {
  PREMIUM_AI: true,
  VOICE_COMMANDS: false,
  MEETING_RECORDER: true,
}

// Or fetched from API
fetch('/api/v1/features').then(r => r.json()).then(flags => { ... })
```

## 3. IPC Architecture Patterns

### Direct Handle/Invoke (most common)

```javascript
// Main process
ipcMain.handle('auth:getUser', async () => {
  return await supabase.auth.getUser()
})

// Renderer
const user = await ipcRenderer.invoke('auth:getUser')
```

### Context Bridge (more secure)

```javascript
// Preload script
contextBridge.exposeInMainWorld('electronAPI', {
  getUser: () => ipcRenderer.invoke('auth:getUser'),
  getSubscription: () => ipcRenderer.invoke('billing:getSubscription'),
})

// Renderer
const user = await window.electronAPI.getUser()
```

### Message Port (rare, for streaming)

```javascript
// Main
const { port1, port2 } = new MessageChannelMain()
ipcMain.handle('stream:start', (event) => port1)

// Renderer
const port = await ipcRenderer.invoke('stream:start')
port.onmessage = (event) => { ... }
```

## 4. Subscription State Management

### Redux Pattern

```javascript
// Initial state
const initialState = {
  auth: {
    user: null,
    subscription: { status: 'none', plan: 'basic', isSubscribed: false },
    authSignedIn: false,
  }
}

// Reducer
case 'SET_SUBSCRIPTION':
  return { ...state, subscription: action.payload }
```

### Zustand Pattern

```javascript
const useStore = create((set) => ({
  user: null,
  subscription: null,
  isPremium: false,
  setSubscription: (sub) => set({ subscription: sub, isPremium: sub?.status === 'active' }),
}))
```

### React Context

```javascript
const AuthContext = createContext({
  user: null,
  isSubscribed: false,
  plan: 'free',
})
```

## 5. Update/Download Infrastructure

### Electron Updater (electron-builder)

```javascript
import { autoUpdater } from 'electron-updater'
autoUpdater.setFeedURL('https://dl.example.com/updates/{platform}/{version}')
autoUpdater.checkForUpdatesAndNotify()
```

### Custom Update Check

```javascript
// GET /api/v1/updates/check?version=X&platform=linux
const update = await api.get('/api/v1/updates/check', { params: { version, platform } })
if (update.available) {
  // Download from update.download_url
}
```

## 6. Error/Logging Infrastructure

### Sentry

```javascript
import * as Sentry from '@sentry/electron'
Sentry.init({ dsn: 'https://...@....ingest.sentry.io/...' })
```

### Custom Error Tracking

```javascript
const reportError = async (error) => {
  await fetch('https://api.example.com/v1/errors', {
    method: 'POST',
    body: JSON.stringify({ error: error.message, stack: error.stack, version: APP_VERSION }),
  })
}
```

## 7. Machine Fingerprinting

```javascript
// Common pattern for device identification
const machineId = await getMachineId()  // npm: node-machine-id
const deviceId = crypto.createHash('sha256').update(machineId).digest('hex')

// Sent with subscription queries
fetch(`/api/v1/payment/subscription?device_id=${deviceId}`)
```
