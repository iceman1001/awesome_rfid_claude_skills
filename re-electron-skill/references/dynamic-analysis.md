# Dynamic Analysis of Electron Apps

## Enabling DevTools

### Method 1: Remote Debugging Port

```bash
# Start the app with debugging enabled
./AppName --remote-debugging-port=9222

# Connect Chrome
# Open chrome://inspect in Chrome
# Find the Electron app under "Remote Target"
# Click "inspect"
```

### Method 2: ELECTRON_RUN_AS_NODE

Run the Electron binary as a Node.js process:

```bash
# Execute arbitrary code in the Electron environment
ELECTRON_RUN_AS_NODE=1 ./app-binary -e "
  const fs = require('fs');
  const config = fs.readFileSync(process.argv[1], 'utf-8');
  console.log(config);
"
```

### Method 3: Environment Variables

```bash
# Enable Chromium logging
ELECTRON_ENABLE_LOGGING=1 ./AppName

# Enable stack traces
ELECTRON_ENABLE_STACK_DUMPING=1 ./AppName

# Disable GPU (useful for headless analysis)
./AppName --disable-gpu --disable-software-rasterizer
```

### Method 4: Debug Mode (App-Specific)

Some apps have a debug mode:
```bash
./AppName --debug
./AppName --dev
./AppName --inspect
NODE_ENV=development ./AppName
```

## Setting Breakpoints

Once DevTools is connected:

### Main Process Debugging

```javascript
// In DevTools console, set breakpoints on IPC handlers:
// The main process code is under "Sources" → "file://"

// Find auth-related functions by searching in Sources tab
// Ctrl+Shift+F → search for "getSubscription", "getUser", etc.
```

### Renderer Process Debugging

```javascript
// In renderer DevTools, override functions via console:
const original = window.electronAPI.getSubscription;
window.electronAPI.getSubscription = async () => {
  const result = await original();
  console.log('Real subscription:', result);
  // Return modified result
  return { ...result, status: 'active', isSubscribed: true, plan: 'pro_yearly' };
};
```

## Runtime Modification Techniques

### 1. IPC Interception

```javascript
// In main process DevTools:
const { ipcMain } = require('electron');
const originalHandle = ipcMain.handle.bind(ipcMain);
ipcMain.handle = (channel, handler) => {
  console.log('IPC handler registered:', channel);
  return originalHandle(channel, async (...args) => {
    console.log('IPC call:', channel, args);
    const result = await handler(...args);
    console.log('IPC result:', channel, result);
    return result;
  });
};
```

### 2. API Response Modification

```javascript
// Intercept fetch/axios
const originalFetch = window.fetch;
window.fetch = async (...args) => {
  const response = await originalFetch(...args);

  // Modify subscription API responses
  if (args[0].includes('/api/v1/payment/subscription')) {
    const clone = response.clone();
    const data = await clone.json();
    console.log('Original subscription response:', data);

    // Return modified response
    return new Response(JSON.stringify({
      ...data, status: 'active', is_subscribed: true, plan: 'FLOW_PRO_YEARLY'
    }), { status: 200, headers: response.headers });
  }

  return response;
};
```

### 3. Node.js require() Patching

```javascript
// For main process modules:
const Module = require('module');
const originalRequire = Module.prototype.require;
Module.prototype.require = function(id) {
  const exports = originalRequire.apply(this, arguments);
  if (id === '@supabase/supabase-js') {
    // Hook into Supabase client creation
  }
  return exports;
};
```

## Extracting Token Storage

### Linux

```bash
# Check common config dirs
ls -la ~/.config/<AppName>/
ls -la ~/.local/share/<AppName>/

# If using libsecret (safeStorage backend)
secret-tool search --all

# Check for SQLite databases
sqlite3 ~/.config/<AppName>/data.db ".tables"
sqlite3 ~/.config/<AppName>/data.db "SELECT * FROM sessions;"
```

### macOS

```bash
# Keychain
security find-generic-password -s "<AppName>"
security dump-keychain -d ~/Library/Keychains/login.keychain-db

# App support
ls -la ~/Library/Application\ Support/<AppName>/

# Preferences
defaults read <bundle-id>
```

### Windows

```powershell
# Credential Manager (via cmdkey)
cmdkey /list

# Registry
Get-ChildItem HKCU:\Software\<AppName>\
Get-ChildItem HKCU:\Software\<AppName>\

# AppData
ls $env:APPDATA\<AppName>\
ls $env:LOCALAPPDATA\<AppName>\
```

## Tracing Network Requests

### Using mitmproxy

```bash
# Start mitmproxy
mitmproxy -p 8888

# Run Electron app with proxy
./AppName --proxy-server=http://localhost:8888

# With SSL interception
# Set NODE_EXTRA_CA_CERTS to mitmproxy's CA cert
NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem \
  ./AppName --proxy-server=http://localhost:8888 \
  --ignore-certificate-errors
```

### Using Electron's built-in netLog

```javascript
// In main process DevTools:
const { netLog } = require('electron');
await netLog.startLogging('/tmp/electron-net-log.json');
// ... use the app ...
await netLog.stopLogging();
// Analyze /tmp/electron-net-log.json
```
