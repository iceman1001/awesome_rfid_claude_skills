# Electron Auth Pattern Reference

## Pattern 1: Supabase Auth

Most common in modern Electron apps (2024+). Provides full OAuth + JWT infrastructure out of the box.

### Identification

```javascript
// Bundle signatures:
import { createClient } from '@supabase/supabase-js'
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)

// Auth operations:
supabase.auth.signInWithOAuth({ provider: 'google' })
supabase.auth.signInWithPassword({ email, password })
supabase.auth.signInWithOtp({ email })
supabase.auth.getSession()
supabase.auth.getUser()
supabase.auth.onAuthStateChange((event, session) => { ... })
supabase.auth.refreshSession()
supabase.auth.signOut({ scope: 'local' })
```

### Token Storage

Supabase by default stores tokens in `localStorage`. In Electron, some apps override this to use `safeStorage`:

```javascript
// Custom storage adapter pattern
const storage = {
  getItem: (key) => electronSafeStorage.decryptString(readFromFile(key)),
  setItem: (key, value) => writeToFile(key, electronSafeStorage.encryptString(value)),
  removeItem: (key) => deleteFile(key),
}
```

### Attack Surface

- **localStorage**: Tokens are readable by any renderer process. Extract via DevTools.
- **safeStorage**: Uses OS-level encryption (DPAPI on Windows, Keychain on macOS, libsecret on Linux). Harder but not impossible.
- **File-based**: Look in `~/.config/<app>/`, `%APPDATA%/<app>/`, `~/Library/Application Support/<app>/`

### CTF Tips

1. Check if `SUPABASE_URL` and `SUPABASE_ANON_KEY` are hardcoded (they always are for Supabase)
2. Supabase anon key is public by design — look for service_role key leaks
3. Check if RLS (Row Level Security) is misconfigured by querying tables directly with anon key
4. `supabase.from('profiles').select('*')` with anon key might leak subscription status

## Pattern 2: Firebase Auth

### Identification

```javascript
import { initializeApp } from 'firebase/app'
import { getAuth, signInWithEmailAndPassword, onAuthStateChanged } from 'firebase/auth'

const auth = getAuth()
auth.signInWithEmailAndPassword(email, password)
auth.onAuthStateChanged(user => { ... })
```

### Key Difference from Supabase

Firebase Auth is more likely to be bundled with Firestore for subscription data:

```javascript
import { getFirestore, doc, getDoc } from 'firebase/firestore'
const subDoc = await getDoc(doc(db, 'subscriptions', userId))
```

## Pattern 3: Custom OAuth / OpenID Connect

### Identification

```javascript
// Direct HTTP calls to OAuth endpoints
fetch('https://auth.example.com/oauth/authorize?client_id=...')
fetch('https://auth.example.com/oauth/token', { body: { grant_type: 'authorization_code' } })

// PKCE flow
const codeVerifier = generateCodeVerifier()
const codeChallenge = sha256(codeVerifier)
```

### Attack Surface

- Client secret may be hardcoded (CWE-798)
- Redirect URI validation may be weak
- Token endpoint may lack CORS protection (less relevant for Electron but still worth checking)

## Pattern 4: Offline/Local JWT Validation

Rare but dangerous. App validates JWT signature locally without server check.

### Identification

```javascript
import jwt from 'jsonwebtoken'
const decoded = jwt.verify(token, PUBLIC_KEY)  // Local verification only

// Or worse:
const payload = JSON.parse(atob(token.split('.')[1]))  // No signature check at all!
```

### CTF Tips

If JWT is validated locally:
1. Extract the public key from the bundle
2. Or if no signature check: modify the payload directly
3. Set `exp` far in the future, `sub` to a known premium user ID

## Pattern 5: API Key / Bearer Token

### Identification

```javascript
const API_KEY = 'sk-...'
axios.defaults.headers.common['Authorization'] = `Bearer ${API_KEY}`
```

### CTF Tips

- API keys in Electron bundles are trivially extractable
- Check if the API key has scoped permissions or is a full-access key

## Common Token Storage Locations

```bash
# Linux
~/.config/<AppName>/
~/.local/share/<AppName>/

# macOS
~/Library/Application Support/<AppName>/
~/Library/Preferences/<bundle-id>/
Login Keychain: security find-generic-password -s "<AppName>"

# Windows
%APPDATA%/<AppName>/
%LOCALAPPDATA%/<AppName>/
HKCU\Software\<AppName>\
```

## Authorization Header Patterns

```bash
# Extract all Authorization header constructions from bundle:
grep -oP "Authorization.*?['\"][^'\"]*['\"]" bundle.js | sort -u
```
