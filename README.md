# 🔐 Password Vault

A secure, client-side password manager built with React and the WebCrypto API. All credentials are encrypted with AES-256-GCM before being saved locally — your data never leaves your device.

---

## ✨ Features

- **AES-256-GCM encryption** — every credential field encrypted individually
- **PBKDF2 key derivation** — 310,000 iterations with a unique random salt
- **Biometric authentication** — Face ID / Touch ID / Fingerprint unlock
- **Master password fallback** — activates after 3 failed biometric attempts
- **Auto-lock** — configurable timer (immediate / 1 min / 5 min / never)
- **Password generator** — length 8–32, customizable character sets
- **Password strength meter** — Weak / Moderate / Strong indicator
- **Clipboard auto-clear** — copies clear automatically after 30 seconds
- **Vault health check** — flags weak and duplicate passwords with a score
- **Encrypted export** — AES-256-GCM backup protected by a separate password
- **Category tags** — Email, Banking, Social, Work, Shopping, Other
- **Search & filter** — search by service name, username, or email
- **Dark & Light mode** — toggle in Settings

---

## 🚀 Setup

### Prerequisites
- [Node.js](https://nodejs.org/) v18 or higher
- npm v9 or higher

### Install & Run

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/vault-app.git
cd vault-app

# 2. Install dependencies
npm install

# 3. Start the development server
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Build for Production

```bash
npm run build
npm run preview
```

### Deploy to Vercel

```bash
npm install -g vercel
vercel
```

Or connect your GitHub repo at [vercel.com](https://vercel.com) for automatic deployments on every push to `main`.

---

## 🔑 First Run

1. You'll be prompted to **create a master password** (minimum 8 characters)
2. A unique salt is generated and stored locally
3. Your master key is derived via PBKDF2 and used to encrypt all data
4. On subsequent visits, authenticate with **biometric** or your **master password**

> **Demo hint:** If you're testing, use `DemoPassword123!` as the master password after the first setup.

---

## 🛡️ Encryption Flow

```
Master Password + Random Salt (32 bytes)
          │
          ▼
    PBKDF2 (SHA-256)
    310,000 iterations
          │
          ▼
   AES-256-GCM Master Key
          │
    ┌─────┴──────┐
    │            │
    ▼            ▼
Encrypt       Encrypt
each field    verification
(IV + cipher) token
    │
    ▼
 localStorage
 (base64 encoded)
```

### Key points
- A **fresh 12-byte IV** is generated for every encryption operation
- The IV is prepended to the ciphertext and stored together as base64
- The master key is **never stored** — it is re-derived on every unlock
- A verification token (`VAULT_OK`) is encrypted on setup to validate the password on unlock without storing the key

---

## 🧬 Biometric Fallback Behavior

```
User opens app
      │
      ▼
Biometric prompt shown
      │
   ┌──┴──┐
  Pass  Fail
   │      │
   │   attempt++ 
   │      │
   │   3 attempts?
   │    Yes │  No
   │      │   │
   │   Show  Retry
   │   master biometric
   │   password
   │      │
   └──────┘
      │
      ▼
  Vault unlocked
```

- After **3 biometric failures**, the master password form is shown automatically
- The user can also manually switch to master password at any time
- Biometric is re-enabled on the next app launch

---

## 📁 Project Structure

```
vault-app/
├── .gitignore
├── README.md
├── index.html
├── package.json
├── vite.config.js
└── src/
    ├── main.jsx      # React entry point
    └── App.jsx       # Entire application (crypto, UI, state)
```

---

## 🔒 Security Notes

- This is a **client-side only** app — no server, no cloud sync, no telemetry
- All data is stored in `localStorage` (simulating SQLite for web)
- In a production React Native app, replace `localStorage` with `expo-sqlite` and store the derived key in `react-native-keychain` bound to biometrics
- Screenshots are not programmatically blocked in the web version; this is enforced natively in the React Native version via `FLAG_SECURE`
- The clipboard is cleared after 30 seconds using the Clipboard API

---

## 🧪 Encryption Unit Tests

To run tests (if added):

```bash
npm test
```

Core logic to test lives in the `CryptoEngine` object in `src/App.jsx`:
- `deriveMasterKey(password, salt)` — PBKDF2 key derivation
- `encrypt(plaintext, key)` — AES-GCM encrypt → base64
- `decrypt(ciphertextB64, key)` — base64 → AES-GCM decrypt
- `generateSalt()` — 32-byte random salt

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `react` | UI framework |
| `react-dom` | DOM rendering |
| `vite` | Build tool & dev server |
| `@vitejs/plugin-react` | JSX transform |

No third-party crypto libraries — encryption uses the native **WebCrypto API** built into all modern browsers.

---

## 📄 License

MIT — free to use, modify, and distribute.
