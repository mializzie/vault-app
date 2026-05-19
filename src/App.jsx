import { useState, useEffect, useRef } from "react";

// WebAuthn Biometrics engine 
const BiometricEngine = {
  isSupported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  },

  async isPlatformAvailable() {
    if (!this.isSupported()) return false;
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch { return false; }
  },

  // Register biometric credential (called once on setup)
  async register(userId, userName) {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const publicKeyOptions = {
      challenge,
      rp: { name: "Password Vault", id: window.location.hostname || "localhost" },
      user: {
        id: new TextEncoder().encode(userId),
        name: userName,
        displayName: "Vault User",
      },
      pubKeyCredParams: [
        { alg: -7, type: "public-key" },   // ES256
        { alg: -257, type: "public-key" }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform", // Forces Face ID / Touch ID
        userVerification: "required",
        residentKey: "preferred",
      },
      timeout: 60000,
      attestation: "none",
    };

    const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });
    if (!credential) throw new Error("Biometric registration failed");

    // Store credential ID for future authentication
    const credId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
    localStorage.setItem("vault_cred_id", credId);
    return credId;
  },

  // Authenticate with biometric(s) 
  async authenticate() {
    const storedCredId = localStorage.getItem("vault_cred_id");
    if (!storedCredId) throw new Error("No biometric registered");

    const credIdBytes = Uint8Array.from(atob(storedCredId), c => c.charCodeAt(0));
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const assertionOptions = {
      challenge,
      allowCredentials: [{
        id: credIdBytes,
        type: "public-key",
        transports: ["internal"],
      }],
      userVerification: "required",
      timeout: 60000,
    };

    const assertion = await navigator.credentials.get({ publicKey: assertionOptions });
    if (!assertion) throw new Error("Biometric authentication failed");
    return true;
  },

  hasRegistered() {
    return !!localStorage.getItem("vault_cred_id");
  },
};

// Crypto Utilities (WebCrypto API) 
const CryptoEngine = {
  async deriveMasterKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  async encrypt(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, key, enc.encode(plaintext)
    );
    const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.byteLength);
    return btoa(String.fromCharCode(...combined));
  },

  async decrypt(ciphertextB64, key) {
    const combined = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const dec = new TextDecoder();
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return dec.decode(plaintext);
  },

  generateSalt() { return crypto.getRandomValues(new Uint8Array(32)); },
  saltToB64(salt) { return btoa(String.fromCharCode(...salt)); },
  b64ToSalt(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); },
};

// Password Generator (in the case there is need)
function generatePassword({ length = 16, upper = true, lower = true, numbers = true, symbols = true }) {
  const sets = [];
  if (upper) sets.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  if (lower) sets.push("abcdefghijklmnopqrstuvwxyz");
  if (numbers) sets.push("0123456789");
  if (symbols) sets.push("!@#$%^&*()_+-=[]{}|;:,.<>?");
  if (!sets.length) sets.push("abcdefghijklmnopqrstuvwxyz");
  const charset = sets.join("");
  const arr = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(arr).map(b => charset[b % charset.length]).join("");
}

// Password Strength 
function getStrength(pw) {
  if (!pw) return { label: "", score: 0, color: "#333" };
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 14) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[a-z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  if (s <= 2) return { label: "Weak", score: s, color: "#FF4757" };
  if (s <= 4) return { label: "Moderate", score: s, color: "#FFA502" };
  return { label: "Strong", score: s, color: "#2ED573" };
}

// Local DB (localStorage as SQLite stand-in) 
const MockDB = {
  get(key) { try { return JSON.parse(localStorage.getItem(key) || "null"); } catch { return null; } },
  set(key, val) { localStorage.setItem(key, JSON.stringify(val)); },
  del(key) {  Icon = ({ name, size = 20, color = "currentColor" }) => {
    localStorage.removeItem(key); },
};

// ─── Icons ─────────────────────────────────────────────────────────────────────
const
  const paths = {
    lock: "M19 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2zM12 3a4 4 0 014 4v4H8V7a4 4 0 014-4z",
    eye: "M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z M12 9a3 3 0 100 6 3 3 0 000-6z",
    eyeOff: "M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24 M1 1l22 22",
    copy: "M8 4H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-2M8 4a2 2 0 012-2h4a2 2 0 012 2M8 4h8",
    trash: "M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6",
    edit: "M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7 M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z",
    plus: "M12 5v14M5 12h14",
    search: "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z",
    shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
    fingerprint: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15h2v-2h-2v2zm1-4c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2h-2c0-2.21 1.79-4 4-4s4 1.79 4 4c0 1.48-.81 2.75-2 3.45V15h-2v-1.27C9.81 13.09 9 11.88 9 10.5V10h2c0 .55.45 1 1 1z",
    key: "M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
    settings: "M12 15a3 3 0 100-6 3 3 0 000 6z M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z",
    logout: "M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4 M16 17l5-5-5-5 M21 12H9",
    health: "M22 12h-4l-3 9L9 3l-3 9H2",
    download: "M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4 M7 10l5 5 5-5 M12 15V3",
    refresh: "M23 4v6h-6 M1 20v-6h6 M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15",
    check: "M20 6L9 17l-5-5",
    x: "M18 6L6 18M6 6l12 12",
    zap: "M13 2L3 14h9l-1 8 10-12h-9l1-8z",
    faceId: "M8 3H5a2 2 0 00-2 2v3 M21 8V5a2 2 0 00-2-2h-3 M3 16v3a2 2 0 002 2h3 M16 21h3a2 2 0 002-2v-3 M9 9h.01 M15 9h.01 M9 15s1 1 3 1 3-1 3-1",
    alert: "M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z M12 9v4 M12 17h.01",
    info: "M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z M12 8h.01 M12 12v4",
  };
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      {(paths[name] || "").split(" M").map((d, i) => (
        <path key={i} d={i === 0 ? d : "M" + d} />
      ))}
    </svg>
  );
};
//MAIN APP
export default function PasswordVault() {
  const [screen, setScreen] = useState("splash");
  const [masterKey, setMasterKey] = useState(null);
  const [saltB64, setSaltB64] = useState(null);
  const [entries, setEntries] = useState([]);
  const [selectedEntry, setSelectedEntry] = useState(null);
  const [isEditing, setIsEditing] = useState(false);
  const [searchQ, setSearchQ] = useState("");
  const [toast, setToast] = useState(null);
  const [clipCount, setClipCount] = useState(30);
  const [biometricAttempts, setBiometricAttempts] = useState(0);
  const [showMasterFallback, setShowMasterFallback] = useState(false);
  const [autoLockSetting, setAutoLockSetting] = useState("5min");
  const [theme, setTheme] = useState("dark");
  const [filterCat, setFilterCat] = useState("All");
  const [bioAvailable, setBioAvailable] = useState(null); // null=checking, true, false
  const [bioRegistered, setBioRegistered] = useState(false);
  const categories = ["All", "Email", "Banking", "Social", "Work", "Shopping", "Other"];
  const autoLockRef = useRef(null);
  const clipIntervalRef = useRef(null);

  // ── Init ──
  useEffect(() => {
    const init = async () => {
      const available = await BiometricEngine.isPlatformAvailable();
      setBioAvailable(available);
      setBioRegistered(BiometricEngine.hasRegistered());
      const existing = MockDB.get("vault_salt");
      setTimeout(() => {
        if (existing) { setSaltB64(existing); setScreen("unlock"); }
        else setScreen("setup");
      }, 1800);
    };
    init();
  }, []);

  // ── Auto-lock ──
  useEffect(() => {
    const activeScreens = ["vault", "add", "detail", "generator", "settings", "health", "export"];
    if (activeScreens.includes(screen)) {
      const ms = autoLockSetting === "immediate" ? 5000 : autoLockSetting === "1min" ? 60000 : autoLockSetting === "5min" ? 300000 : null;
      if (ms) {
        clearTimeout(autoLockRef.current);
        autoLockRef.current = setTimeout(() => lockVault(), ms);
      }
    }
    return () => clearTimeout(autoLockRef.current);
  }, [screen, autoLockSetting]);

  const lockVault = () => {
    setMasterKey(null);
    setEntries([]);
    setSelectedEntry(null);
    setScreen("unlock");
    showToast("🔒 Vault locked");
  };

  const showToast = (msg, type = "info") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  // ── Setup ──
  const handleSetup = async (password) => {
    try {
      const salt = CryptoEngine.generateSalt();
      const sb64 = CryptoEngine.saltToB64(salt);
      const key = await CryptoEngine.deriveMasterKey(password, salt);
      const token = await CryptoEngine.encrypt("VAULT_OK", key);
      MockDB.set("vault_salt", sb64);
      MockDB.set("vault_verify", token);
      MockDB.set("vault_entries", []);
      setSaltB64(sb64);
      setMasterKey(key);
      setEntries([]);

      // Offer biometric registration after setup
      if (bioAvailable) {
        try {
          await BiometricEngine.register("vault-user-" + Date.now(), "vault@local");
          setBioRegistered(true);
          showToast("✅ Vault created & biometric registered!", "success");
        } catch (e) {
          showToast("✅ Vault created! Biometric skipped.", "success");
        }
      } else {
        showToast("✅ Vault created successfully!", "success");
      }
      setScreen("vault");
    } catch (e) { showToast("❌ Setup failed: " + e.message, "error"); }
  };

  // ── Unlock via master password ──
  const handleUnlock = async (password) => {
    try {
      const salt = CryptoEngine.b64ToSalt(saltB64);
      const key = await CryptoEngine.deriveMasterKey(password, salt);
      const token = MockDB.get("vault_verify");
      const check = await CryptoEngine.decrypt(token, key);
      if (check !== "VAULT_OK") throw new Error("Wrong password");
      await openVaultWithKey(key);
      setBiometricAttempts(0);
      setShowMasterFallback(false);
    } catch (e) { showToast("❌ Wrong master password", "error"); }
  };

  const openVaultWithKey = async (key) => {
    setMasterKey(key);
    const raw = MockDB.get("vault_entries") || [];
    const decrypted = await Promise.all(raw.map(e => decryptEntry(e, key)));
    setEntries(decrypted);
    setScreen("vault");
    showToast("🔓 Vault unlocked", "success");
  };

  // ── Real WebAuthn biometric unlock ──
  const handleBiometric = async () => {
    try {
      // Trigger real Face ID / Touch ID / Windows Hello
      await BiometricEngine.authenticate();

      // Biometric passed — still need the master key to decrypt
      // In production: store encrypted master key in keychain bound to biometric
      // Here: prompt for master password once after bio success, then cache
      const cachedPw = sessionStorage.getItem("_vk");
      if (cachedPw) {
        const salt = CryptoEngine.b64ToSalt(saltB64);
        const key = await CryptoEngine.deriveMasterKey(cachedPw, salt);
        await openVaultWithKey(key);
        setBiometricAttempts(0);
      } else {
        // First time: bio succeeded but we need the password to derive the key
        showToast("✅ Biometric passed! Enter password once to link it.", "success");
        setShowMasterFallback(true);
      }
    } catch (err) {
      const attempts = biometricAttempts + 1;
      setBiometricAttempts(attempts);
      if (err.name === "NotAllowedError") {
        showToast("⚠️ Biometric cancelled or timed out", "error");
      } else if (err.name === "InvalidStateError") {
        showToast("⚠️ No biometric registered — use master password", "error");
        setShowMasterFallback(true);
      } else if (attempts >= 3) {
        setShowMasterFallback(true);
        showToast("⚠️ Biometric failed 3× — use master password", "error");
      } else {
        showToast(`⚠️ Biometric failed (${attempts}/3)`, "error");
      }
    }
  };

  // ── Unlock via password + cache for future biometric ──
  const handleUnlockAndCache = async (password) => {
    try {
      const salt = CryptoEngine.b64ToSalt(saltB64);
      const key = await CryptoEngine.deriveMasterKey(password, salt);
      const token = MockDB.get("vault_verify");
      const check = await CryptoEngine.decrypt(token, key);
      if (check !== "VAULT_OK") throw new Error("Wrong password");
      // Cache in sessionStorage so biometric can unlock without re-entering password
      sessionStorage.setItem("_vk", password);
      await openVaultWithKey(key);
      setBiometricAttempts(0);
      setShowMasterFallback(false);
    } catch (e) { showToast("❌ Wrong master password", "error"); }
  };

  // ── Register biometric from settings ──
  const handleRegisterBiometric = async () => {
    try {
      await BiometricEngine.register("vault-user", "vault@local");
      setBioRegistered(true);
      showToast("✅ Biometric registered!", "success");
    } catch (e) {
      if (e.name === "NotAllowedError") showToast("⚠️ Biometric registration cancelled", "error");
      else showToast("❌ Could not register biometric: " + e.message, "error");
    }
  };

  // ── Entry encryption / decryption ──
  const encryptEntry = async (entry, key) => {
    const fields = ["serviceName", "username", "email", "password", "notes"];
    const enc = {};
    for (const f of fields) enc[f] = entry[f] ? await CryptoEngine.encrypt(entry[f], key) : "";
    return { ...entry, ...enc, _encrypted: true };
  };

  const decryptEntry = async (entry, key) => {
    if (!entry._encrypted) return entry;
    const fields = ["serviceName", "username", "email", "password", "notes"];
    const dec = {};
    for (const f of fields) dec[f] = entry[f] ? await CryptoEngine.decrypt(entry[f], key) : "";
    return { ...entry, ...dec, _encrypted: false };
  };

  // ── Save entry ──
  const saveEntry = async (entry) => {
    try {
      const newEntry = { ...entry, id: entry.id || Date.now().toString(), updatedAt: new Date().toISOString() };
      const encrypted = await encryptEntry(newEntry, masterKey);
      const rawEntries = MockDB.get("vault_entries") || [];
      const idx = rawEntries.findIndex(e => e.id === newEntry.id);
      if (idx >= 0) rawEntries[idx] = encrypted; else rawEntries.push(encrypted);
      MockDB.set("vault_entries", rawEntries);
      setEntries(entries.filter(e => e.id !== newEntry.id).concat(newEntry));
      showToast("✅ Entry saved", "success");
      setScreen("vault");
    } catch (e) { showToast("❌ Save failed", "error"); }
  };

  // ── Delete entry ──
  const deleteEntry = async (id) => {
    MockDB.set("vault_entries", (MockDB.get("vault_entries") || []).filter(e => e.id !== id));
    setEntries(entries.filter(e => e.id !== id));
    showToast("🗑️ Entry deleted", "success");
    setScreen("vault");
  };

  // ── Copy to clipboard with auto-clear ──
  const copyToClipboard = (text, label = "Password") => {
    navigator.clipboard.writeText(text).then(() => {
      clearInterval(clipIntervalRef.current);
      setClipCount(30);
      let c = 30;
      clipIntervalRef.current = setInterval(() => {
        c--;
        setClipCount(c);
        if (c <= 0) {
          clearInterval(clipIntervalRef.current);
          navigator.clipboard.writeText("").catch(() => {});
          setClipCount(30);
          showToast("🧹 Clipboard cleared", "info");
        }
      }, 1000);
      showToast(`📋 ${label} copied — clears in 30s`, "success");
    });
  };

  // ── Export ──
  const exportVault = async (exportPw) => {
    try {
      const rawEntries = MockDB.get("vault_entries") || [];
      const exportSalt = CryptoEngine.generateSalt();
      const exportKey = await CryptoEngine.deriveMasterKey(exportPw, exportSalt);
      const blob = JSON.stringify({ entries: rawEntries, exportedAt: new Date().toISOString(), version: "1.0" });
      const encrypted = await CryptoEngine.encrypt(blob, exportKey);
      const exportData = JSON.stringify({ data: encrypted, salt: CryptoEngine.saltToB64(exportSalt) });
      const url = URL.createObjectURL(new Blob([exportData], { type: "application/json" }));
      const a = document.createElement("a"); a.href = url; a.download = "vault_backup.enc.json"; a.click();
      showToast("📤 Vault exported & encrypted", "success");
    } catch (e) { showToast("❌ Export failed", "error"); }
  };

  // ── Health ──
  const getHealthData = () => {
    const dupes = {};
    entries.forEach(e => { dupes[e.password] = (dupes[e.password] || 0) + 1; });
    return {
      weak: entries.filter(e => getStrength(e.password).label === "Weak"),
      moderate: entries.filter(e => getStrength(e.password).label === "Moderate"),
      dupeEntries: entries.filter(e => dupes[e.password] > 1),
      total: entries.length,
    };
  };

  const T = theme === "dark" ? DARK : LIGHT;
  const filteredEntries = entries.filter(e => {
    const q = searchQ.toLowerCase();
    const matchSearch = !q || e.serviceName?.toLowerCase().includes(q) || e.username?.toLowerCase().includes(q) || e.email?.toLowerCase().includes(q);
    const matchCat = filterCat === "All" || e.category === filterCat;
    return matchSearch && matchCat;
  });

  // ── Screen routing ──
  if (screen === "splash") return <SplashScreen T={T} />;
  if (screen === "setup") return <SetupScreen T={T} onSetup={handleSetup} bioAvailable={bioAvailable} />;
  if (screen === "unlock") return (
    <UnlockScreen T={T} onUnlock={handleUnlockAndCache} onBiometric={handleBiometric}
      biometricAttempts={biometricAttempts} showMasterFallback={showMasterFallback}
      setShowMasterFallback={setShowMasterFallback} bioAvailable={bioAvailable}
      bioRegistered={bioRegistered} />
  );
  if (screen === "add" || (screen === "detail" && isEditing)) return (
    <AddEditScreen T={T} entry={isEditing ? selectedEntry : null}
      onSave={saveEntry} onCancel={() => { setIsEditing(false); setScreen(selectedEntry ? "detail" : "vault"); }}
      categories={categories} />
  );
  if (screen === "detail") return (
    <DetailScreen T={T} entry={selectedEntry} onEdit={() => setIsEditing(true)}
      onDelete={() => deleteEntry(selectedEntry.id)} onCopy={copyToClipboard}
      clipCount={clipCount} onBack={() => setScreen("vault")} />
  );
  if (screen === "generator") return <GeneratorScreen T={T} onBack={() => setScreen("vault")} onUse={(pw) => { copyToClipboard(pw, "Generated password"); setScreen("vault"); }} />;
  if (screen === "health") return <HealthScreen T={T} data={getHealthData()} onBack={() => setScreen("vault")} onSelect={(e) => { setSelectedEntry(e); setScreen("detail"); }} />;
  if (screen === "export") return <ExportScreen T={T} onExport={exportVault} onBack={() => setScreen("settings")} />;
  if (screen === "settings") return (
    <SettingsScreen T={T} autoLockSetting={autoLockSetting} setAutoLockSetting={setAutoLockSetting}
      theme={theme} setTheme={setTheme} onBack={() => setScreen("vault")} onLock={lockVault}
      onExport={() => setScreen("export")} entryCount={entries.length}
      bioAvailable={bioAvailable} bioRegistered={bioRegistered}
      onRegisterBio={handleRegisterBiometric} />
  );

  // ── Main Vault Screen ──
  return (
    <div style={{ ...styles.container, background: T.bg, color: T.text, fontFamily: "'Courier New', monospace" }}>
      <div style={{ ...styles.header, background: T.surface, borderBottom: `1px solid ${T.border}` }}>
        <div style={styles.headerLeft}>
          <div style={{ ...styles.logoMark, background: T.accent }}>
            <Icon name="shield" size={16} color="#000" />
          </div>
          <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: 2, color: T.text }}>VAULT</span>
        </div>
        <div style={styles.headerRight}>
          <button onClick={() => setScreen("health")} style={{ ...styles.iconBtn, color: T.textMuted }}><Icon name="health" size={18} /></button>
          <button onClick={() => setScreen("generator")} style={{ ...styles.iconBtn, color: T.textMuted }}><Icon name="zap" size={18} /></button>
          <button onClick={() => setScreen("settings")} style={{ ...styles.iconBtn, color: T.textMuted }}><Icon name="settings" size={18} /></button>
          <button onClick={lockVault} style={{ ...styles.iconBtn, color: T.danger }}><Icon name="lock" size={18} /></button>
        </div>
      </div>

      <div style={{ padding: "12px 16px", background: T.surface, borderBottom: `1px solid ${T.border}` }}>
        <div style={{ ...styles.searchBox, background: T.inputBg, border: `1px solid ${T.border}` }}>
          <Icon name="search" size={16} color={T.textMuted} />
          <input value={searchQ} onChange={e => setSearchQ(e.target.value)} placeholder="Search credentials…"
            style={{ ...styles.searchInput, color: T.text, background: "transparent" }} />
        </div>
        <div style={{ display: "flex", gap: 6, marginTop: 8, overflowX: "auto", paddingBottom: 2 }}>
          {categories.map(cat => (
            <button key={cat} onClick={() => setFilterCat(cat)}
              style={{ ...styles.catChip, background: filterCat === cat ? T.accent : T.inputBg, color: filterCat === cat ? "#000" : T.textMuted, border: `1px solid ${filterCat === cat ? T.accent : T.border}` }}>
              {cat}
            </button>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "8px 0" }}>
        {filteredEntries.length === 0 ? (
          <div style={{ textAlign: "center", padding: "60px 24px", color: T.textMuted }}>
            <div style={{ fontSize: 40, marginBottom: 12 }}>🔐</div>
            <div style={{ fontSize: 14, marginBottom: 6 }}>{searchQ ? "No results found" : "Your vault is empty"}</div>
            <div style={{ fontSize: 12 }}>{searchQ ? "Try a different search" : "Tap + to add your first credential"}</div>
          </div>
        ) : filteredEntries.map(entry => (
          <EntryCard key={entry.id} entry={entry} T={T} onClick={() => { setSelectedEntry(entry); setIsEditing(false); setScreen("detail"); }} />
        ))}
      </div>

      <button onClick={() => { setSelectedEntry(null); setIsEditing(false); setScreen("add"); }}
        style={{ ...styles.fab, background: T.accent }}>
        <Icon name="plus" size={22} color="#000" />
      </button>

      {clipCount < 30 && (
        <div style={{ ...styles.clipBar, background: T.surface, borderTop: `1px solid ${T.border}` }}>
          <Icon name="copy" size={14} color={T.textMuted} />
          <span style={{ fontSize: 12, color: T.textMuted }}>Clipboard clears in {clipCount}s</span>
          <div style={{ flex: 1, height: 3, background: T.border, borderRadius: 2, marginLeft: 8, overflow: "hidden" }}>
            <div style={{ width: `${(clipCount / 30) * 100}%`, height: "100%", background: T.accent, transition: "width 1s linear" }} />
          </div>
        </div>
      )}

      {toast && <Toast msg={toast.msg} type={toast.type} T={T} />}
    </div>
  );
}

// ─── Entry Card ────────────────────────────────────────────────────────────────
function EntryCard({ entry, T, onClick }) {
  const initials = (entry.serviceName || "?").slice(0, 2).toUpperCase();
  const strength = getStrength(entry.password);
  const colors = ["#FF6B6B", "#FFD93D", "#6BCB77", "#4D96FF", "#C77DFF", "#FF9A3C"];
  const avatarColor = colors[(entry.serviceName?.charCodeAt(0) || 0) % colors.length];
  return (
    <button onClick={onClick} style={{ ...styles.entryCard, background: T.surface, borderBottom: `1px solid ${T.border}` }}>
      <div style={{ ...styles.avatar, background: avatarColor + "22", border: `1.5px solid ${avatarColor}44` }}>
        <span style={{ color: avatarColor, fontWeight: 700, fontSize: 13 }}>{initials}</span>
      </div>
      <div style={{ flex: 1, textAlign: "left" }}>
        <div style={{ fontWeight: 600, fontSize: 14, color: T.text }}>{entry.serviceName}</div>
        <div style={{ fontSize: 12, color: T.textMuted, marginTop: 2 }}>{entry.username || entry.email || "—"}</div>
      </div>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
        {entry.category && <span style={{ fontSize: 10, color: T.textMuted, background: T.inputBg, padding: "1px 6px", borderRadius: 4 }}>{entry.category}</span>}
        <span style={{ fontSize: 10, color: strength.color }}>● {strength.label}</span>
      </div>
    </button>
  );
}

// ─── Splash ────────────────────────────────────────────────────────────────────
function SplashScreen({ T }) {
  return (
    <div style={{ ...styles.fullCenter, background: "#0A0A0F", flexDirection: "column", gap: 20 }}>
      <div style={{ position: "relative" }}>
        <div style={{ width: 80, height: 80, borderRadius: 24, background: "linear-gradient(135deg, #00FF94, #0066FF)", display: "flex", alignItems: "center", justifyContent: "center", boxShadow: "0 0 60px #00FF9444" }}>
          <Icon name="shield" size={38} color="#000" />
        </div>
        <div style={{ position: "absolute", inset: -4, borderRadius: 28, border: "1px solid #00FF9422", animation: "pulse 2s infinite" }} />
      </div>
      <div style={{ textAlign: "center" }}>
        <div style={{ fontSize: 28, fontWeight: 900, letterSpacing: 6, color: "#fff", fontFamily: "'Courier New', monospace" }}>VAULT</div>
        <div style={{ fontSize: 11, color: "#00FF94", letterSpacing: 4, marginTop: 4 }}>SECURE · ENCRYPTED · LOCAL</div>
      </div>
      <div style={{ marginTop: 20, display: "flex", gap: 6 }}>
        {[0, 1, 2].map(i => <div key={i} style={{ width: 6, height: 6, borderRadius: "50%", background: "#00FF94", opacity: 0.4, animation: `bounce 1s ${i * 0.2}s infinite` }} />)}
      </div>
      <style>{`@keyframes bounce{0%,100%{transform:translateY(0);opacity:.4}50%{transform:translateY(-6px);opacity:1}} @keyframes pulse{0%,100%{opacity:.3;transform:scale(1)}50%{opacity:.8;transform:scale(1.05)}}`}</style>
    </div>
  );
}

// ─── Setup Screen ──────────────────────────────────────────────────────────────
function SetupScreen({ T, onSetup, bioAvailable }) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [show, setShow] = useState(false);
  const strength = getStrength(pw);
  const valid = pw.length >= 8 && pw === confirm;

  return (
    <div style={{ ...styles.fullCenter, background: T.bg, flexDirection: "column", padding: 32 }}>
      <div style={{ width: "100%", maxWidth: 380 }}>
        <div style={{ marginBottom: 32, textAlign: "center" }}>
          <div style={{ width: 56, height: 56, borderRadius: 18, background: T.accent, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 16px" }}>
            <Icon name="key" size={26} color="#000" />
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: T.text, letterSpacing: 1 }}>Create Your Vault</div>
          <div style={{ fontSize: 13, color: T.textMuted, marginTop: 6 }}>Set a master password to encrypt all your data</div>
        </div>

        <div style={{ background: T.surface, borderRadius: 16, padding: 24, border: `1px solid ${T.border}`, display: "flex", flexDirection: "column", gap: 16 }}>
          <PasswordInput label="Master Password" value={pw} onChange={setPw} show={show} setShow={setShow} T={T} placeholder="Min. 8 characters" />
          <StrengthBar strength={strength} T={T} />
          <PasswordInput label="Confirm Password" value={confirm} onChange={setConfirm} show={show} setShow={setShow} T={T} placeholder="Repeat your password" />

          {bioAvailable && (
            <div style={{ background: T.accent + "11", borderRadius: 10, padding: 12, border: `1px solid ${T.accent}33`, display: "flex", gap: 10, alignItems: "flex-start" }}>
              <Icon name="faceId" size={18} color={T.accent} />
              <div style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.6 }}>
                <strong style={{ color: T.accent }}>Biometric available!</strong> Your device supports Face ID / Touch ID. You'll be asked to register it after creating your vault.
              </div>
            </div>
          )}

          <div style={{ background: T.inputBg, borderRadius: 10, padding: 12, border: `1px solid ${T.border}` }}>
            <div style={{ fontSize: 11, color: T.textMuted, lineHeight: 1.6 }}>
              🔐 Encrypted with <strong style={{ color: T.accent }}>AES-256-GCM</strong> via <strong style={{ color: T.accent }}>PBKDF2</strong> (310,000 iterations). Never leaves your device.
            </div>
          </div>

          <button onClick={() => valid && onSetup(pw)} disabled={!valid}
            style={{ ...styles.primaryBtn, background: valid ? T.accent : T.border, color: valid ? "#000" : T.textMuted, cursor: valid ? "pointer" : "not-allowed" }}>
            Create Vault →
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Unlock Screen (with real WebAuthn) ───────────────────────────────────────
function UnlockScreen({ T, onUnlock, onBiometric, biometricAttempts, showMasterFallback, setShowMasterFallback, bioAvailable, bioRegistered }) {
  const [pw, setPw] = useState("");
  const [show, setShow] = useState(false);
  const [bioPending, setBioPending] = useState(false);

  const triggerBio = async () => {
    setBioPending(true);
    await onBiometric();
    setBioPending(false);
  };

  const canUseBio = bioAvailable && bioRegistered && !showMasterFallback;

  return (
    <div style={{ ...styles.fullCenter, background: T.bg, flexDirection: "column", padding: 32 }}>
      <div style={{ width: "100%", maxWidth: 360, textAlign: "center" }}>
        <div style={{ width: 72, height: 72, borderRadius: 22, background: "linear-gradient(135deg, #00FF94, #0066FF)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px", boxShadow: "0 0 40px #00FF9433" }}>
          <Icon name="lock" size={32} color="#000" />
        </div>
        <div style={{ fontSize: 22, fontWeight: 800, color: T.text, letterSpacing: 1 }}>Unlock Vault</div>
        <div style={{ fontSize: 13, color: T.textMuted, marginTop: 6, marginBottom: 28 }}>Authenticate to access your credentials</div>

        {/* Biometric status banner */}
        {bioAvailable && !bioRegistered && (
          <div style={{ background: "#FFA50211", border: "1px solid #FFA50244", borderRadius: 10, padding: 12, marginBottom: 16, fontSize: 12, color: "#FFA502", textAlign: "left" }}>
            <Icon name="alert" size={14} color="#FFA502" /> No biometric registered yet. Unlock with your master password, then register in Settings.
          </div>
        )}

        {!showMasterFallback ? (
          <>
            {canUseBio && (
              <button onClick={triggerBio} disabled={bioPending}
                style={{ width: "100%", padding: "16px", borderRadius: 14, background: T.surface, border: `2px solid ${T.accent}55`, color: T.text, cursor: bioPending ? "wait" : "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 10, fontSize: 15, fontWeight: 600, marginBottom: 16, transition: "all .2s" }}>
                <Icon name="faceId" size={24} color={T.accent} />
                {bioPending ? "Waiting for biometric…" : "Face ID / Touch ID"}
              </button>
            )}

            {biometricAttempts > 0 && (
              <div style={{ fontSize: 12, color: T.danger, marginBottom: 12 }}>⚠️ {biometricAttempts}/3 biometric attempts failed</div>
            )}

            <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "16px 0" }}>
              <div style={{ flex: 1, height: 1, background: T.border }} />
              <span style={{ fontSize: 12, color: T.textMuted }}>or</span>
              <div style={{ flex: 1, height: 1, background: T.border }} />
            </div>

            <div style={{ background: T.surface, borderRadius: 14, padding: 18, border: `1px solid ${T.border}`, display: "flex", flexDirection: "column", gap: 12 }}>
              <PasswordInput label="Master Password" value={pw} onChange={setPw} show={show} setShow={setShow} T={T} placeholder="Enter master password" />
              <button onClick={() => onUnlock(pw)} style={{ ...styles.primaryBtn, background: T.accent, color: "#000" }}>
                Unlock →
              </button>
            </div>
          </>
        ) : (
          <>
            <div style={{ background: T.surface, borderRadius: 14, padding: 18, border: `1px solid ${T.border}`, display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ fontSize: 13, color: T.textMuted, textAlign: "left" }}>
                {biometricAttempts >= 3 ? "⚠️ Biometric locked after 3 failures. Enter master password:" : "✅ Biometric passed! Enter your password once to link it:"}
              </div>
              <PasswordInput label="Master Password" value={pw} onChange={setPw} show={show} setShow={setShow} T={T} placeholder="Enter master password" />
              <button onClick={() => onUnlock(pw)} style={{ ...styles.primaryBtn, background: T.accent, color: "#000" }}>
                Unlock →
              </button>
            </div>
            {canUseBio && (
              <button onClick={() => setShowMasterFallback(false)} style={{ background: "none", border: "none", color: T.textMuted, fontSize: 12, cursor: "pointer", marginTop: 12 }}>
                ← Try biometric again
              </button>
            )}
          </>
        )}

        {/* WebAuthn info note */}
        <div style={{ marginTop: 24, background: T.surface, borderRadius: 10, padding: 12, border: `1px solid ${T.border}`, textAlign: "left" }}>
          <div style={{ fontSize: 11, color: T.textMuted, lineHeight: 1.7 }}>
            <strong style={{ color: T.accent }}>🔐 WebAuthn</strong> — biometrics use your device's secure enclave (Face ID, Touch ID, Windows Hello). No biometric data ever leaves your device.
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Add / Edit Screen ─────────────────────────────────────────────────────────
function AddEditScreen({ T, entry, onSave, onCancel, categories }) {
  const [form, setForm] = useState(entry || { serviceName: "", username: "", email: "", password: "", notes: "", category: "Other" });
  const [showPw, setShowPw] = useState(false);
  const [genOpts, setGenOpts] = useState({ length: 16, upper: true, lower: true, numbers: true, symbols: true });
  const [showGen, setShowGen] = useState(false);
  const strength = getStrength(form.password);
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  return (
    <div style={{ ...styles.container, background: T.bg }}>
      <div style={{ ...styles.header, background: T.surface, borderBottom: `1px solid ${T.border}` }}>
        <button onClick={onCancel} style={{ ...styles.iconBtn, color: T.textMuted }}><Icon name="x" size={20} /></button>
        <span style={{ fontWeight: 700, fontSize: 15, color: T.text }}>{entry ? "Edit Entry" : "New Credential"}</span>
        <button onClick={() => onSave(form)} style={{ ...styles.iconBtn, color: T.accent }}><Icon name="check" size={20} /></button>
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: 16, display: "flex", flexDirection: "column", gap: 14 }}>
        <FormField label="Service Name *" T={T}>
          <input value={form.serviceName} onChange={e => set("serviceName", e.target.value)} placeholder="e.g. Gmail, Netflix…" style={inputStyle(T)} />
        </FormField>
        <FormField label="Category" T={T}>
          <select value={form.category} onChange={e => set("category", e.target.value)} style={inputStyle(T)}>
            {categories.filter(c => c !== "All").map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </FormField>
        <FormField label="Username" T={T}>
          <input value={form.username} onChange={e => set("username", e.target.value)} placeholder="Your username" style={inputStyle(T)} />
        </FormField>
        <FormField label="Email" T={T}>
          <input value={form.email} onChange={e => set("email", e.target.value)} placeholder="your@email.com" type="email" style={inputStyle(T)} />
        </FormField>
        <FormField label="Password *" T={T}>
          <div style={{ position: "relative" }}>
            <input value={form.password} onChange={e => set("password", e.target.value)}
              type={showPw ? "text" : "password"} placeholder="Enter or generate password"
              style={{ ...inputStyle(T), paddingRight: 80 }} />
            <div style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", display: "flex", gap: 6 }}>
              <button onClick={() => setShowPw(s => !s)} style={{ background: "none", border: "none", cursor: "pointer", color: T.textMuted, padding: 2 }}>
                <Icon name={showPw ? "eyeOff" : "eye"} size={15} />
              </button>
              <button onClick={() => setShowGen(s => !s)} style={{ background: "none", border: "none", cursor: "pointer", color: T.accent, padding: 2 }}>
                <Icon name="zap" size={15} />
              </button>
            </div>
          </div>
          <StrengthBar strength={strength} T={T} />
        </FormField>
        {showGen && (
          <div style={{ background: T.surface, borderRadius: 12, padding: 14, border: `1px solid ${T.border}` }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: T.text, marginBottom: 10 }}>⚡ Generator</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 12, color: T.textMuted, width: 60 }}>Length: {genOpts.length}</span>
                <input type="range" min="8" max="32" value={genOpts.length} onChange={e => setGenOpts(o => ({ ...o, length: +e.target.value }))} style={{ flex: 1, accentColor: T.accent }} />
              </div>
              {[["upper", "A-Z"], ["lower", "a-z"], ["numbers", "0-9"], ["symbols", "!@#"]].map(([k, label]) => (
                <label key={k} style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                  <input type="checkbox" checked={genOpts[k]} onChange={e => setGenOpts(o => ({ ...o, [k]: e.target.checked }))} />
                  <span style={{ fontSize: 12, color: T.textMuted }}>{label}</span>
                </label>
              ))}
              <button onClick={() => set("password", generatePassword(genOpts))}
                style={{ ...styles.primaryBtn, background: T.accent, color: "#000", padding: "8px 16px", fontSize: 13 }}>
                Generate
              </button>
            </div>
          </div>
        )}
        <FormField label="Notes (optional)" T={T}>
          <textarea value={form.notes} onChange={e => set("notes", e.target.value)} placeholder="Any additional notes…" rows={3} style={{ ...inputStyle(T), resize: "vertical", minHeight: 70 }} />
        </FormField>
        <div style={{ background: T.surface, borderRadius: 10, padding: 10, border: `1px solid ${T.border}` }}>
          <div style={{ fontSize: 11, color: T.textMuted }}>🔒 All fields encrypted with AES-256-GCM before storage</div>
        </div>
      </div>
    </div>
  );
}

// ─── Detail Screen ─────────────────────────────────────────────────────────────
function DetailScreen({ T, entry, onEdit, onDelete, onCopy, clipCount, onBack }) {
  const [revealed, setRevealed] = useState({});
  const strength = getStrength(entry?.password);
  if (!entry) return null;
  const initials = (entry.serviceName || "?").slice(0, 2).toUpperCase();

  return (
    <div style={{ ...styles.container, background: T.bg }}>
      <div style={{ ...styles.header, background: T.surface, borderBottom: `1px solid ${T.border}` }}>
        <button onClick={onBack} style={{ ...styles.iconBtn, color: T.textMuted }}><Icon name="x" size={20} /></button>
        <span style={{ fontWeight: 700, fontSize: 15, color: T.text }}>Credential Details</span>
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={onEdit} style={{ ...styles.iconBtn, color: T.accent }}><Icon name="edit" size={18} /></button>
          <button onClick={() => { if (confirm("Delete this entry?")) onDelete(); }} style={{ ...styles.iconBtn, color: T.danger }}><Icon name="trash" size={18} /></button>
        </div>
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: 16, display: "flex", flexDirection: "column", gap: 12 }}>
        <div style={{ background: T.surface, borderRadius: 16, padding: 20, border: `1px solid ${T.border}`, display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ width: 52, height: 52, borderRadius: 16, background: T.accent + "22", display: "flex", alignItems: "center", justifyContent: "center", border: `2px solid ${T.accent}44` }}>
            <span style={{ color: T.accent, fontWeight: 800, fontSize: 18 }}>{initials}</span>
          </div>
          <div>
            <div style={{ fontSize: 18, fontWeight: 800, color: T.text }}>{entry.serviceName}</div>
            {entry.category && <span style={{ fontSize: 11, color: T.textMuted, background: T.inputBg, padding: "2px 8px", borderRadius: 6 }}>{entry.category}</span>}
          </div>
        </div>
        {[
          { key: "username", label: "Username", sensitive: false },
          { key: "email", label: "Email", sensitive: false },
          { key: "password", label: "Password", sensitive: true },
          { key: "notes", label: "Notes", sensitive: false },
        ].filter(f => entry[f.key]).map(({ key, label, sensitive }) => (
          <div key={key} style={{ background: T.surface, borderRadius: 12, padding: 14, border: `1px solid ${T.border}` }}>
            <div style={{ fontSize: 11, color: T.textMuted, marginBottom: 6, fontWeight: 600, textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ flex: 1, fontSize: 14, color: T.text, wordBreak: "break-all", fontFamily: sensitive ? "monospace" : "inherit" }}>
                {sensitive && !revealed[key] ? "••••••••••••" : entry[key]}
              </span>
              <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                {sensitive && (
                  <button onClick={() => setRevealed(r => ({ ...r, [key]: !r[key] }))} style={{ ...styles.iconBtn, color: T.textMuted }}>
                    <Icon name={revealed[key] ? "eyeOff" : "eye"} size={16} />
                  </button>
                )}
                <button onClick={() => onCopy(entry[key], label)} style={{ ...styles.iconBtn, color: T.accent }}>
                  <Icon name="copy" size={16} />
                </button>
              </div>
            </div>
            {key === "password" && (
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 8 }}>
                <div style={{ flex: 1, height: 3, background: T.border, borderRadius: 2, overflow: "hidden" }}>
                  <div style={{ width: `${(strength.score / 6) * 100}%`, height: "100%", background: strength.color, borderRadius: 2 }} />
                </div>
                <span style={{ fontSize: 10, color: strength.color }}>{strength.label}</span>
              </div>
            )}
          </div>
        ))}
        {entry.updatedAt && <div style={{ fontSize: 11, color: T.textMuted, textAlign: "center" }}>Last updated: {new Date(entry.updatedAt).toLocaleString()}</div>}
      </div>
    </div>
  );
}

// ─── Generator Screen ──────────────────────────────────────────────────────────
function GeneratorScreen({ T, onBack, onUse }) {
  const [opts, setOpts] = useState({ length: 16, upper: true, lower: true, numbers: true, symbols: true });
  const [pw, setPw] = useState(() => generatePassword({ length: 16, upper: true, lower: true, numbers: true, symbols: true }));
  const strength = getStrength(pw);
  const regen = () => setPw(generatePassword(opts));

  return (
    <div style={{ ...styles.container, background: T.bg }}>
      <div style={{ ...styles.header, background: T.surface, borderBottom: `1px solid ${T.border}` }}>
        <button onClick={onBack} style={{ ...styles.iconBtn, color: T.textMuted }}><Icon name="x" size={20} /></button>
        <span style={{ fontWeight: 700, fontSize: 15, color: T.text }}>Password Generator</span>
        <div style={{ width: 32 }} />
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: 16, display: "flex", flexDirection: "column", gap: 14 }}>
        <div style={{ background: T.surface, borderRadius: 16, padding: 20, border: `2px solid ${T.accent}44` }}>
          <div style={{ fontSize: 11, color: T.textMuted, marginBottom: 10, textTransform: "uppercase", letterSpacing: 1 }}>Generated Password</div>
          <div style={{ fontSize: 18, fontFamily: "monospace", color: T.text, wordBreak: "break-all", letterSpacing: 2, lineHeight: 1.6 }}>{pw}</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 12 }}>
            <div style={{ flex: 1, height: 4, background: T.border, borderRadius: 2, overflow: "hidden" }}>
              <div style={{ width: `${(strength.score / 6) * 100}%`, height: "100%", background: strength.color, transition: "all .3s" }} />
            </div>
            <span style={{ fontSize: 11, color: strength.color, fontWeight: 700 }}>{strength.label}</span>
          </div>
        </div>
        <div style={{ background: T.surface, borderRadius: 16, padding: 18, border: `1px solid ${T.border}`, display: "flex", flexDirection: "column", gap: 14 }}>
          <div style={{ fontWeight: 700, color: T.text, fontSize: 14 }}>Options</div>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <span style={{ fontSize: 13, color: T.textMuted }}>Length</span>
              <span style={{ fontSize: 13, color: T.accent, fontWeight: 700 }}>{opts.length}</span>
            </div>
            <input type="range" min="8" max="32" value={opts.length} onChange={e => setOpts(o => ({ ...o, length: +e.target.value }))} style={{ width: "100%", accentColor: T.accent }} />
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ fontSize: 10, color: T.textMuted }}>8</span><span style={{ fontSize: 10, color: T.textMuted }}>32</span>
            </div>
          </div>
          {[["upper", "Uppercase (A-Z)"], ["lower", "Lowercase (a-z)"], ["numbers", "Numbers (0-9)"], ["symbols", "Symbols (!@#$)"]].map(([k, label]) => (
            <label key={k} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer" }}>
              <span style={{ fontSize: 13, color: T.text }}>{label}</span>
              <input type="checkbox" checked={opts[k]} onChange={e => setOpts(o => ({ ...o, [k]: e.target.checked }))} style={{ width: 16, height: 16, accentColor: T.accent }} />
            </label>
          ))}
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={regen} style={{ flex: 1, ...styles.primaryBtn, background: T.surface, color: T.text, border: `1px solid ${T.border}` }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}><Icon name="refresh" size={15} /> Regenerate</div>
          </button>
          <button onClick={() => onUse(pw)} style={{ flex: 1, ...styles.primaryBtn, background: T.accent, color: "#000" }}>Copy & Use</button>
        </div>
      </div>
    </div>
  );
}

// ─── Health Screen ─────────────────────────────────────────────────────────────
function HealthScreen({ T, data, onBack, onSelect }) {
  const score = Math.max(0, 100 - data.weak.length * 20 - data.dupeEntries.length * 10 - data.moderate.length * 5);
  const color = score >= 80 ? "#2ED573" : score >= 60 ? "#FFA502" : "#FF4757";
  return (
    <div style={{ ...styles.container, background: T.bg }}>
      <div style={{ ...styles.header, background: T.surface, borderBottom: `1px solid ${T.border}` }}>
        <button onClick={onBack} style={{ ...styles.iconBtn, color: T.textMuted }}><Icon name="x" size={20} /></button>
        <span style={{ fontWeight: 700, fontSize: 15, color: T.text }}>Vault Health</span>
        <div style={{ width: 32 }} />
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: 16, display: "flex", flexDirection: "column", gap: 14 }}>
        <div style={{ background: T.surface, borderRadius: 16, padding: 24, border: `1px solid ${T.border}`, textAlign: "center" }}>
          <div style={{ fontSize: 64, fontWeight: 900, color, fontFamily: "'Courier New', monospace" }}>{score}</div>
          <div style={{ fontSize: 13, color: T.textMuted }}>Vault Health Score</div>
          <div style={{ height: 6, background: T.border, borderRadius: 3, marginTop: 12, overflow: "hidden" }}>
            <div style={{ width: `${score}%`, height: "100%", background: color, borderRadius: 3, transition: "all .5s" }} />
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
          {[["Total", data.total, T.accent], ["Weak", data.weak.length, "#FF4757"], ["Dupes", data.dupeEntries.length, "#FFA502"]].map(([label, val, c]) => (
            <div key={label} style={{ background: T.surface, borderRadius: 12, padding: 14, border: `1px solid ${T.border}`, textAlign: "center" }}>
              <div style={{ fontSize: 26, fontWeight: 800, color: c }}>{val}</div>
              <div style={{ fontSize: 11, color: T.textMuted }}>{label}</div>
            </div>
          ))}
        </div>
        {data.weak.length > 0 && <IssueSection title="⚠️ Weak Passwords" entries={data.weak} T={T} onSelect={onSelect} color="#FF4757" />}
        {data.dupeEntries.length > 0 && <IssueSection title="🔁 Duplicate Passwords" entries={data.dupeEntries} T={T} onSelect={onSelect} color="#FFA502" />}
        {data.weak.length === 0 && data.dupeEntries.length === 0 && (
          <div style={{ textAlign: "center", padding: 30, color: "#2ED573" }}>
            <div style={{ fontSize: 40 }}>✅</div>
            <div style={{ marginTop: 10, fontWeight: 600 }}>All passwords look great!</div>
          </div>
        )}
      </div>
    </div>
  );
}

function IssueSection({ title, entries, T, onSelect, color }) {
  return (
    <div style={{ background: T.surface, borderRadius: 14, border: `1px solid ${color}44`, overflow: "hidden" }}>
      <div style={{ padding: "12px 16px", borderBottom: `1px solid ${T.border}`, fontWeight: 700, fontSize: 13, color }}>{title}</div>
      {entries.map(e => (
        <button key={e.id} onClick={() => onSelect(e)} style={{ width: "100%", padding: "12px 16px", background: "none", border: "none", borderBottom: `1px solid ${T.border}`, cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 13, color: T.text }}>{e.serviceName}</span>
          <span style={{ fontSize: 11, color }}>Fix →</span>
        </button>
      ))}
    </div>
  );
}

// ─── Export Screen ─────────────────────────────────────────────────────────────
function ExportScreen({ T, onExport, onBack }) {
  const [pw, setPw] = useState("");
  const [show, setShow] = useState(false);
  return (
    <div style={{ ...styles.container, background: T.bg }}>
      <div style={{ ...styles.header, background: T.surface, borderBottom: `1px solid ${T.border}` }}>
        <button onClick={onBack} style={{ ...styles.iconBtn, color: T.textMuted }}><Icon name="x" size={20} /></button>
        <span style={{ fontWeight: 700, fontSize: 15, color: T.text }}>Export Backup</span>
        <div style={{ width: 32 }} />
      </div>
      <div style={{ flex: 1, padding: 16, display: "flex", flexDirection: "column", gap: 14 }}>
        <div style={{ background: "#FFA50211", borderRadius: 14, padding: 16, border: "1px solid #FFA50244" }}>
          <div style={{ fontSize: 13, color: "#FFA502", fontWeight: 600, marginBottom: 6 }}>⚠️ Security Notice</div>
          <div style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.6 }}>Your backup is encrypted with AES-256-GCM using the password you set below. Keep this file and password safe.</div>
        </div>
        <div style={{ background: T.surface, borderRadius: 14, padding: 16, border: `1px solid ${T.border}`, display: "flex", flexDirection: "column", gap: 12 }}>
          <PasswordInput label="Export Password" value={pw} onChange={setPw} show={show} setShow={setShow} T={T} placeholder="Password for the backup file" />
          <button onClick={() => pw.length >= 6 ? onExport(pw) : alert("Min 6 characters")}
            style={{ ...styles.primaryBtn, background: T.accent, color: "#000" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}><Icon name="download" size={16} /> Export Encrypted Backup</div>
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Settings Screen ───────────────────────────────────────────────────────────
function SettingsScreen({ T, autoLockSetting, setAutoLockSetting, theme, setTheme, onBack, onLock, onExport, entryCount, bioAvailable, bioRegistered, onRegisterBio }) {
  return (
    <div style={{ ...styles.container, background: T.bg }}>
      <div style={{ ...styles.header, background: T.surface, borderBottom: `1px solid ${T.border}` }}>
        <button onClick={onBack} style={{ ...styles.iconBtn, color: T.textMuted }}><Icon name="x" size={20} /></button>
        <span style={{ fontWeight: 700, fontSize: 15, color: T.text }}>Settings</span>
        <div style={{ width: 32 }} />
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: 16, display: "flex", flexDirection: "column", gap: 14 }}>

        {/* Biometric section */}
        <div style={{ background: T.surface, borderRadius: 14, border: `1px solid ${T.border}` }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${T.border}` }}>
            <div style={{ fontSize: 11, color: T.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: 1 }}>Biometric (WebAuthn)</div>
          </div>
          <div style={{ padding: "12px 16px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 13, color: T.text }}>Device Support</span>
            <span style={{ fontSize: 12, color: bioAvailable ? "#2ED573" : T.danger }}>{bioAvailable === null ? "Checking…" : bioAvailable ? "✓ Available" : "✗ Not available"}</span>
          </div>
          <div style={{ padding: "12px 16px", borderTop: `1px solid ${T.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 13, color: T.text }}>Registered</span>
            <span style={{ fontSize: 12, color: bioRegistered ? "#2ED573" : T.textMuted }}>{bioRegistered ? "✓ Yes" : "✗ No"}</span>
          </div>
          {bioAvailable && (
            <div style={{ padding: "12px 16px", borderTop: `1px solid ${T.border}` }}>
              <button onClick={onRegisterBio}
                style={{ width: "100%", padding: "10px", borderRadius: 10, background: T.accent + "22", border: `1px solid ${T.accent}44`, color: T.accent, cursor: "pointer", fontSize: 13, fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
                <Icon name="faceId" size={16} color={T.accent} />
                {bioRegistered ? "Re-register Biometric" : "Register Face ID / Touch ID"}
              </button>
            </div>
          )}
        </div>

        {/* Vault info */}
        <div style={{ background: T.surface, borderRadius: 14, border: `1px solid ${T.border}` }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${T.border}` }}>
            <div style={{ fontSize: 11, color: T.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: 1 }}>Vault</div>
          </div>
          <div style={{ padding: "12px 16px", display: "flex", justifyContent: "space-between" }}>
            <span style={{ fontSize: 13, color: T.text }}>Total Credentials</span>
            <span style={{ fontSize: 13, color: T.accent, fontWeight: 700 }}>{entryCount}</span>
          </div>
          <div style={{ padding: "12px 16px", borderTop: `1px solid ${T.border}`, display: "flex", justifyContent: "space-between" }}>
            <span style={{ fontSize: 13, color: T.text }}>Encryption</span>
            <span style={{ fontSize: 13, color: "#2ED573" }}>AES-256-GCM ✓</span>
          </div>
        </div>

        {/* Auto-lock */}
        <div style={{ background: T.surface, borderRadius: 14, border: `1px solid ${T.border}` }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${T.border}` }}>
            <div style={{ fontSize: 11, color: T.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: 1 }}>Auto-Lock</div>
          </div>
          {[["immediate", "Immediately"], ["1min", "After 1 minute"], ["5min", "After 5 minutes"], ["never", "Never"]].map(([val, label], i) => (
            <button key={val} onClick={() => setAutoLockSetting(val)}
              style={{ width: "100%", padding: "13px 16px", background: "none", border: "none", borderTop: i > 0 ? `1px solid ${T.border}` : "none", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: 13, color: T.text }}>{label}</span>
              {autoLockSetting === val && <Icon name="check" size={16} color={T.accent} />}
            </button>
          ))}
        </div>

        {/* Theme */}
        <div style={{ background: T.surface, borderRadius: 14, border: `1px solid ${T.border}` }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${T.border}` }}>
            <div style={{ fontSize: 11, color: T.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: 1 }}>Appearance</div>
          </div>
          {[["dark", "Dark Mode"], ["light", "Light Mode"]].map(([val, label], i) => (
            <button key={val} onClick={() => setTheme(val)}
              style={{ width: "100%", padding: "13px 16px", background: "none", border: "none", borderTop: i > 0 ? `1px solid ${T.border}` : "none", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: 13, color: T.text }}>{label}</span>
              {theme === val && <Icon name="check" size={16} color={T.accent} />}
            </button>
          ))}
        </div>

        <div style={{ background: T.surface, borderRadius: 14, border: `1px solid ${T.border}` }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${T.border}` }}>
            <div style={{ fontSize: 11, color: T.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: 1 }}>Data</div>
          </div>
          <button onClick={onExport} style={{ width: "100%", padding: "13px 16px", background: "none", border: "none", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 13, color: T.text }}>Export Encrypted Backup</span>
            <Icon name="download" size={16} color={T.textMuted} />
          </button>
        </div>

        <button onClick={onLock} style={{ ...styles.primaryBtn, background: T.danger + "22", color: T.danger, border: `1px solid ${T.danger}44` }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}><Icon name="lock" size={16} /> Lock Vault</div>
        </button>

        <div style={{ padding: "12px 0", textAlign: "center" }}>
          <div style={{ fontSize: 11, color: T.textMuted }}>Password Vault v2.0 — WebAuthn Edition</div>
          <div style={{ fontSize: 10, color: T.textMuted, marginTop: 4 }}>WebCrypto AES-256-GCM · PBKDF2 · WebAuthn · Local Only</div>
        </div>
      </div>
    </div>
  );
}

// ─── Shared Components ─────────────────────────────────────────────────────────
function PasswordInput({ label, value, onChange, show, setShow, T, placeholder }) {
  return (
    <div>
      <div style={{ fontSize: 12, color: T.textMuted, marginBottom: 6, fontWeight: 600 }}>{label}</div>
      <div style={{ position: "relative" }}>
        <input value={value} onChange={e => onChange(e.target.value)} type={show ? "text" : "password"}
          placeholder={placeholder} style={{ ...inputStyle(T), paddingRight: 40 }} />
        <button onClick={() => setShow(s => !s)} style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", color: T.textMuted }}>
          <Icon name={show ? "eyeOff" : "eye"} size={16} />
        </button>
      </div>
    </div>
  );
}

function StrengthBar({ strength, T }) {
  if (!strength.label) return null;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}>
      <div style={{ flex: 1, height: 3, background: T.border, borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${(strength.score / 6) * 100}%`, height: "100%", background: strength.color, transition: "all .3s" }} />
      </div>
      <span style={{ fontSize: 11, color: strength.color, fontWeight: 600, minWidth: 50 }}>{strength.label}</span>
    </div>
  );
}

function FormField({ label, T, children }) {
  return (
    <div>
      <div style={{ fontSize: 12, color: T.textMuted, marginBottom: 6, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</div>
      {children}
    </div>
  );
}

function Toast({ msg, type, T }) {
  const bg = type === "success" ? "#2ED57322" : type === "error" ? "#FF475722" : T.surface;
  const border = type === "success" ? "#2ED573" : type === "error" ? "#FF4757" : T.border;
  return (
    <div style={{ position: "absolute", bottom: 80, left: 16, right: 16, background: bg, border: `1px solid ${border}`, borderRadius: 12, padding: "12px 16px", fontSize: 13, color: T.text, zIndex: 100, backdropFilter: "blur(10px)", animation: "slideUp .2s ease" }}>
      {msg}
      <style>{`@keyframes slideUp{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}`}</style>
    </div>
  );
}

// ─── Themes ───────────────────────────────────────────────────────────────────
const DARK  = { bg: "#0A0A0F", surface: "#12121A", border: "#1E1E2E", text: "#E8E8F0", textMuted: "#5A5A7A", accent: "#00FF94", danger: "#FF4757", inputBg: "#0E0E18" };
const LIGHT = { bg: "#F5F5F8", surface: "#FFFFFF",  border: "#E0E0E8", text: "#1A1A2E", textMuted: "#8888A8", accent: "#0066FF", danger: "#FF4757", inputBg: "#F0F0F5" };

// ─── Styles ───────────────────────────────────────────────────────────────────
const inputStyle = T => ({
  width: "100%", padding: "11px 14px", borderRadius: 10, background: T.inputBg,
  border: `1px solid ${T.border}`, color: T.text, fontSize: 14, outline: "none",
  boxSizing: "border-box", fontFamily: "inherit",
});

const styles = {
  container:  { display: "flex", flexDirection: "column", height: "100vh", position: "relative", overflow: "hidden" },
  fullCenter: { display: "flex", alignItems: "center", justifyContent: "center", height: "100vh" },
  header:     { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", minHeight: 56, flexShrink: 0 },
  headerLeft: { display: "flex", alignItems: "center", gap: 8 },
  headerRight:{ display: "flex", alignItems: "center", gap: 4 },
  logoMark:   { width: 30, height: 30, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" },
  iconBtn:    { background: "none", border: "none", cursor: "pointer", padding: 6, display: "flex", alignItems: "center", justifyContent: "center", borderRadius: 8 },
  searchBox:  { display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", borderRadius: 10 },
  searchInput:{ flex: 1, border: "none", outline: "none", fontSize: 14, fontFamily: "inherit" },
  catChip:    { padding: "4px 10px", borderRadius: 20, fontSize: 11, cursor: "pointer", whiteSpace: "nowrap", fontWeight: 600 },
  entryCard:  { width: "100%", display: "flex", alignItems: "center", gap: 12, padding: "12px 16px", cursor: "pointer", border: "none" },
  avatar:     { width: 44, height: 44, borderRadius: 13, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 },
  fab:        { position: "absolute", bottom: 28, right: 20, width: 54, height: 54, borderRadius: 16, border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", boxShadow: "0 4px 20px rgba(0,255,148,0.3)" },
  primaryBtn: { width: "100%", padding: "14px", borderRadius: 12, border: "none", fontSize: 14, fontWeight: 700, cursor: "pointer", fontFamily: "inherit" },
  clipBar:    { display: "flex", alignItems: "center", gap: 8, padding: "8px 16px", flexShrink: 0 },
};
