const STORAGE_KEY = 'aidefender_client_id'

// Random anonymous ID: survives refreshes and is shared across same-origin tabs.
// This is a fairness hint, not a login credential or device fingerprint.
export function getClientId(storage, cryptoProvider) {
  try {
    const saved = storage?.getItem(STORAGE_KEY)
    if (/^[0-9a-f]{32}$/.test(saved || '')) return saved
  } catch { /* Storage can be disabled by browser policy. */ }
  const bytes = new Uint8Array(16)
  cryptoProvider.getRandomValues(bytes)
  const id = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('')
  try { storage?.setItem(STORAGE_KEY, id) } catch { /* Keep ID in page memory. */ }
  return id
}
