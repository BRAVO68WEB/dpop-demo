import type { DpopKey, EcPublicJwk } from './dpop'
import type { TokenResponse } from './types'

const DB_NAME = 'dpop-demo'
const STORE = 'keys'
const KEY_ID = 'current'
const TX_KEY = 'dpop-demo.transaction'
const TOKEN_KEY = 'dpop-demo.tokens'

export type Transaction = {
  state: string
  nonce: string
  codeVerifier: string
  jkt: string
  redirectUri: string
}

type StoredRecord = {
  publicJwk: EcPublicJwk
  jkt: string
  privateKey: CryptoKey
  publicKey: CryptoKey
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1)
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE)
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('IndexedDB failed to open.'))
  })
}

async function idb<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb()
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode)
      const request = run(tx.objectStore(STORE))
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed.'))
    })
  } finally {
    db.close()
  }
}

export async function saveKey(key: DpopKey): Promise<void> {
  const record: StoredRecord = {
    publicJwk: key.publicJwk,
    jkt: key.jkt,
    privateKey: key.privateKey,
    publicKey: key.publicKey,
  }
  await idb('readwrite', (store) => store.put(record, KEY_ID))
}

export async function loadKey(): Promise<DpopKey | null> {
  const record = await idb<StoredRecord | undefined>('readonly', (store) => store.get(KEY_ID))
  if (!record) return null
  return record
}

export async function clearKey(): Promise<void> {
  await idb('readwrite', (store) => store.delete(KEY_ID))
}

export function saveTransaction(transaction: Transaction): void {
  sessionStorage.setItem(TX_KEY, JSON.stringify(transaction))
}

export function loadTransaction(): Transaction | null {
  const raw = sessionStorage.getItem(TX_KEY)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as Transaction
    if (!parsed.state || !parsed.nonce || !parsed.codeVerifier || !parsed.jkt || !parsed.redirectUri) return null
    return parsed
  } catch {
    return null
  }
}

export function clearTransaction(): void {
  sessionStorage.removeItem(TX_KEY)
}

export function saveTokens(tokens: TokenResponse): void {
  sessionStorage.setItem(TOKEN_KEY, JSON.stringify(tokens))
}

export function loadTokens(): TokenResponse | null {
  const raw = sessionStorage.getItem(TOKEN_KEY)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as TokenResponse
    if (!parsed.access_token || !parsed.token_type) return null
    return parsed
  } catch {
    return null
  }
}

export async function clearSession(): Promise<void> {
  clearTransaction()
  sessionStorage.removeItem(TOKEN_KEY)
  await clearKey()
}
