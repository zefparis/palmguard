/**
 * PalmGuard Vault — AES-256-GCM Private Key Encryption
 *
 * Encrypts the ML-KEM-768 private key before persisting to Supabase so that
 * plaintext private key material NEVER touches disk or network in any form.
 *
 * Key Derivation:
 *   KEK = HKDF-SHA-256(
 *           ikm  = HCS_TOKEN_SECRET (server-side secret),
 *           salt = userId (UTF-8 bytes),
 *           info = "palmguard-kek" (UTF-8 bytes),
 *           len  = 256 bits
 *         )
 *
 * Encryption:
 *   encryptedKey = AES-256-GCM(KEK, iv=random 12 bytes, plaintext=privateKey)
 *
 * Storage layout in palm_enrollments:
 *   kem_privkey_enc  BYTEA  — ciphertext (privateKey.length + 16 bytes GCM tag)
 *   kek_iv           BYTEA  — 12-byte IV
 *
 * Security properties:
 *   - Different KEK per user (salt = userId in HKDF)
 *   - Different IV per enrollment (random 12 bytes)
 *   - Private key never leaves server in plaintext
 *   - Compromise of DB alone does NOT expose private keys (KEK not in DB)
 *   - Compromise of HCS_TOKEN_SECRET + DB together exposes keys (acceptable)
 *
 * Runtime: Node.js 20+ (WebCrypto globalThis.crypto.subtle) or browser.
 */

import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EncryptedVaultEntry {
  /** AES-256-GCM ciphertext of the ML-KEM private key (bytes). */
  encryptedKey: Uint8Array;
  /** 12-byte AES-GCM initialisation vector (unique per enrollment). */
  iv: Uint8Array;
}

// ─── Key Derivation ───────────────────────────────────────────────────────────

const KEK_INFO = new TextEncoder().encode("palmguard-kek");

/**
 * Derive the Key Encryption Key (KEK) for a given user.
 *
 * @param hcsTokenSecret  Raw server secret (from HCS_TOKEN_SECRET env var).
 *                        Minimum 32 chars recommended.
 * @param userId          User identifier — used as HKDF salt to make the KEK
 *                        unique per user. Not secret.
 */
export async function deriveKEK(
  hcsTokenSecret: string,
  userId: string
): Promise<CryptoKey> {
  const ikmBytes = new TextEncoder().encode(hcsTokenSecret);
  const saltBytes = new TextEncoder().encode(userId);

  const ikm = await subtle.importKey("raw", ikmBytes, "HKDF", false, ["deriveKey"]);

  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBytes,
      info: KEK_INFO,
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable
    ["encrypt", "decrypt"]
  );
}

// ─── Encrypt ──────────────────────────────────────────────────────────────────

/**
 * Encrypt the ML-KEM private key with the derived KEK.
 * The IV is generated fresh using a CSPRNG.
 *
 * @param kek         Non-extractable AES-256-GCM CryptoKey (from deriveKEK).
 * @param privateKey  Raw ML-KEM-768 private key bytes (2400 bytes).
 * @returns EncryptedVaultEntry with ciphertext + IV, ready for Supabase storage.
 */
export async function encryptPrivateKey(
  kek: CryptoKey,
  privateKey: Uint8Array
): Promise<EncryptedVaultEntry> {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const encrypted = await subtle.encrypt({ name: "AES-GCM", iv }, kek, privateKey);
  return { encryptedKey: new Uint8Array(encrypted), iv };
}

// ─── Decrypt ──────────────────────────────────────────────────────────────────

/**
 * Decrypt the stored ML-KEM private key for authentication.
 * Called server-side during verify: re-derive KEK from session token + userId,
 * then decrypt the stored ciphertext.
 *
 * @param kek          AES-256-GCM CryptoKey (re-derived from same secret + userId).
 * @param encryptedKey Ciphertext from Supabase `kem_privkey_enc`.
 * @param iv           12-byte IV from Supabase `kek_iv`.
 * @returns Raw ML-KEM-768 private key bytes.
 * @throws DOMException if KEK is wrong or ciphertext is tampered (GCM auth fail).
 */
export async function decryptPrivateKey(
  kek: CryptoKey,
  encryptedKey: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  const decrypted = await subtle.decrypt({ name: "AES-GCM", iv }, kek, encryptedKey);
  return new Uint8Array(decrypted);
}

// ─── Serialization helpers ────────────────────────────────────────────────────

/**
 * Encode an EncryptedVaultEntry as a single Uint8Array for compact storage.
 *
 * Wire format: [12 bytes IV] [N bytes ciphertext]
 * Total: N + 12 bytes (for ML-KEM-768 privkey: 2400 + 16 GCM tag + 12 = 2428 bytes)
 */
export function serializeVaultEntry(entry: EncryptedVaultEntry): Uint8Array {
  const out = new Uint8Array(12 + entry.encryptedKey.byteLength);
  out.set(entry.iv, 0);
  out.set(entry.encryptedKey, 12);
  return out;
}

/**
 * Deserialize a compact vault blob back into { encryptedKey, iv }.
 * Inverse of serializeVaultEntry.
 */
export function deserializeVaultEntry(blob: Uint8Array): EncryptedVaultEntry {
  if (blob.byteLength < 13) {
    throw new RangeError(`Vault blob too short: ${blob.byteLength} bytes`);
  }
  return {
    iv: blob.slice(0, 12),
    encryptedKey: blob.slice(12),
  };
}
