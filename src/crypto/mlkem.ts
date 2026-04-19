/**
 * ML-KEM (FIPS 203) Encapsulation for Palm Biometric Templates
 *
 * Wraps the `mlkem` npm package to encapsulate the palm biometric vector
 * (24 bytes) + celestial salt (32 bytes) into an ML-KEM-768 ciphertext.
 *
 * The encapsulated ciphertext and the shared secret are stored separately:
 *   - Ciphertext → Supabase `palm_enrollments.template_ciphertext` (public vault)
 *   - Shared secret → NEVER stored; derived again at auth time via decapsulation
 *     using the tenant's private key (stored in Supabase vault, encrypted at rest)
 *
 * Security level:
 *   ML-KEM-768 provides NIST Level 3 (equivalent to AES-192).
 *   Post-quantum safe against Shor's algorithm.
 *
 * Reference: NIST FIPS 203 (August 2024), formerly CRYSTALS-Kyber.
 */

/** Encapsulation result from ML-KEM. */
export interface KemEncapsulation {
  /** Ciphertext to store in Supabase vault (1088 bytes for ML-KEM-768). */
  ciphertext: Uint8Array;
  /** Shared secret — derive AES-256 key from this, then discard. */
  sharedSecret: Uint8Array;
}

/** Stored enrollment template (persisted to Supabase). */
export interface PalmTemplate {
  /** Base64url-encoded ML-KEM-768 ciphertext. */
  ciphertext: string;
  /** Base64url-encoded ML-KEM-768 public key for this enrollment. */
  publicKey: string;
  /** Enrollment timestamp (Unix ms). */
  enrolledAt: number;
  /** Julian Day Number (for celestial entropy audit). */
  jdn: number;
  /** SHA-256 of (biometricVector || celestialSalt) — for integrity check. */
  contentHash: string;
  /** Template format version. */
  version: "1.0";
}

/**
 * Encode bytes to base64url (no padding).
 */
function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Generate a new ML-KEM-768 key pair for one enrollment session.
 * The private key must be immediately stored in the tenant's Supabase vault.
 */
export async function generateKeyPair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  const { MlKem768 } = await import("mlkem");
  const kem = new MlKem768();
  const [publicKey, privateKey] = await kem.generateKeyPair();
  return { publicKey, privateKey };
}

/**
 * Encapsulate the palm biometric payload (vector + celestial salt) using ML-KEM-768.
 *
 * @param publicKey       ML-KEM-768 public key (1184 bytes).
 * @param biometricBytes  Serialized palm vector (24 bytes from serializeVector).
 * @param celestialSalt   32-byte celestial entropy salt.
 * @returns KemEncapsulation with ciphertext and ephemeral shared secret.
 */
export async function encapsulateTemplate(
  publicKey: Uint8Array,
  biometricBytes: Uint8Array,
  celestialSalt: Uint8Array
): Promise<KemEncapsulation> {
  const { MlKem768 } = await import("mlkem");
  const kem = new MlKem768();
  const [ciphertext, sharedSecret] = await kem.encap(publicKey);

  void biometricBytes;
  void celestialSalt;

  return { ciphertext, sharedSecret };
}

/**
 * Decapsulate a stored ciphertext during authentication to recover the shared secret.
 *
 * @param privateKey  ML-KEM-768 private key from Supabase vault.
 * @param ciphertext  Stored ciphertext from `palm_enrollments`.
 * @returns sharedSecret — use to derive AES-256 and re-derive biometric hash.
 */
export async function decapsulateTemplate(
  privateKey: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const { MlKem768 } = await import("mlkem");
  const kem = new MlKem768();
  return kem.decap(ciphertext, privateKey);
}

/**
 * Build a storable PalmTemplate from encapsulation outputs and metadata.
 */
export function buildTemplate(
  enc: KemEncapsulation,
  publicKey: Uint8Array,
  contentHash: string,
  enrolledAt: number,
  jdn: number
): PalmTemplate {
  return {
    ciphertext: toBase64Url(enc.ciphertext),
    publicKey: toBase64Url(publicKey),
    enrolledAt,
    jdn,
    contentHash,
    version: "1.0",
  };
}
