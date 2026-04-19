/**
 * Vault unit tests — AES-256-GCM private key encryption
 */

import { describe, it, expect } from "vitest";
import {
  deriveKEK,
  encryptPrivateKey,
  decryptPrivateKey,
  serializeVaultEntry,
  deserializeVaultEntry,
  type EncryptedVaultEntry,
} from "../../src/crypto/vault.js";

const SECRET = "hcs-test-secret-32-bytes-minimum!";
const USER_A = "user-alice-001";
const USER_B = "user-bob-002";

// ML-KEM-768 private key is 2400 bytes; simulate with random bytes
function mockPrivateKey(size = 2400): Uint8Array {
  const buf = new Uint8Array(size);
  for (let i = 0; i < size; i++) buf[i] = (i * 7 + 13) % 256;
  return buf;
}

describe("deriveKEK", () => {
  it("returns a CryptoKey", async () => {
    const kek = await deriveKEK(SECRET, USER_A);
    expect(kek).toBeDefined();
    expect(kek.type).toBe("secret");
    expect(kek.algorithm.name).toBe("AES-GCM");
  });

  it("is deterministic for the same inputs", async () => {
    const kek1 = await deriveKEK(SECRET, USER_A);
    const kek2 = await deriveKEK(SECRET, USER_A);
    // Encrypt same plaintext with both keys — results should be identical
    // (same key → same ciphertext only if we reuse the IV, which we can't
    //  since keys are non-extractable; test via roundtrip instead)
    const privKey = mockPrivateKey(64);
    const iv = new Uint8Array(12).fill(1);
    const { webcrypto } = await import("node:crypto");
    const enc1 = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, kek1, privKey);
    const enc2 = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, kek2, privKey);
    expect(Buffer.from(enc1).toString("hex")).toBe(Buffer.from(enc2).toString("hex"));
  });

  it("produces different KEKs for different users", async () => {
    const kekA = await deriveKEK(SECRET, USER_A);
    const kekB = await deriveKEK(SECRET, USER_B);
    const privKey = mockPrivateKey(64);
    const iv = new Uint8Array(12).fill(1);
    const { webcrypto } = await import("node:crypto");
    const encA = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, kekA, privKey);
    const encB = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, kekB, privKey);
    expect(Buffer.from(encA).toString("hex")).not.toBe(Buffer.from(encB).toString("hex"));
  });

  it("produces different KEKs for different secrets", async () => {
    const kek1 = await deriveKEK("secret-one", USER_A);
    const kek2 = await deriveKEK("secret-two", USER_A);
    const privKey = mockPrivateKey(64);
    const iv = new Uint8Array(12).fill(1);
    const { webcrypto } = await import("node:crypto");
    const enc1 = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, kek1, privKey);
    const enc2 = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, kek2, privKey);
    expect(Buffer.from(enc1).toString("hex")).not.toBe(Buffer.from(enc2).toString("hex"));
  });
});

describe("encryptPrivateKey / decryptPrivateKey", () => {
  it("round-trips the private key correctly", async () => {
    const privKey = mockPrivateKey();
    const kek = await deriveKEK(SECRET, USER_A);
    const entry = await encryptPrivateKey(kek, privKey);
    const recovered = await decryptPrivateKey(kek, entry.encryptedKey, entry.iv);
    expect(recovered).toEqual(privKey);
  });

  it("produces a random IV each time (distinct ciphertexts)", async () => {
    const privKey = mockPrivateKey(64);
    const kek = await deriveKEK(SECRET, USER_A);
    const e1 = await encryptPrivateKey(kek, privKey);
    const e2 = await encryptPrivateKey(kek, privKey);
    expect(Buffer.from(e1.iv).toString("hex")).not.toBe(Buffer.from(e2.iv).toString("hex"));
    expect(Buffer.from(e1.encryptedKey).toString("hex")).not.toBe(
      Buffer.from(e2.encryptedKey).toString("hex")
    );
  });

  it("IV is exactly 12 bytes", async () => {
    const kek = await deriveKEK(SECRET, USER_A);
    const entry = await encryptPrivateKey(kek, mockPrivateKey(64));
    expect(entry.iv.byteLength).toBe(12);
  });

  it("ciphertext is privateKey.length + 16 bytes (GCM auth tag)", async () => {
    const privKey = mockPrivateKey(2400);
    const kek = await deriveKEK(SECRET, USER_A);
    const entry = await encryptPrivateKey(kek, privKey);
    expect(entry.encryptedKey.byteLength).toBe(2400 + 16);
  });

  it("decryption fails with wrong KEK", async () => {
    const privKey = mockPrivateKey(64);
    const kekRight = await deriveKEK(SECRET, USER_A);
    const kekWrong = await deriveKEK("wrong-secret", USER_A);
    const entry = await encryptPrivateKey(kekRight, privKey);
    await expect(
      decryptPrivateKey(kekWrong, entry.encryptedKey, entry.iv)
    ).rejects.toThrow();
  });

  it("decryption fails with tampered ciphertext", async () => {
    const privKey = mockPrivateKey(64);
    const kek = await deriveKEK(SECRET, USER_A);
    const entry = await encryptPrivateKey(kek, privKey);
    const tampered = new Uint8Array(entry.encryptedKey);
    tampered[0] ^= 0xff;
    await expect(
      decryptPrivateKey(kek, tampered, entry.iv)
    ).rejects.toThrow();
  });

  it("decryption fails with wrong IV", async () => {
    const privKey = mockPrivateKey(64);
    const kek = await deriveKEK(SECRET, USER_A);
    const entry = await encryptPrivateKey(kek, privKey);
    const wrongIv = new Uint8Array(12).fill(0xab);
    await expect(
      decryptPrivateKey(kek, entry.encryptedKey, wrongIv)
    ).rejects.toThrow();
  });
});

describe("serializeVaultEntry / deserializeVaultEntry", () => {
  it("round-trips correctly", async () => {
    const kek = await deriveKEK(SECRET, USER_A);
    const entry = await encryptPrivateKey(kek, mockPrivateKey());
    const blob = serializeVaultEntry(entry);
    const recovered = deserializeVaultEntry(blob);
    expect(Buffer.from(recovered.iv).toString("hex")).toBe(
      Buffer.from(entry.iv).toString("hex")
    );
    expect(Buffer.from(recovered.encryptedKey).toString("hex")).toBe(
      Buffer.from(entry.encryptedKey).toString("hex")
    );
  });

  it("blob size is 12 + encryptedKey.length", async () => {
    const kek = await deriveKEK(SECRET, USER_A);
    const entry = await encryptPrivateKey(kek, mockPrivateKey(2400));
    const blob = serializeVaultEntry(entry);
    expect(blob.byteLength).toBe(12 + entry.encryptedKey.byteLength);
  });

  it("throws on blob too short", () => {
    expect(() => deserializeVaultEntry(new Uint8Array(5))).toThrow(RangeError);
  });

  it("full vault roundtrip: serialize → deserialize → decrypt", async () => {
    const privKey = mockPrivateKey();
    const kek = await deriveKEK(SECRET, USER_B);
    const entry = await encryptPrivateKey(kek, privKey);
    const blob = serializeVaultEntry(entry);

    // Simulate DB fetch + re-derive KEK
    const kek2 = await deriveKEK(SECRET, USER_B);
    const { iv, encryptedKey } = deserializeVaultEntry(blob);
    const recovered = await decryptPrivateKey(kek2, encryptedKey, iv);
    expect(recovered).toEqual(privKey);
  });
});
