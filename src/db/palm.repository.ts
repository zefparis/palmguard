/**
 * PalmGuard Supabase Repository
 *
 * - Real impl: uses @supabase/supabase-js v2 service-role client (bypasses RLS)
 * - NoopRepository: returned when SUPABASE_URL is absent (dev / CI)
 * - MemoryRepository: in-memory store for integration tests (inject via createPalmRepository(mock))
 *
 * Errors are never forwarded raw to callers — only RepositoryError is thrown,
 * keeping Supabase internals off the wire.
 */

import type { SupabaseClient } from "@supabase/supabase-js";
import type { EnrollRecord, AuditEntry, PalmRepository } from "./types.js";

export type { PalmRepository, EnrollRecord, AuditEntry };
export { type AuditEventType } from "./types.js";

// ─── Error sentinel ───────────────────────────────────────────────────────────

export class RepositoryError extends Error {
  public readonly kind: "DB_ERROR" | "CONFLICT" | "NOT_FOUND";
  public readonly sourceError: unknown;

  constructor(
    kind: "DB_ERROR" | "CONFLICT" | "NOT_FOUND",
    message: string,
    sourceError?: unknown
  ) {
    super(message);
    this.name = "RepositoryError";
    this.kind = kind;
    this.sourceError = sourceError;
  }
}

// ─── Noop (CI / missing Supabase creds) ─────────────────────────────────────

class NoopRepository implements PalmRepository {
  async enroll(_r: EnrollRecord): Promise<void> {
    console.warn("[palmguard] NoopRepository.enroll — no Supabase configured");
  }
  async findEnrollment(_t: string, _u: string): Promise<EnrollRecord | null> {
    return null;
  }
  async deleteEnrollment(_t: string, _u: string): Promise<void> {
    console.warn("[palmguard] NoopRepository.deleteEnrollment — no Supabase configured");
  }
  async appendAuditLog(_e: AuditEntry): Promise<void> {}
  async ping(): Promise<boolean> { return false; }
}

// ─── In-memory (integration tests) ───────────────────────────────────────────

export class MemoryRepository implements PalmRepository {
  private enrollments = new Map<string, EnrollRecord>();
  private auditLog: AuditEntry[] = [];

  private key(tenantId: string, userId: string) { return `${tenantId}:${userId}`; }

  async enroll(record: EnrollRecord): Promise<void> {
    const k = this.key(record.tenantId, record.userId);
    if (this.enrollments.has(k)) {
      throw new RepositoryError("CONFLICT", "User already enrolled", null);
    }
    this.enrollments.set(k, record);
  }

  async findEnrollment(tenantId: string, userId: string): Promise<EnrollRecord | null> {
    return this.enrollments.get(this.key(tenantId, userId)) ?? null;
  }

  async deleteEnrollment(tenantId: string, userId: string): Promise<void> {
    this.enrollments.delete(this.key(tenantId, userId));
  }

  async appendAuditLog(entry: AuditEntry): Promise<void> {
    this.auditLog.push(entry);
  }

  async ping(): Promise<boolean> { return true; }

  /** Test helper — expose internal state */
  getAuditLog(): readonly AuditEntry[] { return this.auditLog; }
  getEnrollments(): ReadonlyMap<string, EnrollRecord> { return this.enrollments; }
  _reset(): void { this.enrollments.clear(); this.auditLog.length = 0; }
}

// ─── Supabase real implementation ─────────────────────────────────────────────

class SupabaseRepository implements PalmRepository {
  constructor(private readonly client: SupabaseClient) {}

  async enroll(record: EnrollRecord): Promise<void> {
    const { error } = await this.client.from("palm_enrollments").insert({
      id:                  record.enrollmentId,
      tenant_id:           record.tenantId,
      user_id:             record.userId,
      content_hash:        record.contentHash,
      template_ciphertext: record.templateCiphertext,
      public_key:          record.publicKey,
      kem_privkey_enc:     record.kemPrivkeyEnc,
      kek_iv:              record.kekIv,
      captured_at:         record.capturedAt,
      julian_day_number:   record.celestialJdn,
      capture_confidence:  record.captureConfidence ?? 1.0,
      template_version:    record.templateVersion ?? '1.0',
      is_active:           true,
    });

    if (error) {
      // Supabase returns code "23505" for unique constraint violations
      if (error.code === "23505") {
        throw new RepositoryError("CONFLICT", "User already enrolled", error);
      }
      console.error("[palmguard] Supabase enroll error:", error.message);
      throw new RepositoryError("DB_ERROR", "Database error during enrollment", error);
    }
  }

  async findEnrollment(tenantId: string, userId: string): Promise<EnrollRecord | null> {
    const { data, error } = await this.client
      .from("palm_enrollments")
      .select("*")
      .eq("tenant_id", tenantId)
      .eq("user_id", userId)
      .eq("is_active", true)
      .order("captured_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) {
      console.error("[palmguard] Supabase findEnrollment error:", error.message);
      throw new RepositoryError("DB_ERROR", "Database error during lookup", error);
    }
    if (!data) return null;

    return {
      tenantId:           data.tenant_id           as string,
      userId:             data.user_id              as string,
      contentHash:        data.content_hash         as string,
      enrollmentId:       data.id                   as string,
      templateCiphertext: Buffer.from((data.template_ciphertext as string).replace(/^\\x/, ""), "hex"),
      publicKey:          Buffer.from((data.public_key          as string).replace(/^\\x/, ""), "hex"),
      kemPrivkeyEnc:      Buffer.from((data.kem_privkey_enc     as string).replace(/^\\x/, ""), "hex"),
      kekIv:              Buffer.from((data.kek_iv              as string).replace(/^\\x/, ""), "hex"),
      capturedAt:         data.captured_at          as number,
      celestialJdn:       data.julian_day_number    as number,
      templateVersion:    data.template_version     as string,
    };
  }

  async deleteEnrollment(tenantId: string, userId: string): Promise<void> {
    const { error } = await this.client
      .from("palm_enrollments")
      .update({ is_active: false })
      .eq("tenant_id", tenantId)
      .eq("user_id", userId);

    if (error) {
      console.error("[palmguard] Supabase deleteEnrollment error:", error.message);
      throw new RepositoryError("DB_ERROR", "Database error during deletion", error);
    }
  }

  async appendAuditLog(entry: AuditEntry): Promise<void> {
    const { error } = await this.client.from("palm_audit_log").insert({
      tenant_id:   entry.tenantId,
      user_id:     entry.userId,
      event_type:  entry.eventType,
      ip_hash:     entry.ipHash,
      audit_token: entry.auditToken ?? null,
      metadata:    entry.metadata ?? null,
    });

    if (error) {
      // Audit log failures are logged but NOT surfaced to callers
      console.error("[palmguard] Supabase audit log error:", error.message);
    }
  }

  async ping(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      const { error } = await this.client
        .from("palm_enrollments")
        .select("id")
        .limit(1)
        .abortSignal(controller.signal);
      clearTimeout(timeout);
      return !error;
    } catch {
      return false;
    }
  }
}

// ─── Factory ──────────────────────────────────────────────────────────────────

/** Singleton client — created once, shared across all requests. */
let _sharedClient: SupabaseClient | null = null;

async function getSharedClient(url: string, key: string): Promise<SupabaseClient> {
  if (!_sharedClient) {
    const { createClient } = await import("@supabase/supabase-js");
    _sharedClient = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  }
  return _sharedClient;
}

/**
 * Create a PalmRepository.
 *
 * - Inject a mock/MemoryRepository as `overrideClient` in tests.
 * - Production: pass `url` + `key` (or rely on env via config.ts).
 * - CI/dev without Supabase: returns NoopRepository (logs a warning).
 */
export async function createPalmRepository(
  overrideClient?: SupabaseClient | PalmRepository | null,
  url?: string | null,
  serviceKey?: string | null
): Promise<PalmRepository> {
  // Direct PalmRepository override (e.g. MemoryRepository in tests)
  if (overrideClient && "enroll" in overrideClient) {
    return overrideClient as PalmRepository;
  }
  // SupabaseClient override (integration tests with mock client)
  if (overrideClient) {
    return new SupabaseRepository(overrideClient as SupabaseClient);
  }
  // Real Supabase — env-driven
  const effectiveUrl = url ?? process.env["SUPABASE_URL"];
  const effectiveKey = serviceKey ?? process.env["SUPABASE_SERVICE_ROLE_KEY"];
  if (!effectiveUrl || !effectiveKey) {
    console.warn("[palmguard] SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY absent — using NoopRepository");
    return new NoopRepository();
  }
  const client = await getSharedClient(effectiveUrl, effectiveKey);
  return new SupabaseRepository(client);
}

/** Synchronous factory used at server startup — returns Noop if env vars are absent. */
export function createPalmRepositorySync(
  overrideRepo?: PalmRepository | null
): PalmRepository {
  if (overrideRepo) return overrideRepo;
  return new NoopRepository();
}
