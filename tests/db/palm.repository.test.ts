/**
 * PalmGuard Repository — unit tests
 *
 * All tests use MemoryRepository (no network calls).
 * SupabaseRepository tests use a mock Supabase client via factory injection.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  MemoryRepository,
  RepositoryError,
  createPalmRepository,
} from "../../src/db/palm.repository.js";
import type { EnrollRecord, AuditEntry } from "../../src/db/types.js";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeRecord(overrides?: Partial<EnrollRecord>): EnrollRecord {
  return {
    tenantId:           "tenant-1",
    userId:             "user-1",
    contentHash:        "abc123",
    enrollmentId:       "enroll-id-001",
    templateCiphertext: new Uint8Array(32),
    publicKey:          new Uint8Array(32),
    kemPrivkeyEnc:      new Uint8Array(64),
    kekIv:              new Uint8Array(12),
    capturedAt:         Date.now(),
    celestialJdn:       2_460_000,
    templateVersion:    "1.0",
    ...overrides,
  };
}

function makeAudit(overrides?: Partial<AuditEntry>): AuditEntry {
  return {
    tenantId:   "tenant-1",
    userId:     "user-1",
    eventType:  "ENROLL",
    ipHash:     "deadbeef",
    ...overrides,
  };
}

// ─── MemoryRepository ─────────────────────────────────────────────────────────

describe("MemoryRepository — enroll", () => {
  let repo: MemoryRepository;
  beforeEach(() => { repo = new MemoryRepository(); });

  it("stores and retrieves an enrollment", async () => {
    const record = makeRecord();
    await repo.enroll(record);
    const found = await repo.findEnrollment("tenant-1", "user-1");
    expect(found).not.toBeNull();
    expect(found?.enrollmentId).toBe("enroll-id-001");
  });

  it("throws CONFLICT when same tenant+user enrolled twice", async () => {
    await repo.enroll(makeRecord());
    await expect(repo.enroll(makeRecord())).rejects.toThrow(
      expect.objectContaining({ kind: "CONFLICT" })
    );
  });

  it("allows different users to enroll independently", async () => {
    await repo.enroll(makeRecord({ userId: "user-A" }));
    await repo.enroll(makeRecord({ userId: "user-B" }));
    const a = await repo.findEnrollment("tenant-1", "user-A");
    const b = await repo.findEnrollment("tenant-1", "user-B");
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
  });

  it("isolates tenants — same userId different tenant is allowed", async () => {
    await repo.enroll(makeRecord({ tenantId: "tenant-A", userId: "user-1" }));
    await repo.enroll(makeRecord({ tenantId: "tenant-B", userId: "user-1" }));
    expect(await repo.findEnrollment("tenant-A", "user-1")).not.toBeNull();
    expect(await repo.findEnrollment("tenant-B", "user-1")).not.toBeNull();
  });
});

describe("MemoryRepository — findEnrollment", () => {
  let repo: MemoryRepository;
  beforeEach(() => { repo = new MemoryRepository(); });

  it("returns null for unknown user", async () => {
    expect(await repo.findEnrollment("tenant-1", "ghost")).toBeNull();
  });

  it("returns null for unknown tenant", async () => {
    await repo.enroll(makeRecord());
    expect(await repo.findEnrollment("unknown-tenant", "user-1")).toBeNull();
  });

  it("returns the correct record fields", async () => {
    const record = makeRecord({ contentHash: "hash-xyz", celestialJdn: 1234567 });
    await repo.enroll(record);
    const found = await repo.findEnrollment("tenant-1", "user-1");
    expect(found?.contentHash).toBe("hash-xyz");
    expect(found?.celestialJdn).toBe(1234567);
    expect(found?.templateVersion).toBe("1.0");
  });
});

describe("MemoryRepository — deleteEnrollment", () => {
  let repo: MemoryRepository;
  beforeEach(() => { repo = new MemoryRepository(); });

  it("removes enrollment from store", async () => {
    await repo.enroll(makeRecord());
    await repo.deleteEnrollment("tenant-1", "user-1");
    expect(await repo.findEnrollment("tenant-1", "user-1")).toBeNull();
  });

  it("silently succeeds for non-existent enrollment", async () => {
    await expect(repo.deleteEnrollment("tenant-1", "ghost")).resolves.toBeUndefined();
  });

  it("allows re-enrollment after deletion", async () => {
    await repo.enroll(makeRecord({ enrollmentId: "first" }));
    await repo.deleteEnrollment("tenant-1", "user-1");
    await repo.enroll(makeRecord({ enrollmentId: "second" }));
    const found = await repo.findEnrollment("tenant-1", "user-1");
    expect(found?.enrollmentId).toBe("second");
  });
});

describe("MemoryRepository — appendAuditLog", () => {
  let repo: MemoryRepository;
  beforeEach(() => { repo = new MemoryRepository(); });

  it("records audit entries", async () => {
    await repo.appendAuditLog(makeAudit({ eventType: "ENROLL" }));
    await repo.appendAuditLog(makeAudit({ eventType: "VERIFY_MATCH" }));
    const log = repo.getAuditLog();
    expect(log).toHaveLength(2);
    expect(log[0]?.eventType).toBe("ENROLL");
    expect(log[1]?.eventType).toBe("VERIFY_MATCH");
  });

  it("stores audit token and metadata", async () => {
    await repo.appendAuditLog(makeAudit({ auditToken: "tok123", metadata: { similarity: 0.99 } }));
    const entry = repo.getAuditLog()[0];
    expect(entry?.auditToken).toBe("tok123");
    expect((entry?.metadata as Record<string, unknown>)?.["similarity"]).toBe(0.99);
  });
});

describe("MemoryRepository — ping", () => {
  it("returns true", async () => {
    const repo = new MemoryRepository();
    expect(await repo.ping()).toBe(true);
  });
});

describe("MemoryRepository — _reset", () => {
  it("clears enrollments and audit log", async () => {
    const repo = new MemoryRepository();
    await repo.enroll(makeRecord());
    await repo.appendAuditLog(makeAudit());
    repo._reset();
    expect(await repo.findEnrollment("tenant-1", "user-1")).toBeNull();
    expect(repo.getAuditLog()).toHaveLength(0);
  });
});

// ─── RepositoryError ──────────────────────────────────────────────────────────

describe("RepositoryError", () => {
  it("is instanceof Error", () => {
    const err = new RepositoryError("CONFLICT", "test msg");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("RepositoryError");
    expect(err.kind).toBe("CONFLICT");
    expect(err.message).toBe("test msg");
  });

  it("stores sourceError", () => {
    const cause = new Error("root cause");
    const err   = new RepositoryError("DB_ERROR", "wrap", cause);
    expect(err.sourceError).toBe(cause);
  });
});

// ─── createPalmRepository — fallback to noop ─────────────────────────────────

describe("createPalmRepository — factory", () => {
  it("returns a MemoryRepository when passed directly as override", async () => {
    const mem  = new MemoryRepository();
    const repo = await createPalmRepository(mem);
    await repo.enroll(makeRecord());
    expect(await repo.findEnrollment("tenant-1", "user-1")).not.toBeNull();
  });

  it("returns a NoopRepository when env vars are absent", async () => {
    // Temporarily clear env
    const orig = process.env["SUPABASE_URL"];
    delete process.env["SUPABASE_URL"];
    delete process.env["SUPABASE_SERVICE_ROLE_KEY"];
    const repo = await createPalmRepository(null);
    // Noop: enroll succeeds without throwing, findEnrollment returns null
    await expect(repo.enroll(makeRecord())).resolves.toBeUndefined();
    expect(await repo.findEnrollment("t", "u")).toBeNull();
    expect(await repo.ping()).toBe(false);
    if (orig) process.env["SUPABASE_URL"] = orig;
  });
});

// ─── SupabaseRepository — via mock Supabase client ───────────────────────────

function makeMockClient(overrides: {
  insertError?: { message: string; code?: string } | null;
  selectData?: unknown;
  selectError?: { message: string } | null;
  updateError?: { message: string } | null;
} = {}) {
  const { insertError = null, selectData = null, selectError = null, updateError = null } = overrides;

  return {
    from: (_table: string) => ({
      insert: () => Promise.resolve({ data: null, error: insertError }),
      select: () => ({
        eq: function (this: unknown) { return this; },
        order: function (this: unknown) { return this; },
        limit: function (this: unknown) { return this; },
        abortSignal: function (this: unknown) { return this; },
        maybeSingle: () => Promise.resolve({ data: selectData, error: selectError }),
      }),
      update: () => ({
        eq: () => ({
          eq: () => Promise.resolve({ data: null, error: updateError }),
        }),
      }),
    }),
  };
}

describe("SupabaseRepository — via mock client", () => {
  it("enroll succeeds when insert returns no error", async () => {
    const client = makeMockClient() as unknown as import("@supabase/supabase-js").SupabaseClient;
    const repo   = await createPalmRepository(client);
    await expect(repo.enroll(makeRecord())).resolves.toBeUndefined();
  });

  it("enroll throws CONFLICT on unique constraint violation", async () => {
    const client = makeMockClient({ insertError: { message: "dup", code: "23505" } }) as unknown as import("@supabase/supabase-js").SupabaseClient;
    const repo   = await createPalmRepository(client);
    await expect(repo.enroll(makeRecord())).rejects.toThrow(
      expect.objectContaining({ kind: "CONFLICT" })
    );
  });

  it("enroll throws DB_ERROR on generic Supabase error", async () => {
    const client = makeMockClient({ insertError: { message: "connection error", code: "08006" } }) as unknown as import("@supabase/supabase-js").SupabaseClient;
    const repo   = await createPalmRepository(client);
    await expect(repo.enroll(makeRecord())).rejects.toThrow(
      expect.objectContaining({ kind: "DB_ERROR" })
    );
  });

  it("findEnrollment returns null when Supabase returns no data", async () => {
    const client = makeMockClient({ selectData: null }) as unknown as import("@supabase/supabase-js").SupabaseClient;
    const repo   = await createPalmRepository(client);
    expect(await repo.findEnrollment("t", "u")).toBeNull();
  });

  it("findEnrollment throws DB_ERROR on Supabase error", async () => {
    const client = makeMockClient({ selectError: { message: "timeout" } }) as unknown as import("@supabase/supabase-js").SupabaseClient;
    const repo   = await createPalmRepository(client);
    await expect(repo.findEnrollment("t", "u")).rejects.toThrow(
      expect.objectContaining({ kind: "DB_ERROR" })
    );
  });

  it("deleteEnrollment succeeds with no error", async () => {
    const client = makeMockClient() as unknown as import("@supabase/supabase-js").SupabaseClient;
    const repo   = await createPalmRepository(client);
    await expect(repo.deleteEnrollment("t", "u")).resolves.toBeUndefined();
  });

  it("deleteEnrollment throws DB_ERROR on Supabase error", async () => {
    const client = makeMockClient({ updateError: { message: "fail" } }) as unknown as import("@supabase/supabase-js").SupabaseClient;
    const repo   = await createPalmRepository(client);
    await expect(repo.deleteEnrollment("t", "u")).rejects.toThrow(
      expect.objectContaining({ kind: "DB_ERROR" })
    );
  });

  it("appendAuditLog swallows Supabase errors without throwing", async () => {
    const badClient = {
      from: () => ({ insert: () => Promise.resolve({ data: null, error: { message: "audit fail" } }) }),
    } as unknown as import("@supabase/supabase-js").SupabaseClient;
    const repo = await createPalmRepository(badClient);
    await expect(repo.appendAuditLog(makeAudit())).resolves.toBeUndefined();
  });
});
