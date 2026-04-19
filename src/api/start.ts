/**
 * PalmGuard API — Process entry point.
 * This file is the only place that calls app.listen().
 * Import server.ts (createApp) in tests without side effects.
 */

import { createAppAsync } from "./server.js";

const PORT = process.env["PORT"] ?? 4010;
const app = await createAppAsync();

app.listen(PORT, () => {
  console.log(`PalmGuard API listening on :${PORT}`);
});
