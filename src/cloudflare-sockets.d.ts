// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Minimal ambient declaration for the Cloudflare Workers TCP socket built-in, so this SDK
// type-checks without a hard dependency on `@cloudflare/workers-types`. The module is provided
// by the workerd runtime at execution time; we only ever import it dynamically, guarded by a
// runtime check, so it is never resolved on Node or Deno.
declare module "cloudflare:sockets" {
  export function connect(address: unknown, options?: unknown): unknown;
}
