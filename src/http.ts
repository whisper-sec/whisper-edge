// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

import type { Problem, RequestOptions } from "./types.js";

/**
 * The one error type this SDK throws. It carries the RFC-7807 problem fields the control
 * plane returns (status, detail, title, ...) so a caller sees the server's exact, helpful,
 * secret-free message - never an opaque failure (Postel: a clear error, never a raw 500).
 */
export class WhisperError extends Error {
  readonly status: number;
  readonly detail?: string;
  readonly title?: string;
  readonly type?: string;
  readonly suggestions?: string[];
  /** The control plane's own error code (e.g. "NOT_FOUND", "FORBIDDEN"), when it gave one. */
  readonly code?: string;
  /** Whether the server says retrying could succeed, when it said. */
  readonly retryable?: boolean;

  constructor(message: string, problem: Problem = {}) {
    super(message);
    this.name = "WhisperError";
    this.status = problem.status ?? 0;
    this.detail = problem.detail;
    this.title = problem.title;
    this.type = problem.type;
    this.suggestions = problem.suggestions;
    this.code = problem.code;
    this.retryable = problem.retryable;
    // Keep a correct prototype chain across the ES5 down-level target.
    Object.setPrototypeOf(this, WhisperError.prototype);
  }
}

/**
 * The control plane understood the call and found nothing of yours to act on. From
 * `revoke` it means nothing was revoked: the agent was revoked already, or it is not in your
 * account. That is an answer, not a fault, so never retry it. `code` is "NOT_FOUND", `status`
 * is 404, `retryable` is false, and the message is the server's own.
 */
export class NotFoundError extends WhisperError {
  constructor(message: string, problem: Problem = {}) {
    super(message, { ...problem, status: 404, code: "NOT_FOUND", retryable: false });
    this.name = "NotFoundError";
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

/**
 * True when a problem is the control plane's NOT_FOUND: the code, on a 404 or with no error
 * status. Read off the code, never off a bare 404, which is a mistyped endpoint or a proxy
 * in the way rather than a statement about the agent.
 */
export function isNotFound(problem: Problem | null | undefined): boolean {
  if (!problem || (problem.code ?? "").trim().toUpperCase() !== "NOT_FOUND") return false;
  const s = problem.status ?? 0;
  return s === 404 || s < 400;
}

/** Resolve the fetch to use: an injected one, else the runtime global. */
export function resolveFetch(opts?: RequestOptions): typeof fetch {
  const f = opts?.fetch ?? (typeof fetch !== "undefined" ? fetch : undefined);
  if (!f) {
    throw new WhisperError(
      "no global fetch in this runtime - pass { fetch } (Node <18: use undici, or upgrade)",
      { status: 0 },
    );
  }
  // Bind to preserve `this` for runtimes that require it (some polyfills do).
  return f.bind(globalThis);
}

/**
 * Perform a fetch with a timeout and an optional caller AbortSignal. Returns the Response.
 * A network error (or a timeout) is surfaced as a WhisperError with a clear message.
 */
export async function doFetch(
  url: string,
  init: RequestInit,
  opts: RequestOptions | undefined,
  what: string,
): Promise<Response> {
  const f = resolveFetch(opts);
  const timeoutMs = opts?.timeoutMs ?? 10_000;
  const ac = new AbortController();
  const onAbort = () => ac.abort((opts!.signal as AbortSignal).reason);
  if (opts?.signal) {
    if (opts.signal.aborted) ac.abort(opts.signal.reason);
    else opts.signal.addEventListener("abort", onAbort, { once: true });
  }
  let timer: ReturnType<typeof setTimeout>;
  // Race the fetch against a hard timeout: we abort the request AND reject here, so we
  // never hang even if the runtime's fetch ignores the abort signal (conservative-emit).
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const e = new WhisperError(`${what} timed out after ${timeoutMs}ms`, { status: 0 });
      ac.abort(e);
      reject(e);
    }, timeoutMs);
  });
  try {
    return await Promise.race([f(url, { ...init, signal: ac.signal }), timeout]);
  } catch (err) {
    if (err instanceof WhisperError) throw err;
    const reason = (ac.signal.reason instanceof Error ? ac.signal.reason.message : undefined) ?? (err as Error)?.message;
    throw new WhisperError(`${what} unreachable: ${reason ?? "network error"}`, { status: 0 });
  } finally {
    clearTimeout(timer!);
    if (opts?.signal) opts.signal.removeEventListener("abort", onAbort);
  }
}

/** Read a response body as text, capped so a runaway body can never exhaust memory. */
export async function readCappedText(resp: Response, capBytes = 16 << 20): Promise<string> {
  const buf = await resp.arrayBuffer();
  const bytes = new Uint8Array(buf.byteLength > capBytes ? buf.slice(0, capBytes) : buf);
  return new TextDecoder().decode(bytes);
}

/** Parse text as JSON, tolerating an empty body (→ null). Throws WhisperError on garbage. */
export function parseJson(text: string, what: string, status: number): unknown {
  const t = text.trim();
  if (t === "") return null;
  try {
    return JSON.parse(t);
  } catch {
    throw new WhisperError(`${what} returned a non-JSON body (HTTP ${status})`, { status });
  }
}
