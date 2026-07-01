// SPDX-License-Identifier: MIT
// Whisper on Cloudflare Workers — two-tier agent identity at the edge.
//   Deploy:  wrangler deploy      Dev:  wrangler dev
//   KEYLESS:  GET /?addr=<agent /128 address>   → verify + resolve + RDAP (no key)
//   CONTROL:  GET /?op=list                     → your agents (needs WHISPER_API_KEY secret)
import { resolve, rdap, control } from "whisper-edge";

interface Env {
  // Set with:  wrangler secret put WHISPER_API_KEY   (optional — keyless works without it)
  WHISPER_API_KEY?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const op = url.searchParams.get("op");

    // CONTROL tier — unlocked by the API key (kept in a Worker secret, never in code).
    if (op) {
      if (!env.WHISPER_API_KEY) return Response.json({ error: "set WHISPER_API_KEY to use the control plane" }, { status: 401 });
      const c = control(env.WHISPER_API_KEY);
      const res = op === "list" ? await c.list() : await c.agents(op, {});
      return Response.json({ op, records: res.records });
    }

    // KEYLESS tier — pure HTTPS, no key, runs anywhere.
    const addr = url.searchParams.get("addr");
    if (!addr) return new Response("usage: ?addr=<agent /128 address>   |   ?op=list (needs a key)\n", { status: 400 });
    const identity = await resolve(addr);
    return Response.json({ address: addr, identity, rdap: identity ? await rdap(addr) : null });
  },
};
