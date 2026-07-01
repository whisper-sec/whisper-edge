// SPDX-License-Identifier: MIT
// Whisper on Vercel Functions — two-tier agent identity.  npm i whisper-edge
//   KEYLESS:  GET /api/whisper?addr=<agent /128 address>
//   CONTROL:  GET /api/whisper?op=list      (set WHISPER_API_KEY in Vercel env vars)
import { resolve, rdap, control } from "whisper-edge";

export const config = { runtime: "edge" }; // runs on the Vercel Edge runtime (Web fetch)

export default async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const op = url.searchParams.get("op");

  if (op) {
    const key = process.env.WHISPER_API_KEY;
    if (!key) return Response.json({ error: "set WHISPER_API_KEY to use the control plane" }, { status: 401 });
    const res = op === "list" ? await control(key).list() : await control(key).agents(op, {});
    return Response.json({ op, records: res.records });
  }

  const addr = url.searchParams.get("addr");
  if (!addr) return new Response("usage: ?addr=<agent /128 address>   |   ?op=list (needs a key)\n", { status: 400 });
  const identity = await resolve(addr);
  return Response.json({ address: addr, identity, rdap: identity ? await rdap(addr) : null });
}
