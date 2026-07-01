// SPDX-License-Identifier: MIT
// Whisper on Deno Deploy — two-tier agent identity at the edge.
//   Deploy:  deployctl deploy --project=<p> main.ts     Local:  deno run --allow-net --allow-env main.ts
//   KEYLESS:  GET /?addr=<agent /128 address>
//   CONTROL:  GET /?op=list           (set WHISPER_API_KEY: deployctl ... --env WHISPER_API_KEY=...)
import { resolve, rdap, control } from "npm:whisper-edge@^0.1.0";

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const op = url.searchParams.get("op");

  if (op) {
    const key = Deno.env.get("WHISPER_API_KEY");
    if (!key) return Response.json({ error: "set WHISPER_API_KEY to use the control plane" }, { status: 401 });
    const res = op === "list" ? await control(key).list() : await control(key).agents(op, {});
    return Response.json({ op, records: res.records });
  }

  const addr = url.searchParams.get("addr");
  if (!addr) return new Response("usage: ?addr=<agent /128 address>   |   ?op=list (needs a key)\n", { status: 400 });
  const identity = await resolve(addr);
  return Response.json({ address: addr, identity, rdap: identity ? await rdap(addr) : null });
});
