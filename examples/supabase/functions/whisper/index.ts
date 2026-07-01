// SPDX-License-Identifier: MIT
// Whisper on Supabase Edge Functions (Deno).  supabase functions deploy whisper
//   KEYLESS:  GET /whisper?addr=<agent /128 address>
//   CONTROL:  GET /whisper?op=list      (supabase secrets set WHISPER_API_KEY=<your key>)
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
