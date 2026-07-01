// SPDX-License-Identifier: MIT
// Whisper on Supabase Edge Functions (Deno).  supabase functions deploy whisper
//   KEYLESS: GET /whisper?addr=<agent /128>
//   EGRESS:  GET /whisper?egress            → fetch the source-IP echo THROUGH your agent's /128 (needs a key)
//   CONTROL: GET /whisper?op=list           (supabase secrets set WHISPER_API_KEY=<your key>)
// Egress runs on Deno.connect + Deno.startTls — in-process, no CLI, no local proxy.
import { resolve, rdap, control, agentEgress } from "npm:whisper-edge@^0.2.0";

const ECHO = "https://rdap.whisper.online/egress-ip";

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const key = Deno.env.get("WHISPER_API_KEY");

  if (url.searchParams.has("egress")) {
    if (!key) return Response.json({ error: "set WHISPER_API_KEY to egress" }, { status: 401 });
    const egress = await agentEgress(key, url.searchParams.get("egress") || undefined);
    try {
      const observed = (await (await egress.fetch(ECHO, { headers: { accept: "application/json" } })).json()) as { ip: string };
      return Response.json({
        agent: egress.transport.address,
        observedSourceIP: observed.ip,
        egressedFromYourAgent: observed.ip === egress.transport.address,
        transport: egress.transport,
      });
    } finally {
      egress.close();
    }
  }

  const op = url.searchParams.get("op");
  if (op) {
    if (!key) return Response.json({ error: "set WHISPER_API_KEY to use the control plane" }, { status: 401 });
    const res = op === "list" ? await control(key).list() : await control(key).agents(op, {});
    return Response.json({ op, records: res.records });
  }

  const addr = url.searchParams.get("addr");
  if (!addr) return new Response("usage: ?addr=<agent /128>  |  ?egress (needs key)  |  ?op=list (needs key)\n", { status: 400 });
  const identity = await resolve(addr);
  return Response.json({ address: addr, identity, rdap: identity ? await rdap(addr) : null });
});
