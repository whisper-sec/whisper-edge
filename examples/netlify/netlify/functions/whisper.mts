// SPDX-License-Identifier: MIT
// Whisper on Netlify Functions (Node, Web API).  npm i whisper-edge  ·  netlify deploy
//   KEYLESS: GET /.netlify/functions/whisper?addr=<agent /128>
//   EGRESS:  GET /.netlify/functions/whisper?egress   → fetch the source-IP echo THROUGH your agent's /128 (needs a key)
//   CONTROL: GET /.netlify/functions/whisper?op=list   (set WHISPER_API_KEY in Netlify env)
// Egress runs on Node's built-in net/tls CONNECT tunnel (bearer encrypted to the proxy): no CLI, no local proxy.
import { resolve, rdap, control, agentEgress } from "whisper-edge";

const ECHO = "https://rdap.whisper.online/egress-ip";

export default async (req: Request): Promise<Response> => {
  const url = new URL(req.url);
  const key = Netlify.env.get("WHISPER_API_KEY");

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
};

// Netlify injects a typed `Netlify.env`; declare it for standalone type-checking.
declare const Netlify: { env: { get(k: string): string | undefined } };
