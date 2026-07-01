// SPDX-License-Identifier: MIT
// Whisper on Netlify Functions (Web API).  npm i whisper-edge  ·  netlify deploy
//   KEYLESS:  GET /.netlify/functions/whisper?addr=<agent /128 address>
//   CONTROL:  GET /.netlify/functions/whisper?op=list   (set WHISPER_API_KEY in Netlify env)
import { resolve, rdap, control } from "whisper-edge";

export default async (req: Request): Promise<Response> => {
  const url = new URL(req.url);
  const op = url.searchParams.get("op");

  if (op) {
    const key = Netlify.env.get("WHISPER_API_KEY");
    if (!key) return Response.json({ error: "set WHISPER_API_KEY to use the control plane" }, { status: 401 });
    const res = op === "list" ? await control(key).list() : await control(key).agents(op, {});
    return Response.json({ op, records: res.records });
  }

  const addr = url.searchParams.get("addr");
  if (!addr) return new Response("usage: ?addr=<agent /128 address>   |   ?op=list (needs a key)\n", { status: 400 });
  const identity = await resolve(addr);
  return Response.json({ address: addr, identity, rdap: identity ? await rdap(addr) : null });
};

// Netlify injects a typed `Netlify.env`; declare it for standalone type-checking.
declare const Netlify: { env: { get(k: string): string | undefined } };
