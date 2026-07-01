// SPDX-License-Identifier: MIT
// Whisper on AWS Lambda (Node 18+, Function URL or API Gateway).  npm i whisper-edge
//   KEYLESS: GET /?addr=<agent /128>
//   EGRESS:  GET /?egress            → fetch the source-IP echo THROUGH your agent's /128 (needs a key)
//   CONTROL: GET /?op=list           (set the WHISPER_API_KEY env var — a Secrets Manager ref is best)
// Egress runs on Node's built-in net/tls CONNECT tunnel (bearer encrypted to the proxy) — no CLI, no local proxy.
import { resolve, rdap, control, agentEgress } from "whisper-edge";

const ECHO = "https://rdap.whisper.online/egress-ip";
const json = (statusCode, body) => ({ statusCode, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

export const handler = async (event) => {
  const q = event?.queryStringParameters ?? {};

  if (q.egress !== undefined) {
    const key = process.env.WHISPER_API_KEY;
    if (!key) return json(401, { error: "set WHISPER_API_KEY to egress" });
    const egress = await agentEgress(key, q.egress || undefined);
    try {
      const observed = await (await egress.fetch(ECHO, { headers: { accept: "application/json" } })).json();
      return json(200, {
        agent: egress.transport.address,
        observedSourceIP: observed.ip,
        egressedFromYourAgent: observed.ip === egress.transport.address,
        transport: egress.transport,
      });
    } finally {
      egress.close();
    }
  }

  const op = q.op;
  if (op) {
    const key = process.env.WHISPER_API_KEY;
    if (!key) return json(401, { error: "set WHISPER_API_KEY to use the control plane" });
    const res = op === "list" ? await control(key).list() : await control(key).agents(op, {});
    return json(200, { op, records: res.records });
  }

  const addr = q.addr;
  if (!addr) return { statusCode: 400, body: "usage: ?addr=<agent /128>  |  ?egress (needs key)  |  ?op=list (needs key)" };
  const identity = await resolve(addr);
  return json(200, { address: addr, identity, rdap: identity ? await rdap(addr) : null });
};
