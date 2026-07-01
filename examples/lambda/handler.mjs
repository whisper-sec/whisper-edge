// SPDX-License-Identifier: MIT
// Whisper on AWS Lambda (Node 18+, Function URL or API Gateway).  npm i whisper-edge
//   KEYLESS:  GET /?addr=<agent /128 address>
//   CONTROL:  GET /?op=list      (set the WHISPER_API_KEY Lambda env var — a Secrets Manager ref is best)
import { resolve, rdap, control } from "whisper-edge";

const json = (statusCode, body) => ({
  statusCode,
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});

export const handler = async (event) => {
  const q = event?.queryStringParameters ?? {};
  const op = q.op;

  if (op) {
    const key = process.env.WHISPER_API_KEY;
    if (!key) return json(401, { error: "set WHISPER_API_KEY to use the control plane" });
    const res = op === "list" ? await control(key).list() : await control(key).agents(op, {});
    return json(200, { op, records: res.records });
  }

  const addr = q.addr;
  if (!addr) return { statusCode: 400, body: "usage: ?addr=<agent /128 address>  |  ?op=list (needs a key)" };
  const identity = await resolve(addr);
  return json(200, { address: addr, identity, rdap: identity ? await rdap(addr) : null });
};
