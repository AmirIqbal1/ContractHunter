import http from "node:http";
import net from "node:net";
import os from "node:os";
import { readFileSync, existsSync } from "node:fs";

const socketPath = "/run/impact/fork.sock";
function rpc() {
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath, path: "/", method: "POST", headers: { "content-type": "application/json" }, timeout: 3000 }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (response.statusCode !== 200 || typeof body.result !== "string") throw Error("RPC unavailable");
          resolve(body.result);
        } catch (error) { reject(error); }
      });
    });
    request.on("error", reject);
    request.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }));
  });
}
function tcp(host, port) {
  return new Promise((resolve) => {
    const connection = net.connect({ host, port });
    const finish = (reachable) => { connection.destroy(); resolve(reachable); };
    connection.setTimeout(800, () => finish(false));
    connection.once("connect", () => finish(true));
    connection.once("error", () => finish(false));
  });
}
if (process.argv[2] === "tcp") {
  const host = process.argv[3];
  const port = Number(process.argv[4]);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) process.exit(2);
  console.log(JSON.stringify({ reachable: await tcp(host, port) }));
} else if (process.argv[2] === "socket") {
  const probePath = process.argv[3];
  if (!probePath?.startsWith("/")) process.exit(2);
  const reachable = await new Promise((resolve) => {
    const connection = net.connect({ path: probePath });
    const finish = (value) => { connection.destroy(); resolve(value); };
    connection.setTimeout(800, () => finish(false));
    connection.once("connect", () => finish(true));
    connection.once("error", () => finish(false));
  });
  console.log(JSON.stringify({ reachable }));
} else {
  const chainId = await rpc();
  const interfaces = Object.keys(os.networkInterfaces());
  const routes = readFileSync("/proc/net/route", "utf8").trim().split("\n").slice(1);
  const status = readFileSync("/proc/self/status", "utf8");
  const field = (name) => status.match(new RegExp(`^${name}:\\s*(\\S+)`, "m"))?.[1] ?? null;
  const appArmor = readFileSync("/proc/self/attr/current", "utf8").trim();
  console.log(JSON.stringify({ schema: "impact-probe-v1", chainId, interfaces, routes,
    uid: Number(field("Uid")), capEff: field("CapEff"), capBnd: field("CapBnd"),
    noNewPrivs: field("NoNewPrivs"), seccomp: field("Seccomp"), appArmor,
    dockerSocket: existsSync("/var/run/docker.sock"), dataDir: existsSync("/data"),
    verificationDir: existsSync("/verification"), otherForkSocket: existsSync("/run/impact/other.sock"),
    sensitiveEnvironmentKeys: Object.keys(process.env).filter((key) => /RPC|PROXY|SECRET|TOKEN|PRIVATE|WALLET|DATABASE|OPENAI/i.test(key)) }));
  setInterval(() => undefined, 60_000);
}
