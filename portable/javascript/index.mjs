/** Node.js client for the Rust sovereign-sealer CLI; cryptography remains in Rust. */
import { spawn } from "node:child_process";

export class SealerError extends Error {}
export class Sealer {
  constructor({ executable = "sovereign-sealer", timeoutMs = 30000 } = {}) {
    this.executable = executable;
    this.timeoutMs = timeoutMs;
  }
  call(request) {
    return new Promise((resolve, reject) => {
      const child = spawn(this.executable, [], { shell: false, stdio: ["pipe", "pipe", "pipe"], env: { PATH: "/usr/bin:/bin", LANG: "C" } });
      let out = "", err = "", settled = false;
      const timer = setTimeout(() => { child.kill("SIGKILL"); finish(new SealerError("native_sealer_timeout")); }, this.timeoutMs);
      const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(value); };
      child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
      child.stdout.on("data", chunk => { out += chunk; if (out.length > 2 * 1024 * 1024) child.kill("SIGKILL"); });
      child.stderr.on("data", chunk => { err += chunk.slice(0, 8192); });
      child.on("error", () => finish(new SealerError("native_sealer_unavailable")));
      child.on("close", code => {
        let value; try { value = JSON.parse(out); } catch { return finish(new SealerError("native_sealer_invalid_response")); }
        if (code !== 0 || value.status !== "success") return finish(new SealerError(value.error ?? "native_sealer_failed"));
        finish(null, value);
      });
      child.stdin.end(JSON.stringify(request));
    });
  }
  async seal(plaintext, password, associatedData = Buffer.alloc(0)) {
    return this.call({ operation:"seal", password, provider:"Local",
      plaintext_b64:Buffer.from(plaintext).toString("base64"),
      associated_data_b64:Buffer.from(associatedData).toString("base64") });
  }
  async open(blob, record, password, associatedData = Buffer.alloc(0)) {
    const value = await this.call({ operation:"open", password, provider:"Local",
      blob_b64:Buffer.from(blob).toString("base64"), record,
      associated_data_b64:Buffer.from(associatedData).toString("base64") });
    return Buffer.from(value.plaintext_b64, "base64");
  }
}
