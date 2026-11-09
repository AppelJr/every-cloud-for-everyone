import test from "node:test";
import assert from "node:assert/strict";
import { Sealer, SealerError } from "../index.mjs";

const sealer = new Sealer({ executable: process.env.SOVEREIGN_SEALER_BIN ?? "../rust/target/debug/sovereign-sealer" });
test("seal/open round trip and wrong-password rejection", async () => {
  const sealed = await sealer.seal(Buffer.from("cross-language secret"), "long test password", Buffer.from("context"));
  const blob = Buffer.from(sealed.blob_b64, "base64");
  assert.equal((await sealer.open(blob, sealed.record, "long test password", Buffer.from("context"))).toString(), "cross-language secret");
  await assert.rejects(() => sealer.open(blob, sealed.record, "wrong password", Buffer.from("context")), SealerError);
});
test("reject unsupported provider", async () => {
  await assert.rejects(() => sealer.call({operation:"seal",password:"x",provider:"Google",plaintext_b64:"eA=="}), SealerError);
});
