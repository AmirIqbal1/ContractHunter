import { describe, expect, it } from "vitest";
import { runBoundedProcess } from "./process-runner";

describe("bounded process execution", () => {
  it("passes shell metacharacters as literal argv", async () => {
    const literal = "$(touch /tmp/contracthunter-must-not-exist); & | >";
    const result = await runBoundedProcess({
      command: "/usr/bin/printf",
      args: ["%s", literal],
      timeoutMs: 5_000,
      maxOutputBytes: 1_024,
      env: { PATH: process.env.PATH, NODE_ENV: "test" },
    });
    expect(result).toMatchObject({ exitCode: 0, stdout: literal, stderr: "" });
  });
});
