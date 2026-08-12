export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { getJobRunner } = await import("./lib/runner");
    getJobRunner();
  }
}
