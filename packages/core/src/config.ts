import path from "node:path";
import { z } from "zod";

const absolutePath = z.string().min(1).refine(path.isAbsolute, "must be an absolute path");

export const configSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  DATA_DIR: absolutePath,
  REPOSITORY_DIR: absolutePath,
  DATABASE_PATH: absolutePath,
  GIT_CLONE_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(600_000).default(120_000),
  SLITHER_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(1_800_000).default(300_000),
  SCANNER_MAX_OUTPUT_BYTES: z.coerce.number().int().min(1_024).max(104_857_600).default(20_971_520),
}).superRefine((config, context) => {
  const data = path.resolve(config.DATA_DIR);
  const repo = path.resolve(config.REPOSITORY_DIR);
  const database = path.resolve(config.DATABASE_PATH);
  const inside = (candidate: string) => candidate === data || candidate.startsWith(`${data}${path.sep}`);
  if (!inside(repo)) context.addIssue({ code: "custom", path: ["REPOSITORY_DIR"], message: "must be inside DATA_DIR" });
  if (!inside(database)) context.addIssue({ code: "custom", path: ["DATABASE_PATH"], message: "must be inside DATA_DIR" });
});

export type AppConfig = z.infer<typeof configSchema>;

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): AppConfig {
  const localData = path.resolve(process.cwd(), "data");
  return configSchema.parse({
    NODE_ENV: environment.NODE_ENV,
    DATA_DIR: environment.DATA_DIR ?? localData,
    REPOSITORY_DIR: environment.REPOSITORY_DIR ?? path.join(localData, "repositories"),
    DATABASE_PATH: environment.DATABASE_PATH ?? path.join(localData, "contracthunter.db"),
    GIT_CLONE_TIMEOUT_MS: environment.GIT_CLONE_TIMEOUT_MS,
    SLITHER_TIMEOUT_MS: environment.SLITHER_TIMEOUT_MS,
    SCANNER_MAX_OUTPUT_BYTES: environment.SCANNER_MAX_OUTPUT_BYTES,
  });
}
