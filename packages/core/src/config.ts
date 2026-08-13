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
  ADERYN_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(1_800_000).default(300_000),
  SCANNER_MAX_OUTPUT_BYTES: z.coerce.number().int().min(1_024).max(104_857_600).default(20_971_520),
  SOLC_INSTALL_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(600_000).default(120_000),
  MAX_SOLC_VERSIONS_PER_SCAN: z.coerce.number().int().min(1).max(32).default(8),
  ALLOW_COMPILER_DOWNLOADS: z.enum(["true", "false"]).default("true").transform((value) => value === "true"),
  TOOL_HOME_DIR: absolutePath,
  DEPENDENCY_PREP_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(1_800_000).default(300_000),
  MAX_DEPENDENCY_OUTPUT_BYTES: z.coerce.number().int().min(1_024).max(104_857_600).default(20_971_520),
  MAX_SUBMODULE_DEPTH: z.coerce.number().int().min(1).max(20).default(5),
  MAX_SUBMODULES_PER_SCAN: z.coerce.number().int().min(1).max(1_000).default(100),
  ALLOW_NPM_DEPENDENCIES: z.enum(["true", "false"]).default("true").transform((value) => value === "true"),
  ALLOW_GIT_SUBMODULES: z.enum(["true", "false"]).default("true").transform((value) => value === "true"),
  ALLOWED_GIT_DEPENDENCY_HOSTS: z.string().default("github.com").transform((value, context) => {
    const hosts = [...new Set(value.split(",").map((host) => host.trim().toLowerCase()).filter(Boolean))];
    if (!hosts.length || hosts.some((host) => !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(host))) {
      context.addIssue({ code: "custom", message: "must be a comma-separated hostname allowlist" });
      return z.NEVER;
    }
    return hosts;
  }),
}).superRefine((config, context) => {
  const data = path.resolve(config.DATA_DIR);
  const repo = path.resolve(config.REPOSITORY_DIR);
  const database = path.resolve(config.DATABASE_PATH);
  const toolHome = path.resolve(config.TOOL_HOME_DIR);
  const inside = (candidate: string) => candidate === data || candidate.startsWith(`${data}${path.sep}`);
  if (!inside(repo)) context.addIssue({ code: "custom", path: ["REPOSITORY_DIR"], message: "must be inside DATA_DIR" });
  if (!inside(database)) context.addIssue({ code: "custom", path: ["DATABASE_PATH"], message: "must be inside DATA_DIR" });
  if (!inside(toolHome)) context.addIssue({ code: "custom", path: ["TOOL_HOME_DIR"], message: "must be inside DATA_DIR" });
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
    ADERYN_TIMEOUT_MS: environment.ADERYN_TIMEOUT_MS,
    SCANNER_MAX_OUTPUT_BYTES: environment.SCANNER_MAX_OUTPUT_BYTES,
    SOLC_INSTALL_TIMEOUT_MS: environment.SOLC_INSTALL_TIMEOUT_MS,
    MAX_SOLC_VERSIONS_PER_SCAN: environment.MAX_SOLC_VERSIONS_PER_SCAN,
    ALLOW_COMPILER_DOWNLOADS: environment.ALLOW_COMPILER_DOWNLOADS,
    TOOL_HOME_DIR: environment.TOOL_HOME_DIR ?? path.join(localData, "tool-home"),
    DEPENDENCY_PREP_TIMEOUT_MS: environment.DEPENDENCY_PREP_TIMEOUT_MS,
    MAX_DEPENDENCY_OUTPUT_BYTES: environment.MAX_DEPENDENCY_OUTPUT_BYTES,
    MAX_SUBMODULE_DEPTH: environment.MAX_SUBMODULE_DEPTH,
    MAX_SUBMODULES_PER_SCAN: environment.MAX_SUBMODULES_PER_SCAN,
    ALLOW_NPM_DEPENDENCIES: environment.ALLOW_NPM_DEPENDENCIES,
    ALLOW_GIT_SUBMODULES: environment.ALLOW_GIT_SUBMODULES,
    ALLOWED_GIT_DEPENDENCY_HOSTS: environment.ALLOWED_GIT_DEPENDENCY_HOSTS,
  });
}
