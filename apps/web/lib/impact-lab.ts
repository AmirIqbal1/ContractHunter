import { impactCreateSessionSchema, impactRpcConfigurationSchema, type ImpactForkSession, type ImpactRpcConfiguration } from "@contracthunter/core";
import { getDatabase, readImpactForkSession, recordImpactForkSession } from "@contracthunter/db";
import { ImpactForkService, ImpactPoCRuntimeService, type ImpactForkHandle } from "@contracthunter/scanners";

// Only server configuration names a provider. Browser input can select an ID, never a URL or secret reference.
export function configuredImpactRpcs(): ImpactRpcConfiguration[] {
  let raw: unknown;
  try { raw = JSON.parse(process.env.IMPACT_RPC_CONFIGS ?? "[]"); }
  catch { throw new Error("impact_rpc_configuration_invalid"); }
  if (!Array.isArray(raw) || raw.length > 20) throw new Error("impact_rpc_configuration_invalid");
  const configs = raw.map((entry) => impactRpcConfigurationSchema.parse(entry));
  if (new Set(configs.map((config) => config.id)).size !== configs.length) throw new Error("impact_rpc_configuration_invalid");
  return configs;
}

const state = globalThis as typeof globalThis & { contractHunterImpact?: { service: ImpactForkService; handles: Map<string, ImpactForkHandle>;
  pocRuntime?: ImpactPoCRuntimeService } };
function registry() {
  if (!state.contractHunterImpact) state.contractHunterImpact = {
    service: new ImpactForkService({ onStatus: (session) => recordImpactForkSession(getDatabase(), session) }),
    handles: new Map<string, ImpactForkHandle>(),
  };
  return state.contractHunterImpact;
}

export function createImpactForkService(): ImpactForkService { return registry().service; }
export function resolveImpactHandle(sessionId: string): ImpactForkHandle | undefined { return registry().handles.get(sessionId); }

export function createImpactPoCRuntimeService(): ImpactPoCRuntimeService {
  const current = registry();
  if (!current.pocRuntime) current.pocRuntime = new ImpactPoCRuntimeService(current.service,
    (sessionId) => current.handles.get(sessionId), process.env.IMPACT_PROBE_IMAGE_ID ?? "");
  return current.pocRuntime;
}

export function publicImpactSession(session: ImpactForkSession) {
  return { id: session.id, status: session.status, findingId: session.findingId, hypothesisId: session.hypothesisId,
    chainId: session.chainId, network: session.network, rpcConfigId: session.rpcConfigId,
    forkBlock: session.resolvedForkBlock, forkBlockHash: session.forkBlockHash,
    targetContracts: session.targetContracts.map((address) => ({ address, codeHash: session.targetCodeHashes[address] ?? null })),
    anvilVersion: session.anvilVersion, createdAt: session.createdAt, startedAt: session.startedAt,
    stoppedAt: session.stoppedAt, failureCode: session.failureCode };
}

export async function createImpactSession(input: unknown): Promise<ImpactForkSession> {
  const request = impactCreateSessionSchema.parse(input);
  const config = configuredImpactRpcs().find((item) => item.id === request.rpcConfigId && item.enabled);
  if (!config || !process.env[config.upstreamUrlSecretRef]) throw new Error("impact_rpc_configuration_unavailable");
  const { service, handles } = registry();
  const handle = service.createForkSession({ findingId: request.findingId, hypothesisId: request.hypothesisId,
    rpcConfigId: config.id, chainId: config.chainId, network: config.network,
    upstreamRpcRef: config.upstreamUrlSecretRef, forkBlock: request.forkBlock, targetContracts: request.targetContracts });
  handles.set(handle.id, handle);
  return service.startForkSession(handle);
}

export async function stopImpactSession(id: string): Promise<ImpactForkSession> {
  const { service, handles } = registry();
  const handle = handles.get(id);
  if (!handle) throw new Error("impact_session_unavailable");
  try { await registry().pocRuntime?.stopForSession(id); }
  finally {
    try { await service.stopForkSession(handle); }
    finally { handles.delete(id); }
  }
  const stopped = service.getSession(id)!;
  return stopped;
}

export async function recreateImpactSession(id: string): Promise<ImpactForkSession> {
  await registry().pocRuntime?.stopForSession(id);
  const previous = readImpactForkSession(getDatabase(), id);
  if (!previous?.rpcConfigId) throw new Error("impact_recreate_identity_invalid");
  const config = configuredImpactRpcs().find((item) => item.id === previous.rpcConfigId && item.enabled &&
    item.chainId === previous.chainId && item.network === previous.network && item.upstreamUrlSecretRef === previous.upstreamRpcRef);
  if (!config || !process.env[config.upstreamUrlSecretRef]) throw new Error("impact_rpc_configuration_unavailable");
  const { service, handles } = registry();
  const handle = service.recreateForkSession(previous);
  handles.set(handle.id, handle);
  return service.startForkSession(handle);
}
