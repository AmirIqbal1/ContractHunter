/** Fail closed for text that could disclose local paths, endpoints, or credential assignments. */
const sensitive = /(?:\b(?:https?|wss?|file):\/\/[^\s"']+|\/(?:home|root|tmp|Users|mnt|opt|etc|run|srv|private|usr\/local|var\/run|workspace|app)\/[^\s"']+|[A-Za-z]:\\[^\s"']+|docker\.sock|(?:private[_ -]?key|rpc[_ -]?url|worker[_ -]?secret|runtime[_ -]?token|api[_ -]?key|mnemonic|password|seed[_ -]?phrase)["']?\s*[:=]\s*["']?\S+)/i;
const credentialOrEndpoint = /(?:\b(?:https?|wss?|file):\/\/[^\s"']+|(?:private[_ -]?key|rpc[_ -]?url|worker[_ -]?secret|runtime[_ -]?token|api[_ -]?key|mnemonic|password|seed[_ -]?phrase)["']?\s*[:=]\s*["']?\S+)/i;

export function containsSensitiveExportText(value: string): boolean { return sensitive.test(value); }
export function containsCredentialOrEndpointText(value: string): boolean { return credentialOrEndpoint.test(value); }
