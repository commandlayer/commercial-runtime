export const SERVICE_VERSION_DEFAULT = "1.1.0";
export const API_VERSION_DEFAULT = "1.1.0";
export const COMMERCIAL_CLASS = "commercial";

export function buildCommercialEntry(verb, version = API_VERSION_DEFAULT) {
  return `x402://${verb}agent.eth/${verb}/v${version}`;
}
