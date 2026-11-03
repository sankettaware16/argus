/**
 * What a "Check more" entity may be, as far as the page can tell before asking: an address or a
 * domain (the patterns below allow printable ASCII only). The server is the judge (it also knows
 * which addresses are the campus's and which the rule's logs allow); this only spares a person a
 * round trip for a value that could never be asked about. Mirrors
 * argus.investigation.checks.clean. Pure.
 */
export type EntityShape = "address" | "domain";

const IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:.]{2,45}$/i;
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/;

/** The shape of a value ("address" or "domain"), or null when it is neither. */
export function entityShape(raw: string): EntityShape | null {
  const value = raw.trim();
  if (IPV4.test(value)) return "address";
  if (IPV6.test(value) && value.split(":").length >= 3) return "address";
  const name = value.toLowerCase().replace(/\.$/, "");
  return DOMAIN.test(name) ? "domain" : null;
}

/** Why this template cannot be asked about this value, in plain words, or null. */
export function entityProblem(raw: string, takes: string): string | null {
  if (raw.trim() === "") return "Type an address or a domain.";
  const shape = entityShape(raw);
  if (shape === null) return "That is neither an address nor a domain.";
  if (takes !== "indicator" && shape !== "address") return "This check takes an address, not a domain name.";
  return null;
}
