/**
 * App or AI: whether a finding is an application vulnerability or an AI
 * vulnerability. The API decides, from the scanners that reported the finding
 * (model.DomainOf): anything an AI scanner (NuGuard) reported is AI, the rest
 * is App. One set of words for the filter, its chips, the table and the
 * finding page.
 */
export type Domain = 'app' | 'ai';

export const DOMAINS: Domain[] = ['app', 'ai'];

export const DOMAIN_LABEL: Record<Domain, string> = {
  app: 'App vulnerability',
  ai: 'AI vulnerability',
};

export const DOMAIN_SHORT: Record<Domain, string> = {
  app: 'App',
  ai: 'AI',
};

export const DOMAIN_HINT: Record<Domain, string> = {
  app: 'An application vulnerability: found by the code, dependency, secret and configuration scanners',
  ai: 'An AI vulnerability: found by an AI scanner (NuGuard), in how the code uses models, agents, prompts and tools',
};

export function domainLabel(value: string): string {
  return (DOMAIN_LABEL as Record<string, string>)[value] ?? value;
}
