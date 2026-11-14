import {
  type AGENT_CHECK_MAX_PACKAGES as RULES_MAX_PACKAGES,
  type AgentCheckEcosystem as RulesEcosystem,
  type AgentCheckPackage as RulesPackage,
} from '#vendor/agent-rules';
import {
  type AGENT_CHECK_MAX_PACKAGES as SHARED_MAX_PACKAGES,
  type AgentCheckEcosystem,
  type AgentCheckPackage,
} from '#vendor/shared';

/**
 * The install-command parser moved to `@vetkit/agent-rules` (pure, shared with VetKit Agent Watch, which runs
 * it on declared and observed commands). tsdown bundles it into the published package like the other private
 * `@vetkit/*` workspace sources, so `@vetkit/mcp` keeps no runtime dependency on it.
 */
export {
  type InstallRequest,
  parseCargoSpec,
  parseGoSpec,
  parseInstallCommands,
  parseNpmSpec,
  parsePipSpec,
  parsePoetrySpec,
  splitShell,
} from '#vendor/agent-rules';

// Compile-time guard: agent-rules mirrors the shared agent-check contract (it has no dependency on
// @vetkit/shared); a drift on either side fails this package's typecheck.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
type Assert<T extends true> = T;
type _AgentCheckContractInSync = [
  Assert<Same<RulesEcosystem, AgentCheckEcosystem>>,
  Assert<Same<RulesPackage, AgentCheckPackage>>,
  Assert<Same<typeof RULES_MAX_PACKAGES, typeof SHARED_MAX_PACKAGES>>,
];
