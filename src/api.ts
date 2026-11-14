import {
  AccountApi,
  AuditsApi,
  EvaluationsApi,
  FindingsApi,
  MonitoringApi,
  PolicyApi,
  PullRequestsApi,
  ReportsApi,
  ReposApi,
  VetkitTransport,
  type VetkitClientOptions,
  WorkApi,
} from '#vendor/api-client';

/**
 * The only API methods the MCP server and its hook may call. The published bundle includes just
 * the domain clients below, so admin, billing and other internal endpoints never ship in the npm
 * package, and a method outside this list does not exist on the client at runtime.
 */
export const MCP_API_METHODS = [
  'me',
  'listRepos',
  'getRepo',
  'connectRepo',
  'getAnalyzers',
  'createAudit',
  'getAudit',
  'listFindings',
  'getReport',
  'getReportText',
  'getAuditStandards',
  'getRepositoryMemory',
  'refreshRepositoryMemory',
  'getRepoMonitoring',
  'updateRepoMonitoring',
  'listEvaluationRuns',
  'getEvaluationRun',
  'listEvaluationBaselines',
  'listEvaluationBaselineVersions',
  'compareEvaluationBaseline',
  'createEvaluationRun',
  'cancelEvaluationRun',
  'openFixPr',
  'triageFindings',
  'previewAiFix',
  'validateOrgPolicy',
  'checkPackages',
  'scanChanges',
  'listOrgPullRequestReviews',
  'listPullRequestReviews',
  'listWorkItems',
  'getWorkItem',
  'getFindingWorkItem',
  'updateWorkItem',
  'verifyWorkItemFix',
  'listSuppressions',
  'suppressFinding',
] as const satisfies readonly (keyof McpDomains)[];

/** Only the domain clients the MCP server uses, so the published types skip admin and billing APIs. */
type McpDomains = AccountApi &
  AuditsApi &
  EvaluationsApi &
  FindingsApi &
  MonitoringApi &
  PolicyApi &
  PullRequestsApi &
  ReportsApi &
  ReposApi &
  WorkApi;

export type VetkitApi = Pick<McpDomains, (typeof MCP_API_METHODS)[number]>;

const DOMAINS = [
  AccountApi,
  AuditsApi,
  EvaluationsApi,
  FindingsApi,
  MonitoringApi,
  PolicyApi,
  PullRequestsApi,
  ReportsApi,
  ReposApi,
  WorkApi,
] as const;

class McpApiClient extends VetkitTransport {}

for (const name of MCP_API_METHODS) {
  const domain = DOMAINS.find((d) => Object.prototype.hasOwnProperty.call(d.prototype, name));
  if (!domain) throw new Error(`vetkit MCP API method ${name} has no domain client`);
  Object.defineProperty(
    McpApiClient.prototype,
    name,
    Object.getOwnPropertyDescriptor(domain.prototype, name)!,
  );
}

/** API client limited to `MCP_API_METHODS`; it shares one transport for all calls. */
export const createMcpApi = (opts: VetkitClientOptions): VetkitApi =>
  new McpApiClient(opts) as unknown as VetkitApi;
