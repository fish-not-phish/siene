/**
 * Typed service layer for all registry API endpoints.
 *
 * All functions expect NEXT_PUBLIC_BASE_URL to be set (e.g. "http://localhost:8000/api/").
 * They use credentials: 'include' so the Django session cookie is sent automatically.
 * Mutating calls (POST / PATCH / DELETE) require a csrfToken argument.
 */

import { baseUrl } from '@/constants/constants'

// ── Helpers ───────────────────────────────────────────────────────────────────

function api(path: string, init?: RequestInit) {
  return fetch(`${baseUrl}registry/${path}`, {
    credentials: 'include',
    ...init,
  })
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(text || `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
}

function mutate(method: string, csrfToken: string, body?: unknown): RequestInit {
  return {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrfToken,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  }
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface Project {
  id: number
  name: string
  display_name: string
  description: string
  public: boolean
  quota_gb: number | null
  owner_username: string | null
  created_at: string
  updated_at: string
}

export interface ProjectSummary {
  repo_count: number
  tag_count: number
  storage_bytes: number
}

export interface Member {
  id: number
  username: string
  email: string
  role: 'guest' | 'developer' | 'maintainer' | 'admin'
}

export interface Repository {
  id: number
  name: string
  full_name: string
  description: string
  pull_count: number
  push_count: number
  tag_count: number
  created_at: string
  updated_at: string
}

export interface Label {
  id: number
  name: string
  description: string
  color: string
  created_at: string
}

export type SignatureResult = 'signed' | 'not_signed' | 'failed' | 'unknown' | 'not_available'

export interface SignatureStatus {
  cosign: SignatureResult
  notation: SignatureResult
  cosign_output: string
  notation_output: string
  checked_at: string | null
}

export interface Tag {
  id: number
  name: string
  digest: string
  size_bytes: number
  os: string
  architecture: string
  pushed_by_username: string | null
  pushed_at: string
  last_activity_at: string | null
  scan_status: string | null
  secret_scan_status: string | null
  misconfig_scan_status: string | null
  sbom_status: string | null
  labels: Label[]
  cosign_status: SignatureResult
  notation_status: SignatureResult
}

export interface TagDetail extends Tag {
  manifest: Record<string, unknown>
}

export interface PaginatedTags {
  total: number
  items: Tag[]
}

export interface Robot {
  id: number
  name: string
  description: string
  permissions: string[]
  expires_at: string | null
  disabled: boolean
  created_at: string
}

export interface RobotCreated extends Robot {
  secret: string
}

export interface AuditLog {
  id: number
  username: string
  project_name: string | null
  resource_type: string
  resource: string
  operation: string
  result: boolean
  detail: Record<string, unknown>
  timestamp: string
}

export interface SystemStats {
  project_count: number
  repository_count: number
  user_count: number
  storage_bytes: number
}

export interface AdminUser {
  id: number
  username: string
  email: string
  is_admin: boolean
  date_joined: string
  last_login: string | null
}

export interface VulnSummary {
  tag_id: number
  tag_name: string
  repository: string
  project: string
  scan_status: string
  critical: number
  high: number
  medium: number
  low: number
  scanned_at: string | null
}

export interface ScanReport {
  status: string
  summary: Record<string, number>
  started_at: string | null
  finished_at: string | null
  report: Array<{
    vulnerability_id: string
    pkg_name: string
    installed_version: string
    fixed_version: string
    severity: string
    title: string
    suppressed?: boolean
  }>
}

// ── Projects ──────────────────────────────────────────────────────────────────

export const fetchProjects = (): Promise<Project[]> =>
  api('projects').then((r) => json<Project[]>(r))

export const createProject = (
  payload: { name: string; display_name?: string; description?: string; public?: boolean },
  csrfToken: string
): Promise<Project> =>
  api('projects', mutate('POST', csrfToken, payload)).then(async (r) => {
    if (r.status === 201) return r.json()
    throw new Error(await r.text())
  })

export const getProject = (name: string): Promise<Project> =>
  api(`projects/${name}`).then((r) => json<Project>(r))

export const updateProject = (
  name: string,
  payload: Partial<Pick<Project, 'display_name' | 'description' | 'public' | 'quota_gb'>>,
  csrfToken: string
): Promise<Project> =>
  api(`projects/${name}`, mutate('PATCH', csrfToken, payload)).then((r) => json<Project>(r))

export const deleteProject = (name: string, csrfToken: string): Promise<void> =>
  api(`projects/${name}`, mutate('DELETE', csrfToken)).then((r) => json<void>(r))

export const getProjectSummary = (name: string): Promise<ProjectSummary> =>
  api(`projects/${name}/summary`).then((r) => json<ProjectSummary>(r))

export const checkProjectNameAvailable = async (name: string): Promise<boolean> => {
  const r = await api(`projects/${name}`)
  return r.status === 404
}

// ── Members ───────────────────────────────────────────────────────────────────

export const fetchMembers = (project: string): Promise<Member[]> =>
  api(`projects/${project}/members`).then((r) => json<Member[]>(r))

export const addMember = (
  project: string,
  payload: { username: string; role: Member['role'] },
  csrfToken: string
): Promise<Member> =>
  api(`projects/${project}/members`, mutate('POST', csrfToken, payload)).then(async (r) => {
    if (r.status === 201) return r.json()
    throw new Error(await r.text())
  })

export const updateMember = (
  project: string,
  memberId: number,
  role: Member['role'],
  csrfToken: string
): Promise<Member> =>
  api(`projects/${project}/members/${memberId}`, mutate('PATCH', csrfToken, { role })).then((r) =>
    json<Member>(r)
  )

export const removeMember = (
  project: string,
  memberId: number,
  csrfToken: string
): Promise<void> =>
  api(`projects/${project}/members/${memberId}`, mutate('DELETE', csrfToken)).then((r) =>
    json<void>(r)
  )

// ── Repositories ──────────────────────────────────────────────────────────────

export const fetchRepositories = (project: string): Promise<Repository[]> =>
  api(`projects/${project}/repositories`).then((r) => json<Repository[]>(r))

export const getRepository = (project: string, repo: string): Promise<Repository> =>
  api(`projects/${project}/repositories/${repo}`).then((r) => json<Repository>(r))

export const updateRepository = (
  project: string,
  repo: string,
  description: string,
  csrfToken: string
): Promise<Repository> =>
  api(`projects/${project}/repositories/${repo}`, mutate('PATCH', csrfToken, { description })).then(
    (r) => json<Repository>(r)
  )

export const deleteRepository = (
  project: string,
  repo: string,
  csrfToken: string
): Promise<void> =>
  api(`projects/${project}/repositories/${repo}`, mutate('DELETE', csrfToken)).then((r) =>
    json<void>(r)
  )

// ── Tags ──────────────────────────────────────────────────────────────────────

export const fetchTags = (project: string, repo: string): Promise<PaginatedTags> =>
  api(`projects/${project}/repositories/${repo}/tags`).then((r) => json<PaginatedTags>(r))

export const getTag = (project: string, repo: string, tag: string): Promise<TagDetail> =>
  api(`projects/${project}/repositories/${repo}/tags/${tag}`).then((r) => json<TagDetail>(r))

export const deleteTag = (
  project: string,
  repo: string,
  tag: string,
  csrfToken: string
): Promise<void> =>
  api(`projects/${project}/repositories/${repo}/tags/${tag}`, mutate('DELETE', csrfToken)).then(
    (r) => json<void>(r)
  )

export const fetchTagLabels = (project: string, repo: string, tag: string): Promise<Label[]> =>
  api(`projects/${project}/repositories/${repo}/tags/${tag}/labels`).then((r) => json<Label[]>(r))

export const setTagLabels = (
  project: string,
  repo: string,
  tag: string,
  labelIds: number[],
  csrfToken: string
): Promise<Label[]> =>
  api(
    `projects/${project}/repositories/${repo}/tags/${tag}/labels`,
    mutate('PUT', csrfToken, { label_ids: labelIds })
  ).then((r) => json<Label[]>(r))

export const fetchSignatureStatus = (project: string, repo: string, tag: string): Promise<SignatureStatus> =>
  api(`projects/${project}/repositories/${repo}/tags/${tag}/signature`).then((r) => json<SignatureStatus>(r))

export const triggerSignatureVerify = (
  project: string,
  repo: string,
  tag: string,
  csrfToken: string
): Promise<void> =>
  api(
    `projects/${project}/repositories/${repo}/tags/${tag}/signature/verify`,
    mutate('POST', csrfToken)
  ).then((r) => json<void>(r))

export const triggerScan = (
  project: string,
  repo: string,
  tag: string,
  csrfToken: string
): Promise<void> =>
  api(
    `projects/${project}/repositories/${repo}/tags/${tag}/scan`,
    mutate('POST', csrfToken)
  ).then((r) => json<void>(r))

export const getScanReport = (
  project: string,
  repo: string,
  tag: string
): Promise<ScanReport | null> =>
  api(`projects/${project}/repositories/${repo}/tags/${tag}/scan/report`).then((r) =>
    r.status === 404 ? null : json<ScanReport>(r)
  )

export interface AuditLogFilters {
  operation?: string
  projectName?: string  // system-scope only
  dateFrom?: string     // YYYY-MM-DD
  dateTo?: string       // YYYY-MM-DD
  q?: string
  limit?: number
  offset?: number
}

export const fetchProjectAuditLogs = (project: string, filters: AuditLogFilters = {}): Promise<AuditLog[]> => {
  const p = new URLSearchParams()
  p.set('limit', String(filters.limit ?? 200))
  p.set('offset', String(filters.offset ?? 0))
  if (filters.operation) p.set('operation', filters.operation)
  if (filters.dateFrom)  p.set('date_from', filters.dateFrom)
  if (filters.dateTo)    p.set('date_to', filters.dateTo)
  if (filters.q)         p.set('q', filters.q)
  return api(`projects/${project}/audit-logs?${p}`).then((r) => json<AuditLog[]>(r))
}

export const fetchProjectSecurity = (project: string, severity = ''): Promise<VulnSummary[]> => {
  const params = new URLSearchParams()
  if (severity && severity !== 'all') params.set('severity', severity)
  const qs = params.toString()
  return api(`projects/${project}/security${qs ? `?${qs}` : ''}`).then((r) => json<VulnSummary[]>(r))
}

// ── Robot Accounts ────────────────────────────────────────────────────────────

export const fetchRobots = (project: string): Promise<Robot[]> =>
  api(`projects/${project}/robots`).then((r) => json<Robot[]>(r))

export const createRobot = (
  project: string,
  payload: { name: string; description?: string; permissions?: string[]; expires_at?: string },
  csrfToken: string
): Promise<RobotCreated> =>
  api(`projects/${project}/robots`, mutate('POST', csrfToken, payload)).then(async (r) => {
    if (r.status === 201) return r.json()
    throw new Error(await r.text())
  })

export const updateRobot = (
  project: string,
  robotId: number,
  payload: Partial<Pick<Robot, 'description' | 'disabled' | 'permissions' | 'expires_at'>>,
  csrfToken: string
): Promise<Robot> =>
  api(`projects/${project}/robots/${robotId}`, mutate('PATCH', csrfToken, payload)).then((r) =>
    json<Robot>(r)
  )

export const rotateRobot = (
  project: string,
  robotId: number,
  csrfToken: string,
): Promise<{ secret: string }> =>
  api(`projects/${project}/robots/${robotId}/rotate`, mutate('POST', csrfToken)).then((r) =>
    json<{ secret: string }>(r)
  )

export const deleteRobot = (
  project: string,
  robotId: number,
  csrfToken: string
): Promise<void> =>
  api(`projects/${project}/robots/${robotId}`, mutate('DELETE', csrfToken)).then((r) =>
    json<void>(r)
  )

// ── Project Policy ────────────────────────────────────────────────────────────

export interface TagRetentionRule {
  match: string          // glob pattern, e.g. "v*" or "**"
  keep_count: number | null
  keep_days: number | null
}

export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low'

/** Per-severity max allowed counts. null = not enforced, 0 = zero tolerance. */
export type VulnBlockRules = Partial<Record<VulnSeverity, number | null>>

export interface ProjectPolicy {
  sbom_enabled: boolean
  scanning_enabled: boolean
  secret_scanning_enabled: boolean
  misconfig_scanning_enabled: boolean
  cosign_required: boolean
  notation_required: boolean
  prevent_vulnerable_images: boolean
  /** Per-severity thresholds. Missing keys = not enforced for that severity. */
  vuln_block_rules: VulnBlockRules
  prevent_secret_images: boolean
  /** Max allowed secrets count. null = not enforced, 0 = zero tolerance. */
  secret_block_threshold: number | null
  prevent_misconfig_images: boolean
  /** Max allowed FAIL misconfig count. null = not enforced, 0 = zero tolerance. */
  misconfig_fail_threshold: number | null
  tag_immutability: boolean
  tag_retention_rules: TagRetentionRule[]
  /** Enable periodic automated vulnerability re-scans (only applies when scanning_enabled=true). */
  vuln_rescan_enabled: boolean
  /** How many days between automated vulnerability re-scans. Supported values: 1, 7, 14, 30. */
  vuln_rescan_interval_days: number
  /** Only re-scan tags that have had push/pull activity within vuln_rescan_active_days days. */
  vuln_rescan_active_only: boolean
  /** Staleness window in days. Tags with no activity older than this are skipped and marked stale. */
  vuln_rescan_active_days: number
}

export const fetchProjectPolicy = (projectName: string): Promise<ProjectPolicy> =>
  api(`projects/${projectName}/policy`).then((r) => json<ProjectPolicy>(r))

export const updateProjectPolicy = (
  projectName: string,
  patch: Partial<ProjectPolicy>,
  csrfToken: string,
): Promise<ProjectPolicy> =>
  api(`projects/${projectName}/policy`, mutate('PATCH', csrfToken, patch)).then((r) =>
    json<ProjectPolicy>(r),
  )

// ── System / Admin ────────────────────────────────────────────────────────────

export interface UserSearchResult {
  id: number
  username: string
  email: string
}

export const searchUsers = (q: string, projectName?: string, limit = 10): Promise<UserSearchResult[]> => {
  const params = new URLSearchParams({ q, limit: String(limit) })
  if (projectName) params.set('project_name', projectName)
  return api(`users/search?${params}`).then((r) => json<UserSearchResult[]>(r))
}

export const fetchAdminUsers = (): Promise<AdminUser[]> =>
  api('system/users').then((r) => json<AdminUser[]>(r))

export const checkUserAvailability = (
  params: { username?: string; email?: string },
): Promise<{ username_available?: boolean; email_available?: boolean }> => {
  const qs = new URLSearchParams()
  if (params.username) qs.set('username', params.username)
  if (params.email) qs.set('email', params.email)
  return api(`system/users/check-availability?${qs}`).then((r) =>
    json<{ username_available?: boolean; email_available?: boolean }>(r),
  )
}

export const createAdminUser = (
  payload: { username: string; email: string; password: string },
  csrfToken: string,
): Promise<AdminUser> =>
  api('system/users', mutate('POST', csrfToken, payload)).then((r) => json<AdminUser>(r))

export const deleteAdminUser = (userId: number, csrfToken: string): Promise<void> =>
  api(`system/users/${userId}`, mutate('DELETE', csrfToken)).then((r) => json<void>(r))

export const patchAdminUser = (
  userId: number,
  payload: { is_admin: boolean },
  csrfToken: string,
): Promise<AdminUser> =>
  api(`system/users/${userId}`, mutate('PATCH', csrfToken, payload)).then((r) => json<AdminUser>(r))

export const fetchAuditLogs = (filters: AuditLogFilters = {}): Promise<AuditLog[]> => {
  const p = new URLSearchParams()
  p.set('limit', String(filters.limit ?? 200))
  p.set('offset', String(filters.offset ?? 0))
  if (filters.operation)   p.set('operation', filters.operation)
  if (filters.projectName) p.set('project_name', filters.projectName)
  if (filters.dateFrom)    p.set('date_from', filters.dateFrom)
  if (filters.dateTo)      p.set('date_to', filters.dateTo)
  if (filters.q)           p.set('q', filters.q)
  return api(`system/audit-logs?${p}`).then((r) => json<AuditLog[]>(r))
}

export const fetchSystemStats = (): Promise<SystemStats> =>
  api('system/statistics').then((r) => json<SystemStats>(r))

export const triggerGC = (csrfToken: string): Promise<void> =>
  api('system/gc', mutate('POST', csrfToken)).then((r) => json<void>(r))

export const syncRegistry = (csrfToken: string): Promise<void> =>
  api('system/registry/sync', mutate('POST', csrfToken)).then((r) => json<void>(r))

export interface ActivityDay {
  date: string   // YYYY-MM-DD
  pushes: number
  pulls: number
}

export const fetchSystemActivity = (days = 365, projects?: string[]): Promise<ActivityDay[]> => {
  const params = new URLSearchParams({ days: String(days) })
  if (projects && projects.length > 0) params.set('projects', projects.join(','))
  return api(`system/activity?${params}`).then((r) => json<ActivityDay[]>(r))
}

export const fetchProjectActivity = (project: string, days = 365): Promise<ActivityDay[]> =>
  api(`projects/${project}/activity?days=${days}`).then((r) => json<ActivityDay[]>(r))

// ── Insight / Aggregation ─────────────────────────────────────────────────────

export interface StorageByProject {
  project: string
  storage_bytes: number
  tag_count: number
}

export interface TopRepo {
  name: string
  project: string
  full_name: string
  pull_count: number
  push_count: number
  tag_count: number
}

export interface OperationCount {
  operation: string
  count: number
}

export interface ImagePlatform {
  os: string
  architecture: string
  count: number
  label: string
}

export interface ScanCoverageByProject {
  project: string
  total: number
  scanned: number
}

export interface ScanCoverage {
  total: number
  scanned: number
  by_project: ScanCoverageByProject[]
}

export interface VulnByProject {
  project: string
  critical: number
  high: number
  medium: number
  low: number
  image_count: number
}

export interface ImageStats {
  avg_bytes: number
  max_bytes: number
  min_bytes: number
  total_bytes: number
  total_tags: number
}

export interface MemberRoleCount {
  role: string
  count: number
}

// System-wide insight fetchers (admin only)
export const fetchSystemStorageByProject = (): Promise<StorageByProject[]> =>
  api('system/insights/storage-by-project').then((r) => json<StorageByProject[]>(r))

export const fetchSystemTopRepos = (limit = 10, orderBy: 'pulls' | 'pushes' = 'pulls', projects?: string[]): Promise<TopRepo[]> => {
  const params = new URLSearchParams({ limit: String(limit), order_by: orderBy })
  if (projects && projects.length > 0) params.set('projects', projects.join(','))
  return api(`system/insights/top-repos?${params}`).then((r) => json<TopRepo[]>(r))
}

export const fetchSystemOperationMix = (days = 30, projects?: string[]): Promise<OperationCount[]> => {
  const params = new URLSearchParams({ days: String(days) })
  if (projects && projects.length > 0) params.set('projects', projects.join(','))
  return api(`system/insights/operation-mix?${params}`).then((r) => json<OperationCount[]>(r))
}

export const fetchSystemImagePlatforms = (projects?: string[]): Promise<ImagePlatform[]> => {
  const params = new URLSearchParams()
  if (projects && projects.length > 0) params.set('projects', projects.join(','))
  const qs = params.toString()
  return api(`system/insights/image-platforms${qs ? `?${qs}` : ''}`).then((r) => json<ImagePlatform[]>(r))
}

export const fetchSystemScanCoverage = (projects?: string[]): Promise<ScanCoverage> => {
  const params = new URLSearchParams()
  if (projects && projects.length > 0) params.set('projects', projects.join(','))
  const qs = params.toString()
  return api(`system/insights/scan-coverage${qs ? `?${qs}` : ''}`).then((r) => json<ScanCoverage>(r))
}

export const fetchSystemVulnByProject = (projects?: string[]): Promise<VulnByProject[]> => {
  const params = new URLSearchParams()
  if (projects && projects.length > 0) params.set('projects', projects.join(','))
  const qs = params.toString()
  return api(`system/insights/vuln-by-project${qs ? `?${qs}` : ''}`).then((r) => json<VulnByProject[]>(r))
}

export const fetchSystemImageStats = (projects?: string[]): Promise<ImageStats> => {
  const params = new URLSearchParams()
  if (projects && projects.length > 0) params.set('projects', projects.join(','))
  const qs = params.toString()
  return api(`system/insights/image-stats${qs ? `?${qs}` : ''}`).then((r) => json<ImageStats>(r))
}

// Per-project insight fetchers
export const fetchProjectTopRepos = (project: string, limit = 10): Promise<TopRepo[]> =>
  api(`projects/${project}/insights/top-repos?limit=${limit}`).then((r) => json<TopRepo[]>(r))

export const fetchProjectOperationMix = (project: string, days = 30): Promise<OperationCount[]> =>
  api(`projects/${project}/insights/operation-mix?days=${days}`).then((r) => json<OperationCount[]>(r))

export const fetchProjectImagePlatforms = (project: string): Promise<ImagePlatform[]> =>
  api(`projects/${project}/insights/image-platforms`).then((r) => json<ImagePlatform[]>(r))

export const fetchProjectScanCoverage = (project: string): Promise<{ total: number; scanned: number }> =>
  api(`projects/${project}/insights/scan-coverage`).then((r) => json<{ total: number; scanned: number }>(r))

export const fetchProjectImageStats = (project: string): Promise<ImageStats> =>
  api(`projects/${project}/insights/image-stats`).then((r) => json<ImageStats>(r))

export const fetchProjectMemberRoles = (project: string): Promise<MemberRoleCount[]> =>
  api(`projects/${project}/insights/member-roles`).then((r) => json<MemberRoleCount[]>(r))

// ── Security summaries (secret + misconfig) ───────────────────────────────────

export interface SecretSummary {
  tag_id: number
  tag_name: string
  repository: string
  project: string
  scan_status: string
  total: number
  scanned_at: string | null
}

export interface MisconfigSummary {
  tag_id: number
  tag_name: string
  repository: string
  project: string
  scan_status: string
  fail: number
  warn: number
  pass_count: number
  scanned_at: string | null
}

export const fetchProjectSecuritySecrets = (project: string): Promise<SecretSummary[]> =>
  api(`projects/${project}/security/secrets`).then((r) => json<SecretSummary[]>(r))

export const fetchProjectSecurityMisconfigs = (project: string): Promise<MisconfigSummary[]> =>
  api(`projects/${project}/security/misconfigs`).then((r) => json<MisconfigSummary[]>(r))

export const fetchSystemSecuritySecrets = (project?: string, projects?: string[]): Promise<SecretSummary[]> => {
  const params = new URLSearchParams()
  if (projects && projects.length > 0) params.set('projects', projects.join(','))
  else if (project) params.set('project', project)
  const qs = params.toString()
  return api(`system/security/secrets${qs ? `?${qs}` : ''}`).then((r) => json<SecretSummary[]>(r))
}

export const fetchSystemSecurityMisconfigs = (project?: string, projects?: string[]): Promise<MisconfigSummary[]> => {
  const params = new URLSearchParams()
  if (projects && projects.length > 0) params.set('projects', projects.join(','))
  else if (project) params.set('project', project)
  const qs = params.toString()
  return api(`system/security/misconfigs${qs ? `?${qs}` : ''}`).then((r) => json<MisconfigSummary[]>(r))
}

// ── CVE Allowlist ─────────────────────────────────────────────────────────────

export interface AllowlistEntry {
  id: number
  cve_id: string
  reason: string
  expires_at: string | null
  created_at: string
  is_expired: boolean
  tag_id: number | null
  tag_name: string | null
  added_by_username: string | null
}

export const fetchAllowlist = (project: string): Promise<AllowlistEntry[]> =>
  api(`projects/${encodeURIComponent(project)}/allowlist`).then((r) => json<AllowlistEntry[]>(r))

export const createAllowlistEntry = (
  project: string,
  payload: { cve_id: string; reason?: string; expires_at?: string | null; tag_id?: number | null },
  csrfToken: string
): Promise<AllowlistEntry> =>
  api(`projects/${encodeURIComponent(project)}/allowlist`, mutate('POST', csrfToken, payload))
    .then(async (r) => {
      if (r.status === 201) return r.json()
      throw new Error(await r.text())
    })

export const deleteAllowlistEntry = (
  project: string,
  entryId: number,
  csrfToken: string
): Promise<void> =>
  api(`projects/${encodeURIComponent(project)}/allowlist/${entryId}`, mutate('DELETE', csrfToken))
    .then(async (r) => {
      if (!r.ok) throw new Error(await r.text())
    })

// ── Secret Allowlist ──────────────────────────────────────────────────────────

export interface SecretAllowlistEntry {
  id: number
  rule_id: string
  reason: string
  expires_at: string | null
  created_at: string
  is_expired: boolean
  project_id: number | null
  tag_id: number | null
  added_by_username: string | null
}

// Project-wide secret allowlist CRUD
export const fetchProjectSecretAllowlist = (project: string): Promise<SecretAllowlistEntry[]> =>
  api(`projects/${encodeURIComponent(project)}/secret-allowlist`).then((r) => json<SecretAllowlistEntry[]>(r))

export const createProjectSecretAllowlistEntry = (
  project: string,
  payload: { rule_id: string; reason?: string; expires_at?: string | null },
  csrfToken: string
): Promise<SecretAllowlistEntry> =>
  api(`projects/${encodeURIComponent(project)}/secret-allowlist`, mutate('POST', csrfToken, payload))
    .then(async (r) => {
      if (r.status === 201) return r.json()
      throw new Error(await r.text())
    })

export const deleteProjectSecretAllowlistEntry = (
  project: string,
  entryId: number,
  csrfToken: string
): Promise<void> =>
  api(`projects/${encodeURIComponent(project)}/secret-allowlist/${entryId}`, mutate('DELETE', csrfToken))
    .then(async (r) => {
      if (!r.ok) throw new Error(await r.text())
    })

const tagAllowlistBase = (project: string, repo: string, tag: string) =>
  `projects/${encodeURIComponent(project)}/repositories/${encodeURIComponent(repo)}/tags/${encodeURIComponent(tag)}`

export const fetchSecretAllowlist = (project: string, repo: string, tag: string): Promise<SecretAllowlistEntry[]> =>
  api(`${tagAllowlistBase(project, repo, tag)}/secret-allowlist`).then((r) => json<SecretAllowlistEntry[]>(r))

export const createSecretAllowlistEntry = (
  project: string,
  repo: string,
  tag: string,
  payload: { rule_id: string; reason?: string; expires_at?: string | null },
  csrfToken: string
): Promise<SecretAllowlistEntry> =>
  api(`${tagAllowlistBase(project, repo, tag)}/secret-allowlist`, mutate('POST', csrfToken, payload))
    .then(async (r) => {
      if (r.status === 201) return r.json()
      throw new Error(await r.text())
    })

export const deleteSecretAllowlistEntry = (
  project: string,
  repo: string,
  tag: string,
  entryId: number,
  csrfToken: string
): Promise<void> =>
  api(`${tagAllowlistBase(project, repo, tag)}/secret-allowlist/${entryId}`, mutate('DELETE', csrfToken))
    .then(async (r) => {
      if (!r.ok) throw new Error(await r.text())
    })

// ── Misconfig Allowlist ───────────────────────────────────────────────────────

export interface MisconfigAllowlistEntry {
  id: number
  check_id: string
  reason: string
  expires_at: string | null
  created_at: string
  is_expired: boolean
  project_id: number | null
  tag_id: number | null
  added_by_username: string | null
}

// Project-wide misconfig allowlist CRUD
export const fetchProjectMisconfigAllowlist = (project: string): Promise<MisconfigAllowlistEntry[]> =>
  api(`projects/${encodeURIComponent(project)}/misconfig-allowlist`).then((r) => json<MisconfigAllowlistEntry[]>(r))

export const createProjectMisconfigAllowlistEntry = (
  project: string,
  payload: { check_id: string; reason?: string; expires_at?: string | null },
  csrfToken: string
): Promise<MisconfigAllowlistEntry> =>
  api(`projects/${encodeURIComponent(project)}/misconfig-allowlist`, mutate('POST', csrfToken, payload))
    .then(async (r) => {
      if (r.status === 201) return r.json()
      throw new Error(await r.text())
    })

export const deleteProjectMisconfigAllowlistEntry = (
  project: string,
  entryId: number,
  csrfToken: string
): Promise<void> =>
  api(`projects/${encodeURIComponent(project)}/misconfig-allowlist/${entryId}`, mutate('DELETE', csrfToken))
    .then(async (r) => {
      if (!r.ok) throw new Error(await r.text())
    })

export const fetchMisconfigAllowlist = (project: string, repo: string, tag: string): Promise<MisconfigAllowlistEntry[]> =>
  api(`${tagAllowlistBase(project, repo, tag)}/misconfig-allowlist`).then((r) => json<MisconfigAllowlistEntry[]>(r))

export const createMisconfigAllowlistEntry = (
  project: string,
  repo: string,
  tag: string,
  payload: { check_id: string; reason?: string; expires_at?: string | null },
  csrfToken: string
): Promise<MisconfigAllowlistEntry> =>
  api(`${tagAllowlistBase(project, repo, tag)}/misconfig-allowlist`, mutate('POST', csrfToken, payload))
    .then(async (r) => {
      if (r.status === 201) return r.json()
      throw new Error(await r.text())
    })

export const deleteMisconfigAllowlistEntry = (
  project: string,
  repo: string,
  tag: string,
  entryId: number,
  csrfToken: string
): Promise<void> =>
  api(`${tagAllowlistBase(project, repo, tag)}/misconfig-allowlist/${entryId}`, mutate('DELETE', csrfToken))
    .then(async (r) => {
      if (!r.ok) throw new Error(await r.text())
    })

// ── Tag retention preview ─────────────────────────────────────────────────────

export interface RetentionPreviewRepo {
  repo: string
  matched: number
  kept: string[]
  deleted: string[]
}

export interface RetentionPreviewResult {
  total_matched: number
  total_deleted: number
  repos: RetentionPreviewRepo[]
}

export const previewRetentionRule = (
  project: string,
  rule: TagRetentionRule,
  csrfToken: string
): Promise<RetentionPreviewResult> =>
  api(
    `projects/${project}/policy/retention/preview`,
    mutate('POST', csrfToken, rule)
  ).then(async (r) => {
    if (!r.ok) throw new Error(await r.text())
    return r.json()
  })
