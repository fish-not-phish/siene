# Container Registry UI

A self-hostable container registry management UI — Harbor feature-parity replacement — built with Django (backend) and Next.js (frontend).

## Architecture

- **Backend**: Django 6 + Django Ninja (REST API) + django-allauth (authentication + MFA)
- **Frontend**: Next.js 16 + React 19 + Tailwind CSS 4 + Shadcn/UI components
- **Database**: PostgreSQL 16
- **Workers**: Celery (`default` / `scans` / `sbom` queues, three separate containers) + Celery Beat (DB scheduler)
- **Registry**: Docker Distribution v3 (OCI)
- **Scanner**: Trivy (sidecar service, server mode for vuln DB caching)

## Project Structure

```
siene/
├── backend/
│   ├── backend/           # Django project settings
│   │   ├── settings.py
│   │   ├── urls.py
│   │   ├── api.py         # Ninja API root
│   │   └── wsgi.py
│   ├── registry/          # Main registry app
│   │   ├── models.py      # All ORM models
│   │   ├── api.py         # All registry endpoints + log_action()
│   │   ├── schemas.py     # All Ninja schemas
│   │   ├── auth.py        # JWT RS256 Docker token issuer
│   │   ├── crypto.py      # Fernet field encryption for RemoteRegistry.password_enc
│   │   ├── permissions.py # RBAC helpers (can_pull, can_push, can_delete, …)
│   │   ├── tasks.py       # All Celery tasks
│   │   ├── apps.py        # AppConfig (signals disconnected — no-op ready())
│   │   ├── signals.py     # Disconnected — do NOT re-enable
│   │   └── migrations/    # 0001–0031 all applied
│   ├── users/             # Auth app
│   │   ├── models.py      # UserProfile, PersonalAccessToken, SiteSettings
│   │   ├── api.py         # Auth endpoints + site-settings + PAT CRUD
│   │   ├── auth.py        # session_mfa_auth, admin_session_auth
│   │   ├── views.py
│   │   ├── adapters.py    # Social account adapter
│   │   └── signals.py
│   ├── templates/         # Allauth + MFA HTML templates
│   ├── manage.py
│   └── example.env
│
├── frontend/
│   ├── app/
│   │   ├── (app)/                    # Sidebar layout (auth-protected)
│   │   │   ├── dashboard/
│   │   │   ├── developer/            # Opens Swagger/OpenAPI docs in new tab
│   │   │   ├── projects/
│   │   │   │   ├── page.tsx          # Projects list
│   │   │   │   └── [project]/        # Per-project pages
│   │   │   │       ├── layout.tsx    # "new" slug → /projects/new redirect
│   │   │   │       ├── page.tsx      # Project overview
│   │   │   │       ├── repositories/ # Repo list → tag list (copy/retag + bulk delete; multi-arch badge on index tags) → tag detail (7 tabs; platforms card for index tags)
│   │   │   │       ├── members/
│   │   │   │       ├── robots/
│   │   │   │       ├── labels/
│   │   │   │       ├── quota/
│   │   │   │       ├── security/     # Vuln / Secrets / Misconfigs tabs (scan results)
│   │   │   │       ├── logs/         # Project audit log (server-side filtered)
│   │   │   │       └── settings/     # General + storage quota + security policy + tag policy + danger zone
│   │   │   ├── admin/
│   │   │   │   ├── dashboard/
│   │   │   │   ├── users/
│   │   │   │   ├── registries/       # Remote registry providers (card grid)
│   │   │   │   ├── replications/     # Replication rules (card list + Sheet form)
│   │   │   │   ├── jobs/             # GC + catalog sync
│   │   │   │   ├── security/
│   │   │   │   ├── settings/
│   │   │   │   └── logs/             # System audit log (server-side filtered)
│   │   │   └── profile/
│   │   │       ├── page.tsx
│   │   │       └── tokens/           # Personal Access Tokens
│   │   ├── (app-no-sidebar)/         # Auth-protected, no sidebar
│   │   │   └── projects/new/         # Full-screen new project page
│   │   ├── (auth)/                   # Login / signup
│   │   ├── (onboarding)/             # First-run onboarding
│   │   └── layout.tsx
│   ├── components/
│   │   ├── ui/                       # Shadcn/UI primitives
│   │   ├── layout/                   # AppSidebar, etc.
│   │   └── shadcn-studio/blocks/     # Feature blocks (see below)
│   ├── services/
│   │   ├── registry.ts               # All registry API calls + types
│   │   └── projects.ts
│   ├── providers/
│   │   └── ProjectsContext.tsx       # projects list + lastProject persistence
│   ├── store/
│   │   └── AuthContext.tsx           # useAuthContext() → { user }
│   ├── lib/
│   │   ├── utils.ts
│   │   └── auditLogDescription.ts    # describeLog() — human-readable log sentences
│   └── constants/
│       └── constants.ts              # baseUrl, baseUrlAccounts
│
└── docker/
    ├── docker-compose.yml            # Canonical dev compose
    ├── docker-compose.traefik.yml    # Production — Traefik reverse proxy
    └── docker-compose.nginx.yml      # Production — Nginx reverse proxy
```

## Project Security Page (`/projects/[project]/security`)

Three tabs, each with a search bar and refresh button. A summary strip across the top shows fleet-wide worst counts and turns green when nothing is found.

| Tab | Description |
|---|---|
| Vulnerabilities | Per-image Critical/High/Medium/Low badges; severity filter dropdown; links to tag detail `?tab=vulnerabilities` |
| Secrets | Per-image secrets count; green "Clean" badge if zero; links to tag detail `?tab=secrets` |
| Misconfigs | Per-image FAIL/WARN/PASS counts; links to tag detail `?tab=misconfigs` |

Data fetched via `fetchProjectSecurity`, `fetchProjectSecuritySecrets`, `fetchProjectSecurityMisconfigs` from `services/registry.ts`.

## Block Components (`frontend/components/shadcn-studio/blocks/`)

| Block | File | Description |
|---|---|---|
| Project settings | `project-settings/project-settings.tsx` | Tabbed settings: general, storage, security policy, tag policy, danger zone |
| General settings | `project-settings/content/general-settings.tsx` | |
| Storage settings | `project-settings/content/storage-settings.tsx` | |
| Security policy | `project-settings/content/security-policy.tsx` | Trivy scanning (vuln + secret + misconfig), SBOM, Cosign/Notation, pull prevention: per-severity vuln thresholds + secret count threshold + FAIL misconfig threshold; CVE/secret/misconfig project-wide allowlists |
| Tag policy | `project-settings/content/tag-policy.tsx` | Immutability toggle + retention rules |
| Danger zone | `project-settings/content/danger-zone.tsx` | |
| Members | `members/members-list.tsx` | |
| Robot accounts | `robots/robots-list.tsx` | Two-phase create (form → secret reveal) |
| Labels | `labels/labels-list.tsx` | |
| Admin users | `admin-users/admin-users-list.tsx` | Promote/demote admin via per-row dropdown; spinner during toggle; self-demotion blocked |
| Remote registries | `registries/registries-list.tsx` | Card grid per provider, connect/edit modal, real brand icons via `simple-icons` |
| Replication rules | `replications/replication-rule-sheet.tsx` | Full Sheet form: mode, filters, destination, trigger, bandwidth, options |
| Date picker filter | `date-picker-filter.tsx` | Reusable Calendar+Popover date filter for log pages |

## Tag Detail Page Tabs

The `[tag]/page.tsx` renders 7 tabs, each with its own poll loop (3 s interval):

| Tab value | Icon | Description |
|---|---|---|
| `vulnerabilities` | `ShieldAlertIcon` | Vuln scan results + CVE table; "Scan now" button |
| `secrets` | `KeySquareIcon` | Secret scan findings (rule_id, title, target, severity, line); "Scan now" button |
| `misconfigs` | `WrenchIcon` | Misconfig scan FAIL/WARN/PASS badges + collapsible findings; "Scan now" button |
| `layers` | `LayersIcon` | Image manifest layer list |
| `sbom` | `PackageIcon` | SPDX SBOM package list + license breakdown; "Generate SBOM" button |
| `signatures` | `KeyRoundIcon` | Cosign + Notation verification status |
| `manifest` | `FileTextIcon` | Raw manifest JSON |

Scan status `pending` = "In queue…"; `running` = "Scanning…" — displayed distinctly in both the card description and body spinner text.

The sticky header contains two action buttons in the `ml-auto` slot: **"Copy tag"** (opens copy/retag dialog — new tag name + optional destination repo, no data transfer) and **"Delete tag"** (destructive, with confirmation dialog).

### Multi-arch index tags

When `is_index=true` the tag detail page adapts:

- Header shows a blue **Multi-arch** badge and the platform count (e.g. `3 platforms`) instead of a single OS/arch.
- A **Platforms** card lists each child tag with its `platform` string and aggregated scan status (worst-case severity badge for vulns, FAIL/WARN/PASS for misconfigs, count for secrets). Each row links to the child tag's detail page.
- Vulnerabilities / Secrets / Misconfigs tabs show an informational notice explaining that scans run per-platform and link down to the platforms card.
- The Manifest tab renders `index_manifest` (the raw OCI index JSON) instead of `manifest`.
- Scan / SBOM trigger buttons are hidden (the backend returns HTTP 400 for index tags; scanning happens on child tags only).

## Backend Models (`registry/models.py`)

| Model | Key fields |
|---|---|
| `Project` | `name`, `display_name`, `public`, `owner`, `quota_gb` |
| `ProjectMember` | `project`, `user`, `role` (admin/maintainer/developer/guest) |
| `Repository` | `project`, `name`, `description`, `pull_count`, `push_count` |
| `Tag` | `repository`, `name`, `digest`, `size_bytes`, `os`, `architecture`, `pushed_at`, `pushed_by`, `last_activity_at` (nullable, indexed), `manifest` (JSON), `image_config` (JSON — OCI image config blob), `labels` (M2M), `is_index` (bool, db\_index — True for manifest-list/OCI-index tags), `index_manifest` (JSON — raw index manifest, nullable), `parent_tag` (FK self CASCADE nullable — set on platform child tags), `platform` (CharField nullable — e.g. `linux/amd64`) |
| `RobotAccount` | `project`, `name`, `description`, `secret_hash`, `disabled`, `expires_at`, `permissions` (JSON), `created_by` |
| `AuditLog` | `user`, `project` (nullable FK), `operation`, `resource_type`, `resource`, `result`, `detail` (JSON), `timestamp` |
| `VulnerabilityScan` | `tag` (FK, `related_name='scans'`), `status`, `started_at`, `finished_at`, `scanner` (default `'trivy'`), `summary` (JSON), `report` (JSON) |
| `SecretScan` | `tag` (FK, `related_name='secret_scans'`), `status`, `started_at`, `finished_at`, `total` (int), `report` (JSON list) |
| `MisconfigScan` | `tag` (FK, `related_name='misconfig_scans'`), `status`, `started_at`, `finished_at`, `summary` (JSON `{FAIL,WARN,PASS}`), `report` (JSON list) |
| `SBOMReport` | `tag` (FK, `related_name='sbom_reports'`), `status`, `created_at`, `finished_at`, `report` (SPDX JSON dict) |
| `TagSignatureStatus` | `tag` (OneToOne), `cosign`, `notation`, `cosign_output`, `notation_output`, `checked_at` — 5 result choices: `signed`, `not_signed`, `failed`, `unknown`, `not_available` |
| `Label` | `project`, `name`, `color`, `description` |
| `RemoteRegistry` | `name`, `registry_type` (11 providers — see below), `endpoint`, `username`, `password_enc` (Fernet-encrypted), `insecure`, `verified` |
| `ReplicationRule` | See below |
| `ReplicationJob` | `rule` (FK), `status` (pending/running/success/partial/error), `started_at`, `finished_at`, `copied`, `errors`, `log` (append-only via `.append_log(line)`) |
| `ProjectPolicy` | `scanning_enabled`, `vuln_rescan_enabled`, `vuln_rescan_interval_days`, `vuln_rescan_active_only`, `vuln_rescan_active_days`, `secret_scanning_enabled`, `misconfig_scanning_enabled`, `sbom_enabled`, `cosign_required`, `notation_required`, `prevent_vulnerable_images`, `vuln_block_rules` (JSON), `prevent_secret_images`, `secret_block_threshold` (int, nullable), `prevent_misconfig_images`, `misconfig_fail_threshold` (int, nullable), `tag_immutability`, `tag_retention_rules` (JSON) |

### SiteSettings fields

Singleton accessed via `SiteSettings.get()` (`get_or_create(pk=1)`):

| Field | Description |
|---|---|
| `gc_enabled` | Boolean — enable automatic GC |
| `gc_schedule_type` | `hourly` / `every_n_hours` / `daily` / `weekly` / `monthly` |
| `gc_interval_hours` | How often GC runs (used when `gc_schedule_type=every_n_hours`) |
| `gc_schedule_time` | HH:MM string — used for daily / weekly / monthly schedules |
| `gc_schedule_day_of_week` | 0=Monday ... 6=Sunday — used for weekly |
| `gc_schedule_day_of_month` | 1-28 — used for monthly |
| `gc_last_run_at` | Datetime of last GC run |
| `audit_log_retention_days` | Days to retain audit log entries; 0 = keep forever (default 365) |
| `job_log_retention_days` | Days to retain GC/sync/replication/Trivy job rows; 0 = keep forever (default 30) |
| `trivy_db_update_enabled` | Boolean — enable automatic Trivy DB updates |
| `trivy_db_update_interval_hours` | How often to update the Trivy vulnerability DB (default 12) |
| `trivy_db_last_updated_at` | Datetime of last Trivy DB update |
| `rescan_batch_size` | Max pending vuln scans allowed system-wide before `run_rescan_stale` skips a tick (default 200) |

### ReplicationRule fields

| Field | Default | Notes |
|---|---|---|
| `name`, `description` | | |
| `remote` | | FK → RemoteRegistry |
| `direction` | `push` | push / pull |
| `source_filter` | `''` | Glob on repo name |
| `tag_filter` | `''` | Glob on tag |
| `label_filter` | `''` | `key=value` comma list |
| `resource_type` | `all` | all / image / chart / artifact |
| `destination_namespace` | `''` | Override path on remote |
| `flatten_mode` | `flatten_1` | none / flatten\_1 / flatten\_all |
| `trigger` | `manual` | manual / on\_push / scheduled |
| `schedule` | `''` | Cron when trigger=scheduled |
| `bandwidth_limit_kb` | `-1` | -1 = unlimited |
| `override_existing` | `True` | Overwrite at destination |
| `single_active` | `False` | Queue instead of parallelise |
| `delete_remote_on_local_delete` | `False` | |
| `enabled` | `True` | |
| `last_run_at` | null | Datetime of last execution |
| `last_run_status` | `''` | Status string from last job |
| `created_at`, `updated_at` | auto | Timestamps |

### RemoteRegistry types (11 active)

`docker-hub`, `docker-registry`, `ghcr`, `ecr`, `gcr`, `acr-azure`, `tcr`, `swr`, `harbor`, `jfrog`, `generic`

(`acr-alibaba` was removed in migration 0010.)

## API Endpoints

### Auth (`/api/accounts/`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | /csrf | No | CSRF token |
| GET | /status | No | Auth status |
| GET | /me | Yes | Current user |
| POST | /change-password | Yes | Change password |
| GET | /site-settings | Admin | Site settings |
| PATCH | /site-settings | Admin | Update site settings |
| GET | /tokens | Yes | List PATs |
| POST | /tokens | Yes | Create PAT |
| DELETE | /tokens/{id} | Yes | Delete PAT |
| POST | /tokens/{id}/rotate | Yes | Rotate PAT secret — regenerates token, preserves name/expiry |

### Registry (`/api/registry/`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | /auth/token | Basic | Docker token auth (enforces quota on push-scope; enforces vuln/secret/misconfig pull prevention on pull-scope) |
| POST | /events/ | None | Registry webhook |
| GET/POST | /projects | Yes | List / create projects |
| GET/PATCH/DELETE | /projects/{name} | Yes | Project CRUD |
| GET | /projects/{name}/summary | Yes | Stats summary |
| GET/POST/PATCH/DELETE | /projects/{name}/members | Yes | Members CRUD |
| GET | /projects/{name}/repositories | Yes | List repos |
| GET/PATCH/DELETE | /projects/{name}/repositories/{repo} | Yes | Repo CRUD |
| GET | /projects/{name}/repositories/{repo}/tags | Yes | List tags |
| GET/DELETE | /projects/{name}/repositories/{repo}/tags/{tag} | Yes | Tag detail / delete |
| POST | /projects/{name}/repositories/{repo}/tags/{tag}/copy | Yes | Copy/retag — pushes manifest under a new name; `new_tag` required, `dest_repo` optional (same project); no blob transfer |
| POST | /projects/{name}/repositories/{repo}/tags/{tag}/scan | Yes | Trigger vulnerability scan |
| GET | /projects/{name}/repositories/{repo}/tags/{tag}/scan/report | Yes | Vulnerability scan report |
| POST | /projects/{name}/repositories/{repo}/tags/{tag}/secret-scan | Yes | Trigger secret scan |
| GET | /projects/{name}/repositories/{repo}/tags/{tag}/secret-scan/report | Yes | Secret scan report |
| POST | /projects/{name}/repositories/{repo}/tags/{tag}/misconfig-scan | Yes | Trigger misconfiguration scan |
| GET | /projects/{name}/repositories/{repo}/tags/{tag}/misconfig-scan/report | Yes | Misconfiguration scan report |
| POST | /projects/{name}/repositories/{repo}/tags/{tag}/sbom | Yes | Trigger SBOM generation |
| GET | /projects/{name}/repositories/{repo}/tags/{tag}/sbom | Yes | SBOM report |
| GET | /projects/{name}/repositories/{repo}/tags/{tag}/signature | Yes | Signature verification status |
| POST | /projects/{name}/repositories/{repo}/tags/{tag}/signature/verify | Yes | Queue on-demand signature verify |
| GET | /projects/{name}/repositories/{repo}/tags/{tag}/labels | Yes | Get tag labels |
| PUT | /projects/{name}/repositories/{repo}/tags/{tag}/labels | Yes | Set/replace tag labels |
| GET | /projects/{name}/audit-logs | Yes | Project audit log (filterable) |
| GET | /projects/{name}/audit-logs/export | Yes | Export project audit log as CSV or JSON (`?format=csv\|json`); same filters, no pagination |
| GET | /projects/{name}/activity | Yes | Daily push/pull counts (`days` param) |
| GET | /projects/{name}/security | Yes | Project vuln summary |
| GET | /projects/{name}/security/secrets | Yes | Per-tag secret scan summary (`SecretSummaryOut[]`) |
| GET | /projects/{name}/security/misconfigs | Yes | Per-tag misconfig scan summary (`MisconfigSummaryOut[]`) |
| GET/POST/PATCH/DELETE | /projects/{name}/robots | Yes | Robot accounts CRUD |
| POST | /projects/{name}/robots/{robot_id}/rotate | Yes | Rotate robot secret |
| GET | /users/search | Yes | User search |
| GET/POST/PATCH/DELETE | /projects/{name}/labels | Yes | Labels CRUD |
| GET/PATCH | /projects/{name}/quota | Yes | Quota |
| GET/PATCH | /projects/{name}/policy | Yes | Project policy (get_or_create) |
| POST | /projects/{name}/policy/retention/preview | Yes | Dry-run retention rules — returns kept/deleted per repo without writing |
| GET | /projects/{name}/insights/top-repos | Yes | Top repos by pull/push |
| GET | /projects/{name}/insights/operation-mix | Yes | Op breakdown |
| GET | /projects/{name}/insights/image-platforms | Yes | OS × arch distribution |
| GET | /projects/{name}/insights/scan-coverage | Yes | Scanned vs total tags |
| GET | /projects/{name}/insights/image-stats | Yes | Avg/max/min/total image size |
| GET | /projects/{name}/insights/member-roles | Yes | Member role distribution |
| GET | /system/users | Admin | All users |
| GET | /system/users/check-availability | Admin | Username + email uniqueness check |
| POST | /system/users | Admin | Create user |
| PATCH | /system/users/{id} | Admin | Promote/demote admin (`is_admin` bool); self-demotion blocked |
| DELETE | /system/users/{id} | Admin | Delete user |
| GET | /system/audit-logs | Admin | System audit log (filterable) |
| GET | /system/audit-logs/export | Admin | Export system audit log as CSV or JSON (`?format=csv\|json`); same filters, no pagination |
| GET | /system/statistics | Admin | System stats |
| GET | /system/activity | Admin | System-wide daily push/pull counts |
| GET | /system/disk | Yes | Registry storage volume free/used/total bytes |
| GET/PATCH | /system/gc/config | Admin | GC schedule config |
| POST | /system/gc | Admin | Trigger GC |
| POST | /system/gc/dry-run | Admin | Simulate GC — returns what would be deleted (orphans, retention, scan history, log rows) without writing anything; synchronous, no GCJob row created |
| GET | /system/gc/jobs | Admin | List recent GC jobs |
| GET | /system/gc/jobs/latest | Admin | Latest GC job |
| GET/PATCH | /system/trivy/config | Admin | Trivy DB update schedule config |
| POST | /system/trivy/update | Admin | Trigger Trivy DB update now |
| GET | /system/trivy/jobs | Admin | List recent Trivy DB update jobs |
| POST | /system/registry/sync | Admin | Trigger catalog sync |
| GET | /system/registry/sync/latest | Admin | Latest catalog sync job |
| GET | /system/sync/jobs | Admin | List recent catalog sync jobs |
| GET | /system/replications/all-jobs | Admin | List last 50 replication jobs across all rules |
| POST | /system/workers/reset-stale | Admin | Reset stuck pending/running scan + SBOM rows to error; flush orphaned Redis queue messages |
| GET/POST/PATCH/DELETE | /system/remote-registries | Admin | Remote registries CRUD |
| POST | /system/remote-registries/{id}/ping | Admin | Test connection |
| GET/POST/PATCH/DELETE | /system/replications | Admin | Replication rules CRUD |
| POST | /system/replications/{id}/execute | Admin | Run rule now |
| GET | /system/replications/{rule_id}/jobs | Admin | List last 50 jobs for a rule |
| GET | /system/replications/{rule_id}/jobs/{job_id} | Admin | Get a specific job |
| GET | /system/security | Admin | System-wide vuln summary |
| GET | /system/security/secrets | Admin | Per-tag secret scan summary (`SecretSummaryOut[]`); optional `?project=` filter |
| GET | /system/security/misconfigs | Admin | Per-tag misconfig scan summary (`MisconfigSummaryOut[]`); optional `?project=` filter |
| GET | /system/insights/storage-by-project | Admin | Storage per project |
| GET | /system/insights/top-repos | Admin | Top repos by pull/push |
| GET | /system/insights/operation-mix | Admin | Audit log op breakdown (last N days) |
| GET | /system/insights/image-platforms | Admin | OS × arch distribution |
| GET | /system/insights/scan-coverage | Admin | Scanned vs total tags by project |
| GET | /system/insights/vuln-by-project | Admin | CVE totals per project |
| GET | /system/insights/image-stats | Admin | Avg/max/min/total image size |

## Audit Log Filtering

Both project and system audit log endpoints support query params:

| Param | Description |
|---|---|
| `operation` | Exact match: push, pull, delete, create, update, login |
| `project_name` | System log only — filter by project name |
| `date_from` | `YYYY-MM-DD` inclusive start |
| `date_to` | `YYYY-MM-DD` inclusive end |
| `q` | `icontains` on username or resource |
| `limit` / `offset` | Pagination (default 200) |

The `/export` variants accept the same filter params (except `limit`/`offset`) plus `format=csv` (default) or `format=json` and return a file download via `Content-Disposition: attachment`. The UI exposes these as an **Export** dropdown (CSV / JSON) in the header of both log pages, passing through the current active filters.

## Celery Tasks (`registry/tasks.py`)

| Task | Queue | Description |
|---|---|---|
| `run_vulnerability_scan` | `scans` | Trivy `--scanners vuln`; preserves full CVSS v2/v3, CWE, references |
| `run_secret_scan` | `scans` | Trivy `--scanners secret` (standalone, no server mode); takes `scan_id` (SecretScan PK) |
| `run_misconfig_scan` | `scans` | Trivy `--scanners misconfig` (uses Trivy server for DB skip); takes `scan_id` (MisconfigScan PK) |
| `run_combined_scan` | `scans` | On-push path: downloads image once, runs all three enabled scan types sequentially using pre-created pending rows by PK; eliminates triple image download; safe to retry (no new rows created); dispatched once per **child** tag for multi-arch images (never on the index tag itself) |
| `run_sbom` | `sbom` | Syft SPDX generation; takes `tag_id` |
| `run_signature_check` | `default` | `cosign` + `notation` verify; updates `TagSignatureStatus` |
| `run_replication` | `default` | `skopeo copy`; creates `ReplicationJob` rows |
| `run_registry_sync` | `default` | Walks `v2/_catalog` and reconciles DB |
| `run_gc` | `default` | Orphan manifest check + tag retention + audit log rotation + schedule gating |
| `run_rescan_stale` | `default` | Periodic (every 6 h at :30); re-queues vuln scans for stale tags per project's `vuln_rescan_interval_days`; backpressure gate skips the tick if pending scan count already meets `SiteSettings.rescan_batch_size`; oldest-scanned-first ordering; filters `.filter(is_index=False)` — rescans child platform tags, never the bare index tag; secrets and misconfigs not re-queued (image content is immutable) |
| `run_trivy_db_update` | `scans` | Beat every hour at :15; interval gating from SiteSettings; runs `trivy image --download-db-only` then `--download-java-db-only`; updates `trivy_db_last_updated_at`; creates TrivyUpdateJob rows |

### Concurrency & inflight guard

- **`scans` queue**: `--concurrency 1` — all three Trivy scan types serialise here to prevent OOM
- **`sbom` queue**: `--concurrency 1` — Syft isolated to prevent OOM
- **`default` queue**: `--concurrency 4`
- **`CELERY_WORKER_PREFETCH_MULTIPLIER = 1`** — worker holds only one task in memory at a time; prevents silent task loss on OOM-kill
- **`CELERY_TASK_ACKS_LATE = True`** — task acknowledged only after completion; crashed tasks are redelivered automatically
- **`_scan_already_inflight(model_class, tag)`** in `api.py`: checked at all 6 scan/SBOM dispatch sites; returns 409 if a row with `status in ('pending', 'running')` already exists

### CELERY_BEAT_SCHEDULE

| Key | Task | Schedule |
|---|---|---|
| `gc-hourly` | `run_gc` | Every hour |
| `rescan-stale-images` | `run_rescan_stale` | Every 6 hours at :30 |
| `trivy-db-update` | `run_trivy_db_update` | Every hour at :15 |

## Key Conventions

### Frontend

- `baseUrl` must end with `/` — all fetch calls use it as `${baseUrl}registry/...`
- `useAuthContext()` → `{ user: { csrfToken, isLoggedIn, isLoading, isAdmin, username, email } }`
- `session_mfa_auth` returns `None` if unauthenticated → 401; `admin_session_auth` also checks `UserProfile.is_admin`
- **Page header**: sticky blurred header with `SidebarTrigger` + vertical `Separator` + icon + breadcrumb text; `ml-auto` for actions
- **Page body**: `<main className='flex-1 px-6 py-6'>` — add `max-w-* mx-auto` for centred narrow layouts
- **Settings blocks**: section header (title + desc left, action right), rows with `<Separator className='my-2' />` between them
- Shadcn/UI components only — no raw HTML tables outside of `<Table>` component, no Bootstrap
- `bun` is the package manager
- Secret-scan and misconfig-scan **trigger/report** calls (per-tag, on the tag detail page) are made directly via `fetch` — they are **not** exported from `services/registry.ts`
- `SecretSummary` / `MisconfigSummary` **aggregate** fetch functions (`fetchProjectSecuritySecrets`, `fetchProjectSecurityMisconfigs`, `fetchSystemSecuritySecrets`, `fetchSystemSecurityMisconfigs`) **are** exported from `services/registry.ts` — used by project dashboard, admin dashboard, and security pages

### Backend

- `log_action()` in `api.py` — non-throwing helper; call in every mutating endpoint
- **No-op guard** on all PATCH endpoints: `payload.dict(exclude_unset=True)` → `if not changes: return` before DB write and log
- `ProjectPolicy` is `get_or_create` — first access auto-creates defaults
- `SiteSettings.get()` — singleton via `get_or_create(pk=1)`
- PAT tokens and robot secrets: plaintext returned once at creation only; SHA-256 hash stored
- `registry/signals.py` exists on disk but is disconnected (`apps.py` `ready()` is a no-op) — **do not re-enable**
- `AuditLog.project` is a nullable FK — system-level events have `project=None`
- `registry/crypto.py`: Fernet (AES-128-CBC + HMAC-SHA256) encryption for `RemoteRegistry.password_enc`; key derived from `DJANGO_SECRET_KEY` via HKDF-SHA256; backwards-compatible (values without `fernet1:` prefix returned as-is)
- `_registry_delete_manifest(repo_full, digest)` in `api.py`: calls `DELETE /v2/{name}/manifests/{digest}` on Docker Distribution before removing Tag rows — used by both `delete_tag` and `delete_repository`
- `RobotAccount.disabled` (not `enabled`) — boolean, `default=False`; `ProjectMember` has 4 roles: admin / maintainer / developer / guest
- **Multi-arch**: `_process_registry_events_sync` detects manifest lists; creates one index Tag (`is_index=True`) + one child Tag per platform (`parent_tag` FK set, `platform` e.g. `linux/amd64`); child tags are named `<parent>@<platform_slug>` (e.g. `latest@linux_amd64`) and are **hidden from `list_tags`** (filtered by `parent_tag__isnull=True`); scan/SBOM endpoints return HTTP 400 on index tags; `_pull_image_to_oci_dir` accepts optional `child_digest` to pull a specific platform manifest without resolving the index; all scan tasks detect child tags via `tag.parent_tag_id` and build `docker_ref` from `tag.parent_tag.name`; schemas expose `PlatformChildOut` inside `TagDetailOut.platform_children` with aggregated scan status via `_aggregate_child_scan_status()`

## Dashboard Security Additions

Both the project dashboard (`/projects/[project]`) and admin dashboard (`/admin/dashboard`) include:

- **Security posture strip** — 3 stat cards: Critical CVEs / Secrets detected / Misconfig failures, each linking to the relevant security page
- **Extended scan coverage** (`RegistryScanCoverage`) — when `secretTotal`/`misconfigTotal` props are provided, renders three mini rings (Vuln / Secrets / Misconfigs) instead of the legacy single ring

`RegistryScanCoverage` (`components/registry-scan-coverage.tsx`) is backward-compatible: omitting the extended props falls back to the original single-ring layout.

## Route Groups

| Group | Layout | Purpose |
|---|---|---|
| `(app)` | Sidebar + `ProjectsProvider` + auth redirect | All main app pages |
| `(app-no-sidebar)` | `ProjectsProvider` + auth redirect, no sidebar | `/projects/new` full-screen |
| `(auth)` | Bare | Login, signup |
| `(onboarding)` | Bare + auth redirect | First-run onboarding |

## Migrations

| Migration | Contents |
|---|---|
| `0001_initial` | All core models |
| `0002_labels_remotes_replications` | Label, RemoteRegistry, ReplicationRule |
| `0003_projectpolicy` | ProjectPolicy |
| `0004_projectpolicy_scanning_vuln_rules` | Scanning + vuln rules fields |
| `0005_auditlog_detail` | AuditLog.detail JSONField, nullable project FK |
| `0006_replicationrule_extended_fields` | label\_filter, resource\_type, flatten\_mode, bandwidth\_limit\_kb, override\_existing, single\_active; expanded RemoteRegistry TYPE\_CHOICES |
| `0007_sbom_report` | SBOMReport model |
| `0008_tag_labels` | Tag.labels ManyToManyField to Label |
| `0009_tagsignaturestatus` | TagSignatureStatus model |
| `0010_remove_acr_alibaba` | Removes acr-alibaba from RemoteRegistry.TYPE\_CHOICES |
| `0011_replication_job` | ReplicationJob model |
| `0012_encrypt_remote_registry_passwords` | Data migration: encrypts existing plaintext passwords via Fernet |
| `0013_alter_remoteregistry_password_enc` | Alters password\_enc field schema |
| `0014_secret_misconfig_scans` | SecretScan, MisconfigScan models; ProjectPolicy.secret\_scanning\_enabled, misconfig\_scanning\_enabled |
| `0015_vuln_allowlist` | VulnAllowlistEntry model (project + optional tag scoped) |
| `0016_secret_misconfig_allowlists` | SecretAllowlistEntry, MisconfigAllowlistEntry models (tag-scoped) |
| `0017_secret_misconfig_allowlists_project_scope` | Adds nullable `project` FK to both allowlist tables; makes `tag` nullable; updates `unique_together`; backfills `project` from existing tag rows |
| `0018_projectpolicy_secret_misconfig_prevention` | ProjectPolicy: `prevent_secret_images`, `secret_block_threshold`, `prevent_misconfig_images`, `misconfig_fail_threshold` |
| `0019_drop_stale_allowlist_constraints` | Drops named UniqueConstraints from SecretAllowlistEntry left over from 0016 |
| `0020_drop_stale_vuln_allowlist_constraint` | Drops named UniqueConstraint from VulnAllowlistEntry left over from 0015 |
| `0021_fix_projectpolicy_schema` | Fixes schema discrepancies in ProjectPolicy |
| `0022_tag_image_config` | Tag.image\_config JSONField (OCI image config blob) |
| `0023_sync_job` | SyncJob model |
| `0024_gc_job` | GCJob model |
| `0025_log_retention_and_trivy_job` | TrivyUpdateJob model; SiteSettings log retention + Trivy DB schedule fields |
| `0026_projectpolicy_vuln_rescan` | ProjectPolicy: `vuln_rescan_enabled`, `vuln_rescan_interval_days` |
| `0027_scan_auditlog_indexes` | DB indexes on scan `status`, `finished_at`, and AuditLog `timestamp` |
| `0028_tag_last_activity_at` | Tag.last\_activity\_at (nullable, indexed) |
| `0029_projectpolicy_active_rescan` | ProjectPolicy: `vuln_rescan_active_only`, `vuln_rescan_active_days` |
| `0030_tag_pushed_at_no_auto_now` | Tag.pushed\_at: removes `auto_now`, set explicitly on push events only |
| `0031_multiarch_tag_fields` | Tag: `is_index` (BooleanField, db\_index), `index_manifest` (JSONField nullable), `parent_tag` (FK self CASCADE nullable), `platform` (CharField nullable) |

## Docker Compose Services

| Service | Description |
|---|---|
| `postgres` | PostgreSQL 16 |
| `redis` | Redis (Celery broker) |
| `registry` | Docker Distribution v3 (OCI) |
| `trivy` | Trivy in server mode — vuln DB caching for scan workers |
| `backend` | Django + Gunicorn |
| `siene-worker` | Celery, `default` queue, concurrency 4 — replication, GC, registry sync, signature checks |
| `siene-worker-scans` | Celery, `scans` queue, **concurrency 1** — vuln + secret + misconfig scans; mounts `trivy_cache` volume (read-only) |
| `siene-worker-sbom` | Celery, `sbom` queue, **concurrency 1** — SBOM generation (Syft); no Trivy env vars |
| `siene-beat` | Celery Beat with Django DB scheduler |
| `frontend` | Next.js |

Three compose files are kept in sync: `docker-compose.yml` (dev), `docker-compose.traefik.yml`, `docker-compose.nginx.yml`.

## Backend Dockerfile

Installs `syft` (SBOM generation), `cosign` (v2.4.3), `skopeo` (replication), and the `registry` binary (blob GC via `registry garbage-collect`) into `/usr/local/bin`.

## Environment Variables

### Core (`backend/example.env`)

| Variable | Description |
|---|---|
| `DJANGO_SECRET_KEY` / `SECRET_KEY` | Primary Django secret; also used as Fernet key derivation input |
| `DEBUG` | `1` for development |
| `ALLOWED_HOSTS` | Comma-separated |
| `CUSTOM_DOMAIN` | For CORS/cookies |
| `APP_NAME` | UI application name (default: `'Example Name'`) |
| `USE_SQLITE` | `1` to force SQLite instead of PostgreSQL |
| `DB_NAME/USER/PASSWORD/HOST/PORT` | PostgreSQL connection |
| `DB_CONN_MAX_AGE` | PostgreSQL connection max age seconds (default: `60`) |

### Registry integration

| Variable | Description |
|---|---|
| `REGISTRY_EXTERNAL_URL` | Externally reachable backend URL — baked into registry token realm and Next.js bundle |
| `REGISTRY_INTERNAL_URL` | Internal URL for registry API calls from workers (default: `http://registry:5000`) |
| `REGISTRY_INTERNAL_TOKEN` | Bearer token for registry webhook auth and internal API calls |
| `REGISTRY_HTTP_SECRET` | Docker Distribution shared secret |
| `REGISTRY_TOKEN_ISSUER` | JWT `iss` claim — must match `REGISTRY_AUTH_TOKEN_ISSUER` in Distribution config |
| `REGISTRY_TOKEN_SERVICE` | JWT `service` claim — must match `REGISTRY_AUTH_TOKEN_SERVICE` in Distribution config |
| `REGISTRY_PRIVATE_KEY_PATH` | Path to RS256 private key PEM (auto-generated if unset) |
| `REGISTRY_CERTS_DIR` | Directory for TLS certificates |
| `REGISTRY_STORAGE_PATH` | Path checked by `system/disk` endpoint (default: `'/var/lib/registry'`) |

### Trivy

| Variable | Description |
|---|---|
| `TRIVY_SERVER_URL` | Trivy server URL for vuln DB caching (e.g. `http://siene-trivy:4954`) |
| `TRIVY_CACHE_DIR` | Trivy cache directory in scan worker container |
| `TRIVY_INSECURE` | Set `true` — internal registry has no TLS |
| `TRIVY_NON_SSL` | Set `true` — internal registry has no TLS |

### OIDC / SSO

| Variable | Description |
|---|---|
| `OIDC_PROVIDER_TYPE` (or `OIDC_PROVIDER_ID`) | `keycloak` / `authelia` / `authentik` |
| `OIDC_CLIENT_ID` | OIDC client ID |
| `OIDC_CLIENT_SECRET` | OIDC client secret |
| `OIDC_SERVER_URL` | OIDC server URL |

### Email

| Variable | Description |
|---|---|
| `EMAIL_ENABLED` | `1` to enable SMTP; `0` = silent discard (default) |
| `EMAIL_HOST` | SMTP host (default: `smtp.gmail.com`) |
| `EMAIL_PORT` | SMTP port (default: `587`) |
| `EMAIL_USE_TLS` | SMTP TLS flag |
| `EMAIL_HOST_USER` | SMTP username |
| `EMAIL_HOST_PASSWORD` | SMTP password |
| `DEFAULT_FROM_EMAIL` | From address |

### Auth / security

| Variable | Description |
|---|---|
| `ACCOUNT_ALLOW_SIGNUPS` | `True`/`False` — disable to prevent self-registration |
| `SESSION_COOKIE_SECURE` | `1` when running behind HTTPS proxy |
| `CSRF_COOKIE_SECURE` | `1` with HTTPS |
| `SECURE_SSL_REDIRECT` | `1` to redirect HTTP → HTTPS |
| `SECURE_HSTS_SECONDS` | HSTS max-age (production) |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | HSTS subdomains flag |
| `SECURE_HSTS_PRELOAD` | HSTS preload flag |

### Frontend build args (baked at build time)

| Variable | Description |
|---|---|
| `NEXT_PUBLIC_BASE_URL` | External API URL — baked into Next.js bundle |
| `NEXT_PUBLIC_BASE_URL_ACCOUNTS` | External accounts URL — baked into Next.js bundle |
| `NEXT_INTERNAL_API_URL` | Server-side internal API URL inside Docker network |

## Running

```bash
# Docker
cd docker && docker-compose up -d

# Manual backend
cd backend && cp example.env .env
DJANGO_SECRET_KEY=dev python manage.py migrate
DJANGO_SECRET_KEY=dev python manage.py runserver

# Manual frontend
cd frontend && bun install && bun dev
```
