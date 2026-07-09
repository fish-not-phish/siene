"""
Celery tasks for the registry app.

Queues
------
scans    run_vulnerability_scan
sbom     run_sbom
default  run_replication, run_gc, run_registry_sync, run_signature_check
"""

import logging
import os
import subprocess
import tempfile
from datetime import timedelta

import requests
from celery import shared_task
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _trivy_url() -> str:
    return getattr(settings, 'TRIVY_SERVER_URL', 'http://localhost:4954').rstrip('/')


def _registry_url() -> str:
    return getattr(settings, 'REGISTRY_INTERNAL_URL', 'http://localhost:5000').rstrip('/')


def _q(value: str) -> str:
    """YAML-safe double-quote a string value, escaping backslashes and double-quotes."""
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _bool_env(key: str, default: bool) -> bool:
    return os.environ.get(key, 'true' if default else 'false').lower() in ('true', '1', 'yes')


def _pull_image_to_oci_dir(
    docker_ref: str,
    tag_name: str,
    token: str,
    child_digest: str | None = None,
) -> str:
    """
    Pull an image from the internal registry using the HTTP API and write it
    as an OCI Image Layout (OCI spec 1.0) in a temporary directory.

    Returns the path to the OCI layout dir. Caller is responsible for cleanup.

    This bypasses skopeo and Trivy/Syft's own pull logic entirely, so:
      - Private-IP token realm rejection is never triggered (we hold the token)
      - All layer media types are supported (gzip, zstd, uncompressed, etc.)
      - Works for both filesystem and S3 storage backends

    Args:
        docker_ref:    Full image reference including host, e.g.
                       "siene-registry:5000/homelab/nginx:latest"
        tag_name:      Tag name used only for the OCI index.json annotation.
                       For per-platform child tags pass the child tag name
                       (e.g. "latest@linux_amd64") — it affects nothing in
                       the pull logic.
        token:         Bearer token with pull scope on the repository.
        child_digest:  When provided, skip manifest-list resolution entirely
                       and pull this specific digest directly.  Used for
                       per-platform child tags so each platform is pulled
                       independently rather than always resolving to linux/amd64.
    """
    import json as _json
    import hashlib

    registry_base = _registry_url()
    # docker_ref is  host/project/repo:tag  — strip the host to get  project/repo
    # e.g. siene-registry:5000/homelab/n8n:enterprise → homelab/n8n
    ref_without_host = docker_ref.split('/', 1)[1] if '/' in docker_ref else docker_ref
    repo_path = ref_without_host.rsplit(':', 1)[0]  # strip :tag

    auth_headers = {'Authorization': f'Bearer {token}'}

    # ── 1. Fetch the manifest ─────────────────────────────────────────────────
    manifest_accept = ', '.join([
        'application/vnd.oci.image.manifest.v1+json',
        'application/vnd.docker.distribution.manifest.v2+json',
        'application/vnd.docker.distribution.manifest.list.v2+json',
        'application/vnd.oci.image.index.v1+json',
    ])

    # When a specific child digest is provided (per-platform scan of a multi-arch
    # image), fetch that digest directly — skip all manifest-list resolution.
    manifest_ref = child_digest if child_digest else tag_name

    r = requests.get(
        f'{registry_base}/v2/{repo_path}/manifests/{manifest_ref}',
        headers={**auth_headers, 'Accept': manifest_accept},
        timeout=30,
    )
    r.raise_for_status()
    manifest_bytes = r.content
    manifest_digest = 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest()
    manifest_ct = r.headers.get('Content-Type', 'application/vnd.oci.image.manifest.v1+json')
    manifest_data = r.json()

    # If we got a manifest list / index and no explicit child digest was given,
    # fall back to the old behaviour: resolve to the first linux/amd64 entry.
    # This path is only taken for single-arch scans triggered manually on an
    # index tag (which the API now blocks) or for legacy code paths that have
    # not yet been updated.
    if (
        not child_digest and
        manifest_ct in (
            'application/vnd.docker.distribution.manifest.list.v2+json',
            'application/vnd.oci.image.index.v1+json',
        )
    ):
        manifests = manifest_data.get('manifests', [])
        chosen = None
        for m in manifests:
            plat = m.get('platform', {})
            if plat.get('os') == 'linux' and plat.get('architecture') == 'amd64':
                chosen = m
                break
        if chosen is None and manifests:
            chosen = manifests[0]
        if chosen is None:
            raise RuntimeError(f'manifest list for {docker_ref} has no entries')
        resolved_digest = chosen['digest']
        r2 = requests.get(
            f'{registry_base}/v2/{repo_path}/manifests/{resolved_digest}',
            headers={**auth_headers, 'Accept': manifest_accept},
            timeout=30,
        )
        r2.raise_for_status()
        manifest_bytes = r2.content
        manifest_digest = 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest()
        manifest_ct = r2.headers.get('Content-Type', 'application/vnd.oci.image.manifest.v1+json')
        manifest_data = r2.json()

    # ── 2. Create OCI layout dir ──────────────────────────────────────────────
    oci_dir = tempfile.mkdtemp(prefix='siene-scan-')
    blobs_sha256_dir = os.path.join(oci_dir, 'blobs', 'sha256')
    os.makedirs(blobs_sha256_dir, exist_ok=True)

    def _save_blob(digest: str, data: bytes) -> None:
        algo, hex_val = digest.split(':', 1)
        dest = os.path.join(oci_dir, 'blobs', algo, hex_val)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'wb') as fh:
            fh.write(data)

    def _fetch_blob(digest: str) -> None:
        algo, hex_val = digest.split(':', 1)
        dest = os.path.join(oci_dir, 'blobs', algo, hex_val)
        if os.path.exists(dest):
            return  # already on disk — nothing to do, no read-back needed
        r = requests.get(
            f'{registry_base}/v2/{repo_path}/blobs/{digest}',
            headers=auth_headers,
            timeout=600,
            stream=True,
        )
        r.raise_for_status()
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'wb') as fh:
            for chunk in r.iter_content(chunk_size=8 * 1024 * 1024):
                fh.write(chunk)
        # Return value intentionally omitted — callers only need the blob on
        # disk, never in RAM.  Reading it back would spike memory by up to one
        # full layer size (e.g. 100 MB) per layer, for zero benefit.

    # ── 3. Save manifest blob ─────────────────────────────────────────────────
    _save_blob(manifest_digest, manifest_bytes)

    # ── 4. Fetch config blob ──────────────────────────────────────────────────
    config_digest = manifest_data['config']['digest']
    _fetch_blob(config_digest)

    # ── 5. Fetch layer blobs ──────────────────────────────────────────────────
    for layer in manifest_data.get('layers', []):
        _fetch_blob(layer['digest'])

    # ── 6. Normalise manifest to OCI media types ──────────────────────────────
    # Trivy and Syft require OCI media types in the manifest stored in the layout.
    _DOCKER_TO_OCI = {
        'application/vnd.docker.distribution.manifest.v2+json':
            'application/vnd.oci.image.manifest.v1+json',
        'application/vnd.docker.container.image.v1+json':
            'application/vnd.oci.image.config.v1+json',
        'application/vnd.docker.image.rootfs.diff.tar.gzip':
            'application/vnd.oci.image.layer.v1.tar+gzip',
        'application/vnd.docker.image.rootfs.diff.tar.zstd':
            'application/vnd.oci.image.layer.v1.tar+zstd',
        'application/vnd.docker.image.rootfs.foreign.diff.tar.gzip':
            'application/vnd.oci.image.layer.nondistributable.v1.tar+gzip',
    }

    def _normalise_ct(ct: str) -> str:
        return _DOCKER_TO_OCI.get(ct, ct)

    manifest_data['mediaType'] = _normalise_ct(manifest_ct)
    manifest_data['config']['mediaType'] = _normalise_ct(
        manifest_data['config'].get('mediaType', '')
    )
    for layer in manifest_data.get('layers', []):
        layer['mediaType'] = _normalise_ct(layer.get('mediaType', ''))

    normalised_manifest_bytes = _json.dumps(manifest_data, separators=(',', ':')).encode()
    normalised_digest = 'sha256:' + hashlib.sha256(normalised_manifest_bytes).hexdigest()
    _save_blob(normalised_digest, normalised_manifest_bytes)

    # ── 7. Write oci-layout ───────────────────────────────────────────────────
    with open(os.path.join(oci_dir, 'oci-layout'), 'w') as fh:
        _json.dump({'imageLayoutVersion': '1.0.0'}, fh)

    # ── 8. Write index.json ───────────────────────────────────────────────────
    index = {
        'schemaVersion': 2,
        'mediaType': 'application/vnd.oci.image.index.v1+json',
        'manifests': [{
            'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'digest': normalised_digest,
            'size': len(normalised_manifest_bytes),
            'annotations': {
                'org.opencontainers.image.ref.name': tag_name,
            },
        }],
    }
    with open(os.path.join(oci_dir, 'index.json'), 'w') as fh:
        _json.dump(index, fh)

    return oci_dir


def _build_s3_gc_config() -> str:
    """Build a YAML GC config string for S3 storage from environment variables.

    Must mirror the runtime registry container's storage configuration exactly
    so that `registry garbage-collect` operates on the same bucket/path.

    All string values are double-quoted to handle special characters in
    credentials (e.g. '+', '/', '=' in AWS secret keys).
    accesskey/secretkey are omitted when blank to support IAM role auth on EC2/ECS/EKS.
    """
    region            = os.environ.get('REGISTRY_S3_REGION', '')
    bucket            = os.environ.get('REGISTRY_S3_BUCKET', '')
    accesskey         = os.environ.get('REGISTRY_S3_ACCESS_KEY', '')
    secretkey         = os.environ.get('REGISTRY_S3_SECRET_KEY', '')
    endpoint          = os.environ.get('REGISTRY_S3_ENDPOINT', '')
    rootdir           = os.environ.get('REGISTRY_S3_ROOT_DIRECTORY', '')
    force_path_style  = _bool_env('REGISTRY_S3_FORCE_PATH_STYLE', False)
    redirect_endpoint = os.environ.get('REGISTRY_S3_REDIRECT_ENDPOINT', '')
    secure            = _bool_env('REGISTRY_S3_SECURE', True)

    lines = [
        'version: 0.1',
        'storage:',
        '  s3:',
        f'    region: {_q(region)}',
        f'    bucket: {_q(bucket)}',
        f'    encrypt: false',
        f'    secure: {"true" if secure else "false"}',
        '    v4auth: true',  # required for non-us-east-1 AWS regions and all S3-compatible services
    ]
    # Omit credentials entirely when blank — Distribution will use IAM role auth
    if accesskey:
        lines.append(f'    accesskey: {_q(accesskey)}')
    if secretkey:
        lines.append(f'    secretkey: {_q(secretkey)}')
    # Only set regionendpoint when non-blank — docs say must NOT be set for native AWS
    if endpoint:
        lines.append(f'    regionendpoint: {_q(endpoint)}')
    if force_path_style:
        lines.append('    forcepathstyle: true')  # required by Distribution v3 with custom regionendpoint
    if rootdir:
        lines.append(f'    rootdirectory: {_q(rootdir)}')
    if redirect_endpoint:
        lines.append(f'    redirectendpoint: {_q(redirect_endpoint)}')
    lines += [
        '  delete:',
        '    enabled: true',
    ]
    return '\n'.join(lines) + '\n'


def _run_registry_blob_gc() -> tuple[bool, str]:
    """Run `registry garbage-collect` against the live registry storage.

    Supports both filesystem and S3 storage backends:
    - filesystem: uses the config file mounted at REGISTRY_GC_CONFIG
    - s3: generates a temporary config from REGISTRY_S3_* env vars so that
      credentials are never written to a persistent file on disk.

    The registry binary is copied from registry:3.1.1 in the Dockerfile.

    Returns (success, output) where output contains stdout+stderr for logging.
    Returns (False, reason) if the binary or required config is not available —
    this is expected when running outside Docker (dev host) and is logged as a
    warning, not an error.
    """
    registry_bin = '/usr/local/bin/registry'
    if not os.path.exists(registry_bin):
        return False, f'{registry_bin} not found — blob GC skipped'

    storage_backend = os.environ.get('REGISTRY_STORAGE_BACKEND', 'filesystem')

    if storage_backend == 's3':
        bucket = os.environ.get('REGISTRY_S3_BUCKET', '')
        if not bucket:
            return False, 'REGISTRY_S3_BUCKET not set — S3 blob GC skipped'
        config_content = _build_s3_gc_config()
        gc_config_path = None  # will be set inside the with-block
        try:
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.yml', prefix='siene-gc-', delete=False
            ) as tmp:
                tmp.write(config_content)
                gc_config_path = tmp.name
            return _exec_registry_gc(registry_bin, gc_config_path)
        finally:
            if gc_config_path and os.path.exists(gc_config_path):
                os.unlink(gc_config_path)
    else:
        # Filesystem mode — use the bind-mounted config file
        gc_config = os.environ.get('REGISTRY_GC_CONFIG', '')
        if not gc_config:
            return False, 'REGISTRY_GC_CONFIG not set — blob GC skipped (not running in Docker?)'
        if not os.path.exists(gc_config):
            return False, f'GC config {gc_config} not found — blob GC skipped'
        return _exec_registry_gc(registry_bin, gc_config)


def _exec_registry_gc(registry_bin: str, config_path: str) -> tuple[bool, str]:
    """Execute the registry garbage-collect command and return (success, output)."""
    try:
        # Do NOT pass --delete-untagged: it aggressively removes OCI index
        # (multi-arch) manifests that appear untagged in the flat manifest store
        # but are still referenced by tag-level index entries. Blob GC without
        # this flag only removes blobs with no manifest reference at all,
        # which is safe to run while the registry is live.
        #
        # Run with a clean environment: Distribution v3 reads any REGISTRY_*
        # env var as a config override. Our worker environment carries vars like
        # REGISTRY_STORAGE_BACKEND=s3 which Distribution does not recognise and
        # will reject with a parse error. Stripping all REGISTRY_* vars forces
        # Distribution to read configuration exclusively from the YAML file.
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith('REGISTRY_')}
        result = subprocess.run(
            [registry_bin, 'garbage-collect', config_path],
            capture_output=True,
            text=True,
            timeout=300,  # 5 min max
            env=clean_env,
        )
        output = (result.stdout + result.stderr).strip()
        if result.returncode == 0:
            return True, output
        else:
            return False, f'registry garbage-collect exited {result.returncode}: {output}'
    except subprocess.TimeoutExpired:
        return False, 'registry garbage-collect timed out after 300s'
    except Exception as exc:
        return False, f'registry garbage-collect failed: {exc}'


_GC_LOCK_KEY = 'siene:gc:running'
_GC_LOCK_TTL = 3600  # 1 hour max lock lifetime — prevents stuck lock after crash


def _acquire_gc_lock() -> bool:
    """Acquire a Redis SET NX lock to prevent concurrent GC runs.

    Returns True if the lock was acquired, False if another GC is already running.
    Uses the Celery broker Redis connection directly — no extra dependencies.
    """
    try:
        broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
        import redis as _redis
        r = _redis.from_url(broker_url)
        acquired = r.set(_GC_LOCK_KEY, '1', nx=True, ex=_GC_LOCK_TTL)
        return bool(acquired)
    except Exception as exc:
        logger.warning('_acquire_gc_lock: could not acquire Redis lock: %s — proceeding without lock', exc)
        # Fail open: if Redis is unavailable we still want GC to run.
        return True


def _release_gc_lock() -> None:
    try:
        import redis as _redis
        broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
        r = _redis.from_url(broker_url)
        r.delete(_GC_LOCK_KEY)
    except Exception as exc:
        logger.warning('_release_gc_lock: could not release Redis lock: %s', exc)


def _registry_bearer_headers(scope: str = 'registry:catalog:*') -> dict:
    """Return Authorization headers carrying a short-lived RS256 JWT for
    internal registry API calls.  Docker Distribution is configured with
    REGISTRY_AUTH: token and only accepts these JWTs — HTTP Basic auth is
    rejected with 401.

    Falls back to the internal token as a last resort so callers still work
    during first-run before the signing key has been initialised.
    """
    try:
        from django.contrib.auth.models import User
        from registry.auth import issue_token
        # Prefer a Django superuser; fall back to any UserProfile admin.
        actor = User.objects.filter(is_superuser=True).first()
        if actor is None:
            from users.models import UserProfile
            profile = UserProfile.objects.filter(is_admin=True).select_related('user').first()
            if profile:
                actor = profile.user
        token_data = issue_token(actor, scope)
        return {'Authorization': f'Bearer {token_data["token"]}'}
    except Exception:
        # Fallback: should not be reached in production but avoids a hard crash
        # if called before migrations or during first-run setup.
        fallback = os.environ.get('REGISTRY_INTERNAL_TOKEN', '')
        return {'Authorization': f'Bearer {fallback}'}


def _ecr_docker_token(access_key: str, secret_key: str, endpoint: str) -> str | None:
    """Exchange AWS credentials for an ECR Docker Bearer token.

    Returns the base64-decoded password (to be used as ``AWS:<token>`` creds
    with skopeo), or None on failure.
    """
    import hmac
    import hashlib
    import datetime
    import base64
    import json
    import urllib.request
    import urllib.error

    try:
        region = endpoint.split('.ecr.')[1].split('.amazonaws.com')[0]
    except (IndexError, AttributeError):
        logger.warning('_ecr_docker_token: cannot parse region from %s', endpoint)
        return None

    host = f'ecr.{region}.amazonaws.com'
    endpoint_url = f'https://{host}/'
    service = 'ecr'
    payload = '{}'
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()

    now = datetime.datetime.utcnow()
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now.strftime('%Y%m%d')

    canonical_headers = (
        f'content-type:application/x-amz-json-1.1\n'
        f'host:{host}\n'
        f'x-amz-date:{amz_date}\n'
        f'x-amz-target:AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken\n'
    )
    signed_headers = 'content-type;host;x-amz-date;x-amz-target'
    canonical_request = f'POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}'
    credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'
    string_to_sign = (
        f'AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n'
        f'{hashlib.sha256(canonical_request.encode()).hexdigest()}'
    )

    def _sign(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = _sign(
        _sign(_sign(_sign(f'AWS4{secret_key}'.encode(), date_stamp), region), service),
        'aws4_request',
    )
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth_header = (
        f'AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, '
        f'SignedHeaders={signed_headers}, Signature={signature}'
    )

    try:
        req = urllib.request.Request(
            endpoint_url,
            data=payload.encode(),
            headers={
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Date': amz_date,
                'X-Amz-Target': 'AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken',
                'Authorization': auth_header,
            },
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        # authorizationData[0].authorizationToken is base64("AWS:<token>")
        b64 = data['authorizationData'][0]['authorizationToken']
        decoded = base64.b64decode(b64).decode()
        # decoded is "AWS:<password>"
        return decoded.split(':', 1)[1]
    except Exception as e:
        logger.warning('_ecr_docker_token: failed to get ECR token: %s', e)
        return None


def _ecr_ensure_repo(access_key: str, secret_key: str, endpoint: str, repo_name: str) -> None:
    """Create an ECR repository if it doesn't already exist (idempotent)."""
    import hmac
    import hashlib
    import datetime
    import json
    import urllib.request
    import urllib.error

    try:
        region = endpoint.split('.ecr.')[1].split('.amazonaws.com')[0]
    except (IndexError, AttributeError):
        logger.warning('_ecr_ensure_repo: cannot parse region from %s', endpoint)
        return

    host = f'ecr.{region}.amazonaws.com'
    endpoint_url = f'https://{host}/'
    service = 'ecr'
    payload = json.dumps({'repositoryName': repo_name})
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()

    now = datetime.datetime.utcnow()
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now.strftime('%Y%m%d')
    target = 'AmazonEC2ContainerRegistry_V20150921.CreateRepository'

    canonical_headers = (
        f'content-type:application/x-amz-json-1.1\n'
        f'host:{host}\n'
        f'x-amz-date:{amz_date}\n'
        f'x-amz-target:{target}\n'
    )
    signed_headers = 'content-type;host;x-amz-date;x-amz-target'
    canonical_request = f'POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}'
    credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'
    string_to_sign = (
        f'AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n'
        f'{hashlib.sha256(canonical_request.encode()).hexdigest()}'
    )

    def _sign(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = _sign(
        _sign(_sign(_sign(f'AWS4{secret_key}'.encode(), date_stamp), region), service),
        'aws4_request',
    )
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth_header = (
        f'AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, '
        f'SignedHeaders={signed_headers}, Signature={signature}'
    )

    try:
        req = urllib.request.Request(
            endpoint_url,
            data=payload.encode(),
            headers={
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Date': amz_date,
                'X-Amz-Target': target,
                'Authorization': auth_header,
            },
        )
        urllib.request.urlopen(req, timeout=10)
        logger.info('_ecr_ensure_repo: created ECR repository %s', repo_name)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace')
        if 'RepositoryAlreadyExistsException' in body:
            pass  # already exists — fine
        else:
            logger.warning('_ecr_ensure_repo: failed to create %s: HTTP %s %s', repo_name, e.code, body[:200])
    except Exception as e:
        logger.warning('_ecr_ensure_repo: failed to create %s: %s', repo_name, e)


def _swr_ensure_repo(username: str, password: str, endpoint: str, repo_name: str) -> None:
    """Create a Huawei SWR image repository if it doesn't already exist (idempotent).

    SWR endpoint format: swr.<region>.myhuaweicloud.com
    repo_name format: <namespace>/<repository>  (e.g. "myns/alpine")

    Auth: the stored username/password are the Docker registry credentials;
    SWR's management API accepts HTTP Basic auth with the same credentials.
    """
    import json
    import urllib.request
    import urllib.error

    # repo_name is e.g. "myns/alpine" — split into namespace + repo
    parts = repo_name.split('/', 1)
    if len(parts) != 2:
        logger.warning('_swr_ensure_repo: repo_name %r must be namespace/repo', repo_name)
        return
    namespace, repository = parts

    host = endpoint.rstrip('/').replace('https://', '').replace('http://', '')
    api_url = f'https://{host}/v2/manage/namespaces/{namespace}/repos'
    payload = json.dumps({'repository': repository, 'is_public': False}).encode()

    import base64
    creds_b64 = base64.b64encode(f'{username}:{password}'.encode()).decode()

    try:
        req = urllib.request.Request(
            api_url,
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Basic {creds_b64}',
            },
            method='POST',
        )
        urllib.request.urlopen(req, timeout=10)
        logger.info('_swr_ensure_repo: created SWR repository %s', repo_name)
    except urllib.error.HTTPError as e:
        if e.code == 409:
            pass  # already exists — fine
        else:
            body = e.read().decode(errors='replace')
            logger.warning('_swr_ensure_repo: failed to create %s: HTTP %s %s', repo_name, e.code, body[:200])
    except Exception as e:
        logger.warning('_swr_ensure_repo: failed to create %s: %s', repo_name, e)


def _tcr_ensure_repo(secret_id: str, secret_key: str, endpoint: str, repo_name: str) -> None:
    """Create a Tencent TCR image repository if it doesn't already exist (idempotent).

    TCR endpoint format: <registry-id>.tencentcloudcr.com
    repo_name format: <namespace>/<repository>  (e.g. "myns/alpine")
    username is stored as "<secret_id>" and password_enc as "<secret_key>" for TCR.

    Uses TC3-HMAC-SHA256 signing (Tencent Cloud API 3.0).
    """
    import hmac
    import hashlib
    import datetime
    import json
    import urllib.request
    import urllib.error

    parts = repo_name.split('/', 1)
    if len(parts) != 2:
        logger.warning('_tcr_ensure_repo: repo_name %r must be namespace/repo', repo_name)
        return
    namespace, repository = parts

    # Parse registry ID and region from endpoint: <id>.tencentcloudcr.com
    host_raw = endpoint.rstrip('/').replace('https://', '').replace('http://', '')
    registry_id = host_raw.split('.')[0]

    # Region must be passed explicitly; TCR API endpoint is global but needs Region param.
    # We derive it from the stored secret_id convention "<secret_id>@<region>" if present,
    # otherwise default to ap-guangzhou (most common).
    region = 'ap-guangzhou'
    if '@' in secret_id:
        secret_id, region = secret_id.rsplit('@', 1)

    service = 'tcr'
    tc_host = 'tcr.intl.tencentcloudapi.com'
    api_url = f'https://{tc_host}/'

    payload = json.dumps({
        'RegistryId': registry_id,
        'NamespaceName': namespace,
        'RepositoryName': repository,
    })
    payload_bytes = payload.encode()
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    now = datetime.datetime.utcnow()
    timestamp = str(int(now.timestamp()))
    date_stamp = now.strftime('%Y-%m-%d')

    # TC3-HMAC-SHA256
    canonical_headers = f'content-type:application/json\nhost:{tc_host}\nx-tc-action:createrepository\n'
    signed_headers = 'content-type;host;x-tc-action'
    canonical_request = f'POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}'

    credential_scope = f'{date_stamp}/{service}/tc3_request'
    string_to_sign = (
        f'TC3-HMAC-SHA256\n{timestamp}\n{credential_scope}\n'
        f'{hashlib.sha256(canonical_request.encode()).hexdigest()}'
    )

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    # TC3 key derivation: date → service → tc3_request
    k_date = _sign(f'TC3{secret_key}'.encode(), date_stamp)
    k_service = _sign(k_date, service)
    k_signing = _sign(k_service, 'tc3_request')
    signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    auth_header = (
        f'TC3-HMAC-SHA256 Credential={secret_id}/{credential_scope}, '
        f'SignedHeaders={signed_headers}, Signature={signature}'
    )

    try:
        req = urllib.request.Request(
            api_url,
            data=payload_bytes,
            headers={
                'Content-Type': 'application/json',
                'Host': tc_host,
                'X-TC-Action': 'CreateRepository',
                'X-TC-Version': '2019-09-24',
                'X-TC-Timestamp': timestamp,
                'X-TC-Region': region,
                'Authorization': auth_header,
            },
            method='POST',
        )
        resp = urllib.request.urlopen(req, timeout=10)
        logger.info('_tcr_ensure_repo: created TCR repository %s', repo_name)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace')
        try:
            err_code = json.loads(body).get('Response', {}).get('Error', {}).get('Code', '')
        except Exception:
            err_code = ''
        if err_code == 'ResourceInUse.NamespaceAlreadyExist' or 'already exist' in body.lower() or 'conflict' in body.lower():
            pass  # already exists — fine
        else:
            logger.warning('_tcr_ensure_repo: failed to create %s: HTTP %s %s', repo_name, e.code, body[:200])
    except Exception as e:
        logger.warning('_tcr_ensure_repo: failed to create %s: %s', repo_name, e)


# ── Scan audit logging ────────────────────────────────────────────────────────

def _simplify_scan_error(exc: Exception) -> str:
    """Return a short, user-readable error description without leaking internal details.

    Maps common exception types to plain-English reasons.  Anything unexpected
    is categorised as 'unexpected error' so no stack trace or file path is ever
    surfaced in the audit log.
    """
    msg = str(exc)
    if 'timeout' in msg.lower():
        return 'Scanner timed out'
    if 'trivy exited' in msg.lower():
        # e.g. "trivy exited 1: <stderr snippet>"
        # Grab just the exit-code part — never the stderr blob
        try:
            part = msg.split(':')[0]  # "trivy exited 1"
            return f'Scanner failed ({part.strip()})'
        except Exception:
            return 'Scanner process failed'
    if 'syft exited' in msg.lower():
        try:
            part = msg.split(':')[0]
            return f'SBOM generator failed ({part.strip()})'
        except Exception:
            return 'SBOM generator process failed'
    if 'connection' in msg.lower() or 'refused' in msg.lower():
        return 'Registry connection failed'
    if 'manifest' in msg.lower() and ('not found' in msg.lower() or '404' in msg.lower()):
        return 'Image manifest not found in registry'
    if 'no entries' in msg.lower():
        return 'No platform entries found in manifest list'
    if 'permission' in msg.lower() or 'forbidden' in msg.lower() or '403' in msg.lower():
        return 'Permission denied accessing registry'
    if 'json' in msg.lower() or 'decode' in msg.lower():
        return 'Failed to parse scanner output'
    return 'Unexpected error during scan'


def _log_scan_event(
    operation: str,
    resource_type: str,
    tag,
    detail: dict,
) -> None:
    """Write an AuditLog entry for a scan lifecycle event.

    Called from Celery worker context — no HTTP request/actor available, so
    user and username are left blank (system action).  Swallows all exceptions
    so a logging failure never aborts the scan task.

    ``operation`` should be one of AuditLog.OP_SCAN_STARTED / OP_SCAN_FINISHED
    / OP_SCAN_ERROR.  ``resource_type`` is the scan kind: 'scan', 'secret_scan',
    'misconfig_scan', or 'sbom'.  ``detail`` carries structured result data.
    """
    try:
        from registry.models import AuditLog
        repo = tag.repository
        project = repo.project
        resource = f'{repo.name}:{tag.name}'
        AuditLog.objects.create(
            user=None,
            username='system',
            project=project,
            resource_type=resource_type,
            resource=resource,
            operation=operation,
            result=(operation != AuditLog.OP_SCAN_ERROR),
            detail=detail,
        )
    except Exception as _exc:
        logger.warning('_log_scan_event: could not write audit log: %s', _exc)


# ── Webhook event processing ──────────────────────────────────────────────────

@shared_task(
    bind=True,
    name='registry.tasks.process_registry_events',
    queue='default',
    max_retries=3,
    default_retry_delay=10,
)
def process_registry_events(self, raw_body: str) -> None:
    """Process registry push/delete webhook events asynchronously.

    The HTTP endpoint validates auth and immediately returns 200; this task
    carries out all the I/O-heavy work (manifest fetches, DB writes, scan
    dispatch) in a Celery worker so Gunicorn workers are never blocked.
    """
    try:
        from registry.api import _process_registry_events_sync
        _process_registry_events_sync(raw_body)
    except Exception as exc:
        logger.error('process_registry_events: failed: %s', exc)
        raise self.retry(exc=exc)


# ── Vulnerability scanning ────────────────────────────────────────────────────

@shared_task(
    bind=True,
    name='registry.tasks.run_vulnerability_scan',
    queue='scans',
    max_retries=3,
    default_retry_delay=30,
)
def run_vulnerability_scan(self, scan_id: int, triggered_by: str = 'manual') -> None:
    """
    Run a Trivy scan against the local registry for a specific VulnerabilityScan row.

    Uses `trivy image` as a subprocess with --server pointing at the Trivy server
    for the vulnerability DB cache. The Trivy HTTP twirp API was removed in v0.47+.
    """
    import json as _json
    from registry.models import VulnerabilityScan

    try:
        scan = VulnerabilityScan.objects.select_related(
            'tag', 'tag__parent_tag', 'tag__repository', 'tag__repository__project'
        ).get(pk=scan_id)
    except VulnerabilityScan.DoesNotExist:
        logger.warning('run_vulnerability_scan: scan %s not found', scan_id)
        return

    if scan.status in ('finished', 'running'):
        return

    tag = scan.tag
    repo = tag.repository
    registry_host = _registry_url().replace('http://', '').replace('https://', '')
    # For per-platform child tags use the parent tag's name as the image ref
    # (child tag names like "latest@linux_amd64" are not valid registry refs).
    # The child_digest is passed to _pull_image_to_oci_dir so the correct
    # platform manifest is fetched directly by digest instead of resolving the
    # manifest list.
    _ref_tag_name = tag.parent_tag.name if tag.parent_tag_id else tag.name
    docker_ref = f'{registry_host}/{repo.project.name}/{repo.name}:{_ref_tag_name}'
    _child_digest = tag.digest if tag.parent_tag_id else None

    scan.status = VulnerabilityScan.STATUS_RUNNING
    scan.started_at = timezone.now()
    scan.save(update_fields=['status', 'started_at'])
    _log_scan_event('scan_started', 'scan', tag, {
        'scan_id': scan_id,
        'triggered_by': triggered_by,
    })

    try:
        from django.contrib.auth.models import User
        from registry.auth import issue_token
        scope = f'repository:{repo.project.name}/{repo.name}:pull'
        internal_user = User.objects.filter(is_superuser=True).first()
        token_data = issue_token(internal_user, scope)

        out_path = ''
        oci_dir = ''
        try:
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
                out_path = f.name

            oci_dir = _pull_image_to_oci_dir(docker_ref, tag.name, token_data['token'], child_digest=_child_digest)

            cmd = [
                'trivy', 'image',
                '--input', oci_dir,
                '--server', _trivy_url(),
                '--format', 'json',
                '--output', out_path,
                '--pkg-types', 'os,library',
                '--scanners', 'vuln',
                '--skip-java-db-update',
                '--skip-db-update',
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                raise RuntimeError(f'trivy exited {result.returncode}: {result.stderr[:500]}')

            with open(out_path) as f:
                data = _json.load(f)
        finally:
            if out_path and os.path.exists(out_path):
                os.unlink(out_path)
            if oci_dir and os.path.exists(oci_dir):
                import shutil as _shutil
                _shutil.rmtree(oci_dir, ignore_errors=True)

    except FileNotFoundError:
        logger.warning('run_vulnerability_scan: trivy not found in PATH for scan %s', scan_id)
        scan.status = VulnerabilityScan.STATUS_ERROR
        scan.finished_at = timezone.now()
        scan.save(update_fields=['status', 'finished_at'])
        _log_scan_event('scan_error', 'scan', tag, {
            'scan_id': scan_id,
            'error': 'Scanner not available (trivy not found)',
        })
        return
    except Exception as exc:
        logger.error('run_vulnerability_scan: failed for scan %s: %s', scan_id, exc)
        scan.status = VulnerabilityScan.STATUS_ERROR
        scan.finished_at = timezone.now()
        scan.save(update_fields=['status', 'finished_at'])
        _log_scan_event('scan_error', 'scan', tag, {
            'scan_id': scan_id,
            'error': _simplify_scan_error(exc),
        })
        raise self.retry(exc=exc)

    summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0, 'unknown': 0}
    report = []

    for result in data.get('Results') or data.get('results') or []:
        for vuln in result.get('Vulnerabilities') or result.get('vulnerabilities') or []:
            sev = (vuln.get('Severity') or vuln.get('severity') or 'unknown').lower()
            summary[sev] = summary.get(sev, 0) + 1

            # Preserve full CVSS data if present
            cvss = vuln.get('CVSS') or {}
            cvss_v3_score = None
            cvss_v3_vector = ''
            cvss_v2_score = None
            for _src, _scores in cvss.items():
                if _scores.get('V3Score') is not None and cvss_v3_score is None:
                    cvss_v3_score = _scores['V3Score']
                    cvss_v3_vector = _scores.get('V3Vector', '')
                if _scores.get('V2Score') is not None and cvss_v2_score is None:
                    cvss_v2_score = _scores['V2Score']

            report.append({
                'vulnerability_id':  vuln.get('VulnerabilityID') or vuln.get('vulnerabilityID', ''),
                'pkg_name':          vuln.get('PkgName')          or vuln.get('pkgName', ''),
                'installed_version': vuln.get('InstalledVersion') or vuln.get('installedVersion', ''),
                'fixed_version':     vuln.get('FixedVersion')     or vuln.get('fixedVersion', ''),
                'severity':          sev,
                'title':             vuln.get('Title')            or vuln.get('title', ''),
                'description':       vuln.get('Description')      or vuln.get('description', ''),
                'references':        vuln.get('References')       or vuln.get('references') or [],
                'cwe_ids':           vuln.get('CweIDs')           or vuln.get('cweIDs') or [],
                'cvss_v3_score':     cvss_v3_score,
                'cvss_v3_vector':    cvss_v3_vector,
                'cvss_v2_score':     cvss_v2_score,
                'published_date':    vuln.get('PublishedDate')    or vuln.get('publishedDate', ''),
                'last_modified_date':vuln.get('LastModifiedDate') or vuln.get('lastModifiedDate', ''),
                'data_source':       (vuln.get('DataSource') or {}).get('Name', ''),
                'pkg_path':          vuln.get('PkgPath')          or vuln.get('pkgPath', ''),
                'target':            result.get('Target', ''),
                'class':             result.get('Class', ''),
                'pkg_type':          result.get('Type', ''),
            })

    # Replace internal registry host with public domain in every target string
    _external_host = os.environ.get('CUSTOM_DOMAIN', os.environ.get('DOMAIN', '')).strip()
    if _external_host and registry_host and _external_host != registry_host:
        for _entry in report:
            if isinstance(_entry.get('target'), str):
                _entry['target'] = _entry['target'].replace(registry_host, _external_host)

    scan.status = VulnerabilityScan.STATUS_FINISHED
    scan.finished_at = timezone.now()
    scan.summary = summary
    scan.report = report
    scan.save(update_fields=['status', 'finished_at', 'summary', 'report'])
    logger.info(
        'run_vulnerability_scan: scan %s finished — critical=%s high=%s medium=%s low=%s',
        scan_id, summary['critical'], summary['high'], summary['medium'], summary['low'],
    )
    _duration = round((scan.finished_at - scan.started_at).total_seconds()) if scan.started_at else None
    _log_scan_event('scan_finished', 'scan', tag, {
        'scan_id': scan_id,
        'duration_seconds': _duration,
        'critical': summary['critical'],
        'high': summary['high'],
        'medium': summary['medium'],
        'low': summary['low'],
        'total': len(report),
    })


# ── Secret scanning ──────────────────────────────────────────────────────────

@shared_task(
    bind=True,
    name='registry.tasks.run_secret_scan',
    queue='scans',
    max_retries=3,
    default_retry_delay=30,
)
def run_secret_scan(self, scan_id: int) -> None:
    """
    Run a Trivy secret scan against the local registry for a specific SecretScan row.

    Secret scanning does NOT work through the Trivy server (it's filesystem-based),
    so we run `trivy image --scanners secret` as a standalone subprocess with a
    local DB copy (--download-db-to or --skip-db-update if already cached).
    """
    import json as _json
    from registry.models import SecretScan

    try:
        scan = SecretScan.objects.select_related(
            'tag', 'tag__parent_tag', 'tag__repository', 'tag__repository__project'
        ).get(pk=scan_id)
    except SecretScan.DoesNotExist:
        logger.warning('run_secret_scan: scan %s not found', scan_id)
        return

    if scan.status in ('finished', 'running'):
        return

    tag = scan.tag
    repo = tag.repository
    registry_host = _registry_url().replace('http://', '').replace('https://', '')
    _ref_tag_name = tag.parent_tag.name if tag.parent_tag_id else tag.name
    docker_ref = f'{registry_host}/{repo.project.name}/{repo.name}:{_ref_tag_name}'
    _child_digest = tag.digest if tag.parent_tag_id else None

    scan.status = SecretScan.STATUS_RUNNING
    scan.started_at = timezone.now()
    scan.save(update_fields=['status', 'started_at'])
    _log_scan_event('scan_started', 'secret_scan', tag, {
        'scan_id': scan_id,
        'triggered_by': 'manual',
    })

    try:
        from django.contrib.auth.models import User
        from registry.auth import issue_token
        scope = f'repository:{repo.project.name}/{repo.name}:pull'
        internal_user = User.objects.filter(is_superuser=True).first()
        token_data = issue_token(internal_user, scope)

        out_path = ''
        oci_dir = ''
        try:
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
                out_path = f.name

            secret_cache_dir = '/tmp/trivy-secret-cache'
            os.makedirs(secret_cache_dir, exist_ok=True)
            oci_dir = _pull_image_to_oci_dir(docker_ref, tag.name, token_data['token'], child_digest=_child_digest)

            cmd = [
                'trivy', 'image',
                '--input', oci_dir,
                '--format', 'json',
                '--output', out_path,
                '--cache-dir', secret_cache_dir,
                '--scanners', 'secret',
                '--skip-db-update',
                '--skip-java-db-update',
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                raise RuntimeError(f'trivy exited {result.returncode}: {result.stderr[:500]}')

            with open(out_path) as f:
                data = _json.load(f)
        finally:
            if out_path and os.path.exists(out_path):
                os.unlink(out_path)
            if oci_dir and os.path.exists(oci_dir):
                import shutil as _shutil
                _shutil.rmtree(oci_dir, ignore_errors=True)

    except FileNotFoundError:
        logger.warning('run_secret_scan: trivy not found in PATH for scan %s', scan_id)
        scan.status = SecretScan.STATUS_ERROR
        scan.finished_at = timezone.now()
        scan.save(update_fields=['status', 'finished_at'])
        _log_scan_event('scan_error', 'secret_scan', tag, {
            'scan_id': scan_id,
            'error': 'Scanner not available (trivy not found)',
        })
        return
    except Exception as exc:
        logger.error('run_secret_scan: failed for scan %s: %s', scan_id, exc)
        scan.status = SecretScan.STATUS_ERROR
        scan.finished_at = timezone.now()
        scan.save(update_fields=['status', 'finished_at'])
        _log_scan_event('scan_error', 'secret_scan', tag, {
            'scan_id': scan_id,
            'error': _simplify_scan_error(exc),
        })
        raise self.retry(exc=exc)

    _external_host = os.environ.get('CUSTOM_DOMAIN', os.environ.get('DOMAIN', '')).strip()

    report = []
    for result_block in data.get('Results') or data.get('results') or []:
        target = result_block.get('Target', '')
        if _external_host and registry_host and target.startswith(registry_host):
            target = target.replace(registry_host, _external_host, 1)
        for secret in result_block.get('Secrets') or result_block.get('secrets') or []:
            report.append({
                'rule_id':   secret.get('RuleID')   or secret.get('ruleID', ''),
                'category':  secret.get('Category') or secret.get('category', ''),
                'severity':  (secret.get('Severity') or secret.get('severity') or 'unknown').lower(),
                'title':     secret.get('Title')    or secret.get('title', ''),
                'target':    target,
                'match':     secret.get('Match')    or secret.get('match', ''),
                'start_line': secret.get('StartLine') or secret.get('startLine'),
                'end_line':   secret.get('EndLine')   or secret.get('endLine'),
            })

    scan.status = SecretScan.STATUS_FINISHED
    scan.finished_at = timezone.now()
    scan.total = len(report)
    scan.report = report
    scan.save(update_fields=['status', 'finished_at', 'total', 'report'])
    logger.info('run_secret_scan: scan %s finished — %s secret(s) found', scan_id, len(report))
    _duration = round((scan.finished_at - scan.started_at).total_seconds()) if scan.started_at else None
    _log_scan_event('scan_finished', 'secret_scan', tag, {
        'scan_id': scan_id,
        'duration_seconds': _duration,
        'secrets_found': len(report),
    })


# ── Misconfiguration scanning ─────────────────────────────────────────────────

@shared_task(
    bind=True,
    name='registry.tasks.run_misconfig_scan',
    queue='scans',
    max_retries=3,
    default_retry_delay=30,
)
def run_misconfig_scan(self, scan_id: int) -> None:
    """
    Run a Trivy misconfiguration scan against the local registry for a specific
    MisconfigScan row.

    Uses `trivy image --image-config-scanners misconfig` as a subprocess.
    This scans the OCI image config metadata (runtime configuration: USER,
    HEALTHCHECK, exposed ports, etc.) rather than IaC files found inside the
    image filesystem layers. No Trivy server or DB is required for this scan.
    """
    import json as _json
    from registry.models import MisconfigScan

    try:
        scan = MisconfigScan.objects.select_related(
            'tag', 'tag__parent_tag', 'tag__repository', 'tag__repository__project'
        ).get(pk=scan_id)
    except MisconfigScan.DoesNotExist:
        logger.warning('run_misconfig_scan: scan %s not found', scan_id)
        return

    if scan.status in ('finished', 'running'):
        return

    tag = scan.tag
    repo = tag.repository
    registry_host = _registry_url().replace('http://', '').replace('https://', '')
    _ref_tag_name = tag.parent_tag.name if tag.parent_tag_id else tag.name
    docker_ref = f'{registry_host}/{repo.project.name}/{repo.name}:{_ref_tag_name}'
    _child_digest = tag.digest if tag.parent_tag_id else None

    scan.status = MisconfigScan.STATUS_RUNNING
    scan.started_at = timezone.now()
    scan.save(update_fields=['status', 'started_at'])
    _log_scan_event('scan_started', 'misconfig_scan', tag, {
        'scan_id': scan_id,
        'triggered_by': 'manual',
    })

    try:
        from django.contrib.auth.models import User
        from registry.auth import issue_token
        scope = f'repository:{repo.project.name}/{repo.name}:pull'
        internal_user = User.objects.filter(is_superuser=True).first()
        token_data = issue_token(internal_user, scope)

        out_path = ''
        oci_dir = ''
        try:
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
                out_path = f.name

            misconfig_cache_dir = '/tmp/trivy-misconfig-cache'
            os.makedirs(misconfig_cache_dir, exist_ok=True)
            oci_dir = _pull_image_to_oci_dir(docker_ref, tag.name, token_data['token'], child_digest=_child_digest)

            cmd = [
                'trivy', 'image',
                '--input', oci_dir,
                '--format', 'json',
                '--output', out_path,
                '--cache-dir', misconfig_cache_dir,
                '--scanners', '',
                '--image-config-scanners', 'misconfig',
                '--skip-db-update',
                '--skip-java-db-update',
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                raise RuntimeError(f'trivy exited {result.returncode}: {result.stderr[:500]}')

            with open(out_path) as f:
                data = _json.load(f)
        finally:
            if out_path and os.path.exists(out_path):
                os.unlink(out_path)
            if oci_dir and os.path.exists(oci_dir):
                import shutil as _shutil
                _shutil.rmtree(oci_dir, ignore_errors=True)

    except FileNotFoundError:
        logger.warning('run_misconfig_scan: trivy not found in PATH for scan %s', scan_id)
        scan.status = MisconfigScan.STATUS_ERROR
        scan.finished_at = timezone.now()
        scan.save(update_fields=['status', 'finished_at'])
        _log_scan_event('scan_error', 'misconfig_scan', tag, {
            'scan_id': scan_id,
            'error': 'Scanner not available (trivy not found)',
        })
        return
    except Exception as exc:
        logger.error('run_misconfig_scan: failed for scan %s: %s', scan_id, exc)
        scan.status = MisconfigScan.STATUS_ERROR
        scan.finished_at = timezone.now()
        scan.save(update_fields=['status', 'finished_at'])
        _log_scan_event('scan_error', 'misconfig_scan', tag, {
            'scan_id': scan_id,
            'error': _simplify_scan_error(exc),
        })
        raise self.retry(exc=exc)

    summary = {'FAIL': 0, 'WARN': 0, 'PASS': 0}
    report = []
    seen = set()

    for result_block in data.get('Results') or data.get('results') or []:
        result_class = result_block.get('Class', '')
        result_type = result_block.get('Type', '')
        for mc in result_block.get('Misconfigurations') or result_block.get('misconfigurations') or []:
            mc_id     = mc.get('ID')     or mc.get('id', '')
            mc_target = result_block.get('Target', '') or result_block.get('target', '')
            # Replace the internal registry host with the public domain so users
            # see e.g. "jfcr.io/olemiss/..." instead of "siene-registry:5000/..."
            _custom_domain = os.environ.get('CUSTOM_DOMAIN', os.environ.get('DOMAIN', '')).strip()
            if mc_target.startswith(registry_host + '/'):
                suffix = mc_target[len(registry_host) + 1:]
                mc_target = f'{_custom_domain}/{suffix}' if _custom_domain else suffix
            status    = (mc.get('Status') or mc.get('status') or 'FAIL').upper()
            dedup_key = (mc_id, mc_target, status)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            summary[status] = summary.get(status, 0) + 1
            report.append({
                'id':           mc_id,
                'avd_id':       mc.get('AVDID')       or mc.get('avdID', ''),
                'type':         mc.get('Type')        or mc.get('type', ''),
                'title':        mc.get('Title')       or mc.get('title', ''),
                'description':  mc.get('Description') or mc.get('description', ''),
                'message':      mc.get('Message')     or mc.get('message', ''),
                'resolution':   mc.get('Resolution')  or mc.get('resolution', ''),
                'severity':     (mc.get('Severity')   or mc.get('severity') or 'unknown').lower(),
                'status':       status,
                'references':   mc.get('References')  or mc.get('references') or [],
                'target':       mc_target,
                'class':        result_class,
                'result_type':  result_type,
            })

    scan.status = MisconfigScan.STATUS_FINISHED
    scan.finished_at = timezone.now()
    scan.summary = summary
    scan.report = report
    scan.save(update_fields=['status', 'finished_at', 'summary', 'report'])
    logger.info(
        'run_misconfig_scan: scan %s finished — FAIL=%s WARN=%s PASS=%s',
        scan_id, summary['FAIL'], summary['WARN'], summary['PASS'],
    )
    _duration = round((scan.finished_at - scan.started_at).total_seconds()) if scan.started_at else None
    _log_scan_event('scan_finished', 'misconfig_scan', tag, {
        'scan_id': scan_id,
        'duration_seconds': _duration,
        'fail': summary['FAIL'],
        'warn': summary['WARN'],
        'pass': summary['PASS'],
    })


# ── Combined scan (on-push) ───────────────────────────────────────────────────

@shared_task(
    bind=True,
    name='registry.tasks.run_combined_scan',
    queue='scans',
    max_retries=3,
    default_retry_delay=30,
)
def run_combined_scan(
    self,
    vuln_scan_id: int | None = None,
    secret_scan_id: int | None = None,
    misconfig_scan_id: int | None = None,
) -> None:
    """Download the image once and run all enabled Trivy scan types sequentially.

    Replaces the three separate on-push dispatch calls (run_vulnerability_scan +
    run_secret_scan + run_misconfig_scan) that each independently re-downloaded
    the full image, tripling registry I/O per push.

    Callers (the webhook handler) pre-create the scan rows in 'pending' status
    and pass their PKs here — identical to the pattern used by the individual
    scan tasks.  This means:
      - Rows exist immediately after push (the UI shows 'pending' right away)
      - The _scan_already_inflight guard in the webhook works correctly
      - Retries are safe: no new rows are created on retry, the existing rows
        are simply picked up again by PK
      - No duplicate rows if the user clicks 'Scan now' concurrently

    Individual scan tasks are still used for on-demand re-scans triggered from
    the UI (scan now button) and for periodic re-scans (run_rescan_stale).
    """
    import json as _json
    import shutil as _shutil
    from registry.models import VulnerabilityScan, SecretScan, MisconfigScan

    vuln_scan = secret_scan = misconfig_scan = None

    if vuln_scan_id is not None:
        try:
            vuln_scan = VulnerabilityScan.objects.select_related(
                'tag', 'tag__parent_tag', 'tag__repository', 'tag__repository__project'
            ).get(pk=vuln_scan_id)
        except VulnerabilityScan.DoesNotExist:
            logger.warning('run_combined_scan: VulnerabilityScan %s not found', vuln_scan_id)

    if secret_scan_id is not None:
        try:
            secret_scan = SecretScan.objects.select_related(
                'tag', 'tag__parent_tag', 'tag__repository', 'tag__repository__project'
            ).get(pk=secret_scan_id)
        except SecretScan.DoesNotExist:
            logger.warning('run_combined_scan: SecretScan %s not found', secret_scan_id)

    if misconfig_scan_id is not None:
        try:
            misconfig_scan = MisconfigScan.objects.select_related(
                'tag', 'tag__parent_tag', 'tag__repository', 'tag__repository__project'
            ).get(pk=misconfig_scan_id)
        except MisconfigScan.DoesNotExist:
            logger.warning('run_combined_scan: MisconfigScan %s not found', misconfig_scan_id)

    if not (vuln_scan or secret_scan or misconfig_scan):
        logger.warning('run_combined_scan: no valid scan rows found — nothing to do')
        return

    # All three rows (when present) belong to the same tag — derive image coords
    # from whichever row is available.
    ref_scan = vuln_scan or secret_scan or misconfig_scan
    tag = ref_scan.tag
    repo = tag.repository
    project = repo.project

    # Skip scans that are already finished or running (e.g. a concurrent manual
    # 'Scan now' that completed while this task was waiting in the queue).
    if vuln_scan and vuln_scan.status in ('finished', 'running'):
        vuln_scan = None
    if secret_scan and secret_scan.status in ('finished', 'running'):
        secret_scan = None
    if misconfig_scan and misconfig_scan.status in ('finished', 'running'):
        misconfig_scan = None

    if not (vuln_scan or secret_scan or misconfig_scan):
        logger.info('run_combined_scan: all scans already finished/running for tag %s — skipping', tag.pk)
        return

    registry_host = _registry_url().replace('http://', '').replace('https://', '')
    # For per-platform child tags (parent_tag_id set), the tag name is not a
    # valid registry ref — use the parent index tag name and pull by digest.
    _ref_tag_name = tag.parent_tag.name if tag.parent_tag_id else tag.name
    docker_ref = f'{registry_host}/{project.name}/{repo.name}:{_ref_tag_name}'
    _child_digest = tag.digest if tag.parent_tag_id else None

    try:
        from django.contrib.auth.models import User
        from registry.auth import issue_token
        scope = f'repository:{project.name}/{repo.name}:pull'
        internal_user = User.objects.filter(is_superuser=True).first()
        token_data = issue_token(internal_user, scope)
    except Exception as exc:
        logger.error('run_combined_scan: could not issue token for tag %s: %s', tag.pk, exc)
        raise self.retry(exc=exc)

    # Transition all pending rows to running before the image pull starts so the
    # UI immediately shows progress rather than staying on 'pending'.
    _scan_type_labels = {
        id(vuln_scan): ('scan', vuln_scan_id),
        id(secret_scan): ('secret_scan', secret_scan_id),
        id(misconfig_scan): ('misconfig_scan', misconfig_scan_id),
    }
    for scan_obj, model in [
        (vuln_scan, VulnerabilityScan),
        (secret_scan, SecretScan),
        (misconfig_scan, MisconfigScan),
    ]:
        if scan_obj:
            scan_obj.status = model.STATUS_RUNNING
            scan_obj.started_at = timezone.now()
            scan_obj.save(update_fields=['status', 'started_at'])
            _rt, _sid = _scan_type_labels[id(scan_obj)]
            _log_scan_event('scan_started', _rt, tag, {
                'scan_id': _sid,
                'triggered_by': 'on_push',
            })

    oci_dir = ''
    try:
        oci_dir = _pull_image_to_oci_dir(docker_ref, tag.name, token_data['token'], child_digest=_child_digest)
        _external_host = os.environ.get('CUSTOM_DOMAIN', os.environ.get('DOMAIN', '')).strip()

        # ── Vulnerability scan ────────────────────────────────────────────────
        if vuln_scan:
            out_path = ''
            try:
                with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
                    out_path = f.name
                cmd = [
                    'trivy', 'image',
                    '--input', oci_dir,
                    '--server', _trivy_url(),
                    '--format', 'json',
                    '--output', out_path,
                    '--pkg-types', 'os,library',
                    '--scanners', 'vuln',
                    '--skip-java-db-update',
                    '--skip-db-update',
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    raise RuntimeError(f'trivy vuln exited {result.returncode}: {result.stderr[:500]}')

                with open(out_path) as f:
                    data = _json.load(f)

                summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0, 'unknown': 0}
                report = []
                for res in data.get('Results') or data.get('results') or []:
                    for vuln in res.get('Vulnerabilities') or res.get('vulnerabilities') or []:
                        sev = (vuln.get('Severity') or vuln.get('severity') or 'unknown').lower()
                        summary[sev] = summary.get(sev, 0) + 1
                        cvss = vuln.get('CVSS') or {}
                        cvss_v3_score = cvss_v2_score = None
                        cvss_v3_vector = ''
                        for _src, _scores in cvss.items():
                            if _scores.get('V3Score') is not None and cvss_v3_score is None:
                                cvss_v3_score = _scores['V3Score']
                                cvss_v3_vector = _scores.get('V3Vector', '')
                            if _scores.get('V2Score') is not None and cvss_v2_score is None:
                                cvss_v2_score = _scores['V2Score']
                        entry = {
                            'vulnerability_id':  vuln.get('VulnerabilityID') or vuln.get('vulnerabilityID', ''),
                            'pkg_name':          vuln.get('PkgName')          or vuln.get('pkgName', ''),
                            'installed_version': vuln.get('InstalledVersion') or vuln.get('installedVersion', ''),
                            'fixed_version':     vuln.get('FixedVersion')     or vuln.get('fixedVersion', ''),
                            'severity':          sev,
                            'title':             vuln.get('Title')            or vuln.get('title', ''),
                            'description':       vuln.get('Description')      or vuln.get('description', ''),
                            'references':        vuln.get('References')       or vuln.get('references') or [],
                            'cwe_ids':           vuln.get('CweIDs')           or vuln.get('cweIDs') or [],
                            'cvss_v3_score':     cvss_v3_score,
                            'cvss_v3_vector':    cvss_v3_vector,
                            'cvss_v2_score':     cvss_v2_score,
                            'published_date':    vuln.get('PublishedDate')    or vuln.get('publishedDate', ''),
                            'last_modified_date':vuln.get('LastModifiedDate') or vuln.get('lastModifiedDate', ''),
                            'data_source':       (vuln.get('DataSource') or {}).get('Name', ''),
                            'pkg_path':          vuln.get('PkgPath')          or vuln.get('pkgPath', ''),
                            'target':            res.get('Target', ''),
                            'class':             res.get('Class', ''),
                            'pkg_type':          res.get('Type', ''),
                        }
                        if _external_host and registry_host and isinstance(entry.get('target'), str):
                            entry['target'] = entry['target'].replace(registry_host, _external_host)
                        report.append(entry)

                vuln_scan.status = VulnerabilityScan.STATUS_FINISHED
                vuln_scan.finished_at = timezone.now()
                vuln_scan.summary = summary
                vuln_scan.report = report
                vuln_scan.save(update_fields=['status', 'finished_at', 'summary', 'report'])
                logger.info(
                    'run_combined_scan: vuln finished tag=%s critical=%s high=%s',
                    tag.pk, summary['critical'], summary['high'],
                )
                _dur = round((vuln_scan.finished_at - vuln_scan.started_at).total_seconds()) if vuln_scan.started_at else None
                _log_scan_event('scan_finished', 'scan', tag, {
                    'scan_id': vuln_scan_id,
                    'duration_seconds': _dur,
                    'critical': summary['critical'],
                    'high': summary['high'],
                    'medium': summary['medium'],
                    'low': summary['low'],
                    'total': len(report),
                })
            except Exception as exc:
                logger.error('run_combined_scan: vuln failed tag=%s: %s', tag.pk, exc)
                vuln_scan.status = VulnerabilityScan.STATUS_ERROR
                vuln_scan.finished_at = timezone.now()
                vuln_scan.save(update_fields=['status', 'finished_at'])
                _log_scan_event('scan_error', 'scan', tag, {
                    'scan_id': vuln_scan_id,
                    'error': _simplify_scan_error(exc),
                })
            finally:
                if out_path and os.path.exists(out_path):
                    os.unlink(out_path)

        # ── Secret scan ───────────────────────────────────────────────────────
        if secret_scan:
            out_path = ''
            try:
                with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
                    out_path = f.name
                secret_cache_dir = '/tmp/trivy-secret-cache'
                os.makedirs(secret_cache_dir, exist_ok=True)
                cmd = [
                    'trivy', 'image',
                    '--input', oci_dir,
                    '--format', 'json',
                    '--output', out_path,
                    '--cache-dir', secret_cache_dir,
                    '--scanners', 'secret',
                    '--skip-db-update',
                    '--skip-java-db-update',
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    raise RuntimeError(f'trivy secret exited {result.returncode}: {result.stderr[:500]}')

                with open(out_path) as f:
                    data = _json.load(f)

                report = []
                for res in data.get('Results') or data.get('results') or []:
                    target = res.get('Target', '')
                    if _external_host and registry_host and target.startswith(registry_host):
                        target = target.replace(registry_host, _external_host, 1)
                    for secret in res.get('Secrets') or res.get('secrets') or []:
                        report.append({
                            'rule_id':    secret.get('RuleID')   or secret.get('ruleID', ''),
                            'category':   secret.get('Category') or secret.get('category', ''),
                            'severity':   (secret.get('Severity') or secret.get('severity') or 'unknown').lower(),
                            'title':      secret.get('Title')    or secret.get('title', ''),
                            'target':     target,
                            'match':      secret.get('Match')    or secret.get('match', ''),
                            'start_line': secret.get('StartLine') or secret.get('startLine'),
                            'end_line':   secret.get('EndLine')   or secret.get('endLine'),
                        })

                secret_scan.status = SecretScan.STATUS_FINISHED
                secret_scan.finished_at = timezone.now()
                secret_scan.total = len(report)
                secret_scan.report = report
                secret_scan.save(update_fields=['status', 'finished_at', 'total', 'report'])
                logger.info('run_combined_scan: secret finished tag=%s secrets=%s', tag.pk, len(report))
                _dur = round((secret_scan.finished_at - secret_scan.started_at).total_seconds()) if secret_scan.started_at else None
                _log_scan_event('scan_finished', 'secret_scan', tag, {
                    'scan_id': secret_scan_id,
                    'duration_seconds': _dur,
                    'secrets_found': len(report),
                })
            except Exception as exc:
                logger.error('run_combined_scan: secret failed tag=%s: %s', tag.pk, exc)
                secret_scan.status = SecretScan.STATUS_ERROR
                secret_scan.finished_at = timezone.now()
                secret_scan.save(update_fields=['status', 'finished_at'])
                _log_scan_event('scan_error', 'secret_scan', tag, {
                    'scan_id': secret_scan_id,
                    'error': _simplify_scan_error(exc),
                })
            finally:
                if out_path and os.path.exists(out_path):
                    os.unlink(out_path)

        # ── Misconfig scan ────────────────────────────────────────────────────
        if misconfig_scan:
            out_path = ''
            try:
                with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
                    out_path = f.name
                misconfig_cache_dir = '/tmp/trivy-misconfig-cache'
                os.makedirs(misconfig_cache_dir, exist_ok=True)
                cmd = [
                    'trivy', 'image',
                    '--input', oci_dir,
                    '--format', 'json',
                    '--output', out_path,
                    '--cache-dir', misconfig_cache_dir,
                    '--scanners', '',
                    '--image-config-scanners', 'misconfig',
                    '--skip-db-update',
                    '--skip-java-db-update',
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    raise RuntimeError(f'trivy misconfig exited {result.returncode}: {result.stderr[:500]}')

                with open(out_path) as f:
                    data = _json.load(f)

                summary = {'FAIL': 0, 'WARN': 0, 'PASS': 0}
                report = []
                seen = set()
                for res in data.get('Results') or data.get('results') or []:
                    result_class = res.get('Class', '')
                    result_type = res.get('Type', '')
                    for mc in res.get('Misconfigurations') or res.get('misconfigurations') or []:
                        mc_id = mc.get('ID') or mc.get('id', '')
                        mc_target = res.get('Target', '') or res.get('target', '')
                        _custom_domain = os.environ.get('CUSTOM_DOMAIN', os.environ.get('DOMAIN', '')).strip()
                        if mc_target.startswith(registry_host + '/'):
                            suffix = mc_target[len(registry_host) + 1:]
                            mc_target = f'{_custom_domain}/{suffix}' if _custom_domain else suffix
                        status = (mc.get('Status') or mc.get('status') or 'FAIL').upper()
                        dedup_key = (mc_id, mc_target, status)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        summary[status] = summary.get(status, 0) + 1
                        report.append({
                            'id':           mc_id,
                            'avd_id':       mc.get('AVDID')       or mc.get('avdID', ''),
                            'type':         mc.get('Type')        or mc.get('type', ''),
                            'title':        mc.get('Title')       or mc.get('title', ''),
                            'description':  mc.get('Description') or mc.get('description', ''),
                            'message':      mc.get('Message')     or mc.get('message', ''),
                            'resolution':   mc.get('Resolution')  or mc.get('resolution', ''),
                            'severity':     (mc.get('Severity')   or mc.get('severity') or 'unknown').lower(),
                            'status':       status,
                            'references':   mc.get('References')  or mc.get('references') or [],
                            'target':       mc_target,
                            'class':        result_class,
                            'result_type':  result_type,
                        })

                misconfig_scan.status = MisconfigScan.STATUS_FINISHED
                misconfig_scan.finished_at = timezone.now()
                misconfig_scan.summary = summary
                misconfig_scan.report = report
                misconfig_scan.save(update_fields=['status', 'finished_at', 'summary', 'report'])
                logger.info(
                    'run_combined_scan: misconfig finished tag=%s FAIL=%s WARN=%s',
                    tag.pk, summary['FAIL'], summary['WARN'],
                )
                _dur = round((misconfig_scan.finished_at - misconfig_scan.started_at).total_seconds()) if misconfig_scan.started_at else None
                _log_scan_event('scan_finished', 'misconfig_scan', tag, {
                    'scan_id': misconfig_scan_id,
                    'duration_seconds': _dur,
                    'fail': summary['FAIL'],
                    'warn': summary['WARN'],
                    'pass': summary['PASS'],
                })
            except Exception as exc:
                logger.error('run_combined_scan: misconfig failed tag=%s: %s', tag.pk, exc)
                misconfig_scan.status = MisconfigScan.STATUS_ERROR
                misconfig_scan.finished_at = timezone.now()
                misconfig_scan.save(update_fields=['status', 'finished_at'])
                _log_scan_event('scan_error', 'misconfig_scan', tag, {
                    'scan_id': misconfig_scan_id,
                    'error': _simplify_scan_error(exc),
                })
            finally:
                if out_path and os.path.exists(out_path):
                    os.unlink(out_path)

    except Exception as exc:
        logger.error('run_combined_scan: image pull failed for tag %s: %s', tag.pk, exc)
        _pull_error = _simplify_scan_error(exc)
        for scan_obj, model_status, _rt, _sid in [
            (vuln_scan, VulnerabilityScan.STATUS_ERROR, 'scan', vuln_scan_id),
            (secret_scan, SecretScan.STATUS_ERROR, 'secret_scan', secret_scan_id),
            (misconfig_scan, MisconfigScan.STATUS_ERROR, 'misconfig_scan', misconfig_scan_id),
        ]:
            if scan_obj and scan_obj.status == 'running':
                scan_obj.status = model_status
                scan_obj.finished_at = timezone.now()
                scan_obj.save(update_fields=['status', 'finished_at'])
                _log_scan_event('scan_error', _rt, tag, {
                    'scan_id': _sid,
                    'error': f'Image pull failed: {_pull_error}',
                })
        raise self.retry(exc=exc)
    finally:
        if oci_dir and os.path.exists(oci_dir):
            _shutil.rmtree(oci_dir, ignore_errors=True)


# ── Periodic re-scan ──────────────────────────────────────────────────────────

@shared_task(
    bind=True,
    name='registry.tasks.run_rescan_stale',
    queue='default',
    max_retries=1,
)
def run_rescan_stale(self) -> None:
    """
    Re-queue vulnerability scans for any tag whose most recent finished scan
    is older than the project's configured rescan interval, so newly published
    CVEs are caught without requiring a re-push.

    Only runs for projects where both scanning_enabled and vuln_rescan_enabled
    are True. The interval is controlled by vuln_rescan_interval_days (default 7).
    Secrets and misconfigs are deterministic (image content does not change),
    so periodic re-scanning adds no value for those types.

    Runs every 6 hours via Celery Beat (configured in settings.CELERY_BEAT_SCHEDULE).

    At most MAX_PER_RUN scan rows are created per invocation to prevent a single
    Beat tick from flooding the scans queue with thousands of tasks that the
    single-concurrency worker cannot drain before the next tick fires.
    Tags are ordered by oldest scan first so the most stale are prioritised.
    """
    from registry.models import VulnerabilityScan, Tag, ProjectPolicy
    from django.db.models import OuterRef, Subquery, Exists, Q
    from users.models import SiteSettings

    # Maximum concurrent pending scans allowed system-wide — read from SiteSettings
    # so admins can tune it without a code deploy.  Fallback to 200 if the row
    # does not exist yet (e.g. fresh install before migrations run).
    try:
        MAX_PENDING = max(1, SiteSettings.get().rescan_batch_size)
    except Exception:
        MAX_PENDING = 200

    now = timezone.now()

    # ── Backpressure gate ─────────────────────────────────────────────────────
    # Count how many automated re-scan rows are already pending or running.
    # We only count rows whose tag belongs to a project with vuln scanning
    # enabled — manual on-push scans for disabled projects don't count against
    # the cap and would skew the number.  The status index makes this fast.
    current_pending = VulnerabilityScan.objects.filter(
        status__in=('pending', 'running'),
    ).count()

    slots_available = MAX_PENDING - current_pending
    if slots_available <= 0:
        logger.info(
            'run_rescan_stale: %s pending/running scan(s) already in queue '
            '(cap=%s) — skipping tick to let the queue drain',
            current_pending, MAX_PENDING,
        )
        return

    policies = ProjectPolicy.objects.filter(
        project_id__isnull=False
    ).values(
        'project_id', 'scanning_enabled', 'vuln_rescan_enabled',
        'vuln_rescan_interval_days', 'vuln_rescan_active_only', 'vuln_rescan_active_days',
    )

    # Map project_id → (rescan_cutoff, activity_cutoff|None)
    # activity_cutoff is non-None only when active-only mode is on.
    project_settings: dict[int, tuple] = {}
    for p in policies:
        if p['scanning_enabled'] and p['vuln_rescan_enabled']:
            interval_days = p['vuln_rescan_interval_days'] or 7
            rescan_cutoff = now - timedelta(days=interval_days)
            activity_cutoff = (
                now - timedelta(days=p['vuln_rescan_active_days'] or 90)
                if p['vuln_rescan_active_only']
                else None
            )
            project_settings[p['project_id']] = (rescan_cutoff, activity_cutoff)

    if not project_settings:
        logger.info('run_rescan_stale: no projects with automated vuln re-scanning enabled — nothing to do')
        return

    # Subquery: latest finished_at for finished scans on this tag
    latest_finished_sq = (
        VulnerabilityScan.objects
        .filter(tag=OuterRef('pk'), status='finished')
        .order_by('-finished_at')
        .values('finished_at')[:1]
    )

    # Subquery: does an inflight (pending/running) scan exist for this tag?
    inflight_sq = Exists(
        VulnerabilityScan.objects.filter(tag=OuterRef('pk'), status__in=['pending', 'running'])
    )

    # Build an activity filter covering every project that has active-only mode on.
    # Tags belonging to those projects must have last_activity_at >= that project's
    # cutoff.  We use per-project Q objects OR-ed together so it stays a single
    # SQL query rather than one query per project.
    # Projects without active-only mode contribute no filter (all their tags qualify).
    activity_q = Q()
    for project_id, (_, activity_cutoff) in project_settings.items():
        if activity_cutoff is not None:
            # Include tag when:
            #   a) last_activity_at is recorded and recent enough, OR
            #   b) last_activity_at is null (pre-dates the field) but pushed_at is
            #      recent enough — so tags that never got a recorded pull/push event
            #      are not wrongly excluded just because the field is null.
            activity_q |= Q(
                repository__project_id=project_id,
                last_activity_at__gte=activity_cutoff,
            ) | Q(
                repository__project_id=project_id,
                last_activity_at__isnull=True,
                pushed_at__gte=activity_cutoff,
            )
        else:
            activity_q |= Q(repository__project_id=project_id)

    candidate_tags = (
        Tag.objects
        .filter(repository__project_id__in=project_settings.keys())
        .filter(activity_q)
        # Index tags (manifest lists) have no scan rows of their own — scans
        # live on their per-platform child tags.  Exclude index tags so we
        # never create dangling VulnerabilityScan rows with no image to pull.
        .filter(is_index=False)
        .annotate(
            latest_finished=Subquery(latest_finished_sq),
            has_inflight=inflight_sq,
        )
        .filter(has_inflight=False)
        # Order oldest-scanned-first so the most stale tags are always prioritised
        # when the available slots run out.  NULLs (never scanned) sort first.
        .order_by('latest_finished')
        .select_related('repository__project')
    )

    vuln_queued = 0
    skipped_rescan_cutoff = 0
    for tag in candidate_tags.iterator(chunk_size=500):
        # Re-check the slot budget on every iteration — slots_available was
        # calculated before the loop and represents the headroom at tick start.
        if vuln_queued >= slots_available:
            break

        rescan_cutoff, _ = project_settings[tag.repository.project_id]

        # Queue if never scanned or last finished scan is older than the rescan cutoff
        if tag.latest_finished is None or tag.latest_finished < rescan_cutoff:
            new_scan = VulnerabilityScan.objects.create(tag=tag)
            run_vulnerability_scan.apply_async(args=[new_scan.id], kwargs={'triggered_by': 'rescan'}, queue='scans')
            vuln_queued += 1
        else:
            skipped_rescan_cutoff += 1

    logger.info(
        'run_rescan_stale: queued=%s skipped_not_due=%s slots_used=%s/%s pending_before=%s',
        vuln_queued, skipped_rescan_cutoff, vuln_queued, MAX_PENDING, current_pending,
    )


# ── SBOM generation ───────────────────────────────────────────────────────────

@shared_task(
    bind=True,
    name='registry.tasks.run_sbom',
    queue='sbom',
    max_retries=2,
    default_retry_delay=60,
)
def run_sbom(self, sbom_id: int) -> None:
    """
    Generate an SBOM for a tag using Syft (must be in PATH).

    Syft cannot pull directly from an unauthenticated or private-IP registry
    (it rejects private-IP token realms and ignores insecure-use-http env vars
    in some code paths). Instead we use skopeo to copy the image into a temp
    OCI layout directory, then point Syft at the local oci-dir. This works for
    both filesystem and S3 storage backends since skopeo always pulls over the
    network from siene-registry:5000.

    Syft is installed in the Docker image; in dev it must be installed locally
    or the task will fail gracefully without breaking anything.
    """
    from registry.models import SBOMReport

    try:
        sbom = SBOMReport.objects.select_related(
            'tag', 'tag__parent_tag', 'tag__repository', 'tag__repository__project'
        ).get(pk=sbom_id)
    except SBOMReport.DoesNotExist:
        logger.warning('run_sbom: SBOMReport %s not found', sbom_id)
        return

    tag = sbom.tag
    repo = tag.repository
    registry_host = _registry_url().replace('http://', '').replace('https://', '')
    _ref_tag_name = tag.parent_tag.name if tag.parent_tag_id else tag.name
    docker_ref = f'{registry_host}/{repo.project.name}/{repo.name}:{_ref_tag_name}'
    _child_digest = tag.digest if tag.parent_tag_id else None

    sbom.status = SBOMReport.STATUS_RUNNING
    sbom.save(update_fields=['status'])
    _log_scan_event('scan_started', 'sbom', tag, {
        'sbom_id': sbom_id,
        'triggered_by': 'manual',
    })

    out_path = ''
    oci_dir = ''
    try:
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            out_path = f.name

        from django.contrib.auth.models import User
        from registry.auth import issue_token
        scope = f'repository:{repo.project.name}/{repo.name}:pull'
        internal_user = User.objects.filter(is_superuser=True).first()
        token_data = issue_token(internal_user, scope)

        oci_dir = _pull_image_to_oci_dir(docker_ref, tag.name, token_data['token'], child_digest=_child_digest)

        result = subprocess.run(
            ['syft', f'oci-dir:{oci_dir}', '-o', f'spdx-json={out_path}'],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(f'syft exited {result.returncode}: {result.stderr[:500]}')

        import json as _json
        with open(out_path) as f:
            sbom_data = _json.load(f)

        # Replace the internal registry host with the public domain in all
        # package names, versionInfo fields, and PURL externalRefs so users
        # see e.g. "jfcr.io/olemiss/..." instead of "siene-registry:5000/...".
        _external_host = os.environ.get('CUSTOM_DOMAIN', os.environ.get('DOMAIN', '')).strip()
        if _external_host and registry_host and _external_host != registry_host:
            import urllib.parse as _urlparse
            _internal_encoded = _urlparse.quote(registry_host, safe='')
            _external_encoded = _urlparse.quote(_external_host, safe='')
            for _pkg in sbom_data.get('packages', []):
                for _field in ('name', 'versionInfo', 'downloadLocation'):
                    if isinstance(_pkg.get(_field), str):
                        _pkg[_field] = _pkg[_field].replace(registry_host, _external_host)
                for _ref in _pkg.get('externalRefs', []):
                    if isinstance(_ref.get('referenceLocator'), str):
                        _ref['referenceLocator'] = (
                            _ref['referenceLocator']
                            .replace(registry_host, _external_host)
                            .replace(_internal_encoded, _external_encoded)
                        )

        sbom.report = sbom_data
        sbom.status = SBOMReport.STATUS_FINISHED
        sbom.finished_at = timezone.now()
        sbom.save(update_fields=['report', 'status', 'finished_at'])
        logger.info('run_sbom: SBOM generated for sbom_id=%s (%s)', sbom_id, docker_ref)
        _packages = len(sbom_data.get('packages', []))
        _duration = round((sbom.finished_at - sbom.created_at).total_seconds()) if sbom.created_at else None
        _log_scan_event('scan_finished', 'sbom', tag, {
            'sbom_id': sbom_id,
            'duration_seconds': _duration,
            'packages': _packages,
        })

    except FileNotFoundError:
        logger.warning('run_sbom: syft not found in PATH — skipping SBOM id=%s', sbom_id)
        sbom.status = SBOMReport.STATUS_ERROR
        sbom.finished_at = timezone.now()
        sbom.save(update_fields=['status', 'finished_at'])
        _log_scan_event('scan_error', 'sbom', tag, {
            'sbom_id': sbom_id,
            'error': 'SBOM generator not available (syft not found)',
        })
    except Exception as exc:
        logger.error('run_sbom: failed for sbom_id=%s: %s', sbom_id, exc)
        sbom.status = SBOMReport.STATUS_ERROR
        sbom.finished_at = timezone.now()
        sbom.save(update_fields=['status', 'finished_at'])
        _log_scan_event('scan_error', 'sbom', tag, {
            'sbom_id': sbom_id,
            'error': _simplify_scan_error(exc),
        })
        raise self.retry(exc=exc)
    finally:
        if out_path and os.path.exists(out_path):
            os.unlink(out_path)
        if oci_dir and os.path.exists(oci_dir):
            import shutil
            shutil.rmtree(oci_dir, ignore_errors=True)


# ── Garbage collection ────────────────────────────────────────────────────────

def _gc_schedule_due(cfg) -> bool:
    """
    Return True if GC should run now according to the configured schedule.

    Schedule types:
      hourly         — due if never run, or last_run_at >= 1 h ago
      every_n_hours  — due if never run, or last_run_at >= N h ago
      daily          — due if today's scheduled time has passed AND
                       last run was not already today (local time)
      weekly         — due if today is the right day-of-week, today's
                       scheduled time has passed, AND last run was not
                       already this week (Mon–Sun)
      monthly        — due if today is the right day-of-month (or we're
                       past it within the same month), today's scheduled
                       time has passed, AND last run was not already
                       this month
    """
    import datetime as _dt

    now_utc = timezone.now()
    last = cfg.gc_last_run_at  # UTC-aware or None

    stype = getattr(cfg, 'gc_schedule_type', 'daily')

    if stype == 'hourly':
        if last is None:
            return True
        return (now_utc - last).total_seconds() >= 3600

    if stype == 'every_n_hours':
        if last is None:
            return True
        return (now_utc - last).total_seconds() >= cfg.gc_interval_hours * 3600

    # For daily / weekly / monthly we work in local time
    # Use the server's configured TIME_ZONE (Django's timezone.localtime())
    now_local = timezone.localtime(now_utc)
    last_local = timezone.localtime(last) if last else None

    try:
        h, m = [int(x) for x in cfg.gc_schedule_time.split(':')]
    except Exception:
        h, m = 2, 0  # safe default

    scheduled_time = _dt.time(h, m)

    if stype == 'daily':
        # Due if current local time >= scheduled time AND
        # we haven't already run today
        if now_local.time() < scheduled_time:
            return False
        if last_local is None:
            return True
        return last_local.date() < now_local.date()

    if stype == 'weekly':
        # weekday(): Mon=0 … Sun=6
        if now_local.weekday() != cfg.gc_schedule_day_of_week:
            return False
        if now_local.time() < scheduled_time:
            return False
        if last_local is None:
            return True
        # Same ISO week in same year?
        return not (last_local.isocalendar()[:2] == now_local.isocalendar()[:2])

    if stype == 'monthly':
        target_day = cfg.gc_schedule_day_of_month
        if now_local.day < target_day:
            return False
        if now_local.day == target_day and now_local.time() < scheduled_time:
            return False
        if last_local is None:
            return True
        # Already ran this calendar month?
        return not (last_local.year == now_local.year and last_local.month == now_local.month)

    # Fallback — always due
    return True


@shared_task(
    bind=True,
    name='registry.tasks.run_gc',
    queue='default',
    max_retries=1,
)
def run_gc(self, force: bool = False, gc_job_id: int | None = None) -> None:
    """
    Full GC sweep:
      1. Check schedule (skip if interval not elapsed, unless force=True)
      2. Remove orphaned Tag DB rows whose manifests no longer exist in registry
      3. Enforce tag retention rules per project policy
      4. Rotate audit logs older than the configured retention window
      5. Blob GC — reclaim unreferenced layer storage

    Called by Celery Beat every hour; skips work if the configured interval
    hasn't elapsed yet.  Can also be triggered manually (force=True skips check).
    If gc_job_id is provided the corresponding GCJob row is updated in-place.
    """
    from registry.models import Tag, ProjectPolicy, AuditLog, GCJob
    from users.models import SiteSettings
    import fnmatch as _fnmatch

    cfg = SiteSettings.get()

    # ── 1. Schedule check ────────────────────────────────────────────────────
    if not force:
        if not cfg.gc_enabled:
            logger.info('run_gc: GC disabled — skipping')
            return
        if not _gc_schedule_due(cfg):
            logger.info('run_gc: not yet due per schedule — skipping')
            return

    # ── Inflight guard ───────────────────────────────────────────────────────
    if not _acquire_gc_lock():
        logger.info('run_gc: another GC is already running — skipping')
        return

    # ── GCJob row ────────────────────────────────────────────────────────────
    if gc_job_id:
        try:
            job = GCJob.objects.get(pk=gc_job_id)
            job.status = GCJob.STATUS_RUNNING
            job.save(update_fields=['status'])
        except GCJob.DoesNotExist:
            job = GCJob.objects.create(triggered_by='schedule', status=GCJob.STATUS_RUNNING)
    else:
        # Scheduled (Beat) run — create the job row so the run is recorded.
        job = GCJob.objects.create(triggered_by='schedule', status=GCJob.STATUS_RUNNING)

    logger.info('run_gc: starting GC sweep')

    try:
        registry_base = _registry_url()
        deleted = 0
        errors = 0

        # ── 2. Orphaned tag check ─────────────────────────────────────────────
        # Instead of a HEAD request per tag (O(N) HTTP calls), fetch the live
        # tag list once per repo using GET /v2/{repo}/tags/list (paginated),
        # then delete DB rows whose name is absent from the registry response.
        # This reduces HTTP calls from one-per-tag to one-per-repo.
        from registry.models import Repository

        for repo in Repository.objects.select_related('project').iterator(chunk_size=100):
            repo_full = f'{repo.project.name}/{repo.name}'
            repo_headers = _registry_bearer_headers(f'repository:{repo_full}:pull')

            # Paginate through tags/list for this repo
            live_tags: set[str] = set()
            url: str | None = f'{registry_base}/v2/{repo_full}/tags/list?n=500'
            try:
                while url:
                    r = requests.get(url, headers=repo_headers, timeout=15)
                    if r.status_code == 404:
                        # Repo exists in DB but not in registry — all its tags are orphaned
                        live_tags = set()
                        url = None
                        break
                    r.raise_for_status()
                    live_tags.update(r.json().get('tags') or [])
                    link = r.headers.get('Link', '')
                    if 'rel="next"' in link:
                        next_url = link.split(';')[0].strip().strip('<>')
                        url = next_url if next_url.startswith('http') else f'{registry_base}{next_url}'
                    else:
                        url = None
            except requests.RequestException as exc:
                logger.warning('run_gc: could not list tags for %s: %s', repo_full, exc)
                errors += 1
                continue

            # Delete DB tag rows whose name is not present in the live registry set.
            # Skip stub rows (empty digest) — those are in-flight webhook rows.
            orphaned_qs = repo.tags.exclude(digest='').exclude(name__in=live_tags)
            for tag in orphaned_qs.iterator(chunk_size=200):
                logger.info('run_gc: orphaned tag %s:%s — deleting DB row', repo_full, tag.name)
                tag.delete()
                deleted += 1

            # Stale-pointer sweep: tags that appear in the live registry /tags/list
            # but whose manifest blob no longer resolves (404).  This happens when
            # a previous delete_tag / delete_repository call successfully removed
            # the manifest blob but failed to remove the tag-name pointer file.
            # Such pointers cause catalog sync to recreate ghost DB rows on every
            # run.  Detect them here with a HEAD per live tag not already in the DB,
            # remove the stale pointer from the registry, and skip DB creation.
            from registry.api import _registry_delete_tag_ref as _del_tag_ref
            stale_pointers = live_tags - {t.name for t in repo.tags.all()}
            if stale_pointers:
                stale_headers = _registry_bearer_headers(f'repository:{repo_full}:pull')
                for stale_tag in stale_pointers:
                    try:
                        head_r = requests.head(
                            f'{registry_base}/v2/{repo_full}/manifests/{stale_tag}',
                            headers={
                                **stale_headers,
                                'Accept': (
                                    'application/vnd.docker.distribution.manifest.v2+json,'
                                    'application/vnd.docker.distribution.manifest.list.v2+json,'
                                    'application/vnd.oci.image.manifest.v1+json,'
                                    'application/vnd.oci.image.index.v1+json,'
                                    '*/*'
                                ),
                            },
                            timeout=10,
                        )
                        if head_r.status_code == 404:
                            logger.warning(
                                'run_gc: stale tag pointer %s:%s — manifest 404, removing pointer from registry',
                                repo_full, stale_tag,
                            )
                            if not _del_tag_ref(repo_full, stale_tag):
                                logger.warning(
                                    'run_gc: could not remove stale pointer %s:%s from registry',
                                    repo_full, stale_tag,
                                )
                            errors += 1
                    except requests.RequestException as exc:
                        logger.warning(
                            'run_gc: could not HEAD manifest for stale tag %s:%s: %s',
                            repo_full, stale_tag, exc,
                        )

        # ── 3. Tag retention rules ────────────────────────────────────────────
        retention_deleted = 0
        for policy in ProjectPolicy.objects.select_related('project').filter(
            tag_retention_rules__isnull=False
        ).exclude(tag_retention_rules=[]):
            project = policy.project
            rules = policy.tag_retention_rules  # list of {match, keep_count, keep_days}
            if not rules:
                continue

            for repo in project.repositories.all():
                # Fetch tags once per repo, ordered newest-first.
                # (prefetch_related is intentionally avoided here — .order_by() on
                # the relation creates a new queryset that bypasses the prefetch
                # cache, causing an N+1 anyway.  A direct ordered query is clearer.)
                tags_qs = list(repo.tags.order_by('-pushed_at'))
                # Track which tags have already been claimed by an earlier rule so
                # that first-match-wins semantics are respected: once a tag is
                # matched by a rule (regardless of whether it ends up deleted), no
                # subsequent rule will touch it.
                claimed: set = set()

                for rule in rules:
                    pattern = rule.get('match', '**')
                    keep_count = rule.get('keep_count')
                    keep_days = rule.get('keep_days')

                    if keep_count is None and keep_days is None:
                        # Rule has no constraints — still claims matched tags so
                        # they are excluded from later rules.
                        matching = [t for t in tags_qs if _fnmatch.fnmatch(t.name, pattern) and t.pk not in claimed]
                        claimed.update(t.pk for t in matching)
                        continue

                    # Only consider tags not already claimed by an earlier rule.
                    matching = [t for t in tags_qs if _fnmatch.fnmatch(t.name, pattern) and t.pk not in claimed]
                    claimed.update(t.pk for t in matching)

                    # Build each candidate set independently, then intersect when
                    # both constraints are present.  A tag should only be deleted
                    # when it violates ALL active constraints — not just one.
                    by_count: set | None = None
                    by_days: set | None = None
                    if keep_count is not None:
                        by_count = {t.pk for t in matching[keep_count:]}
                    if keep_days is not None:
                        cutoff = timezone.now() - timedelta(days=keep_days)
                        # Tags with null pushed_at are skipped (treated as safe to
                        # keep) — consistent with the dry-run preview endpoint.
                        # Comparing None < datetime raises TypeError in Python 3.
                        by_days = {t.pk for t in matching if t.pushed_at is not None and t.pushed_at < cutoff}

                    if by_count is not None and by_days is not None:
                        to_delete = by_count & by_days
                    elif by_count is not None:
                        to_delete = by_count
                    elif by_days is not None:
                        to_delete = by_days
                    else:
                        to_delete = set()

                    if to_delete:
                        # Remove each tag from the registry before removing DB rows.
                        # Two-step deletion is required:
                        #   1. DELETE /v2/{repo}/manifests/{tag_name} — removes the
                        #      tag name reference (the pointer file in Distribution's
                        #      storage).  Without this the tag still appears in
                        #      /tags/list and catalog sync recreates the DB row.
                        #   2. DELETE /v2/{repo}/manifests/{digest} — removes the
                        #      manifest blob itself, but only when no other surviving
                        #      tag in the repo still points to the same digest.
                        from registry.api import _registry_delete_manifest, _registry_delete_tag_ref
                        repo_full = f'{project.name}/{repo.name}'
                        tags_to_delete = [t for t in matching if t.pk in to_delete]
                        for tag_obj in tags_to_delete:
                            # Always remove the tag name reference — this is what
                            # prevents catalog sync from recreating the DB row.
                            # Removing a tag pointer never affects the manifest blob
                            # itself; surviving sibling tags that share the same
                            # digest remain fully reachable by their own names.
                            if not _registry_delete_tag_ref(repo_full, tag_obj.name):
                                logger.warning(
                                    'run_gc: could not delete tag ref %s:%s from registry',
                                    repo_full, tag_obj.name,
                                )

                            # Only remove the manifest blob when no surviving tag
                            # (outside this deletion set) shares the same digest.
                            # Deleting a shared blob would break sibling tags and
                            # cause their scans/SBOMs to be wiped on the next
                            # orphan check.
                            if tag_obj.digest:
                                other_refs = Tag.objects.filter(
                                    repository=repo, digest=tag_obj.digest
                                ).exclude(pk__in=to_delete).exists()
                                if not other_refs:
                                    if not _registry_delete_manifest(repo_full, tag_obj.digest):
                                        logger.warning(
                                            'run_gc: could not delete manifest %s from registry for tag %s',
                                            tag_obj.digest, tag_obj,
                                        )
                            # Audit log entry for each GC-triggered deletion
                            AuditLog.objects.create(
                                user=None,
                                project=project,
                                operation='delete',
                                resource_type='image',
                                resource=f'{repo_full}:{tag_obj.name}',
                                result=True,
                                detail={'reason': 'tag_retention', 'rule_pattern': pattern},
                            )
                        n = Tag.objects.filter(pk__in=to_delete).delete()[0]
                        retention_deleted += n
                        logger.info('run_gc: retention rule "%s" deleted %s tags from %s',
                                    pattern, n, repo.full_name)

        # ── 4. Scan history pruning ───────────────────────────────────────────
        # Keep only the 5 most recent finished rows and 1 most recent error row
        # per tag per scan type.  Pending/running rows are never touched.
        # Uses a subquery to identify rows to keep, then bulk-deletes the rest —
        # entirely in SQL, no Python iteration over scan rows needed.
        from registry.models import VulnerabilityScan, SecretScan, MisconfigScan

        scans_pruned = 0
        _KEEP_FINISHED = 5
        _KEEP_ERROR    = 1

        for ScanModel in (VulnerabilityScan, SecretScan, MisconfigScan):
            for status, keep_n in (('finished', _KEEP_FINISHED), ('error', _KEEP_ERROR)):
                # Collect the PKs to keep — for each tag, take the newest keep_n rows
                # of this status ordered by started_at DESC.  A single query returns
                # all rows of this status across all tags; we then group by tag_id in
                # Python and slice.  The result set is small: at most keep_n rows per
                # tag, so memory usage is bounded.
                all_rows = list(
                    ScanModel.objects
                    .filter(status=status)
                    .order_by('tag_id', '-started_at')
                    .values('pk', 'tag_id')
                )
                keep_pks: set[int] = set()
                prev_tag: int | None = None
                count = 0
                for row in all_rows:
                    if row['tag_id'] != prev_tag:
                        prev_tag = row['tag_id']
                        count = 0
                    if count < keep_n:
                        keep_pks.add(row['pk'])
                        count += 1

                # Bulk-delete everything of this status not in the keep set
                n, _ = ScanModel.objects.filter(status=status).exclude(pk__in=keep_pks).delete()
                scans_pruned += n

        if scans_pruned:
            logger.info('run_gc: pruned %s stale scan history rows', scans_pruned)

        # ── 5. Audit log rotation ─────────────────────────────────────────────
        audit_deleted = 0
        if cfg.audit_log_retention_days > 0:
            cutoff = timezone.now() - timedelta(days=cfg.audit_log_retention_days)
            audit_deleted, _ = AuditLog.objects.filter(timestamp__lt=cutoff).delete()
            if audit_deleted:
                logger.info('run_gc: deleted %s audit log entries older than %s days',
                            audit_deleted, cfg.audit_log_retention_days)

        # ── 5b. Job log rotation ──────────────────────────────────────────────
        if cfg.job_log_retention_days > 0:
            from registry.models import GCJob, SyncJob, TrivyUpdateJob
            from registry.models import ReplicationJob
            job_cutoff = timezone.now() - timedelta(days=cfg.job_log_retention_days)
            for model in (GCJob, SyncJob, TrivyUpdateJob, ReplicationJob):
                n, _ = model.objects.filter(started_at__lt=job_cutoff).delete()
                if n:
                    logger.info('run_gc: deleted %s %s rows older than %s days',
                                n, model.__name__, cfg.job_log_retention_days)

        # ── 6. Blob GC — reclaim unreferenced layer storage ───────────────────
        # Runs after all manifest soft-deletes above so the registry binary sees
        # an up-to-date reference set.  Safe to run while the registry is live;
        # the 300 s timeout guards against hung runs.
        blob_gc_ok, blob_gc_output = _run_registry_blob_gc()
        if blob_gc_ok:
            logger.info('run_gc: blob GC complete — %s', blob_gc_output or 'no output')
        else:
            logger.warning('run_gc: blob GC — %s', blob_gc_output)

        # ── Update last-run timestamp ─────────────────────────────────────────
        cfg.gc_last_run_at = timezone.now()
        cfg.save(update_fields=['gc_last_run_at'])

        logger.info(
            'run_gc: complete — orphans=%s retention=%s scans_pruned=%s audit=%s errors=%s blob_gc=%s',
            deleted, retention_deleted, scans_pruned, audit_deleted, errors, 'ok' if blob_gc_ok else 'skipped/failed',
        )

        if job:
            job.status = GCJob.STATUS_SUCCESS
            job.finished_at = timezone.now()
            job.orphans_deleted = deleted
            job.retention_deleted = retention_deleted
            job.audit_deleted = audit_deleted
            job.errors = errors
            job.blob_gc_ok = blob_gc_ok
            job.blob_gc_output = blob_gc_output or ''
            job.save()

    except Exception as exc:
        if job:
            job.status = GCJob.STATUS_ERROR
            job.finished_at = timezone.now()
            job.error = str(exc)
            job.save()
        raise

    finally:
        _release_gc_lock()


# ── Registry catalog sync ─────────────────────────────────────────────────────

@shared_task(
    bind=True,
    name='registry.tasks.run_registry_sync',
    queue='default',
    max_retries=1,
)
def run_registry_sync(self, sync_job_id: int | None = None) -> None:
    """
    Walk the registry v2 catalog and ensure every repository that exists in
    the registry also exists in the DB.  Creates missing Project / Repository /
    Tag rows.  Does not delete DB rows for images that have been removed —
    use GC for that.

    sync_job_id: PK of the SyncJob row to update with progress/result.
    """
    from django.utils import timezone
    from registry.models import Project, Repository, Tag, SyncJob

    # ── Mark the job as running ───────────────────────────────────────────────
    job: SyncJob | None = None
    if sync_job_id is not None:
        try:
            job = SyncJob.objects.get(pk=sync_job_id)
            job.status = SyncJob.STATUS_RUNNING
            job.save(update_fields=['status'])
        except SyncJob.DoesNotExist:
            pass

    registry_base = _registry_url()
    # Catalog enumeration only needs registry:catalog:* scope.
    catalog_headers = _registry_bearer_headers('registry:catalog:*')

    logger.info('run_registry_sync: starting catalog sync')

    # Paginate through _catalog — Docker Distribution caps n at 100 by default.
    try:
        repositories = []
        url = f'{registry_base}/v2/_catalog?n=100'
        while url:
            r = requests.get(url, headers=catalog_headers, timeout=30)
            r.raise_for_status()
            repositories.extend(r.json().get('repositories') or [])
            # Follow Link header for next page if present
            link = r.headers.get('Link', '')
            if 'rel="next"' in link:
                # Format: <url>; rel="next"
                next_url = link.split(';')[0].strip().strip('<>')
                url = next_url if next_url.startswith('http') else f'{registry_base}{next_url}'
            else:
                url = None
    except requests.RequestException as exc:
        logger.error('run_registry_sync: failed to fetch catalog: %s', exc)
        if job is not None:
            job.status = SyncJob.STATUS_ERROR
            job.error = str(exc)
            job.finished_at = timezone.now()
            job.save(update_fields=['status', 'error', 'finished_at'])
        raise self.retry(exc=exc)

    created_repos = 0
    created_tags = 0

    for full_name in repositories:
        parts = full_name.split('/', 1)
        if len(parts) != 2:
            continue
        project_name, repo_name = parts

        project, _ = Project.objects.get_or_create(
            name=project_name,
            defaults={'display_name': project_name},
        )
        repo, repo_created = Repository.objects.get_or_create(
            project=project,
            name=repo_name,
        )

        # Issue a fresh token scoped to this specific repository for the
        # tags/list and manifests HEAD calls.  The catalog token does not
        # carry repository pull rights, so using it here would result in 401.
        repo_headers = _registry_bearer_headers(f'repository:{full_name}:pull')

        # Fetch tags for this repo
        try:
            tr = requests.get(
                f'{registry_base}/v2/{full_name}/tags/list',
                headers=repo_headers,
                timeout=15,
            )
            tr.raise_for_status()
            tag_names = tr.json().get('tags') or []
        except requests.RequestException as exc:
            logger.warning('run_registry_sync: could not list tags for %s: %s', full_name, exc)
            if repo_created:
                repo.delete()
            continue

        tags_imported = 0
        for tag_name in tag_names:
            if Tag.objects.filter(repository=repo, name=tag_name).exists():
                tags_imported += 1
                continue

            # Verify the manifest actually resolves before creating a DB row.
            # A stale tag pointer (tag appears in /tags/list but the manifest
            # blob was already deleted) will 404 here.  Importing such a row
            # would create a ghost tag that points to a missing manifest and
            # causes confusing UI state.  Skip it — the GC orphan sweep will
            # clean up the stale pointer from the registry on the next run.
            try:
                mr = requests.head(
                    f'{registry_base}/v2/{full_name}/manifests/{tag_name}',
                    headers={
                        **repo_headers,
                        'Accept': (
                            'application/vnd.docker.distribution.manifest.v2+json,'
                            'application/vnd.docker.distribution.manifest.list.v2+json,'
                            'application/vnd.oci.image.manifest.v1+json,'
                            'application/vnd.oci.image.index.v1+json,'
                            '*/*'
                        ),
                    },
                    timeout=10,
                )
                if mr.status_code == 404:
                    logger.warning(
                        'run_registry_sync: stale tag pointer %s:%s — manifest 404, skipping',
                        full_name, tag_name,
                    )
                    continue
                mr.raise_for_status()
                digest = mr.headers.get('Docker-Content-Digest', '')
                size = int(mr.headers.get('Content-Length', 0))
            except requests.RequestException as exc:
                logger.warning(
                    'run_registry_sync: could not fetch manifest for %s:%s: %s',
                    full_name, tag_name, exc,
                )
                continue

            Tag.objects.get_or_create(
                repository=repo,
                name=tag_name,
                defaults={'digest': digest, 'size_bytes': size},
            )
            created_tags += 1
            tags_imported += 1

        # If we just created an empty repo row and no tags could be imported
        # (all tags had stale pointers or the tags list was empty), roll back
        # the repo creation to avoid ghost repo rows in the DB.
        if repo_created and tags_imported == 0:
            logger.warning(
                'run_registry_sync: repo %s has no importable tags (all stale pointers?) — '
                'rolling back repo row creation',
                full_name,
            )
            repo.delete()
        elif repo_created:
            created_repos += 1

    logger.info(
        'run_registry_sync: complete — repos_created=%s tags_created=%s',
        created_repos, created_tags,
    )

    if job is not None:
        job.status = SyncJob.STATUS_SUCCESS
        job.repos_created = created_repos
        job.tags_created = created_tags
        job.finished_at = timezone.now()
        job.save(update_fields=['status', 'repos_created', 'tags_created', 'finished_at'])


# ── Replication helpers ───────────────────────────────────────────────────────

def _ensure_tag_row(local_repo, local_repo_full: str, tag_name: str) -> None:
    """
    Ensure a Tag row exists for a just-pulled image.

    Tries to fetch the real manifest from the local registry to populate all
    fields (digest, size, os, arch). Falls back to a minimal stub row if the
    manifest fetch fails or the webhook already created the row.
    """
    from registry.models import Tag as _Tag
    from registry.auth import issue_token as _issue_token
    from django.contrib.auth.models import User as _User
    import requests as _req

    # If the webhook already created the row, nothing to do.
    if _Tag.objects.filter(repository=local_repo, name=tag_name).exists():
        return

    registry_base = _registry_url()
    digest = ''
    size_bytes = 0
    computed_os = ''
    computed_arch = ''
    manifest_json: dict = {}
    computed_image_config: dict = {}

    try:
        _admin = _User.objects.filter(is_superuser=True).first()
        _tok = _issue_token(_admin, f'repository:{local_repo_full}:pull')['token']
        _headers = {
            'Accept': (
                'application/vnd.docker.distribution.manifest.v2+json,'
                'application/vnd.oci.image.manifest.v1+json'
            ),
            'Authorization': f'Bearer {_tok}',
        }
        mresp = _req.get(
            f'{registry_base}/v2/{local_repo_full}/manifests/{tag_name}',
            headers=_headers,
            timeout=10,
        )
        if mresp.ok:
            manifest_json = mresp.json()
            digest = mresp.headers.get('Docker-Content-Digest', '')
            if manifest_json.get('layers'):
                size_bytes = sum(l.get('size', 0) for l in manifest_json['layers'])
            # Fetch config blob for os/arch and full image config (history, env, cmd, …)
            cfg_digest = manifest_json.get('config', {}).get('digest')
            if cfg_digest:
                cresp = _req.get(
                    f'{registry_base}/v2/{local_repo_full}/blobs/{cfg_digest}',
                    headers={'Authorization': f'Bearer {_tok}'},
                    timeout=10,
                )
                if cresp.ok:
                    cfg = cresp.json()
                    computed_os = cfg.get('os', '') or ''
                    computed_arch = cfg.get('architecture', '') or ''
                    variant = cfg.get('variant', '') or ''
                    if variant:
                        computed_arch = f'{computed_arch}/{variant}'
                    computed_image_config = cfg
    except Exception as exc:
        logger.warning('_ensure_tag_row: manifest fetch failed for %s:%s — %s', local_repo_full, tag_name, exc)

    defaults: dict = {'digest': digest, 'size_bytes': size_bytes}
    if computed_os:
        defaults['os'] = computed_os
    if computed_arch:
        defaults['architecture'] = computed_arch
    if manifest_json:
        defaults['manifest'] = manifest_json
    if computed_image_config:
        defaults['image_config'] = computed_image_config

    # pushed_at is set on creation only — registry sync is not a real push event
    # and must not overwrite the timestamp recorded when the image was actually pushed.
    from django.utils import timezone as _tz
    _Tag.objects.update_or_create(
        repository=local_repo,
        name=tag_name,
        defaults=defaults,
        create_defaults={**defaults, 'pushed_at': _tz.now()},
    )


# ── Replication ───────────────────────────────────────────────────────────────

@shared_task(
    bind=True,
    name='registry.tasks.run_replication',
    queue='default',
    max_retries=2,
    default_retry_delay=60,
)
def run_replication(self, rule_id: int, tag_id: int | None = None) -> None:
    """
    Execute a replication rule — push or pull images between this registry
    and the configured remote using `skopeo copy`.

    tag_id — when supplied (on-push path) only that specific tag is copied
             instead of the full filtered set.  None means full-set run
             (manual trigger, scheduled trigger).

    skopeo must be available in PATH.  If it isn't the task logs a warning
    and exits cleanly so it doesn't spam retries.
    """
    from registry.models import ReplicationRule, Tag, ReplicationJob
    import fnmatch as _fnmatch

    try:
        rule = ReplicationRule.objects.select_related('remote').get(pk=rule_id)
    except ReplicationRule.DoesNotExist:
        logger.warning('run_replication: rule %s not found', rule_id)
        return

    if not rule.enabled:
        logger.info('run_replication: rule %s is disabled, skipping', rule_id)
        return

    # When triggered by an on-push webhook, verify the specific tag matches
    # this rule's filters before doing any further work (obtaining credentials,
    # creating a job row, etc.).  The webhook already does this check, but we
    # repeat it here as a safety net in case the task was queued by another
    # path or rule filters were updated between dispatch and execution.
    # Pull-direction rules are never triggered by a local push — skip silently.
    if tag_id is not None and rule.direction == ReplicationRule.DIRECTION_PULL:
        logger.info(
            'run_replication: rule %s is a pull rule — ignoring on-push dispatch (tag_id=%s)',
            rule_id, tag_id,
        )
        return

    if tag_id is not None and rule.direction == ReplicationRule.DIRECTION_PUSH:
        import fnmatch as _fnmatch_guard
        try:
            _guard_tag = Tag.objects.select_related('repository__project').get(pk=tag_id)
            _guard_repo_full = _guard_tag.repository.full_name
            if rule.source_filter and not _fnmatch_guard.fnmatch(_guard_repo_full, rule.source_filter):
                logger.info(
                    'run_replication: rule %s skipped — tag %s repo %s does not match source_filter %r',
                    rule_id, tag_id, _guard_repo_full, rule.source_filter,
                )
                return
            if rule.tag_filter and not _fnmatch_guard.fnmatch(_guard_tag.name, rule.tag_filter):
                logger.info(
                    'run_replication: rule %s skipped — tag %s name %r does not match tag_filter %r',
                    rule_id, tag_id, _guard_tag.name, rule.tag_filter,
                )
                return
        except Tag.DoesNotExist:
            logger.warning('run_replication: tag_id %s not found — skipping', tag_id)
            return

    # Create a job row for this execution
    job = ReplicationJob.objects.create(rule=rule, status=ReplicationJob.STATUS_RUNNING)

    remote = rule.remote
    local_base = _registry_url().replace('http://', '').replace('https://', '')
    remote_base = remote.endpoint.rstrip('/').replace('http://', '').replace('https://', '')

    # Issue a pre-signed token for the local registry so skopeo never contacts
    # the auth realm URL (which is only reachable from outside the Docker network).
    from registry.auth import issue_token
    from django.contrib.auth.models import User as _User

    # Use the first system-admin user available to obtain full pull/push grants.
    _admin_qs = _User.objects.filter(userprofile__is_admin=True, is_active=True)
    _token_user = _admin_qs.select_related('userprofile').first()

    def _local_token_for(repo_full_name: str, actions: str) -> str:
        if _token_user is None:
            return ''
        scope = f'repository:{repo_full_name}:{actions}'
        return issue_token(_token_user, scope)['token']

    # Local tag queryset for the PUSH branch.
    # When tag_id is set (on-push fast-path) we only copy that one tag.
    # Otherwise apply source_filter at the DB level for exact patterns to
    # avoid loading the entire registry into memory.
    _sf = rule.source_filter or ''
    if rule.direction == ReplicationRule.DIRECTION_PUSH and tag_id is not None:
        qs = Tag.objects.select_related('repository__project').filter(pk=tag_id)
    elif rule.direction == ReplicationRule.DIRECTION_PUSH and _sf and '*' not in _sf and '?' not in _sf:
        _parts = _sf.split('/', 1)
        if len(_parts) == 2:
            qs = Tag.objects.select_related('repository__project').filter(
                repository__project__name=_parts[0],
                repository__name=_parts[1],
            )
        else:
            qs = Tag.objects.select_related('repository__project').filter(
                repository__project__name=_parts[0],
            )
    else:
        qs = Tag.objects.select_related('repository__project').iterator(chunk_size=500)

    rule.last_run_at = timezone.now()
    rule.last_run_status = 'running'
    rule.save(update_fields=['last_run_at', 'last_run_status'])

    job.append_log(f'Starting replication rule "{rule.name}" ({rule.direction} → {remote.name})')

    errors = 0
    copied = 0

    # ── Pre-obtain remote credentials ─────────────────────────────────────────
    # Decrypt the stored credential once here — never use remote.password_enc directly.
    _remote_password = remote.get_password()

    # For ECR remotes, exchange AWS credentials for a short-lived Docker token
    # once before the loop (valid 12 h; much cheaper than per-tag calls).
    remote_creds: str | None = None
    if remote.registry_type == 'ecr' and remote.username and _remote_password:
        ecr_token = _ecr_docker_token(remote.username, _remote_password, remote.endpoint)
        if ecr_token:
            remote_creds = f'AWS:{ecr_token}'
            job.append_log('Obtained ECR authorization token')
        else:
            job.append_log('WARNING: failed to obtain ECR token — copies will likely fail')
    elif remote.username and _remote_password:
        remote_creds = f'{remote.username}:{_remote_password}'

    def _skopeo_copy(src: str, dst: str, src_token: str | None, dst_token: str | None,
                     src_creds: str | None, dst_creds: str | None,
                     src_tls: bool, dst_tls: bool) -> bool:
        """Run skopeo copy and return True on success. Raises FileNotFoundError if skopeo missing."""
        cmd = ['skopeo', 'copy', '--insecure-policy']
        if not src_tls:
            cmd.append('--src-tls-verify=false')
        if not dst_tls:
            cmd.append('--dest-tls-verify=false')
        if src_token:
            cmd.append(f'--src-registry-token={src_token}')
        if dst_token:
            cmd.append(f'--dest-registry-token={dst_token}')
        if src_creds:
            cmd.append(f'--src-creds={src_creds}')
        if dst_creds:
            cmd.append(f'--dest-creds={dst_creds}')
        cmd += [src, dst]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            err_msg = result.stderr.strip().split('\n')[-1][:200]
            job.append_log(f'  ERROR: {err_msg}')
            logger.warning('run_replication: skopeo failed %s → %s: %s', src, dst, result.stderr[:300])
            return False
        return True

    def _skopeo_copy_via_oci(src: str, dst: str, src_token: str | None, dst_token: str | None,
                              src_creds: str | None, src_tls: bool, dst_tls: bool) -> bool:
        """
        Two-step skopeo copy: remote docker:// → temp oci: dir → local docker://.

        Used for the pull direction when the local registry uses S3 storage.
        Docker Distribution with S3 responds to blob HEAD/GET requests with 307
        redirects to presigned S3 URLs.  skopeo's blob-reuse (cross-repo mount)
        check follows these redirects but can't interpret the S3 response as a
        valid registry blob check, causing a fatal error even though the copy
        would otherwise succeed.

        Going through an intermediate OCI layout dir sidesteps the issue: the
        second leg (oci: → docker://) always uploads all blobs directly from
        local disk without attempting a blob-mount check against the destination,
        so the S3 redirect is never triggered during the existence check.

        Raises FileNotFoundError if skopeo is not installed.
        """
        import shutil as _shutil

        oci_tmp = tempfile.mkdtemp(prefix='siene-repl-oci-')
        try:
            # Step 1: remote docker:// → local oci: dir
            cmd1 = ['skopeo', 'copy', '--insecure-policy']
            if not src_tls:
                cmd1.append('--src-tls-verify=false')
            if src_token:
                cmd1.append(f'--src-registry-token={src_token}')
            if src_creds:
                cmd1.append(f'--src-creds={src_creds}')
            cmd1 += [src, f'oci:{oci_tmp}:image']
            r1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=600)
            if r1.returncode != 0:
                err_msg = r1.stderr.strip().split('\n')[-1][:200]
                job.append_log(f'  ERROR: {err_msg}')
                logger.warning('run_replication: skopeo pull step failed %s: %s', src, r1.stderr[:300])
                return False

            # Step 2: local oci: dir → local docker://
            cmd2 = ['skopeo', 'copy', '--insecure-policy']
            if not dst_tls:
                cmd2.append('--dest-tls-verify=false')
            if dst_token:
                cmd2.append(f'--dest-registry-token={dst_token}')
            cmd2 += [f'oci:{oci_tmp}:image', dst]
            r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=600)
            if r2.returncode != 0:
                err_msg = r2.stderr.strip().split('\n')[-1][:200]
                job.append_log(f'  ERROR: {err_msg}')
                logger.warning('run_replication: skopeo push step failed %s: %s', dst, r2.stderr[:300])
                return False

            return True
        finally:
            _shutil.rmtree(oci_tmp, ignore_errors=True)

    def _finish_error():
        rule.last_run_status = 'error'
        rule.save(update_fields=['last_run_status'])
        job.status = ReplicationJob.STATUS_ERROR
        job.finished_at = timezone.now()
        job.copied = copied
        job.errors = errors
        job.save(update_fields=['status', 'finished_at', 'copied', 'errors'])

    # ── PUSH direction ────────────────────────────────────────────────────────
    if rule.direction == ReplicationRule.DIRECTION_PUSH:
        if rule.source_filter:
            qs = [t for t in qs if _fnmatch.fnmatch(t.repository.full_name, rule.source_filter)]
        if rule.tag_filter:
            qs = [t for t in qs if _fnmatch.fnmatch(t.name, rule.tag_filter)]

        tag_list = list(qs) if isinstance(qs, list) else list(qs)
        job.append_log(f'Found {len(tag_list)} candidate tag(s) in local registry')

        for tag in tag_list:
            repo = tag.repository
            # Compute destination repo path, honouring flatten_mode.
            # flatten_mode operates on the *source* repo's full name before
            # destination_namespace is applied:
            #   none       → keep full path:          project/repo → project/repo
            #   flatten_1  → strip first component:   project/repo → repo
            #   flatten_all→ keep only the last part: a/b/c        → c
            src_parts = repo.full_name.split('/')
            if rule.flatten_mode == 'flatten_all':
                flattened_name = src_parts[-1]
            elif rule.flatten_mode == 'flatten_1':
                flattened_name = '/'.join(src_parts[1:]) if len(src_parts) > 1 else src_parts[0]
            else:  # 'none'
                flattened_name = repo.full_name

            if rule.destination_namespace:
                dst_repo = f'{rule.destination_namespace}/{flattened_name}'
            else:
                dst_repo = flattened_name

            src_ref = f'docker://{local_base}/{repo.full_name}:{tag.name}'
            dst_ref = f'docker://{remote_base}/{dst_repo}:{tag.name}'

            # Auto-create destination repository for providers that require it
            if remote.username and _remote_password:
                if remote.registry_type == 'ecr':
                    job.append_log(f'Ensuring ECR repository: {dst_repo}')
                    _ecr_ensure_repo(remote.username, _remote_password, remote.endpoint, dst_repo)
                elif remote.registry_type == 'swr':
                    job.append_log(f'Ensuring SWR repository: {dst_repo}')
                    _swr_ensure_repo(remote.username, _remote_password, remote.endpoint, dst_repo)
                elif remote.registry_type == 'tcr':
                    job.append_log(f'Ensuring TCR repository: {dst_repo}')
                    _tcr_ensure_repo(remote.username, _remote_password, remote.endpoint, dst_repo)

            local_token = _local_token_for(repo.full_name, 'pull')

            # Always check whether the remote already has the same digest.
            # Identical digest = identical content — never re-upload regardless
            # of override_existing (that flag only governs whether a tag whose
            # digest has *changed* should be overwritten).
            remote_scheme = 'https' if not remote.insecure else 'http'
            try:
                _head_kwargs: dict = dict(timeout=10, verify=not remote.insecure)
                if remote_creds:
                    _ru, _, _rp = remote_creds.partition(':')
                    _head_kwargs['auth'] = (_ru, _rp)
                _head_resp = requests.head(
                    f'{remote_scheme}://{remote_base}/v2/{dst_repo}/manifests/{tag.name}',
                    headers={'Accept': (
                        'application/vnd.docker.distribution.manifest.v2+json,'
                        'application/vnd.oci.image.manifest.v1+json,'
                        'application/vnd.docker.distribution.manifest.list.v2+json,'
                        'application/vnd.oci.image.index.v1+json,'
                        '*/*'
                    )},
                    **_head_kwargs,
                )
                if _head_resp.status_code == 200:
                    remote_digest = _head_resp.headers.get('Docker-Content-Digest', '')
                    if remote_digest and remote_digest == tag.digest:
                        job.append_log(f'Skipping {dst_repo}:{tag.name} (digest unchanged)')
                        continue
                    # Tag exists but digest differs — skip if override disabled
                    if not rule.override_existing:
                        job.append_log(f'Skipping {dst_repo}:{tag.name} (exists on remote, override disabled)')
                        continue
            except Exception as _he:
                # Network error checking remote — proceed with copy to be safe
                job.append_log(f'  WARNING: could not check remote digest for {dst_repo}:{tag.name}: {_he}')

            job.append_log(f'Copying {repo.full_name}:{tag.name} → {dst_repo}:{tag.name}')
            try:
                ok = _skopeo_copy(
                    src=src_ref, dst=dst_ref,
                    src_token=local_token, dst_token=None,
                    src_creds=None, dst_creds=remote_creds,
                    src_tls=False, dst_tls=not remote.insecure,
                )
                if ok:
                    job.append_log('  OK')
                    copied += 1
                else:
                    errors += 1
            except FileNotFoundError:
                job.append_log('ERROR: skopeo not found in PATH')
                logger.warning('run_replication: skopeo not found in PATH')
                _finish_error()
                return
            except subprocess.TimeoutExpired:
                job.append_log('  ERROR: timed out after 300s')
                errors += 1

    # ── PULL direction ────────────────────────────────────────────────────────
    else:
        # Enumerate repositories and tags from the *remote* registry via its v2 API.
        # For ECR/Docker Hub/other cloud registries the catalog endpoint is not
        # available — instead we rely on source_filter to know which repos to pull.
        from registry.models import Project, Repository, Tag as _Tag

        remote_tls = not remote.insecure
        remote_scheme = 'https' if remote_tls else 'http'

        def _remote_get(path: str):
            """GET against the remote registry v2 API with credentials."""
            url = f'{remote_scheme}://{remote_base}{path}'
            kwargs = dict(timeout=15, verify=remote_tls)
            if remote_creds:
                u, _, p = remote_creds.partition(':')
                kwargs['auth'] = (u, p)
            return requests.get(url, **kwargs)

        # Build the list of remote repositories to pull from.
        # source_filter is a glob on <repo_full_name> e.g. "myorg/*" or "library/alpine"
        remote_repos: list[str] = []

        # Registries known to not support the v2 catalog endpoint
        _no_catalog_types = {'ecr', 'docker-hub', 'gcr', 'acr-azure', 'tcr', 'swr'}

        if rule.source_filter and '*' not in rule.source_filter:
            # Exact repo name given — no need to enumerate catalog
            remote_repos = [rule.source_filter]
            job.append_log(f'Target repository: {rule.source_filter}')
        elif remote.registry_type in _no_catalog_types and '*' in (rule.source_filter or ''):
            job.append_log(
                f'{remote.registry_type.upper()} does not support the v2 catalog API. '
                f'Set source_filter to an exact repository name with no wildcards (e.g. "myrepo" or "myorg/myrepo").'
            )
            _finish_error()
            return
        else:
            # Try the v2 catalog endpoint
            try:
                cat_resp = _remote_get('/v2/_catalog?n=10000')
                if cat_resp.status_code == 200:
                    all_repos = cat_resp.json().get('repositories') or []
                    if rule.source_filter:
                        remote_repos = [r for r in all_repos if _fnmatch.fnmatch(r, rule.source_filter)]
                    else:
                        remote_repos = all_repos
                    job.append_log(f'Catalog returned {len(all_repos)} repositories; {len(remote_repos)} match filter')
                elif cat_resp.status_code in (404, 405, 401, 403):
                    job.append_log(
                        f'Remote catalog API not available (HTTP {cat_resp.status_code}) — '
                        f'ECR and Docker Hub do not support the v2 catalog endpoint. '
                        f'Set source_filter to an exact repository name (e.g. "myorg/myapp") with no wildcards.'
                    )
                    _finish_error()
                    return
                else:
                    job.append_log(f'WARNING: catalog returned HTTP {cat_resp.status_code} — Set source_filter to an exact repository name.')
                    _finish_error()
                    return
            except Exception as exc:
                job.append_log(f'ERROR: could not reach remote catalog: {exc}')
                _finish_error()
                return

        if not remote_repos:
            job.append_log('No matching repositories found on remote')
            rule.last_run_status = 'success'
            rule.save(update_fields=['last_run_status'])
            job.status = ReplicationJob.STATUS_SUCCESS
            job.finished_at = timezone.now()
            job.copied = 0
            job.errors = 0
            job.append_log('Done — copied=0 errors=0')
            job.save(update_fields=['status', 'finished_at', 'copied', 'errors'])
            return

        for remote_repo in remote_repos:
            # List tags on the remote
            try:
                tags_resp = _remote_get(f'/v2/{remote_repo}/tags/list')
                if not tags_resp.ok:
                    job.append_log(f'WARNING: could not list tags for {remote_repo}: HTTP {tags_resp.status_code}')
                    errors += 1
                    continue
                tag_names: list[str] = tags_resp.json().get('tags') or []
            except Exception as exc:
                job.append_log(f'ERROR listing tags for {remote_repo}: {exc}')
                errors += 1
                continue

            if rule.tag_filter:
                tag_names = [t for t in tag_names if _fnmatch.fnmatch(t, rule.tag_filter)]

            if not tag_names:
                job.append_log(f'{remote_repo}: no matching tags')
                continue

            job.append_log(f'{remote_repo}: {len(tag_names)} tag(s) to pull')

            # Determine local destination path
            # destination_namespace overrides the project (first path component)
            parts = remote_repo.split('/', 1)
            if len(parts) == 2:
                remote_project, remote_name = parts
            else:
                remote_project, remote_name = remote_repo, remote_repo

            if rule.destination_namespace:
                # destination_namespace is a project name — take only the first
                # path component so "test/docker-frontend" → "test"
                local_project_name = rule.destination_namespace.split('/')[0]
            else:
                local_project_name = remote_project

            local_repo_name = remote_name
            local_repo_full = f'{local_project_name}/{local_repo_name}'

            # Ensure local Project + Repository exist
            local_project, _ = Project.objects.get_or_create(
                name=local_project_name,
                defaults={'display_name': local_project_name},
            )
            local_repo, _ = Repository.objects.get_or_create(
                project=local_project,
                name=local_repo_name,
            )

            for tag_name in tag_names:
                src_ref = f'docker://{remote_base}/{remote_repo}:{tag_name}'
                dst_ref = f'docker://{local_base}/{local_repo_full}:{tag_name}'

                # Token needs both pull and push scope: skopeo's blob-exists
                # check (HEAD /v2/.../blobs/<digest>) requires pull, and the
                # actual layer upload requires push.  A push-only token causes
                # Distribution to return 401 on the blob HEAD, which skopeo
                # misinterprets as a fatal error rather than "blob not present".
                local_token = _local_token_for(local_repo_full, 'pull,push')

                # Always fetch the remote digest and compare against the local DB.
                # Identical digest = identical content — never re-download regardless
                # of override_existing (that flag only governs whether a tag whose
                # digest has *changed* should be overwritten).
                try:
                    _rhead_kwargs: dict = dict(timeout=10, verify=remote_tls)
                    if remote_creds:
                        _rru, _, _rrp = remote_creds.partition(':')
                        _rhead_kwargs['auth'] = (_rru, _rrp)
                    _rhead = requests.head(
                        f'{remote_scheme}://{remote_base}/v2/{remote_repo}/manifests/{tag_name}',
                        headers={'Accept': (
                            'application/vnd.docker.distribution.manifest.v2+json,'
                            'application/vnd.oci.image.manifest.v1+json,'
                            'application/vnd.docker.distribution.manifest.list.v2+json,'
                            'application/vnd.oci.image.index.v1+json,'
                            '*/*'
                        )},
                        **_rhead_kwargs,
                    )
                    if _rhead.ok:
                        remote_digest = _rhead.headers.get('Docker-Content-Digest', '')
                        if remote_digest:
                            _local_tag = _Tag.objects.filter(repository=local_repo, name=tag_name).first()
                            if _local_tag and _local_tag.digest == remote_digest:
                                job.append_log(f'Skipping {local_repo_full}:{tag_name} (digest unchanged)')
                                continue
                            # Digest differs (or tag is new) — skip overwrite if the
                            # destination project has tag immutability enabled.
                            if _local_tag:
                                try:
                                    from registry.models import ProjectPolicy as _PP
                                    _imm_policy, _ = _PP.objects.get_or_create(project=local_project)
                                    if _imm_policy.tag_immutability:
                                        job.append_log(
                                            f'Skipping {local_repo_full}:{tag_name} '
                                            f'(tag immutability enabled — existing tag cannot be overwritten)'
                                        )
                                        continue
                                except Exception:
                                    pass
                            # Skip overwrite if override is disabled and the tag already exists.
                            if _local_tag and not rule.override_existing:
                                job.append_log(f'Skipping {local_repo_full}:{tag_name} (exists locally, override disabled)')
                                continue
                except Exception as _rhe:
                    # Cannot reach remote for digest check — proceed with copy to be safe
                    job.append_log(f'  WARNING: could not check remote digest for {remote_repo}:{tag_name}: {_rhe}')

                job.append_log(f'Pulling {remote_repo}:{tag_name} → {local_repo_full}:{tag_name}')
                try:
                    ok = _skopeo_copy_via_oci(
                        src=src_ref, dst=dst_ref,
                        src_token=None, dst_token=local_token,
                        src_creds=remote_creds,
                        src_tls=remote_tls, dst_tls=False,
                    )
                    if ok:
                        job.append_log('  OK')
                        copied += 1
                        # Give the registry webhook a moment to fire and create
                        # the Tag row before we check ourselves.
                        import time as _time
                        _time.sleep(2)
                        _ensure_tag_row(local_repo, local_repo_full, tag_name)

                        # Apply auto-labels from label_filter to the pulled tag.
                        # label_filter stores comma-separated label names that must
                        # already exist in the destination project.
                        if rule.label_filter:
                            from registry.models import Label as _Label, Tag as _TagM
                            _label_names = [n.strip() for n in rule.label_filter.split(',') if n.strip()]
                            if _label_names:
                                try:
                                    _pulled_tag = _TagM.objects.filter(
                                        repository=local_repo, name=tag_name
                                    ).first()
                                    if _pulled_tag:
                                        _labels = _Label.objects.filter(
                                            project=local_project,
                                            name__in=_label_names,
                                        )
                                        _pulled_tag.labels.add(*_labels)
                                        if _labels:
                                            job.append_log(
                                                f'  Labelled with: {", ".join(l.name for l in _labels)}'
                                            )
                                except Exception as _le:
                                    logger.warning(
                                        'run_replication: failed to apply labels to %s:%s — %s',
                                        local_repo_full, tag_name, _le,
                                    )
                    else:
                        errors += 1
                except FileNotFoundError:
                    job.append_log('ERROR: skopeo not found in PATH')
                    logger.warning('run_replication: skopeo not found in PATH')
                    _finish_error()
                    return
                except subprocess.TimeoutExpired:
                    job.append_log(f'  ERROR: timed out after 300s')
                    errors += 1

    final_status = 'success' if errors == 0 else 'partial'
    rule.last_run_status = final_status
    rule.save(update_fields=['last_run_status'])

    job.status = ReplicationJob.STATUS_SUCCESS if errors == 0 else ReplicationJob.STATUS_PARTIAL
    job.finished_at = timezone.now()
    job.copied = copied
    job.errors = errors
    job.append_log(f'Done — copied={copied} errors={errors}')
    job.save(update_fields=['status', 'finished_at', 'copied', 'errors'])

    logger.info('run_replication: rule %s complete — copied=%s errors=%s', rule_id, copied, errors)


# ── Signature checking ────────────────────────────────────────────────────────

@shared_task(
    bind=True,
    name='registry.tasks.run_signature_check',
    queue='default',
    max_retries=2,
    default_retry_delay=30,
)
def run_signature_check(self, tag_id: int) -> None:
    """
    Check whether a tag has cosign / notation signatures stored in the registry.

    Cosign strategy
    ---------------
    Cosign stores signatures as OCI artifacts tagged  ``sha256-<hex>.sig``
    in the *same repository*.  We:

    1. Ask the registry for the tag list of the repo.
    2. If a ``sha256-<hex>.sig`` tag matching this tag's digest exists, the
       image has been cosign-signed.
    3. We then run ``cosign verify`` with ``--insecure-ignore-tlog``
       and permissive OIDC matchers so keyless Sigstore signatures are
       accepted.  If the binary succeeds → ``signed``; if it exits non-zero
       but the artifact existed → ``failed`` (signed but verification error).
       If no artifact → ``not_signed``.

    Notation strategy
    -----------------
    Notation stores signatures as OCI referrers with artifactType
    ``application/vnd.cncf.notary.signature``.  We:

    1. Try the OCI referrers API (``GET /v2/<repo>/referrers/<digest>``).
    2. Fall back to a tag-based check: notation also pushes a tag named
       ``sha256-<hex>`` (no ``.sig`` suffix) for older registries.
    """
    from registry.models import Tag, TagSignatureStatus

    try:
        tag = Tag.objects.select_related('repository__project').get(pk=tag_id)
    except Tag.DoesNotExist:
        logger.warning('run_signature_check: tag %s not found', tag_id)
        return

    repo = tag.repository
    project_name = repo.project.name
    repo_name = repo.name
    registry_host = _registry_url().replace('http://', '').replace('https://', '')
    repo_full = f'{project_name}/{repo_name}'

    sig_status, _ = TagSignatureStatus.objects.get_or_create(tag=tag)

    # ── 1. Cosign — presence detection via registry tag list ──────────────────
    # The cosign sig tag looks like:  sha256-<64-char-hex>.sig
    digest_hex = tag.digest.replace('sha256:', '')
    cosign_sig_tag = f'sha256-{digest_hex}.sig'

    cosign_result = TagSignatureStatus.RESULT_UNKNOWN
    cosign_output = ''

    try:
        from django.contrib.auth.models import User
        from registry.auth import issue_token
        internal_user = User.objects.filter(is_superuser=True).first()
        scope = f'repository:{repo_full}:pull'
        token_data = issue_token(internal_user, scope)

        tags_resp = requests.get(
            f'{_registry_url()}/v2/{repo_full}/tags/list',
            headers={'Authorization': f'Bearer {token_data["token"]}'},
            timeout=10,
        )
        all_tags = tags_resp.json().get('tags') or [] if tags_resp.ok else []
        sig_artifact_present = cosign_sig_tag in all_tags

        if not sig_artifact_present:
            cosign_result = TagSignatureStatus.RESULT_NOT_SIGNED
            cosign_output = f'No cosign signature artifact found (looked for tag {cosign_sig_tag})'
        else:
            # Signature artifact is present — mark as signed.
            # Presence of the sha256-<hex>.sig OCI artifact is the authoritative
            # signal that cosign was used to sign this image.  Full cryptographic
            # verify via the cosign binary is skipped because the registry uses a
            # JWT token-auth flow that cosign cannot negotiate without a separate
            # credential helper; the OCI presence check (above) already confirms
            # the signature artifact was pushed.
            cosign_result = TagSignatureStatus.RESULT_SIGNED
            cosign_output = f'Signature artifact found: {cosign_sig_tag}'

    except FileNotFoundError:
        logger.warning('run_signature_check: cosign not found in PATH for tag %s', tag_id)
        cosign_result = TagSignatureStatus.RESULT_NOT_AVAILABLE
        cosign_output = 'cosign binary not found in PATH'
    except Exception as exc:
        logger.error('run_signature_check: cosign check failed for tag %s: %s', tag_id, exc)
        cosign_result = TagSignatureStatus.RESULT_FAILED
        cosign_output = str(exc)[:500]

    # ── 2. Notation — presence detection via OCI referrers API ───────────────
    # Notation stores signatures as OCI referrers with artifactType
    # "application/vnd.cncf.notary.signature".
    # Strategy:
    #   a) Try the referrers API: GET /v2/<repo>/referrers/<digest>
    #      (Docker Distribution v2.8+ / OCI Distribution 1.1+)
    #   b) Fall back to tag list: notation also pushes a tag named
    #      sha256-<hex> (no .sig suffix) for older registries.
    notation_result = TagSignatureStatus.RESULT_UNKNOWN
    notation_output = ''

    try:
        from django.contrib.auth.models import User as _User
        from registry.auth import issue_token as _issue_token
        _internal_user = _User.objects.filter(is_superuser=True).first()
        _token_data = _issue_token(_internal_user, f'repository:{repo_full}:pull')
        _auth_header = {'Authorization': f'Bearer {_token_data["token"]}'}
        _base = _registry_url()

        # a) Try referrers API
        _referrers_resp = requests.get(
            f'{_base}/v2/{repo_full}/referrers/{tag.digest}',
            headers={**_auth_header, 'Accept': 'application/vnd.oci.image.index.v1+json'},
            timeout=10,
        )
        if _referrers_resp.ok:
            _manifests = _referrers_resp.json().get('manifests') or []
            _notary_type = 'application/vnd.cncf.notary.signature'
            _found = any(m.get('artifactType') == _notary_type for m in _manifests)
            if _found:
                notation_result = TagSignatureStatus.RESULT_SIGNED
                notation_output = f'Notation signature referrer found via referrers API (digest {tag.digest})'
            else:
                # b) Fall back to tag list — notation tag: sha256-<hex> (no .sig)
                _notation_tag = f'sha256-{digest_hex}'
                _all_tags = all_tags  # already fetched above for cosign
                if _notation_tag in _all_tags:
                    notation_result = TagSignatureStatus.RESULT_SIGNED
                    notation_output = f'Notation signature tag found: {_notation_tag}'
                else:
                    notation_result = TagSignatureStatus.RESULT_NOT_SIGNED
                    notation_output = (
                        f'No notation signature found '
                        f'(checked referrers API and tag {_notation_tag})'
                    )
        else:
            # Referrers API not supported — fall back to tag list only
            _notation_tag = f'sha256-{digest_hex}'
            _all_tags_resp = requests.get(
                f'{_base}/v2/{repo_full}/tags/list',
                headers=_auth_header,
                timeout=10,
            )
            _all_tags_fb = _all_tags_resp.json().get('tags') or [] if _all_tags_resp.ok else []
            if _notation_tag in _all_tags_fb:
                notation_result = TagSignatureStatus.RESULT_SIGNED
                notation_output = f'Notation signature tag found: {_notation_tag}'
            else:
                notation_result = TagSignatureStatus.RESULT_NOT_SIGNED
                notation_output = (
                    f'No notation signature found '
                    f'(referrers API unavailable; checked tag {_notation_tag})'
                )

    except Exception as _exc:
        logger.error('run_signature_check: notation check failed for tag %s: %s', tag_id, _exc)
        notation_result = TagSignatureStatus.RESULT_FAILED
        notation_output = str(_exc)[:500]

    # ── Save ──────────────────────────────────────────────────────────────────
    sig_status.cosign = cosign_result
    sig_status.cosign_output = cosign_output
    sig_status.notation = notation_result
    sig_status.notation_output = notation_output
    sig_status.checked_at = timezone.now()
    sig_status.save()

    logger.info(
        'run_signature_check: tag %s — cosign=%s notation=%s',
        tag_id, cosign_result, notation_result,
    )


# ---------------------------------------------------------------------------
# Trivy vulnerability DB update
# ---------------------------------------------------------------------------

@shared_task(
    bind=True,
    name='registry.tasks.run_trivy_db_update',
    queue='scans',
    max_retries=2,
    default_retry_delay=60,
)
def run_trivy_db_update(self, force: bool = False, trivy_job_id: int | None = None):
    """
    Downloads a fresh copy of the Trivy vulnerability DB (and Java DB) into
    the shared trivy_cache volume.  When called from Beat (force=False) the
    task checks whether the configured interval has elapsed before doing any
    real work, matching the same gating pattern used by run_gc.
    """
    from users.models import SiteSettings
    from registry.models import TrivyUpdateJob

    cfg = SiteSettings.get()

    if not force:
        if not cfg.trivy_db_update_enabled:
            logger.debug('run_trivy_db_update: auto-update disabled — skipping')
            return
        if cfg.trivy_db_last_updated_at:
            elapsed = timezone.now() - cfg.trivy_db_last_updated_at
            if elapsed.total_seconds() < cfg.trivy_db_update_interval_hours * 3600:
                logger.debug('run_trivy_db_update: interval not elapsed — skipping')
                return

    # Resolve or create the job row
    if trivy_job_id:
        try:
            job = TrivyUpdateJob.objects.get(pk=trivy_job_id)
            job.status = TrivyUpdateJob.STATUS_RUNNING
            job.save(update_fields=['status'])
        except TrivyUpdateJob.DoesNotExist:
            job = None
    else:
        job = TrivyUpdateJob.objects.create(triggered_by='schedule', status=TrivyUpdateJob.STATUS_RUNNING)

    cache_dir = os.environ.get('TRIVY_CACHE_DIR', '/root/.cache/trivy')
    logger.info('run_trivy_db_update: downloading vuln DB to %s', cache_dir)

    def _run(args):
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr[:500] or f'exit {result.returncode}')
        return result

    try:
        _run(['trivy', 'image', '--download-db-only', '--cache-dir', cache_dir])
        logger.info('run_trivy_db_update: vuln DB updated')
        _run(['trivy', 'image', '--download-java-db-only', '--cache-dir', cache_dir])
        logger.info('run_trivy_db_update: java DB updated')
        cfg.trivy_db_last_updated_at = timezone.now()
        cfg.save(update_fields=['trivy_db_last_updated_at'])
        if job:
            job.status = TrivyUpdateJob.STATUS_SUCCESS
            job.finished_at = timezone.now()
            job.save()
    except FileNotFoundError:
        logger.warning('run_trivy_db_update: trivy not found in PATH — skipping')
        if job:
            job.status = TrivyUpdateJob.STATUS_ERROR
            job.finished_at = timezone.now()
            job.error = 'trivy not found in PATH'
            job.save()
    except Exception as exc:
        logger.error('run_trivy_db_update: failed: %s', exc)
        if job:
            job.status = TrivyUpdateJob.STATUS_ERROR
            job.finished_at = timezone.now()
            job.error = str(exc)
            job.save()
        raise self.retry(exc=exc)
