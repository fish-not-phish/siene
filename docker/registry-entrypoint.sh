#!/bin/sh
# Registry entrypoint — wraps /entrypoint.sh to unset REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY
# when using S3 storage. Docker Distribution v3 panics with "multiple storage drivers
# specified" if both a REGISTRY_STORAGE_FILESYSTEM_* env var and REGISTRY_STORAGE=s3
# are present simultaneously (the filesystem var activates the filesystem driver even
# when S3 is the intended backend).
set -e

if [ "$REGISTRY_STORAGE" = "filesystem" ] || [ -z "$REGISTRY_STORAGE" ]; then
    # Filesystem mode: unset REGISTRY_STORAGE and all REGISTRY_STORAGE_S3_* vars.
    # Distribution v3 activates a driver for any REGISTRY_STORAGE_<driver>_* env
    # var it sees — even empty ones — so all S3 vars must be cleared to avoid the
    # "multiple storage drivers specified" panic.
    unset REGISTRY_STORAGE
    unset REGISTRY_STORAGE_S3_REGION
    unset REGISTRY_STORAGE_S3_BUCKET
    unset REGISTRY_STORAGE_S3_ACCESSKEY
    unset REGISTRY_STORAGE_S3_SECRETKEY
    unset REGISTRY_STORAGE_S3_REGIONENDPOINT
    unset REGISTRY_STORAGE_S3_ROOTDIRECTORY
    unset REGISTRY_STORAGE_S3_ENCRYPT
    unset REGISTRY_STORAGE_S3_SECURE
    unset REGISTRY_STORAGE_S3_FORCEPATHSTYLE
    unset REGISTRY_STORAGE_S3_V4AUTH
    unset REGISTRY_STORAGE_S3_REDIRECTENDPOINT
else
    # S3 (or other non-filesystem) mode: the filesystem rootdir env var would
    # activate the filesystem driver alongside S3 — unset it.
    unset REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY
fi

# Replicate the logic of the image's own /entrypoint.sh so the CMD arg
# (/etc/distribution/config.yml) is correctly expanded to:
#   registry serve /etc/distribution/config.yml
case "$1" in
    *.yaml|*.yml) set -- registry serve "$@" ;;
    serve|garbage-collect|help|-*) set -- registry "$@" ;;
esac

exec "$@"
