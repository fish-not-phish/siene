"""
0021 — Fix registry_projectpolicy schema discrepancies.

Two problems this migration resolves:

1. misconfig_block_rules — a JSONField that was added directly to the DB
   outside of Django migrations (no corresponding model field).  It has a
   NOT NULL constraint that causes IntegrityError whenever get_or_create
   tries to INSERT a new ProjectPolicy row.  This migration drops it.

2. The four fields added by 0018 (prevent_secret_images, secret_block_threshold,
   prevent_misconfig_images, misconfig_fail_threshold) may not exist on DBs
   where 0018 was recorded as applied but the DDL never ran (e.g. the migration
   state was manipulated, or 0018 ran against a different DB).  This migration
   adds them with IF NOT EXISTS guards so it is safe to run on both affected
   and unaffected databases.

SeparateDatabaseAndState is used throughout:
  - database_operations: raw SQL with IF NOT EXISTS / IF EXISTS guards
  - state_operations: no-ops (Django state is already correct from 0018/0020)
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0020_drop_stale_vuln_allowlist_constraint'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            # Django ORM state is already correct — 0018 declared the four
            # fields and the phantom column has no model representation.
            # All state_operations are intentionally empty.
            state_operations=[],
            database_operations=[
                migrations.RunSQL(
                    # ── Forward ──────────────────────────────────────────────
                    sql="""
                        -- Drop the phantom column that has no model field.
                        -- IF EXISTS makes this safe on clean DBs that never had it.
                        ALTER TABLE registry_projectpolicy
                            DROP COLUMN IF EXISTS misconfig_block_rules;

                        -- Ensure the four fields from 0018 exist.
                        -- IF NOT EXISTS makes these safe on DBs where 0018 ran correctly.
                        ALTER TABLE registry_projectpolicy
                            ADD COLUMN IF NOT EXISTS prevent_secret_images boolean NOT NULL DEFAULT false;

                        ALTER TABLE registry_projectpolicy
                            ADD COLUMN IF NOT EXISTS secret_block_threshold integer NULL;

                        ALTER TABLE registry_projectpolicy
                            ADD COLUMN IF NOT EXISTS prevent_misconfig_images boolean NOT NULL DEFAULT false;

                        ALTER TABLE registry_projectpolicy
                            ADD COLUMN IF NOT EXISTS misconfig_fail_threshold integer NULL;
                    """,
                    # ── Reverse ──────────────────────────────────────────────
                    # Reversing re-adds the phantom column (nullable so existing
                    # rows are not affected) and drops the four fields.
                    reverse_sql="""
                        ALTER TABLE registry_projectpolicy
                            ADD COLUMN IF NOT EXISTS misconfig_block_rules jsonb;

                        ALTER TABLE registry_projectpolicy
                            DROP COLUMN IF EXISTS prevent_secret_images,
                            DROP COLUMN IF EXISTS secret_block_threshold,
                            DROP COLUMN IF EXISTS prevent_misconfig_images,
                            DROP COLUMN IF EXISTS misconfig_fail_threshold;
                    """,
                ),
            ],
        ),
    ]
