"""
Management command: generate_registry_keys

Generates an RSA-4096 key pair for Docker registry token auth (RS256 JWT).

Files produced:
  <CERTS_DIR>/private.pem   — private key  (Django signs tokens with this)
  <CERTS_DIR>/domain.crt    — self-signed cert (mounted into registry:2)

Runs are idempotent — if both files already exist the command exits immediately
without regenerating anything, so it is safe to call on every container start.

Environment variables (all optional, sensible defaults):
  REGISTRY_CERTS_DIR      Path to write/read key files (default: <BASE_DIR>/certs)
  REGISTRY_TOKEN_ISSUER   CN used in the self-signed cert  (default: siene)
  REGISTRY_KEY_SIZE       RSA key size in bits              (default: 4096)
  REGISTRY_CERT_DAYS      Certificate validity in days      (default: 3650)
"""

import os
from pathlib import Path
from datetime import datetime, timezone, timedelta

from django.core.management.base import BaseCommand
from django.conf import settings


class Command(BaseCommand):
    help = 'Generate RSA key pair for Docker registry token auth (idempotent).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Regenerate keys even if they already exist.',
        )

    def handle(self, *args, **options):
        certs_dir = Path(
            os.environ.get('REGISTRY_CERTS_DIR', str(settings.BASE_DIR / 'certs'))
        )
        private_key_path = certs_dir / 'private.pem'
        cert_path = certs_dir / 'domain.crt'

        if not options['force'] and private_key_path.exists() and cert_path.exists():
            self.stdout.write(
                self.style.SUCCESS(
                    f'Registry keys already exist at {certs_dir} — skipping generation.'
                )
            )
            return

        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            import ipaddress
        except ImportError:
            self.stderr.write(
                self.style.ERROR(
                    'cryptography package is not installed. '
                    'Run: pip install cryptography>=42'
                )
            )
            return

        key_size = int(os.environ.get('REGISTRY_KEY_SIZE', '4096'))
        cert_days = int(os.environ.get('REGISTRY_CERT_DAYS', '3650'))
        issuer_cn = os.environ.get('REGISTRY_TOKEN_ISSUER', 'siene')

        certs_dir.mkdir(parents=True, exist_ok=True)

        # ── Generate private key ───────────────────────────────────────────────
        self.stdout.write(f'Generating RSA-{key_size} private key...')
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_path.write_bytes(private_pem)
        private_key_path.chmod(0o600)
        self.stdout.write(f'  Written: {private_key_path}')

        # ── Generate self-signed certificate ──────────────────────────────────
        self.stdout.write('Generating self-signed certificate...')
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        ])
        now = datetime.now(timezone.utc)

        # Build SAN list: always include localhost and 127.0.0.1.
        # Docker Distribution (Go TLS) requires a SAN — a cert with only a CN
        # will be rejected for token auth verification.
        san_dns = [
            x509.DNSName('localhost'),
            x509.DNSName(issuer_cn),
            x509.DNSName('backend'),
        ]
        san_ips = [
            x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
        ]
        # If CUSTOM_DOMAIN looks like an IP, add it as an IP SAN too
        custom_domain = os.environ.get('CUSTOM_DOMAIN', '').split(':')[0]
        if custom_domain:
            try:
                san_ips.append(x509.IPAddress(ipaddress.ip_address(custom_domain)))
            except ValueError:
                san_dns.append(x509.DNSName(custom_domain))

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=cert_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_dns + san_ips),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_path.write_bytes(cert_pem)
        self.stdout.write(f'  Written: {cert_path}')

        # ── Update env hint ───────────────────────────────────────────────────
        self.stdout.write(
            self.style.SUCCESS(
                '\nRegistry key pair generated successfully.\n'
                'Ensure your .env contains:\n'
                f'  REGISTRY_PRIVATE_KEY_PATH={private_key_path}\n'
                f'  REGISTRY_CERTS_DIR={certs_dir}\n'
            )
        )
