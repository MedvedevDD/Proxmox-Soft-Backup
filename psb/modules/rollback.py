import datetime as dt
import json
import os
import socket
import tempfile
import uuid
import zipfile
from pathlib import Path

from .backup import archive_paths
from .common import iter_files, safe_rel, sha256_file, write_json
from .verify import verify_backup

ROLLBACK_STATE_DIR = Path('/var/lib/proxmox-soft-backup')
RECOVERY_LOCK = ROLLBACK_STATE_DIR / 'recovery.lock'


def _human_bytes(value: int) -> str:
    size = float(value)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if size < 1024 or unit == 'TiB':
            return f'{size:.1f} {unit}' if unit != 'B' else f'{int(size)} B'
        size /= 1024
    return f'{value} B'


def create_rollback_package(preview: dict, destination: Path, name: str | None = None, create_lock: bool = True) -> tuple[Path, dict]:
    if not preview.get('package_valid'):
        raise RuntimeError('Cannot create rollback: source package verification failed')
    selected = [a for a in preview.get('actions', []) if a.get('rollback_required') and a.get('action') in {'restore', 'review'}]
    if not selected:
        raise RuntimeError('Cannot create rollback: recovery plan contains no writable actions')

    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d-%H%M%S')
    rollback_id = str(uuid.uuid4())
    filename = name or f'rollback-{socket.gethostname()}-{stamp}.psbr'
    if not filename.endswith('.psbr'):
        filename += '.psbr'
    package_path = destination / filename
    if package_path.exists():
        raise RuntimeError(f'Rollback package already exists: {package_path}')

    with tempfile.TemporaryDirectory(prefix='psb-rollback-') as temp:
        root = Path(temp)
        artifact_root = root / 'rollback'
        artifact_root.mkdir(parents=True)
        components = []
        for index, action in enumerate(selected, start=1):
            scope = action.get('scope', 'application')
            owner = action.get('application') or 'host'
            component = action.get('component') or f'component-{index:02d}'
            component_dir = artifact_root / scope / owner
            component_dir.mkdir(parents=True, exist_ok=True)
            artifact_path = component_dir / f'{component}.tar.gz'
            sources = [str(p) for p in action.get('sources', [])]
            included = archive_paths(artifact_path, sources)
            artifacts = []
            if artifact_path.exists():
                artifacts.append({
                    'id': f'rollback-{scope}-{owner}-{component}',
                    'type': 'tar-gzip',
                    'path': safe_rel(artifact_path, root),
                    'size': artifact_path.stat().st_size,
                    'sha256': sha256_file(artifact_path),
                    'compression': 'gzip',
                    'included_paths': included,
                })
            components.append({
                'scope': scope,
                'application': action.get('application'),
                'display_name': action.get('display_name'),
                'component': component,
                'component_type': action.get('component_type'),
                'risk': action.get('risk'),
                'sources': sources,
                'included_paths': included,
                'present': bool(included),
                'artifacts': artifacts,
                'original_action': action.get('action'),
            })

        created_at = dt.datetime.now(dt.timezone.utc).isoformat()
        manifest = {
            'format': 'Proxmox Soft Backup Rollback Package',
            'schema_version': 1,
            'tool_version': '0.9.2',
            'rollback_id': rollback_id,
            'created_at': created_at,
            'hostname': socket.gethostname(),
            'source_backup': preview.get('package'),
            'preview_only_recovery': True,
            'restore_execution_enabled': False,
            'components': components,
        }
        write_json(root / 'manifest.json', manifest)
        write_json(root / 'rollback-plan.json', {
            'schema_version': 1,
            'rollback_id': rollback_id,
            'created_at': created_at,
            'components': components,
            'automatic_execution_enabled': False,
            'manual_execution_enabled': False,
        })
        write_json(root / 'recovery-preview.json', preview)
        checksum_lines = []
        for path in iter_files(root):
            if path.name == 'checksums.sha256':
                continue
            checksum_lines.append(f'{sha256_file(path)}  {safe_rel(path, root)}')
        (root / 'checksums.sha256').write_text('\n'.join(checksum_lines) + '\n', encoding='ascii')
        with zipfile.ZipFile(package_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for path in iter_files(root):
                archive.write(path, safe_rel(path, root))

    ok, messages = verify_backup(package_path)
    if not ok:
        package_path.unlink(missing_ok=True)
        raise RuntimeError('Rollback package verification failed: ' + '; '.join(messages))

    total_bytes = sum(a.get('size', 0) for c in components for a in c.get('artifacts', []))
    result = {
        'rollback_id': rollback_id,
        'package': str(package_path),
        'components': len(components),
        'artifact_bytes': total_bytes,
        'artifact_size_human': _human_bytes(total_bytes),
        'verified': True,
        'verification_messages': messages,
        'lock_path': str(RECOVERY_LOCK) if create_lock else None,
    }
    if create_lock:
        ROLLBACK_STATE_DIR.mkdir(parents=True, exist_ok=True)
        lock = {
            'schema_version': 1,
            'state': 'rollback-prepared',
            'execution_enabled': False,
            'rollback_id': rollback_id,
            'source_backup': preview.get('package'),
            'rollback_package': str(package_path),
            'created_at': created_at,
            'pid': os.getpid(),
        }
        RECOVERY_LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True), encoding='utf-8')
        os.chmod(RECOVERY_LOCK, 0o600)
    return package_path, result
