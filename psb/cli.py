import argparse, json, os, sys
from pathlib import Path
from .modules.backup import create_backup
from .modules.restore import build_restore_plan
from .modules.scanner import scan_system
from .modules.verify import verify_backup
from .modules.package import inspect_package
from .modules.host import host_inventory
from .modules.compare import compare_targets, print_compare_report
from .modules.recovery import build_recovery_preview, print_recovery_preview, write_recovery_plan
from .modules.rollback import create_rollback_package
from .modules.execution import execute_grafana_database_recovery, execute_influxdb_database_recovery, execute_telegraf_configuration_recovery, read_recovery_lock, abort_recovery_lock
VERSION="0.9.4"

def require_root(command):
    if command in {"scan","backup","backup-plan","doctor","explain","host","recover","recovery-status","recovery-abort"} and os.geteuid()!=0:
        print("ERROR: This command must be run as root.",file=sys.stderr); raise SystemExit(2)

def parser():
    p=argparse.ArgumentParser(prog='psb',description='Proxmox Soft Backup')
    p.add_argument('--version',action='version',version=f'PSB {VERSION}')
    sub=p.add_subparsers(dest='command',required=True)
    s=sub.add_parser('scan'); s.add_argument('--output',default='psb-inventory.json'); s.add_argument('--summary',action='store_true'); s.add_argument('--debug-services',action='store_true')
    h=sub.add_parser('host'); h.add_argument('--json',action='store_true')
    d=sub.add_parser('doctor'); d.add_argument('area',nargs='?',choices=('applications','recovery'),default='applications'); d.add_argument('--json',action='store_true')
    e=sub.add_parser('explain'); e.add_argument('application'); e.add_argument('--mode',choices=('minimal','standard','full'),default='standard')
    bp=sub.add_parser('backup-plan'); bp.add_argument('--mode',choices=('minimal','standard','full'),default='standard'); bp.add_argument('--output')
    b=sub.add_parser('backup'); b.add_argument('--destination',required=True); b.add_argument('--name'); b.add_argument('--profile',choices=('production','host','applications'),default='production'); b.add_argument('--mode',choices=('minimal','standard','full'),default='standard'); b.add_argument('--include-root',action='store_true'); b.add_argument('--no-stop-services',action='store_true')
    v=sub.add_parser('verify'); v.add_argument('backup_path')
    r=sub.add_parser('restore-plan'); r.add_argument('backup_path'); r.add_argument('--output')
    i=sub.add_parser('inspect'); i.add_argument('backup_path'); i.add_argument('--json',action='store_true')
    c=sub.add_parser('compare'); c.add_argument('left'); c.add_argument('right',nargs='?'); c.add_argument('--json',action='store_true'); c.add_argument('--output')
    rec=sub.add_parser('recover'); rec.add_argument('backup_path'); rec.add_argument('--json',action='store_true'); rec.add_argument('--output'); rec.add_argument('--create-rollback',action='store_true'); rec.add_argument('--rollback-destination'); rec.add_argument('--rollback-name'); rec.add_argument('--no-recovery-lock',action='store_true'); rec.add_argument('--application'); rec.add_argument('--component'); rec.add_argument('--execute',action='store_true')
    sub.add_parser('recovery-status')
    sub.add_parser('recovery-abort')
    return p

def selected_paths(app,mode):
    allowed={'minimal':{'critical'},'standard':{'critical','important'},'full':{'critical','important','optional'}}[mode]
    return [x['path'] for x in app.get('paths',[]) if x.get('exists') and x.get('level') in allowed]

def backup_plan(inv,mode):
    return {'schema_version':2,'mode':mode,'applications':[{'name':a['name'],'display_name':a['display_name'],'confidence':a['confidence'],'recovery_readiness':a.get('recovery_readiness',0),'version':a.get('version','unknown'),'version_family':a.get('version_family','default'),'services':a.get('services',[]),'packages':a.get('packages',[]),'dependencies':a.get('dependencies',[]),'paths':selected_paths(a,mode)} for a in inv['applications']]}

def print_summary(inv):
    print('\nDetected applications'); print('-'*104)
    print(f"{'Application':28} {'Version':14} {'Family':8} {'Confidence':>10} {'Backup':>8} {'Health':12}")
    print('-'*104)
    for a in inv['applications']:
        missing=', '.join(a.get('missing_signals',[])) or 'none'
        print(f"{a['display_name'][:28]:28} {a.get('version','unknown')[:14]:14} {a.get('version_family','default')[:8]:8} {a['confidence']:>9}% {a.get('backup_completeness',0):>7}% {a.get('health','unknown')[:12]:12}")

def explain(app,mode):
    print(f"\n{app['display_name']} ({app['name']})")
    print('='*72); print(f"Category: {app['category']}"); print(f"Version: {app.get('version','unknown')}"); print(f"Version family: {app.get('version_family','default')}"); print(f"Version source: {app.get('version_source','none')}"); print(f"Confidence: {app['confidence']}%"); print(f"Backup completeness: {app.get('backup_completeness',0)}%"); print(f"Health: {app.get('health','unknown')}")
    print('\nDetection checks:')
    for c in app.get('confidence_checks',[]): print(f"  {'PASS' if c['ok'] else 'MISS':4}  {c['label']}: {c['detail']} ({c['weight']} points)")
    print(f"\nBackup selection ({mode}):")
    chosen=set(selected_paths(app,mode))
    for p in app.get('paths',[]): print(f"  {'INCLUDE' if p['path'] in chosen else 'SKIP':7} {p['level']:9} {p['kind']:14} {p['path']}")
    skipped=app.get('skipped_version_components',[])
    if skipped:
        print('\nNot applicable to detected version:')
        for item in skipped: print(f"  SKIP    {item['path']} ({item['reason']})")
    deps=', '.join(app.get('dependencies',[])) or 'none'; print(f"\nDependencies: {deps}")

def doctor(inv):
    rows=[]
    for a in inv['applications']:
        status='OK' if a.get('recovery_readiness',0)==100 and a.get('health')=='healthy' else ('WARNING' if a.get('recovery_readiness',0)>=50 else 'FAIL')
        rows.append({'application':a['display_name'],'status':status,'confidence':a['confidence'],'readiness':a.get('recovery_readiness',0),'health':a.get('health'),'issues':a.get('missing_critical_components',[])})
    overall=round(sum(r['readiness'] for r in rows)/len(rows)) if rows else 0
    return {'overall_readiness':overall,'applications':rows}

def recovery_doctor():
    checks=[]
    def add(name, ok, detail):
        checks.append({'name':name,'ok':bool(ok),'detail':detail})
    add('root', os.geteuid()==0, f'uid={os.geteuid()}')
    add('python urllib', True, 'standard library available')
    add('systemctl', Path('/usr/bin/systemctl').exists() or Path('/bin/systemctl').exists(), 'systemd control command')
    add('grafana service definition', Path('/lib/systemd/system/grafana-server.service').exists() or Path('/etc/systemd/system/grafana-server.service').exists(), 'grafana-server.service')
    add('grafana data directory', Path('/var/lib/grafana').is_dir(), '/var/lib/grafana')
    add('influxdb service definition', any(Path(path).exists() for path in ('/lib/systemd/system/influxdb.service','/etc/systemd/system/influxdb.service','/etc/systemd/system/influxd.service')), 'influxdb.service or influxd.service')
    add('influxdb data directory', Path('/var/lib/influxdb').is_dir(), '/var/lib/influxdb')
    add('state directory writable', os.access('/var/lib/proxmox-soft-backup', os.W_OK) if Path('/var/lib/proxmox-soft-backup').exists() else os.access('/var/lib', os.W_OK), '/var/lib/proxmox-soft-backup')
    lock=read_recovery_lock()
    add('recovery lock clear', lock is None, 'clear' if lock is None else f"state={lock.get('state','unknown')}")
    overall=all(c['ok'] for c in checks)
    return {'area':'recovery','ready':overall,'checks':checks,'supported_execute_targets':['grafana/database','influxdb/database','telegraf/configuration']}

def main():
    args=parser().parse_args(); require_root(args.command)
    if args.command=='scan':
        inv=scan_system(); Path(args.output).resolve().write_text(json.dumps(inv,indent=2,sort_keys=True),encoding='utf-8'); print(f"Inventory written: {Path(args.output).resolve()}"); print(f"Detected applications: {len(inv['applications'])}")
        if args.debug_services: print(f"Low-level services recorded: {len(inv['intelligent_services'])}")
        if args.summary: print_summary(inv)
        return 0
    if args.command=='host':
        data=host_inventory()
        if args.json:
            print(json.dumps(data,indent=2,sort_keys=True))
        else:
            fp=data["fingerprint"]
            print("\nProxmox Host Configuration")
            print("="*96)
            print(f"Hostname: {fp.get('hostname')}")
            print(f"PVE: {fp.get('proxmox_version') or 'not detected'}")
            print(f"Kernel: {fp.get('kernel')}")
            print(f"Boot: {fp.get('boot_mode')}")
            print(f"CPU: {fp.get('cpu')}")
            print(f"Memory: {fp.get('memory')}")
            print(f"Network: {', '.join(fp.get('network_interfaces',[])) or 'none'}")
            print(f"Storages: {', '.join(fp.get('storages',[])) or 'none'}")
            print(f"Backup completeness: {data.get('backup_completeness')}%")
            print("\nComponents:")
            print(f"{'Component':30} {'Risk':16} {'Status':8} Paths")
            print("-"*96)
            for c in data["components"]:
                status='READY' if c['present'] else 'EMPTY'
                print(f"{c['display_name'][:30]:30} {c['risk']:16} {status:8} {len(c['existing_paths'])}")
            print("\nHost recovery: DISABLED in this version")
        return 0
    if args.command=='doctor':
        if args.area=='recovery':
            report=recovery_doctor()
            if args.json: print(json.dumps(report,indent=2,sort_keys=True))
            else:
                print('\nPSB Recovery Doctor'); print('-'*88)
                for c in report['checks']: print(f"{'PASS' if c['ok'] else 'FAIL':4}  {c['name']}: {c['detail']}")
                print(f"\nRecovery ready: {'YES' if report['ready'] else 'NO'}")
                print('Supported execute targets: grafana/database, influxdb/database, telegraf/configuration')
            return 0 if report['ready'] else 1
        report=doctor(scan_system())
        if args.json: print(json.dumps(report,indent=2))
        else:
            print('\nPSB Doctor'); print('-'*88); print(f"{'Application':28} {'Status':9} {'Confidence':>10} {'Readiness':>10} Health")
            print('-'*88)
            for r in report['applications']: print(f"{r['application'][:28]:28} {r['status']:9} {r['confidence']:>9}% {r['readiness']:>9}% {r['health']}")
            print(f"\nOverall backup readiness: {report['overall_readiness']}%")
        return 0 if report['overall_readiness']>=50 else 1
    if args.command=='explain':
        inv=scan_system(); key=args.application.lower(); app=next((a for a in inv['applications'] if a['name'].lower()==key or a['display_name'].lower()==key),None)
        if not app: print(f"ERROR: Application not detected: {args.application}",file=sys.stderr); return 1
        explain(app,args.mode); return 0
    if args.command=='backup-plan':
        text=json.dumps(backup_plan(scan_system(),args.mode),indent=2,sort_keys=True)
        if args.output: Path(args.output).resolve().write_text(text,encoding='utf-8'); print(f"Backup plan written: {Path(args.output).resolve()}")
        else: print(text)
        return 0
    if args.command=='backup': print(f"Backup created: {create_backup(Path(args.destination),args.name,args.include_root,not args.no_stop_services,args.mode,args.profile)}"); return 0
    if args.command=='verify':
        ok,msgs=verify_backup(Path(args.backup_path)); [print(x) for x in msgs]; return 0 if ok else 1
    if args.command=='inspect':
        info=inspect_package(Path(args.backup_path))
        if args.json: print(json.dumps(info,indent=2,sort_keys=True))
        else:
            print("\nPSB Package")
            print("="*72)
            print(f"File: {info['package']}")
            print(f"Created: {info.get('created_at')}")
            print(f"Source host: {info.get('hostname')}")
            print(f"Profile: {info.get('backup_profile')}")
            print(f"Mode: {info.get('backup_mode')}")
            print(f"Applications: {info['applications']}")
            print(f"Components: {info['components']}")
            print(f"Artifacts: {info['artifacts']}")
            print(f"Host components: {info.get('host_components',0)}")
            print(f"Host artifacts: {info.get('host_artifacts',0)}")
            if info.get('host_components',0): print(f"Host backup: {info.get('host_backup_completeness')}%")
            else: print("Host configuration: not included by profile")
            print(f"Host recovery enabled: {info.get('host_recovery_enabled')}")
            print(f"Artifact size: {info['artifact_bytes']} bytes")
            if info.get('host_details'):
                print("\nHost configuration:")
                for item in info['host_details']:
                    print(f"  {item['display_name']}: {item['risk']}, {'saved' if item['artifacts'] else 'not present'}")
            print("\nApplications:")
            for app in info['application_details']:
                print(f"  {app['display_name']} {app.get('version','unknown')} [{app.get('version_family','default')}]: {app['components']} components, backup {app.get('backup_completeness')}%")
        return 0
    if args.command=='recovery-status':
        lock=read_recovery_lock()
        if lock is None:
            print('No recovery operation is recorded.')
            return 0
        print(json.dumps(lock,indent=2,sort_keys=True))
        return 1 if lock.get('state') in {'executing','rollback-failed','invalid'} else 0
    if args.command=='recovery-abort':
        lock=read_recovery_lock()
        if lock and lock.get('state')=='executing':
            print('ERROR: Cannot abort an executing recovery operation.',file=sys.stderr); return 1
        if abort_recovery_lock():
            print('Recovery lock removed. Rollback packages were not deleted.')
        else:
            print('No recovery lock was present.')
        return 0
    if args.command=='recover':
        if args.execute:
            supported={("grafana","database"),("influxdb","database"),("telegraf","configuration")}
            if (args.application,args.component) not in supported:
                print('ERROR: execute mode supports only grafana/database, influxdb/database, and telegraf/configuration',file=sys.stderr); return 2
            if not args.rollback_destination:
                print('ERROR: --rollback-destination is required with --execute',file=sys.stderr); return 2
            if args.json or args.output or args.create_rollback or args.no_recovery_lock:
                print('ERROR: --execute cannot be combined with --json, --output, --create-rollback, or --no-recovery-lock',file=sys.stderr); return 2
            try:
                executors={
                    ("grafana","database"): execute_grafana_database_recovery,
                    ("influxdb","database"): execute_influxdb_database_recovery,
                    ("telegraf","configuration"): execute_telegraf_configuration_recovery,
                }
                result=executors[(args.application,args.component)](Path(args.backup_path),Path(args.rollback_destination),args.rollback_name)
            except RuntimeError as exc:
                print(f'ERROR: {exc}',file=sys.stderr); return 1
            print('\nPSB Safe Recovery completed successfully')
            print('='*72)
            print(f"Application: {result['application']}")
            print(f"Component: {result['component']}")
            print(f"Rollback package: {result['rollback_package']}")
            print(f"Service active: {result.get('service_active_after', bool(result.get('services_active_after')))}")
            if result.get('http_health',{}).get('checked'):
                print(f"HTTP health: {'PASS' if result['http_health'].get('ok') else 'WARNING'}")
            print(f"Duration: {result.get('duration_seconds',0):.3f} seconds")
            if result.get('http_health',{}).get('checked'):
                print(f"HTTP attempts: {result['http_health'].get('attempts',0)}; wait: {result['http_health'].get('wait_seconds',0)} seconds")
            print(f"Recovery lock: {result['lock_path']}")
            return 0
        preview=build_recovery_preview(Path(args.backup_path))
        if args.output:
            target=write_recovery_plan(preview,Path(args.output)); print(f"Recovery plan written: {target}")
        rollback_result=None
        if args.create_rollback:
            if not args.rollback_destination:
                print('ERROR: --rollback-destination is required with --create-rollback',file=sys.stderr); return 2
            try:
                _, rollback_result=create_rollback_package(preview,Path(args.rollback_destination),args.rollback_name,not args.no_recovery_lock)
                preview['rollback_package']=rollback_result
            except RuntimeError as exc:
                print(f'ERROR: {exc}',file=sys.stderr); return 1
        if args.json:
            print(json.dumps(preview,indent=2,sort_keys=True))
        else:
            print_recovery_preview(preview)
            if rollback_result:
                print('\nRollback preparation:')
                print(f"  Package: {rollback_result['package']}")
                print(f"  Components: {rollback_result['components']}")
                print(f"  Size: {rollback_result['artifact_size_human']}")
                print('  Verification: PASS')
                if rollback_result.get('lock_path'): print(f"  Recovery lock: {rollback_result['lock_path']}")
                print('  Restore execution: DISABLED')
        return 0 if preview.get('package_valid') else 1
    if args.command=='compare':
        try:
            report=compare_targets(Path(args.left), Path(args.right) if args.right else None)
        except RuntimeError as exc:
            print(f"ERROR: {exc}",file=sys.stderr); return 1
        text=json.dumps(report,indent=2,sort_keys=True)
        if args.output:
            Path(args.output).resolve().write_text(text,encoding='utf-8'); print(f"Compare report written: {Path(args.output).resolve()}")
        elif args.json: print(text)
        else: print_compare_report(report)
        return 0
    if args.command=='restore-plan':
        text=json.dumps(build_restore_plan(Path(args.backup_path)),indent=2,sort_keys=True)
        if args.output: Path(args.output).resolve().write_text(text,encoding='utf-8'); print(f"Restore plan written: {Path(args.output).resolve()}")
        else: print(text)
        return 0
    return 2
