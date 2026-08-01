import platform, socket
from pathlib import Path
from .package import read_json_member
from .verify import verify_backup


def build_restore_plan(package: Path) -> dict:
    ok,messages=verify_backup(package)
    manifest=read_json_member(package,"manifest.json")
    embedded=read_json_member(package,"restore-plan.json")
    source=manifest.get("source",{})
    warnings=[]
    if source.get("architecture")!=platform.machine(): warnings.append("Architecture differs from the backup source")
    if source.get("hostname")!=socket.gethostname(): warnings.append("Current hostname differs from the backup source")
    warnings += ["Network interface names must be reviewed before restoring network configuration", "The complete /etc/pve archive must not be restored while pmxcfs is active", "Application databases may require application-specific restore commands"]
    return {"backup_valid":ok,"verification_messages":messages,"source":source,"current":{"hostname":socket.gethostname(),"architecture":platform.machine(),"kernel":platform.release()},"applications":embedded.get("application_order",[]),"warnings":warnings,"stages":[{"stage":1,"name":"verify"},{"stage":2,"name":"dry-run"},{"stage":3,"name":"compatibility"},{"stage":4,"name":"dependencies"},{"stage":5,"name":"protect-current-state"},{"stage":6,"name":"restore-components"},{"stage":7,"name":"verify-components"},{"stage":8,"name":"health-check"}],"destructive_restore_enabled":False}
