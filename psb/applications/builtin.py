from pathlib import Path

from .base import ApplicationDetector, PathSpec


class GrafanaDetector(ApplicationDetector):
    name = "grafana"
    display_name = "Grafana"
    category = "Monitoring"
    package_names = ("grafana", "grafana-enterprise")
    service_names = ("grafana-server.service",)
    binary_names = ("grafana-server",)
    path_specs = (
        PathSpec("/etc/grafana", "critical", "configuration"),
        PathSpec("/var/lib/grafana", "critical", "database"),
        PathSpec("/etc/systemd/system/grafana-server.service.d", "critical", "systemd"),
        PathSpec("/var/lib/grafana/plugins", "important", "plugins"),
        PathSpec("/var/log/grafana", "optional", "logs"),
    )
    dependencies = ("influxdb",)


class InfluxDBDetector(ApplicationDetector):
    name = "influxdb"
    display_name = "InfluxDB"
    category = "Monitoring"
    package_names = ("influxdb", "influxdb2")
    service_names = ("influxdb.service", "influxd.service")
    binary_names = ("influxd",)
    path_specs = (
        PathSpec("/etc/influxdb", "critical", "configuration"),
        PathSpec("/etc/influxdb2", "critical", "configuration"),
        PathSpec("/var/lib/influxdb", "critical", "database"),
        PathSpec("/var/lib/influxdb2", "critical", "database"),
        PathSpec("/root/.influxdbv2", "critical", "credentials"),
        PathSpec("/var/log/influxdb", "optional", "logs"),
    )


class TelegrafDetector(ApplicationDetector):
    name = "telegraf"
    display_name = "Telegraf"
    category = "Monitoring"
    package_names = ("telegraf",)
    service_names = ("telegraf.service",)
    binary_names = ("telegraf",)
    path_specs = (
        PathSpec("/etc/telegraf", "critical", "configuration"),
        PathSpec("/etc/systemd/system/telegraf.service", "critical", "systemd"),
        PathSpec("/etc/systemd/system/telegraf.service.d", "critical", "systemd"),
        PathSpec("/var/lib/telegraf", "important", "state"),
        PathSpec("/var/log/telegraf", "optional", "logs"),
    )
    dependencies = ("influxdb",)


class NutDetector(ApplicationDetector):
    name = "nut"
    display_name = "Network UPS Tools"
    category = "UPS"
    package_names = ("nut", "nut-client", "nut-server")
    service_names = ("nut-monitor.service", "nut-server.service", "nut-driver.target")
    binary_names = ("upsd", "upsmon")
    path_specs = (
        PathSpec("/etc/nut", "critical", "configuration"),
        PathSpec("/etc/systemd/system/nut-driver@ippon.service.d", "critical", "systemd"),
        PathSpec("/var/lib/nut", "important", "state"),
        PathSpec("/var/log/nut", "optional", "logs"),
    )


class TelemtDetector(ApplicationDetector):
    name = "telemt"
    display_name = "Telemt"
    category = "Proxy"
    service_names = ("telemt.service", "telemt-stats-helper.service")
    binary_names = ("telemt", "telemt-stats-helper")
    path_specs = (
        PathSpec("/etc/telemt", "critical", "configuration"),
        PathSpec("/opt/telemt", "critical", "application"),
        PathSpec("/opt/telemt-stats-helper", "critical", "application"),
        PathSpec("/usr/local/bin/telemt", "critical", "binary"),
        PathSpec("/usr/local/bin/telemt-stats-helper", "critical", "binary"),
        PathSpec("/var/lib/telemt", "critical", "state"),
        PathSpec("/etc/systemd/system/telemt.service", "critical", "systemd"),
        PathSpec("/etc/systemd/system/telemt-stats-helper.service", "critical", "systemd"),
        PathSpec("/root/telemt.limit.json", "critical", "quota_state"),
        PathSpec("/var/log/telemt", "optional", "logs"),
    )

    def extra_signals(self):
        matches = list(Path("/root").glob("**/telemt.limit.json")) if Path("/root").exists() else []
        return [("quota-state:telemt.limit.json", bool(matches), 10)]


class MegaRAIDDetector(ApplicationDetector):
    name = "megaraid"
    display_name = "MegaRAID Management"
    category = "Storage"
    package_names = ("storcli", "lsistorageauthority", "lsa-lib-utils", "lsa-lib-utils2")
    service_names = ("LSISA.service", "LsiSASH.service", "3dm2.service", "tdm2.service")
    binary_names = ("storcli", "storcli64")
    path_specs = (
        PathSpec("/opt/MegaRAID", "critical", "application"),
        PathSpec("/opt/lsi", "critical", "application"),
        PathSpec("/etc/lsi", "critical", "configuration"),
        PathSpec("/etc/init.d/LsiSASH", "critical", "service"),
        PathSpec("/etc/init.d/tdm2", "critical", "service"),
        PathSpec("/var/log/lsi", "optional", "logs"),
    )


class HomeServerMonitorDetector(ApplicationDetector):
    name = "home-server-monitor"
    display_name = "Home Server Monitor"
    category = "Monitoring"
    service_names = ("home-server-monitor.service", "homeservermonitor.service", "hsm-collector.service")
    binary_names = ("collector.py", "home-server-monitor")
    path_specs = (
        PathSpec("/opt/home-server-monitor", "critical", "application"),
        PathSpec("/opt/Home_Server_Monitor", "critical", "application"),
        PathSpec("/etc/home-server-monitor", "critical", "configuration"),
        PathSpec("/var/lib/home-server-monitor", "critical", "state"),
        PathSpec("/etc/systemd/system/home-server-monitor.service", "critical", "systemd"),
        PathSpec("/root/Home_Server_Monitor-7.8.1-beta.1", "important", "source"),
    )

    def extra_signals(self):
        roots = []
        for base in (Path("/root"), Path("/opt"), Path("/usr/local")):
            if base.exists():
                roots.extend(base.glob("Home_Server_Monitor*"))
                roots.extend(base.glob("home-server-monitor*"))
        return [("installation-directory:home-server-monitor", bool(roots), 30)]


class DockerDetector(ApplicationDetector):
    name = "docker"
    display_name = "Docker Engine"
    category = "Containers"
    package_names = ("docker-ce", "docker.io")
    service_names = ("docker.service",)
    binary_names = ("docker",)
    path_specs = (
        PathSpec("/etc/docker", "critical", "configuration"),
        PathSpec("/var/lib/docker", "critical", "data"),
        PathSpec("/opt/stacks", "important", "compose"),
        PathSpec("/root/docker-compose", "important", "compose"),
        PathSpec("/var/log/docker", "optional", "logs"),
    )


DETECTORS = (
    GrafanaDetector,
    InfluxDBDetector,
    TelegrafDetector,
    NutDetector,
    TelemtDetector,
    MegaRAIDDetector,
    HomeServerMonitorDetector,
    DockerDetector,
)
