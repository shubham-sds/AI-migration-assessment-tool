# src/agents/agent_data_ingestion.py

import json
import logging
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import keyring
import pandas as pd
import yaml
from rich.console import Console
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeRemainingColumn)
from rich.table import Table

from .linux_discovery import LinuxDiscovery
from .vsphere_discovery import VsphereDiscovery
from .windows_discovery import WindowsDiscovery
from .status_manager import StatusManager

logger = logging.getLogger(__name__)

CONNECTION_TIMEOUT = 30
KNOWLEDGE_BASE_FILE = "knowledge_base.yaml"

class DataIngestionAgent:
    """Handles the entire data ingestion process."""

    stop_event = False

    def __init__(self, inventory_path, db_manager, status_manager, max_workers):
        """Initializes the DataIngestionAgent"""
        self.inventory_path = inventory_path
        self.db_manager = db_manager
        self.status_manager = status_manager
        self.max_workers = max_workers
        self.console = Console()
        self.knowledge_base = self._load_knowledge_base()

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, sig, frame):
        self.console.print("[bold yellow]\nStop signal received. Finishing ongoing tasks before shutdown...[/bold yellow]")
        self.stop_event = True

    def _load_knowledge_base(self) -> dict:
        """Loads the YAML knowledge base file."""
        try:
            with open(KNOWLEDGE_BASE_FILE, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Knowledge base file not found: {KNOWLEDGE_BASE_FILE}, using defaults.")
            return {}
        except yaml.YAMLError:
            logger.exception(f"Error parsing knowledge base file: {KNOWLEDGE_BASE_FILE}")
            return {}

    def _validate_inventory(self, inventory_df: pd.DataFrame) -> bool:
        """Validates the structure and content of the inventory DataFrame."""
        required_columns = ['ip', 'os_type', 'user']
        if inventory_df.empty:
            self.console.print("[bold red]Error: Inventory file is empty. Aborting.[/bold red]")
            return False
        if not all(col in inventory_df.columns for col in required_columns):
            missing = set(required_columns) - set(inventory_df.columns)
            self.console.print(
                f"[bold red]Error: Inventory file is missing required columns: {missing}. Aborting.[/bold red]"
            )
            return False
        return True

    def run_discovery(self, dry_run: bool = False, resume: bool = False) -> None:
        """Orchestrates the discovery and data persistence process."""
        inventory_to_process = pd.DataFrame()

        try:
            if resume:
                self.console.print("[yellow]Resume mode activated. Processing all incomplete hosts.[/yellow]")
                inventory_to_process = self.status_manager.get_incomplete_hosts()
                if inventory_to_process.empty:
                    self.console.print("[green]No incomplete hosts found to resume. Exiting.[/green]")
                    return
            else:
                self.console.print(f"[green]Starting new run. Adding hosts from '{self.inventory_path}'.[/green]")
                inventory_from_file = pd.read_csv(self.inventory_path)
                if not self._validate_inventory(inventory_from_file):
                    return
                self.status_manager.add_hosts_from_inventory(inventory_from_file)
                # After adding, fetch all hosts that are currently pending
                all_incomplete = self.status_manager.get_incomplete_hosts()
                inventory_to_process = all_incomplete[all_incomplete['status'] == 'pending']


            self.console.print(f"Found [bold]{len(inventory_to_process)}[/bold] hosts to process.")
        except FileNotFoundError:
            self.console.print(f"[bold red]Error: Inventory file not found at '{self.inventory_path}'.[/bold red]")
            return
        except pd.errors.EmptyDataError:
            self.console.print(f"[bold red]Error: Inventory file '{self.inventory_path}' is empty.[/bold red]")
            return

        summary_results = []
        progress_columns = [
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn()
        ]

        with Progress(*progress_columns, console=self.console) as progress:
            task = progress.add_task("[green]Discovering hosts...", total=len(inventory_to_process))

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Pass the entire row (including run_id) and the progress object to the worker
                future_to_host = {executor.submit(self._discover_host_worker, row, progress): row for _, row in inventory_to_process.iterrows()}

                for future in as_completed(future_to_host):
                    if self.stop_event:
                        self.console.print("[yellow]Discovery interrupted by user. Exiting early.[/yellow]")
                        break
                        
                    res = future.result()
                    if res:
                        summary_results.append(res)
                        if res.get('status', '').startswith('Success') and res.get('data') and not dry_run:
                            self._persist_single_result(res)
                        
                        if res['status'] != 'Success' and not res['status'].startswith('Success'):
                            self.console.print(f"\n[bold red]Discovery failed for {res['ip']}:[/bold red] {res.get('error', 'Unknown error')}")
                    progress.update(task, advance=1)

        if dry_run:
            self._handle_dry_run(summary_results)
        else:
            self.console.print("\n[green]Discovery and persistence complete.[/green]")

    def _discover_host_worker(self, host_info: pd.Series, progress: Progress) -> dict:
        # Extract all info, including the unique run_id for this specific host
        run_id = host_info['run_id']
        ip = host_info['ip']
        os_type = host_info['os_type'].lower().strip()
        user = host_info['user']

        progress.log(f"Starting discovery for run_id: [bold cyan]{run_id}[/bold cyan] ({ip})...")
        self.status_manager.update_host_status(run_id, 'in_progress')

        result = {"ip": ip, "status": "Failed", "data": {}, "error": None, "os_type": os_type}

        try:
            password = keyring.get_password("ai-migration-tool", user)
            if not password:
                result["error"] = f"Password for user '{user}' not found."
                self.status_manager.update_host_status(run_id, 'failed')
                return result

            if os_type == 'windows':
                win_discoverer = WindowsDiscovery(ip, user, password, timeout=CONNECTION_TIMEOUT, knowledge_base=self.knowledge_base)
                result["data"] = win_discoverer.get_all_windows_data()

            elif os_type == 'linux':
                linux_discoverer = LinuxDiscovery(ip, user, password, timeout=CONNECTION_TIMEOUT, knowledge_base=self.knowledge_base)
                result["data"] = linux_discoverer.get_all_linux_data()

            elif os_type == 'vsphere':
                vsphere_config = self.knowledge_base.get('vsphere', {})
                vsphere_discoverer = VsphereDiscovery(
                    host=ip, user=user, password=password,
                    port=vsphere_config.get('port', 443),
                    disable_ssl_verification=vsphere_config.get('disable_ssl_verification', True),
                    config=vsphere_config
                )
                result["data"] = vsphere_discoverer.get_all_vms_data()

            else:
                result["error"] = f"Unsupported OS type: {os_type}"
                logger.error(result["error"])
                self.status_manager.update_host_status(run_id, 'failed')
                return result

            result["status"] = "Success" if result["data"] else "Success (No data returned)"

            status_value = "completed" if result["status"].startswith("Success") else "failed"
            self.status_manager.update_host_status(run_id, status_value)
            
            color = "green" if status_value == "completed" else "red"
            progress.log(f"Finished run_id: [bold cyan]{run_id}[/bold cyan] ({ip}) with status: [{color}]{status_value}[/{color}]")

            return result

        except Exception as e:
            result["error"] = f"An unexpected error occurred: {e}"
            logger.exception(f"Discovery worker failed for host {ip} with run_id {run_id}.")
            self.status_manager.update_host_status(run_id, 'failed')
            progress.log(f"Finished run_id: [bold cyan]{run_id}[/bold cyan] ({ip}) with status: [red]failed[/red]")
            return result

    def _persist_single_result(self, res: dict) -> None:
        """Persists the data for a single successfully discovered host."""
        ip = res['ip']
        os_type = res['os_type']
        data = res['data']

        self.console.print(f"\n[cyan]Persisting data for {ip}...[/cyan]")

        try:
            self.db_manager.conn.execute('BEGIN')

            if os_type in ['windows', 'linux']:
                servers_to_add = [(
                    data.get('hostname'), res['ip'], data.get('os_name'), data.get('os_version'),
                    data.get('cpu_cores'), data.get('total_memory_gb'), datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )]
                self.db_manager.add_servers_bulk(servers_to_add)

                server_id_map = self.db_manager.get_server_ips_to_ids()
                server_id = server_id_map.get(res['ip'])
                if not server_id:
                    raise Exception(f"Could not retrieve server_id for IP {res['ip']} after insertion.")
                
                self.db_manager.clear_snapshot_data_for_server(server_id)

                apps_to_add, conns_to_add, software_to_add, mounts_to_add, tasks_to_add, metrics_to_add = [], [], [], [], [], []
                env_vars_to_add, docker_inv_to_add = [], []

                for proc in data.get('running_processes', []):
                    apps_to_add.append((server_id, proc.get('Name') or proc.get('command_line'), proc.get('ProcessId') or proc.get('pid'), proc.get('User') or proc.get('user'), proc.get('State') or proc.get('state'), proc.get('CommandLine') or proc.get('command_line'), None, proc.get('Company')))
                for conn in data.get('network_connections', []):
                    conns_to_add.append((server_id, conn.get('protocol'), conn.get('state'), conn.get('local_address'), conn.get('local_port'), conn.get('peer_address'), conn.get('peer_port'), conn.get('process_name'), conn.get('pid')))
                for sw in data.get('installed_software', []):
                    software_to_add.append((server_id, sw.get('name'), sw.get('version'), sw.get('vendor')))
                for mount in data.get('storage_mounts', []):
                    mounts_to_add.append((server_id, mount.get('source'), mount.get('mount_point'), mount.get('filesystem_type'), mount.get('storage_type'), mount.get('total_gb'), mount.get('used_gb')))
                for task in data.get('scheduled_tasks', []):
                    command = json.dumps(task.get('command')) if isinstance(task.get('command'), dict) else str(task.get('command') or '')
                    schedule = json.dumps(task.get('schedule')) if isinstance(task.get('schedule'), dict) else str(task.get('schedule') or '')
                    tasks_to_add.append((server_id, task.get('name'), command, schedule, task.get('enabled')))
                for env in data.get('environment_variables', []):
                    env_vars_to_add.append((server_id, env.get('Name'), env.get('Value')))
                for item in data.get('docker_inventory', []):
                    docker_inv_to_add.append((server_id, item.get('container_id'), item.get('container_names'), item.get('container_status'), item.get('ports'), item.get('image_repository'), item.get('image_tag'), item.get('image_id'), item.get('command')))
                for metric in data.get('performance_metrics', []):
                    metrics_to_add.append((server_id, metric.get('alias'), metric.get('instance_name'), metric.get('value'), metric.get('unit'), metric.get('description'), metric.get('threshold')))

                if apps_to_add: self.db_manager.add_applications_bulk(apps_to_add)
                if conns_to_add: self.db_manager.add_network_connections_bulk(conns_to_add)
                if software_to_add: self.db_manager.add_installed_software_bulk(software_to_add)
                if mounts_to_add: self.db_manager.add_storage_mounts_bulk(mounts_to_add)
                if tasks_to_add: self.db_manager.add_scheduled_tasks_bulk(tasks_to_add)
                if env_vars_to_add: self.db_manager.add_environment_variables_bulk(env_vars_to_add)
                if docker_inv_to_add: self.db_manager.add_docker_inventory_bulk(docker_inv_to_add)
                if metrics_to_add: self.db_manager.add_performance_metrics_bulk(metrics_to_add)
            
            elif os_type == 'vsphere':
                vcenter_ip = res['ip']
                infra_data = res['data']

                if not isinstance(infra_data, dict):
                    logger.warning(f"Skipping malformed vSphere data for {vcenter_ip}: expected a dictionary, but got {type(infra_data)}.")
                    self.db_manager.conn.rollback()
                    return

                self.db_manager.clear_snapshot_data_for_vcenter(vcenter_ip)

                datastores_to_add = [(vcenter_ip, ds.get('datastore_name'), ds.get('type'), ds.get('capacity_gb'), ds.get('free_space_gb'), ds.get('uncommitted_gb'), ds.get('accessible'), ds.get('multiple_host_access'), ds.get('thin_provisioning_supported'), ds.get('backing_info')) for ds in infra_data.get('datastores', []) if isinstance(ds, dict)]
                if datastores_to_add: self.db_manager.add_vsphere_datastores_bulk(datastores_to_add)

                clusters_to_add = [(vcenter_ip, c.get('cluster_name'), c.get('drs_enabled'), c.get('ha_enabled'), c.get('num_hosts'), c.get('total_cpu_mhz'), c.get('total_memory_gb'), c.get('used_cpu_mhz'), c.get('used_memory_gb'), c.get('admission_control_policy'), c.get('affinity_rules_summary')) for c in infra_data.get('clusters', []) if isinstance(c, dict)]
                if clusters_to_add: self.db_manager.add_vsphere_clusters_bulk(clusters_to_add)

                cluster_id_map = self.db_manager.get_vsphere_cluster_ids(vcenter_ip)
                cluster_rules_to_add = []
                for c in infra_data.get('clusters', []):
                    if isinstance(c, dict) and (cluster_id := cluster_id_map.get(c.get('cluster_name'))):
                        for rule in c.get('affinity_rules', []):
                            cluster_rules_to_add.append((cluster_id, rule.get('rule_name'), rule.get('enabled'), rule.get('type')))
                if cluster_rules_to_add: self.db_manager.add_vsphere_cluster_rules_bulk(cluster_rules_to_add)

                hosts_to_add = [(vcenter_ip, cluster_id_map.get(h.get('cluster_name')), h.get('host_name'), h.get('model'), h.get('cpu_model'), h.get('cpu_mhz'), h.get('cpu_cores'), h.get('memory_gb'), h.get('version'), h.get('build'), h.get('maintenance_mode'), h.get('health_sensors'), h.get('bios_info'), h.get('uptime'), h.get('physical_nics')) for h in infra_data.get('hosts', []) if isinstance(h, dict)]
                if hosts_to_add: self.db_manager.add_vsphere_hosts_bulk(hosts_to_add)

                host_id_map = self.db_manager.get_vsphere_host_ids(vcenter_ip)
                vms_to_add = [(vcenter_ip, vm.get('vm_name'), host_id_map.get(vm.get('host_name')), cluster_id_map.get(vm.get('cluster_name')), vm.get('guest_os'), vm.get('power_state'), vm.get('ip_address'), vm.get('cpu_count'), vm.get('memory_gb'), vm.get('vmware_tools_status'), vm.get('boot_type'), vm.get('secure_boot_enabled'), vm.get('hardware_version'), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), vm.get('vapp_membership'), vm.get('storage_policy'), vm.get('vgpu_info'), vm.get('custom_attributes')) for vm in infra_data.get('vms', []) if isinstance(vm, dict)]
                if vms_to_add: self.db_manager.add_vsphere_vms_bulk(vms_to_add)

                vm_id_map = self.db_manager.get_vsphere_vm_ids(vcenter_ip)
                snapshots_to_add, disks_to_add, networks_to_add, tags_to_add = [], [], [], []
                for vm in infra_data.get('vms', []):
                    if isinstance(vm, dict) and (vm_id := vm_id_map.get(vm.get('vm_name'))):
                        for snap in vm.get('snapshots', []): snapshots_to_add.append((vm_id, snap.get('snapshot_name'), snap.get('description'), snap.get('created_at'), snap.get('size_gb')))
                        for disk in vm.get('virtual_disks', []): disks_to_add.append((vm_id, disk.get('disk_label'), disk.get('capacity_gb'), disk.get('provisioning_type'), disk.get('storage_policy'), disk.get('datastore_name')))
                        for net in vm.get('networks', []): networks_to_add.append((vm_id, net.get('nic_label'), net.get('mac_address'), net.get('ip_address'), net.get('port_group'), net.get('switch_name'), net.get('vlan_id'), net.get('teaming_policy')))
                        for tag in vm.get('tags', []): tags_to_add.append((vm_id, tag.get('tag_name'), tag.get('category_name')))
                
                if snapshots_to_add: self.db_manager.add_vsphere_snapshots_bulk(snapshots_to_add)
                if disks_to_add: self.db_manager.add_vsphere_virtual_disks_bulk(disks_to_add)
                if networks_to_add: self.db_manager.add_vsphere_networks_bulk(networks_to_add)
                if tags_to_add: self.db_manager.add_vsphere_tags_bulk(tags_to_add)

                perf_metrics_to_add = []
                for p in infra_data.get('performance', []):
                    obj_id = vm_id_map.get(p['object_name']) if p['object_type'] == 'VM' else host_id_map.get(p['object_name'])
                    if obj_id:
                        perf_metrics_to_add.append((obj_id, p['object_type'], p['metric_name'], p.get('instance', ''), p['value'], p['unit'], p['timestamp'], vcenter_ip))
                if perf_metrics_to_add: self.db_manager.add_vsphere_performance_metrics_bulk(perf_metrics_to_add)

            self.db_manager.conn.commit()
            logger.info(f"Successfully persisted data for host {ip}.")

        except Exception:
            self.db_manager.conn.rollback()
            logger.exception(f"Failed to persist data for host {ip}. Transaction rolled back.")
            self.console.print(f"[bold red]Error persisting data for {ip}. Check logs.[/bold red]")

    def _handle_dry_run(self, all_results: list) -> None:
        self.console.rule("[bold cyan]Dry-Run Mode Results[/bold cyan]")
        self.console.print("Data collection complete. Persistence to database was skipped.")
        table = Table(title="Discovery Summary")
        table.add_column("Host IP", style="cyan")
        table.add_column("OS Type", style="magenta")
        table.add_column("Status", style="green")
        table.add_column("Data Points Found")

        for res in all_results:
            status = res.get('status', 'Failed')
            color = "green" if status.startswith('Success') else "red"
            item_count = sum(len(v) for v in res.get('data', {}).values() if isinstance(v, list))
            table.add_row(res.get('ip'), res.get('os_type'), f"[{color}]{status}[/{color}]", str(item_count))

        self.console.print(table)
