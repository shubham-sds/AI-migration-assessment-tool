# src/agents/windows_discovery.py

"""Handles all data collection from a single Windows host via WinRM.

This module defines the WindowsDiscovery class, which connects to a Windows
server using pywinrm and executes a series of PowerShell commands to gather
system information. This includes hardware details, OS configuration, running
processes, network connections, installed software, and more.
"""

import json
import logging

import winrm

# Get a logger instance for this module
logger = logging.getLogger(__name__)


class WindowsDiscovery:
    """Collects system information from a Windows host using WinRM."""

    def __init__(self, ip, user, password, timeout=30, knowledge_base=None):
        """Initializes the WindowsDiscovery and the WinRM session."""
        self.ip = ip
        self.knowledge_base = knowledge_base if knowledge_base else {}
        logger.info(f"Initializing WindowsDiscovery for host: {self.ip}")
        
        try:
            self.session = winrm.Session(
                ip,
                auth=(user, password),
                transport='ntlm',
                server_cert_validation='ignore',
                read_timeout_sec=timeout
            )
            # Test connection by running a simple, non-failing command
            self._execute_ps_command("$env:COMPUTERNAME")
            logger.info(f"Successfully connected to Windows host: {self.ip}")
        except Exception:
            logger.exception(f"Failed to connect to Windows host: {self.ip}")
            # Re-raise the exception to be caught by the worker in agent_data_ingestion
            raise

    def _execute_ps_command(self, command: str) -> str:
        """Executes a PowerShell command and returns the decoded output."""
        try:
            result = self.session.run_ps(command)
            if result.status_code == 0:
                return result.std_out.decode('utf-8', errors='ignore').strip()

            error_message = result.std_err.decode('utf-8', errors='ignore').strip()
            logger.warning(
                f"PowerShell command failed on host {self.ip}. Command: '{command}'. Error: {error_message}"
            )
            return ""
        except Exception:
            logger.exception(f"Exception executing PowerShell command on {self.ip}: {command}")
            return ""

    def get_all_windows_data(self) -> dict:
        """Orchestrates the collection of all data points from the Windows host."""
        logger.info(f"Starting full data discovery for Windows host: {self.ip}")

        all_data = {
            **self._discover_os_and_hardware(),
            'running_processes': self._discover_running_processes(),
            'network_connections': self._discover_network_connections(),
            'installed_software': self._discover_installed_software(),
            'storage_mounts': self._discover_storage_mounts(),
            'scheduled_tasks': self._discover_scheduled_tasks(),
            'performance_metrics': self._discover_performance_metrics(),
            'environment_variables': self._discover_environment_variables(),
            'docker_inventory': self._discover_docker_inventory(),
        }
        return all_data

    def _discover_os_and_hardware(self) -> dict:
        """Discovers basic OS and hardware information."""
        logger.info(f"Discovering OS and Hardware for {self.ip}...")
        data = {}
        try:
            os_command = "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | ConvertTo-Json -Depth 1"
            os_output = self._execute_ps_command(os_command)
            if os_output:
                os_info = json.loads(os_output)
                data['os_name'] = os_info.get('Caption')
                data['os_version'] = os_info.get('Version')

            data['hostname'] = self._execute_ps_command("$env:COMPUTERNAME")
            
            cpu_cores_command = "(Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum"
            data['cpu_cores'] = int(self._execute_ps_command(cpu_cores_command) or 0)
            
            mem_bytes = int(self._execute_ps_command("(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory") or 0)
            data['total_memory_gb'] = round(mem_bytes / (1024**3), 2)
        except Exception:
            logger.exception(f"Failed to discover Windows OS/Hardware for {self.ip}")
        return data

    def _discover_running_processes(self) -> list:
        """Discovers running processes and their owners."""
        logger.info(f"Discovering running processes and owners for {self.ip}...")
        command = """
        Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
        Select-Object @{N='ProcessId';E={$_.Id}}, 
                      @{N='Name';E={$_.ProcessName}}, 
                      CommandLine, 
                      @{N='User';E={$_.UserName}}, 
                      @{N='State';E={$_.Responding}}, 
                      @{N='Company';E={$_.FileVersionInfo.CompanyName}} |
        ConvertTo-Json -Depth 3
        """
        output = self._execute_ps_command(command)
        if not output:
            return []
        try:
            parsed_json = json.loads(output)
            return [parsed_json] if isinstance(parsed_json, dict) else parsed_json
        except json.JSONDecodeError:
            logger.exception(f"Failed to parse process JSON from {self.ip}")
            return []

    def _discover_installed_software(self) -> list:
        """Discovers installed software from the registry."""
        logger.info(f"Discovering installed software for {self.ip}...")
        command = """
        $paths = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
                 'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*';
        Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object @{N='name';E={$_.DisplayName}},
                      @{N='version';E={$_.DisplayVersion}},
                      @{N='vendor';E={$_.Publisher}} |
        ConvertTo-Json -Depth 3
        """
        output = self._execute_ps_command(command)
        if not output:
            return []
        try:
            parsed_json = json.loads(output)
            return [parsed_json] if isinstance(parsed_json, dict) else parsed_json
        except json.JSONDecodeError:
            logger.exception(f"Failed to parse software JSON from {self.ip}")
            return []

    def _discover_storage_mounts(self) -> list:
        """Discovers local fixed disk drives."""
        logger.info(f"Discovering storage mounts for {self.ip}...")
        mounts = []
        command = "Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select-Object DeviceID, FileSystem, Size, FreeSpace, VolumeName | ConvertTo-Json -Depth 2"
        output = self._execute_ps_command(command)
        if not output:
            return []
        try:
            volumes = json.loads(output)
            volumes = [volumes] if isinstance(volumes, dict) else volumes
            for vol in volumes:
                capacity_gb = round(vol.get('Size', 0) / (1024**3), 2)
                free_gb = round(vol.get('FreeSpace', 0) / (1024**3), 2)
                mounts.append({
                    'source': vol.get('VolumeName') or vol.get('DeviceID'),
                    'mount_point': vol.get('DeviceID'),
                    'filesystem_type': vol.get('FileSystem'),
                    'storage_type': 'DAS',
                    'total_gb': capacity_gb,
                    'used_gb': round(capacity_gb - free_gb, 2)
                })
        except Exception:
            logger.exception(f"Failed to parse storage mount JSON from {self.ip}")
        return mounts

    def _discover_scheduled_tasks(self) -> list:
        """Discovers all scheduled tasks."""
        logger.info(f"Discovering scheduled tasks for {self.ip}...")
        command = """
        Get-ScheduledTask |
        Select-Object TaskPath, TaskName, State, @{N='Actions';E={$_.Actions | Select-Object -ExpandProperty Execute -First 1}}, @{N='Triggers';E={$_.Triggers.GetType().Name -join ';'}} |
        ConvertTo-Json -Depth 3
        """
        output = self._execute_ps_command(command)
        if not output:
            return []
        try:
            tasks = json.loads(output)
            tasks = [tasks] if isinstance(tasks, dict) else tasks
            return [
                {
                    'name': f"{task.get('TaskPath')}{task.get('TaskName')}",
                    'enabled': task.get('State') != 'Disabled',
                    'command': task.get('Actions'),
                    'schedule': task.get('Triggers')
                } for task in tasks
            ]
        except Exception:
            logger.exception(f"Failed to parse scheduled tasks JSON from {self.ip}")
            return []

    def _discover_network_connections(self) -> list:
        """Discovers TCP and UDP network connections."""
        logger.info(f"Discovering network connections for {self.ip}...")
        command = """
        $tcp = Get-NetTCPConnection
        $udp = Get-NetUDPEndpoint
        $results = @()
        $tcp | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            $results += [PSCustomObject]@{ protocol = 'tcp'; state = $_.State.ToString(); local_address = $_.LocalAddress; local_port = $_.LocalPort; peer_address  = $_.RemoteAddress; peer_port = $_.RemotePort; pid = $_.OwningProcess; process_name  = $proc.ProcessName }
        }
        $udp | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            $results += [PSCustomObject]@{ protocol = 'udp'; state = 'N/A'; local_address = $_.LocalAddress; local_port = $_.LocalPort; peer_address  = 'N/A'; peer_port = $null; pid = $_.OwningProcess; process_name  = $proc.ProcessName }
        }
        $results | ConvertTo-Json -Depth 3
        """
        output = self._execute_ps_command(command)
        if not output:
            return []
        try:
            parsed_json = json.loads(output)
            return [parsed_json] if isinstance(parsed_json, dict) else parsed_json
        except json.JSONDecodeError:
            logger.exception(f"Failed to parse network connection JSON from {self.ip}")
            return []

    def _discover_performance_metrics(self) -> list:
        """Discovers performance metrics based on the knowledge base."""
        logger.info(f"Discovering performance metrics for {self.ip}...")
        counter_defs = self.knowledge_base.get('performance_counters', {}).get('windows', [])
        if not counter_defs:
            return []

        all_metrics = []
        for counter_meta in counter_defs:
            path = counter_meta.get('path')
            if not path:
                continue
            try:
                command = f"Get-Counter -Counter \"{path}\" | Select-Object -ExpandProperty CounterSamples | ConvertTo-Json -Depth 3"
                output = self._execute_ps_command(command)
                if not output:
                    continue
                samples = json.loads(output)
                samples = [samples] if isinstance(samples, dict) else samples
                for sample in samples:
                    all_metrics.append({
                        'alias': counter_meta.get('alias', sample.get('Path')),
                        'instance_name': sample.get('InstanceName'),
                        'value': round(sample.get('CookedValue', 0), 2),
                        'unit': counter_meta.get('unit'),
                        'description': counter_meta.get('description'),
                        'threshold': counter_meta.get('threshold')
                    })
            except Exception:
                logger.exception(f"Failed to parse performance metric from {self.ip} for path '{path}'")
        return all_metrics

    def _discover_environment_variables(self) -> list:
        """Discovers system environment variables."""
        logger.info(f"Discovering environment variables for {self.ip}...")
        command = "Get-ChildItem Env: | Select-Object Name, Value | ConvertTo-Json -Depth 2"
        output = self._execute_ps_command(command)
        if not output:
            return []
        try:
            parsed_json = json.loads(output)
            return [parsed_json] if isinstance(parsed_json, dict) else parsed_json
        except json.JSONDecodeError:
            logger.exception(f"Failed to parse environment variables JSON from {self.ip}")
            return []

    def _discover_docker_inventory(self) -> list:
        """Discovers Docker containers and images."""
        logger.info(f"Discovering Docker inventory for {self.ip}...")
        try:
            if "False" in self._execute_ps_command("if (Get-Command docker -ErrorAction SilentlyContinue) { $true } else { $false }"):
                logger.info(f"Docker command not found on {self.ip}. Skipping.")
                return []

            images_map = {}
            images_output = self._execute_ps_command("docker images --format '{{json .}}'")
            if images_output:
                for line in images_output.splitlines():
                    try:
                        img = json.loads(line)
                        images_map[img.get('ID')] = img
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse Docker image JSON line: {line}")

            inventory = []
            containers_output = self._execute_ps_command("docker ps --all --format '{{json .}}'")
            if containers_output:
                for line in containers_output.splitlines():
                    try:
                        container = json.loads(line)
                        image_details = images_map.get(container.get('ImageID'), {})
                        inventory.append({
                            "container_id": container.get("ID"),
                            "container_names": container.get("Names"),
                            "container_status": container.get("Status"),
                            "ports": container.get("Ports"),
                            "image_repository": image_details.get("Repository"),
                            "image_tag": image_details.get("Tag"),
                            "image_id": container.get("ImageID"),
                            "command": container.get("Command")
                        })
                    except (json.JSONDecodeError, AttributeError):
                        logger.warning(f"Could not parse Docker container JSON line: {line}")
            return inventory
        except Exception:
            logger.exception(f"Failed to discover Docker inventory for {self.ip}")
            return []