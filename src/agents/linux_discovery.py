# src/agents/linux_discovery.py

"""Handles all data collection from a single Linux host via SSH.

This module defines the LinuxDiscovery class, which connects to a Linux
server using Paramiko (SSH) and executes a series of shell commands to gather
system information. This includes hardware details, OS configuration, running
processes, network connections, installed software, and more.
"""

import json
import logging
import re

import paramiko

# Get a logger instance for this module
logger = logging.getLogger(__name__)


class LinuxDiscovery:
    """Collects system information from a Linux host using SSH."""

    def __init__(self, ip, user, password, timeout=30, knowledge_base=None):
        """Initializes the LinuxDiscovery client and connects to the host."""
        self.ip = ip
        self.user = user
        self.password = password
        self.timeout = timeout
        self.knowledge_base = knowledge_base if knowledge_base else {}
        self.client = None

        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.ip,
                username=self.user,
                password=self.password,
                timeout=self.timeout
            )
            logger.info(f"Successfully connected to Linux host {self.ip}")
        except Exception:
            logger.exception(f"Failed to connect to Linux host {self.ip}")
            self.client = None
            # Re-raise the exception to be caught by the worker in agent_data_ingestion
            raise

    def _execute_ssh_command(self, command: str) -> str:
        """Executes a command on the remote host and returns the output."""
        if not self.client:
            return ""
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            if error and "command not found" not in error:
                logger.warning(f"SSH command on {self.ip} returned an error. Command: '{command}'. Error: {error}")
            return output
        except Exception:
            logger.exception(f"Exception executing SSH command on {self.ip}: {command}")
            return ""

    def get_all_linux_data(self) -> dict:
        """Orchestrates the collection of all data points from the Linux host."""
        if not self.client:
            return {}

        logger.info(f"Starting full data discovery for Linux host: {self.ip}")

        all_data = {
            **self._discover_os_and_hardware(),
            'running_processes': self._discover_running_processes(),
            'network_connections': self._discover_network_connections(),
            'installed_software': self._discover_installed_software(),
            'storage_mounts': self._discover_storage_mounts(),
            'scheduled_tasks': self._discover_scheduled_tasks(),
            'environment_variables': self._discover_environment_variables(),
            'docker_inventory': self._discover_docker_inventory(),
            'performance_metrics': self._discover_performance_metrics(),
        }

        self.client.close()
        logger.info(f"Connection closed for host {self.ip}")

        return all_data

    def _discover_os_and_hardware(self) -> dict:
        """Discovers basic OS and hardware information."""
        logger.info(f"Discovering OS and Hardware for {self.ip}...")
        data = {}
        try:
            os_release = self._execute_ssh_command("cat /etc/os-release")
            os_name_match = re.search(r'PRETTY_NAME="([^"]+)"', os_release)
            os_version_match = re.search(r'VERSION_ID="([^"]+)"', os_release)
            data['os_name'] = os_name_match.group(1) if os_name_match else "Linux"
            data['os_version'] = os_version_match.group(1) if os_version_match else ""

            data['hostname'] = self._execute_ssh_command("hostname")
            data['cpu_cores'] = int(self._execute_ssh_command("nproc") or 0)

            mem_info = self._execute_ssh_command("grep MemTotal /proc/meminfo")
            total_kb_match = re.search(r'(\d+)', mem_info)
            if total_kb_match:
                total_kb = int(total_kb_match.group(1))
                data['total_memory_gb'] = round(total_kb / (1024**2), 2)
            else:
                data['total_memory_gb'] = 0
        except Exception:
            logger.exception(f"Failed to discover Linux OS/Hardware for {self.ip}")
        return data

    def _discover_running_processes(self) -> list:
        """Discovers running processes using the 'ps' command."""
        logger.info(f"Discovering running processes for {self.ip}...")
        processes = []
        try:
            # Added 'comm' for the clean process name and 'cmd' for the full command line.
            output = self._execute_ssh_command("ps -eo pid,user,state,comm,cmd --no-headers")
            for line in output.splitlines():
                # Split into 5 parts: pid, user, state, name, and the rest is the command line
                parts = line.strip().split(None, 4)
                if len(parts) == 5:
                    processes.append({
                        'pid': int(parts[0]),
                        'user': parts[1],
                        'state': parts[2],
                        'Name': parts[3],  # Use 'Name' to match Windows key
                        'command_line': parts[4]
                    })
        except (ValueError, IndexError):
            logger.exception(f"Failed to parse process line on {self.ip}")
        return processes

    def _discover_installed_software(self) -> list:
        """Discovers installed software using the system's package manager."""
        logger.info(f"Discovering installed software for {self.ip}...")
        software_list = []
        try:
            # Check for dpkg (Debian/Ubuntu)
            if self._execute_ssh_command("command -v dpkg"):
                output = self._execute_ssh_command("dpkg-query -W -f='${Package},${Version},${Maintainer}\\n'")
                for line in output.splitlines():
                    parts = line.strip().split(',', 2)
                    if len(parts) == 3:
                        software_list.append({
                            'name': parts[0],
                            'version': parts[1],
                            'vendor': parts[2]
                        })
            # Placeholder for RPM (RedHat/CentOS)
            elif self._execute_ssh_command("command -v rpm"):
                logger.info(f"RPM detected on {self.ip}, add RPM query logic here.")
        except Exception:
            logger.exception(f"Failed to discover installed software for {self.ip}")
        return software_list

    def _discover_storage_mounts(self) -> list:
        """Discovers mounted filesystems using the 'df' command."""
        logger.info(f"Discovering storage mounts for {self.ip}...")
        mounts = []
        try:
            output = self._execute_ssh_command("df -PT | awk 'NR>1'")
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 7:
                    total_gb = round(int(parts[2]) / (1024**2), 2)
                    used_gb = round(int(parts[3]) / (1024**2), 2)
                    mounts.append({
                        'source': parts[0],
                        'mount_point': parts[6],
                        'total_gb': total_gb,
                        'used_gb': used_gb,
                        'filesystem_type': parts[1]
                    })
        except (ValueError, IndexError):
            logger.exception(f"Failed to parse storage mount line on {self.ip}")
        return mounts

    def _discover_network_connections(self) -> list:
        """Discovers network connections using 'ss' or 'netstat'."""
        logger.info(f"Discovering network connections for {self.ip}...")
        connections = []
        try:
            command = "ss -tunap"
            if not self._execute_ssh_command("command -v ss"):
                command = "netstat -tunap"

            output = self._execute_ssh_command(command)
            for line in output.splitlines():
                if not (line.startswith('tcp') or line.startswith('udp')):
                    continue
                parts = line.strip().split()
                if len(parts) >= 6:
                    local_addr, local_port = parts[4].rsplit(':', 1)
                    peer_addr, peer_port = ('N/A', None)
                    if ':' in parts[5]:
                        peer_addr, peer_port = parts[5].rsplit(':', 1)
                    
                    process_info, pid = 'N/A', None
                    if len(parts) > 6:
                        proc_part = parts[6]
                        match_ss = re.search(r'("([^"]+)",pid=(\d+))', proc_part)
                        match_netstat = re.search(r'(\d+)/([^/]+)', proc_part)
                        if match_ss:
                            process_info, pid = match_ss.group(2), int(match_ss.group(3))
                        elif match_netstat:
                            pid, process_info = int(match_netstat.group(1)), match_netstat.group(2)
                    
                    connections.append({
                        'protocol': parts[0], 'state': parts[1],
                        'local_address': local_addr, 'local_port': local_port,
                        'peer_address': peer_addr, 'peer_port': peer_port,
                        'process_name': process_info, 'pid': pid
                    })
        except (ValueError, IndexError):
            logger.exception(f"Failed to parse network connection line on {self.ip}")
        return connections

    def _discover_scheduled_tasks(self) -> list:
        """Discovers scheduled tasks from cron."""
        logger.info(f"Discovering scheduled tasks (cron) for {self.ip}...")
        tasks = []
        try:
            output = self._execute_ssh_command("ls /etc/cron.d/ | grep -v '^\\.'")
            for line in output.splitlines():
                task_file = f"/etc/cron.d/{line}"
                task_content = self._execute_ssh_command(f"cat {task_file} | grep -v '^#'").replace('\n', '; ')
                tasks.append({
                    'name': task_file,
                    'command': task_content,
                    'schedule': 'Cron',
                    'enabled': True
                })
        except Exception:
            logger.exception(f"Failed to discover scheduled tasks for {self.ip}")
        return tasks

    def _discover_environment_variables(self) -> list:
        """Discovers system-wide environment variables using 'printenv'."""
        logger.info(f"Discovering environment variables for {self.ip}...")
        env_vars = []
        try:
            output = self._execute_ssh_command("printenv")
            for line in output.splitlines():
                if '=' in line:
                    name, value = line.split('=', 1)
                    env_vars.append({'Name': name, 'Value': value})
        except Exception:
            logger.exception(f"Failed to discover environment variables for {self.ip}")
        return env_vars

    def _discover_docker_inventory(self) -> list:
        """Discovers Docker containers and images."""
        logger.info(f"Discovering Docker inventory for {self.ip}...")
        try:
            if not self._execute_ssh_command("command -v docker"):
                logger.info(f"Docker not found on {self.ip}. Skipping.")
                return []

            images_map = {}
            images_output = self._execute_ssh_command("docker images --format '{{json .}}'")
            if images_output:
                for line in images_output.splitlines():
                    try:
                        img = json.loads(line)
                        images_map[img.get('ID')] = img
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse Docker image JSON line on {self.ip}: {line}")

            inventory = []
            containers_output = self._execute_ssh_command("docker ps --all --format '{{json .}}'")
            if containers_output:
                for line in containers_output.splitlines():
                    try:
                        container = json.loads(line)
                        image_id_short = container.get("Image")
                        image_details = images_map.get(image_id_short, {})
                        inventory.append({
                            "container_id": container.get("ID"),
                            "container_names": container.get("Names"),
                            "container_status": container.get("Status"),
                            "ports": container.get("Ports"),
                            "image_repository": image_details.get("Repository", container.get("Image", "").split(":")[0]),
                            "image_tag": image_details.get("Tag", "latest"),
                            "image_id": image_id_short,
                            "command": container.get("Command")
                        })
                    except (json.JSONDecodeError, AttributeError):
                        logger.warning(f"Could not parse Docker container JSON line on {self.ip}: {line}")
            return inventory
        except Exception:
            logger.exception(f"Failed to discover Docker inventory on {self.ip}")
            return []

    def _discover_performance_metrics(self) -> list:
        """Discovers performance metrics based on the knowledge base."""
        logger.info(f"Discovering performance metrics for {self.ip}...")
        metric_definitions = self.knowledge_base.get('performance_counters', {}).get('linux', [])
        if not metric_definitions:
            logger.warning(f"No Linux performance counters defined in knowledge_base.yaml for host {self.ip}.")
            return []

        collected_metrics = []
        for metric in metric_definitions:
            value_str = ""
            try:
                command = metric.get('command')
                if not command:
                    continue
                value_str = self._execute_ssh_command(command)
                value = float(value_str)
                collected_metrics.append({
                    'alias': metric.get('alias'),
                    'value': value,
                    'unit': metric.get('unit'),
                    'description': metric.get('description'),
                    'threshold': metric.get('threshold')
                })
            except (ValueError, TypeError):
                logger.warning(f"Could not convert performance metric value '{value_str}' to float for alias '{metric.get('alias')}' on host {self.ip}")
            except Exception:
                logger.exception(f"Failed to collect performance metric '{metric.get('alias')}' on {self.ip}")
        return collected_metrics