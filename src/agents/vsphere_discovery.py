# src/agents/vsphere_discovery.py

"""Handles all data collection from a vCenter Server environment.

This module defines the VsphereDiscovery class, which connects to a vCenter
Server using the pyVim and vSphere Automation SDKs. It is responsible for
discovering and collecting detailed information about the entire virtual
infrastructure, including clusters, hosts, virtual machines, datastores,
networks, tags, and performance metrics.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from com.vmware.vapi.std_client import DynamicID
from pyVim import connect
from pyVmomi import vim
from vmware.vapi.vsphere.client import create_vsphere_client
from rich.progress import Progress

logger = logging.getLogger(__name__)

# --- Constants ---
PERF_METRICS = {
    "cpu.usage.average": "CPU Usage",
    "mem.usage.average": "Memory Usage",
    "disk.usage.average": "Disk Usage Rate",
    "net.usage.average": "Network Usage Rate",
    "disk.totalLatency.average": "Disk Latency"
}


class VsphereDiscovery:
    """Collects infrastructure and performance data from a vCenter Server."""

    def __init__(self, host, user, password, port, disable_ssl_verification, config):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.disable_ssl = disable_ssl_verification
        self.config = config if config else {}
        self.service_instance = None
        self.vapi_client = None
        
        # Check if individual VM export is enabled
        self.export_vms = self.config.get('export_individual_vms', False)
        self.export_dir = Path("data/vm_exports")

        if self.export_vms:
            # Create the export directory if it doesn't exist
            self.export_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Individual VM JSON export is ENABLED. Output will be saved to: {self.export_dir}")

        logger.info(f"VsphereDiscovery Initialized for vCenter: {self.host}")

    def connect(self) -> bool:
        """Establishes connections to the vCenter SOAP and VAPI endpoints."""
        try:
            self.service_instance = connect.SmartConnect(
                host=self.host, user=self.user, pwd=self.password, port=self.port,
                disableSslCertValidation=self.disable_ssl
            )
            if not self.service_instance:
                logger.error(f"vCenter SOAP API connection returned None for {self.host}.")
                return False
            
            logger.info(f"Successfully connected to vCenter SOAP API: {self.host}")

            session = requests.Session()
            session.verify = not self.disable_ssl

            self.vapi_client = create_vsphere_client(
                server=self.host,
                username=self.user,
                password=self.password,
                session=session
            )
            logger.info(f"Successfully connected to vCenter VAPI endpoint: {self.host}")
            return True
        except Exception:
            logger.exception(f"Could not connect to vCenter: {self.host}")
            return False

    def disconnect(self) -> None:
        """Disconnects from the vCenter Server."""
        if self.service_instance:
            connect.Disconnect(self.service_instance)
            logger.info(f"Disconnected from vCenter: {self.host}")

    def get_all_vms_data(self) -> dict:
        """Orchestrates the collection of all data from the vCenter."""
        if not self.connect():
            return {}

        all_data = {'clusters': [], 'hosts': [], 'vms': [], 'datastores': [], 'performance': []}
        try:
            content = self.service_instance.RetrieveContent()
            custom_field_map = {field.key: field.name for field in content.customFieldsManager.field}

            should_collect_perf = self.config.get('collect_performance', False)
            if should_collect_perf:
                logger.info(f"--- Starting Performance metric collection for {self.host} ---")
                vm_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                host_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
                entities_for_perf = vm_view.view + host_view.view
                all_data['performance'] = self.get_performance_metrics(entities_for_perf)
                vm_view.Destroy()
                host_view.Destroy()
                logger.info(f"--- Finished Performance metric collection. Found {len(all_data['performance'])} data points. ---")
            else:
                logger.info("--- Performance collection is DISABLED in knowledge_base.yaml. Skipping. ---")

            # --- Non-VM discovery (usually fast, done sequentially) ---
            sequential_tasks = [
                (vim.ClusterComputeResource, 'clusters', self._get_cluster_details),
                (vim.HostSystem, 'hosts', self._get_host_details),
                (vim.Datastore, 'datastores', self._get_datastore_details)
            ]
            for view_type, key, detail_func in sequential_tasks:
                logger.info(f"--- Starting {key} discovery ---")
                container_view = content.viewManager.CreateContainerView(content.rootFolder, [view_type], True)
                for item in container_view.view:
                    try:
                        details = detail_func(item)
                        if details:
                            all_data[key].append(details)
                    except Exception:
                        item_name = getattr(item, 'name', 'N/A')
                        logger.exception(f"Failed to collect details for {key[:-1]} '{item_name}'. Skipping.")
                        continue
                container_view.Destroy()
                logger.info(f"--- Finished {key} discovery. Found {len(all_data[key])} {key}. ---")

            # --- Multithreaded VM Discovery ---
            logger.info("--- Starting VM discovery (using multithreading) ---")
            vm_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
            vms_to_process = list(vm_view.view)
            vm_view.Destroy()
            
            with Progress() as progress:
                task = progress.add_task("[cyan]Discovering VMs...", total=len(vms_to_process))
                with ThreadPoolExecutor(max_workers=self.config.get('max_vm_workers', 10)) as executor:
                    future_to_vm = {executor.submit(self._get_vm_details, vm, custom_field_map): vm for vm in vms_to_process}
                    for future in as_completed(future_to_vm):
                        try:
                            vm_details = future.result()
                            if vm_details:
                                all_data['vms'].append(vm_details)
                                # Export the VM data if the feature is enabled
                                if self.export_vms:
                                    self._export_vm_to_json(vm_details)
                        except Exception:
                            vm = future_to_vm[future]
                            logger.exception(f"Error processing VM: {getattr(vm, 'name', 'N/A')}")
                        progress.update(task, advance=1)
            
            logger.info(f"--- Finished VM discovery. Found {len(all_data['vms'])} VMs. ---")

        except Exception:
            logger.exception(f"A critical error occurred during infrastructure discovery for {self.host}")
        finally:
            self.disconnect()

        return all_data

    def _export_vm_to_json(self, vm_data: dict):
        """Saves the details of a single VM to a JSON file."""
        vm_name = vm_data.get('vm_name', 'unknown_vm')
        # Sanitize the VM name to create a valid filename
        safe_filename = "".join(c for c in vm_name if c.isalnum() or c in (' ', '_', '-')).rstrip()
        output_path = self.export_dir / f"{safe_filename}.json"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                # Use a custom default converter to handle non-serializable types like datetime
                json.dump(vm_data, f, indent=4, ensure_ascii=False, default=str)
            logger.info(f"Successfully exported VM '{vm_name}' to {output_path}")
        except (IOError, TypeError) as e:
            logger.error(f"Could not export VM '{vm_name}' to JSON. Error: {e}")

    def get_performance_metrics(self, entities: list, batch_size: int = 50) -> list:
        """Queries the vCenter Performance Manager for specific metrics."""
        all_perf_data = []
        try:
            if not self.service_instance or not entities:
                return []

            perf_manager = self.service_instance.content.perfManager
            counter_info = {c.key: c for c in perf_manager.perfCounter}
            counter_name_map = {f"{c.groupInfo.key}.{c.nameInfo.key}.{c.rollupType}": c.key for c in counter_info.values()}
            metric_ids = [vim.PerformanceManager.MetricId(counterId=counter_name_map[name], instance="*") for name in PERF_METRICS if name in counter_name_map]

            if not metric_ids:
                logger.warning(f"Could not find any of the requested performance counters in vCenter {self.host}.")
                return []

            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=1)
            
            logger.info(f"Querying performance metrics for {len(entities)} entities in batches of {batch_size}...")
            for i in range(0, len(entities), batch_size):
                batch = entities[i:i + batch_size]
                query_specs = [vim.PerformanceManager.QuerySpec(entity=entity, startTime=start_time, endTime=end_time, metricId=metric_ids, intervalId=300) for entity in batch]
                try:
                    query_result = perf_manager.QueryPerf(query_specs)
                    logger.info(f"Successfully processed performance batch {i//batch_size + 1}...")
                    for entity_metric in query_result:
                        object_type = 'VM' if isinstance(entity_metric.entity, vim.VirtualMachine) else 'Host'
                        object_name = entity_metric.entity.name
                        for series in entity_metric.value:
                            counter_id = series.id.counterId
                            counter_full_name = f"{counter_info[counter_id].groupInfo.key}.{counter_info[counter_id].nameInfo.key}.{counter_info[counter_id].rollupType}"
                            for j, value in enumerate(series.value):
                                timestamp = entity_metric.sampleInfo[j].timestamp
                                all_perf_data.append({
                                    'object_name': object_name, 'object_type': object_type,
                                    'metric_name': counter_full_name, 'instance': series.id.instance,
                                    'value': value, 'unit': counter_info[counter_id].unitInfo.label,
                                    'timestamp': timestamp.isoformat(),
                                })
                except Exception:
                    logger.exception(f"Error querying performance for a batch from {self.host}")
                    continue
        except Exception:
            logger.exception(f"Failed during performance metric collection setup for {self.host}")
        return all_perf_data

    def _parse_admission_control(self, policy):
        """Parses the admission control policy object into a human-readable string."""
        if not policy: return "Disabled"
        if isinstance(policy, vim.cluster.FailoverLevelAdmissionControlPolicy): return f"Tolerate {policy.failoverLevel} host failure(s)"
        if isinstance(policy, vim.cluster.FailoverResourcesAdmissionControlPolicy): return f"CPU: {policy.cpuFailoverResourcesPercent}% RAM: {policy.memoryFailoverResourcesPercent}%"
        if isinstance(policy, vim.cluster.FailoverHostAdmissionControlPolicy): return "Designated failover host(s)"
        return "Enabled (Unknown Policy)"

    def _get_cluster_details(self, cluster: vim.ClusterComputeResource) -> dict:
        """Extracts detailed information from a vSphere Cluster object."""
        try:
            summary = cluster.summary
            config = cluster.configurationEx
            rules_data = [{'rule_name': rule.name, 'enabled': rule.enabled, 'type': type(rule).__name__} for rule in config.rule] if config.rule else []
            enabled_rules = sum(1 for rule in rules_data if rule['enabled'])
            affinity_summary = f"{len(rules_data)} rules (Enabled: {enabled_rules})"
            used_memory_mb = summary.usageSummary.mem.consumed if hasattr(summary.usageSummary, 'mem') else 0
            admission_control_str = self._parse_admission_control(config.dasConfig.admissionControlPolicy)
            return {
                'cluster_name': cluster.name,
                'drs_enabled': config.drsConfig.enabled if config.drsConfig else False,
                'ha_enabled': config.dasConfig.enabled if config.dasConfig else False,
                'num_hosts': summary.numHosts,
                'total_cpu_mhz': summary.totalCpu,
                'total_memory_gb': round((summary.totalMemory or 0) / (1024**3), 2),
                'used_cpu_mhz': summary.usageSummary.cpuDemandMhz,
                'used_memory_gb': round((used_memory_mb or 0) / 1024, 2),
                'admission_control_policy': admission_control_str,
                'affinity_rules': rules_data,
                'affinity_rules_summary': affinity_summary
            }
        except Exception:
            cluster_name = getattr(cluster, 'name', 'N/A')
            logger.exception(f"Failed to get details for cluster '{cluster_name}'.")
            return {}

    def _get_host_details(self, host: vim.HostSystem) -> dict:
        """Extracts detailed information from a vSphere Host object."""
        try:
            summary = host.summary
            hardware = summary.hardware
            cluster = host.parent.name if isinstance(host.parent, vim.ClusterComputeResource) else None
            maintenance_mode = summary.runtime.inMaintenanceMode
            health_sensors_summary = []
            if host.runtime.healthSystemRuntime and host.runtime.healthSystemRuntime.systemHealthInfo:
                if hasattr(host.runtime.healthSystemRuntime.systemHealthInfo, 'numericSensor'):
                    for sensor in host.runtime.healthSystemRuntime.systemHealthInfo.numericSensor:
                        if sensor.healthState.key != 'ok':
                            health_sensors_summary.append(f"{sensor.name}: {sensor.healthState.label}")
            bios_info_str = "N/A"
            if hasattr(hardware, 'biosInfo') and hardware.biosInfo:
                bios_info_str = f"{hardware.biosInfo.biosVersion} ({hardware.biosInfo.releaseDate.strftime('%Y-%m-%d')})"
            uptime_str = "N/A"
            if summary.runtime.bootTime:
                uptime_delta = datetime.now(timezone.utc) - summary.runtime.bootTime
                days, remainder = divmod(uptime_delta.total_seconds(), 86400)
                hours, remainder = divmod(remainder, 3600)
                minutes, _ = divmod(remainder, 60)
                uptime_str = f"{int(days)}d {int(hours)}h {int(minutes)}m"
            physical_nics = []
            if host.config.network and host.config.network.pnic:
                for pnic in host.config.network.pnic:
                    speed = pnic.linkSpeed.speedMb if pnic.linkSpeed else 'N/A'
                    physical_nics.append({'name': pnic.device, 'mac': pnic.mac, 'speed_mb': speed})
            return {
                'host_name': host.name,
                'cluster_name': cluster,
                'model': hardware.model,
                'cpu_model': hardware.cpuModel,
                'cpu_mhz': hardware.cpuMhz,
                'cpu_cores': hardware.numCpuCores,
                'memory_gb': round((hardware.memorySize or 0) / (1024**3), 2),
                'version': summary.config.product.version,
                'build': summary.config.product.build,
                'maintenance_mode': maintenance_mode,
                'health_sensors': ", ".join(health_sensors_summary),
                'bios_info': bios_info_str,
                'uptime': uptime_str,
                'physical_nics': json.dumps(physical_nics)
            }
        except Exception:
            host_name = getattr(host, 'name', 'N/A')
            logger.exception(f"Failed to get details for host '{host_name}'.")
            return {}

    def _get_vm_details(self, vm: vim.VirtualMachine, custom_field_map: dict) -> dict:
        """Extracts detailed information from a Virtual Machine object."""
        try:
            summary = vm.summary
            config = vm.config
            guest = vm.guest
            vm_name = summary.config.name
            ip_address = guest.ipAddress if guest and guest.ipAddress else None
            host_name = vm.runtime.host.name if vm.runtime.host else None
            cluster_name = vm.runtime.host.parent.name if vm.runtime.host and isinstance(vm.runtime.host.parent, vim.ClusterComputeResource) else None
            secure_boot_enabled = False
            if config.bootOptions and hasattr(config.bootOptions, 'secureBootEnabled'):
                secure_boot_enabled = config.bootOptions.secureBootEnabled
            vapp_membership = None
            parent = vm.parent
            while parent:
                if isinstance(parent, vim.VirtualApp):
                    vapp_membership = parent.name
                    break
                parent = getattr(parent, 'parent', None)
            storage_policy = "Datastore Default"
            if hasattr(vm.config, 'storagePolicy') and vm.config.storagePolicy and hasattr(vm.config.storagePolicy, 'policy') and vm.config.storagePolicy.policy:
                storage_policy = vm.config.storagePolicy.policy.name
            vgpu_devices = [dev.deviceInfo.label for dev in config.hardware.device if isinstance(dev, vim.vm.device.VirtualPCIPassthrough) and 'nvidia' in dev.deviceInfo.label.lower()]
            custom_attributes = {custom_field_map.get(attr.key, f"unknown_key_{attr.key}"): attr.value for attr in summary.customValue} if summary.customValue else {}
            
            logger.info(f"  -> Collecting VM Details: Snapshots for {vm_name}")
            snapshots = self._get_snapshot_details(vm)
            logger.info(f"  -> Collecting VM Details: Virtual Disks for {vm_name}")
            virtual_disks = self._get_disk_details(vm)
            logger.info(f"  -> Collecting VM Details: Networks for {vm_name}")
            networks = self._get_vm_network_details(vm)
            logger.info(f"  -> Collecting VM Details: Tags for {vm_name}")
            tags = self._get_tag_details(vm)
            
            return {
                'vm_name': vm_name, 'host_name': host_name, 'cluster_name': cluster_name,
                'guest_os': summary.config.guestFullName, 'power_state': summary.runtime.powerState,
                'ip_address': ip_address, 'cpu_count': summary.config.numCpu,
                'memory_gb': round((summary.config.memorySizeMB or 0) / 1024, 2),
                'vmware_tools_status': guest.toolsStatus if guest else 'notInstalled',
                'boot_type': config.firmware, 'secure_boot_enabled': secure_boot_enabled,
                'hardware_version': config.version, 'snapshots': snapshots,
                'virtual_disks': virtual_disks, 'networks': networks, 'tags': tags,
                'vapp_membership': vapp_membership, 'storage_policy': storage_policy,
                'vgpu_info': json.dumps(vgpu_devices), 'custom_attributes': json.dumps(custom_attributes)
            }
        except Exception:
            vm_name = getattr(vm, 'name', 'N/A')
            logger.exception(f"Failed to get details for VM '{vm_name}'.")
            return {}

    def _get_snapshot_details(self, vm: vim.VirtualMachine) -> list:
        """Recursively collects all snapshots for a VM."""
        snapshots_data = []
        try:
            if vm.snapshot:
                def collect_snapshots(snapshot_tree):
                    for snap in snapshot_tree:
                        snapshots_data.append({'snapshot_name': snap.name, 'description': snap.description, 'created_at': snap.createTime.isoformat(), 'size_gb': 0})
                        collect_snapshots(snap.childSnapshotList)
                collect_snapshots(vm.snapshot.rootSnapshotList)
        except Exception:
            logger.exception(f"Failed to get snapshot details for VM '{vm.name}'.")
        return snapshots_data

    def _get_disk_details(self, vm: vim.VirtualMachine) -> list:
        """Collects details for all virtual disks attached to a VM."""
        disks_data = []
        try:
            for device in vm.config.hardware.device:
                if isinstance(device, vim.vm.device.VirtualDisk):
                    datastore = device.backing.datastore.summary.name if device.backing.datastore else "N/A"
                    disk_storage_policy = "N/A"
                    if hasattr(vm.config, 'storagePolicy') and vm.config.storagePolicy and hasattr(vm.config.storagePolicy, 'policy') and vm.config.storagePolicy.policy:
                         disk_storage_policy = vm.config.storagePolicy.policy.name
                    disks_data.append({
                        'disk_label': device.deviceInfo.label,
                        'capacity_gb': round((device.capacityInKB or 0) / (1024*1024), 2),
                        'provisioning_type': 'Thin' if device.backing.thinProvisioned else 'Thick',
                        'storage_policy': disk_storage_policy,
                        'datastore_name': datastore
                    })
        except Exception:
            logger.exception(f"Failed to get disk details for VM '{vm.name}'.")
        return disks_data

    def _get_vm_network_details(self, vm: vim.VirtualMachine) -> list:
        """Collects details for all virtual NICs attached to a VM."""
        networks_data = []
        try:
            for device in vm.config.hardware.device:
                if isinstance(device, vim.vm.device.VirtualEthernetCard):
                    port_group_name, switch_name, vlan_id, teaming_policy = "N/A", "N/A", 0, "N/A"
                    if hasattr(device, 'backing') and device.backing and hasattr(device.backing, 'port') and device.backing.port:
                        port_group_key = device.backing.port.portgroupKey
                        dvs_uuid = device.backing.port.switchUuid
                        dvs = self.service_instance.content.searchIndex.FindByUuid(uuid=dvs_uuid, vmSearch=False, instanceUuid=False)
                        if dvs:
                            switch_name = dvs.name
                            for pg in dvs.portgroup:
                                if pg.key == port_group_key:
                                    port_group_name = pg.name
                                    if isinstance(pg.config.defaultPortConfig, vim.dvs.VmwareDistributedVirtualSwitch.VlanIdSpec):
                                        vlan_id = pg.config.defaultPortConfig.vlan.vlanId
                                    if pg.config.defaultPortConfig.uplinkTeamingPolicy:
                                        teaming_policy = pg.config.defaultPortConfig.uplinkTeamingPolicy.policy
                                    break
                    elif hasattr(device.backing, 'deviceName'):
                        port_group_name = device.backing.deviceName
                    networks_data.append({
                        'nic_label': device.deviceInfo.label, 'mac_address': device.macAddress,
                        'ip_address': vm.guest.ipAddress if vm.guest else None,
                        'port_group': port_group_name, 'switch_name': switch_name,
                        'vlan_id': vlan_id, 'teaming_policy': teaming_policy
                    })
        except Exception:
            logger.exception(f"Failed to get network details for VM '{vm.name}'.")
        return networks_data

    def _get_tag_details(self, vm: vim.VirtualMachine) -> list:
        """Collects all tags attached to a VM using the VAPI."""
        tags_data = []
        try:
            if self.vapi_client:
                dynamic_id = DynamicID(type='VirtualMachine', id=vm._moId)
                tag_ids = self.vapi_client.tagging.TagAssociation.list_attached_tags(dynamic_id)
                for tag_id in tag_ids:
                    tag_model = self.vapi_client.tagging.Tag.get(tag_id)
                    category_model = self.vapi_client.tagging.Category.get(tag_model.category_id)
                    tags_data.append({'tag_name': tag_model.name, 'category_name': category_model.name})
        except Exception:
            logger.warning(f"Could not retrieve tags for VM '{vm.name}'. VAPI connection may have failed or tags do not exist.")
        return tags_data

    def _get_datastore_details(self, ds: vim.Datastore) -> dict:
        """Extracts detailed information from a Datastore object."""
        try:
            summary = ds.summary
            thin_provisioning_supported = getattr(ds.capability, 'perFileThinProvisioningSupported', None)
            backing_info = {}
            if summary.type == 'vsan':
                backing_info['vsan_info'] = "This is a vSAN Datastore"
            elif hasattr(ds, 'info') and ds.info:
                if ds.info._wsdlName == 'HostVmfsDatastoreInfo' and hasattr(ds.info, 'vmfs') and ds.info.vmfs:
                    backing_info['vmfs_version'] = ds.info.vmfs.version
                elif ds.info._wsdlName == 'HostNfsDatastoreInfo' and hasattr(ds.info, 'nas') and ds.info.nas:
                    backing_info['nfs_host'] = ds.info.nas.remoteHost
                    backing_info['nfs_path'] = ds.info.nas.remotePath
            return {
                'datastore_name': summary.name, 'type': summary.type,
                'capacity_gb': round((summary.capacity or 0) / (1024**3), 2),
                'free_space_gb': round((summary.freeSpace or 0) / (1024**3), 2),
                'uncommitted_gb': round((summary.uncommitted or 0) / (1024**3), 2),
                'accessible': summary.accessible, 'multiple_host_access': summary.multipleHostAccess,
                'thin_provisioning_supported': thin_provisioning_supported,
                'backing_info': json.dumps(backing_info)
            }
        except Exception:
            ds_name = getattr(ds, 'name', 'N/A')
            logger.exception(f"Failed to get details for datastore '{ds_name}'.")
            return {}
