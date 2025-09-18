CREATE TABLE IF NOT EXISTS vsphere_vms (
    id INTEGER PRIMARY KEY AUTOINCREMENT, vcenter_ip TEXT, vm_name TEXT, host_id INTEGER, cluster_id INTEGER,
    guest_os TEXT, power_state TEXT, ip_address TEXT, cpu_count INTEGER, memory_gb REAL,
    vmware_tools_status TEXT, boot_type TEXT, secure_boot_enabled BOOLEAN, hardware_version TEXT,
    discovered_at TIMESTAMP,
    vapp_membership TEXT, storage_policy TEXT, vgpu_info TEXT, custom_attributes TEXT,
    FOREIGN KEY (host_id) REFERENCES vsphere_hosts (id) ON DELETE SET NULL,
    FOREIGN KEY (cluster_id) REFERENCES vsphere_clusters (id) ON DELETE SET NULL
);