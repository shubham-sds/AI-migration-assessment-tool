INSERT INTO vsphere_hosts (
    vcenter_ip, cluster_id, host_name, model, cpu_model, 
    cpu_mhz, cpu_cores, memory_gb, version, build, 
    maintenance_mode, health_sensors, bios_info, uptime, physical_nics
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) 
ON CONFLICT(host_name) DO NOTHING;