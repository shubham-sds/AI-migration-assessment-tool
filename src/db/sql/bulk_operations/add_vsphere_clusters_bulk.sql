INSERT INTO vsphere_clusters (vcenter_ip, cluster_name, drs_enabled, ha_enabled, num_hosts, total_cpu_mhz, total_memory_gb, used_cpu_mhz, used_memory_gb, admission_control_policy, affinity_rules_summary) 
VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(cluster_name) DO NOTHING;