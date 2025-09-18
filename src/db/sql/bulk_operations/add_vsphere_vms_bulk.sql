INSERT INTO vsphere_vms (
    vcenter_ip, vm_name, host_id, cluster_id, guest_os, power_state, 
    ip_address, cpu_count, memory_gb, vmware_tools_status, boot_type, 
    secure_boot_enabled, hardware_version, discovered_at, vapp_membership, 
    storage_policy, vgpu_info, custom_attributes
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);