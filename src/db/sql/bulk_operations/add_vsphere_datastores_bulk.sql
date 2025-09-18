INSERT INTO vsphere_datastores (
    vcenter_ip, datastore_name, type, capacity_gb, free_space_gb, 
    uncommitted_gb, accessible, multiple_host_access, 
    thin_provisioning_supported, backing_info
) VALUES (?,?,?,?,?,?,?,?,?,?) 
ON CONFLICT(vcenter_ip, datastore_name) DO NOTHING;