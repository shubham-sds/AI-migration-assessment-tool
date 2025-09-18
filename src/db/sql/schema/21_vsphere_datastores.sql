CREATE TABLE IF NOT EXISTS vsphere_datastores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vcenter_ip TEXT,
    datastore_name TEXT,
    type TEXT,
    capacity_gb REAL,
    free_space_gb REAL,
    uncommitted_gb REAL,
    accessible BOOLEAN,
    multiple_host_access BOOLEAN,
    thin_provisioning_supported BOOLEAN,
    backing_info TEXT,
    UNIQUE(vcenter_ip, datastore_name)
);