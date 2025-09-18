CREATE TABLE IF NOT EXISTS vsphere_virtual_disks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, disk_label TEXT, capacity_gb REAL,
    provisioning_type TEXT, storage_policy TEXT, datastore_name TEXT,
    FOREIGN KEY (vm_id) REFERENCES vsphere_vms (id) ON DELETE CASCADE
);