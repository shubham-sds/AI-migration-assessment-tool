CREATE TABLE IF NOT EXISTS vsphere_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, snapshot_name TEXT, description TEXT,
    created_at TIMESTAMP, size_gb REAL,
    FOREIGN KEY (vm_id) REFERENCES vsphere_vms (id) ON DELETE CASCADE
);