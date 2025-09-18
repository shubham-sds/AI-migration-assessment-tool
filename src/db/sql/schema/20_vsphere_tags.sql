CREATE TABLE IF NOT EXISTS vsphere_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, tag_name TEXT, category_name TEXT,
    FOREIGN KEY (vm_id) REFERENCES vsphere_vms (id) ON DELETE CASCADE
);