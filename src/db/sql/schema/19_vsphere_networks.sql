CREATE TABLE IF NOT EXISTS vsphere_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, nic_label TEXT, mac_address TEXT,
    ip_address TEXT, port_group TEXT, switch_name TEXT, vlan_id INTEGER, teaming_policy TEXT,
    FOREIGN KEY (vm_id) REFERENCES vsphere_vms (id) ON DELETE CASCADE
);