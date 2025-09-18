CREATE TABLE IF NOT EXISTS vsphere_clusters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vcenter_ip TEXT,
    cluster_name TEXT UNIQUE,
    drs_enabled BOOLEAN,
    ha_enabled BOOLEAN,
    num_hosts INTEGER,
    total_cpu_mhz INTEGER,
    total_memory_gb REAL,
    used_cpu_mhz INTEGER,
    used_memory_gb REAL,
    admission_control_policy TEXT,
    affinity_rules_summary TEXT
);