CREATE TABLE IF NOT EXISTS vsphere_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, vcenter_ip TEXT, cluster_id INTEGER, host_name TEXT UNIQUE,
    model TEXT, cpu_model TEXT, cpu_mhz INTEGER, cpu_cores INTEGER, memory_gb REAL, version TEXT, build TEXT,
    maintenance_mode BOOLEAN, health_sensors TEXT,
    bios_info TEXT, uptime TEXT, physical_nics TEXT,
    FOREIGN KEY (cluster_id) REFERENCES vsphere_clusters (id) ON DELETE SET NULL
);