CREATE TABLE IF NOT EXISTS vsphere_performance_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id INTEGER,
    object_type TEXT, -- 'VM' or 'Host'
    metric_name TEXT,
    instance TEXT,
    value REAL,
    unit TEXT,
    timestamp TIMESTAMP,
    vcenter_ip TEXT
);