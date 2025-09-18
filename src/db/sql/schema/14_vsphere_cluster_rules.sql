CREATE TABLE IF NOT EXISTS vsphere_cluster_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id INTEGER,
    rule_name TEXT,
    enabled BOOLEAN,
    type TEXT,
    FOREIGN KEY (cluster_id) REFERENCES vsphere_clusters (id) ON DELETE CASCADE
);