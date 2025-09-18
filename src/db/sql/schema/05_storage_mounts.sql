CREATE TABLE IF NOT EXISTS storage_mounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    source TEXT,
    mount_point TEXT,
    filesystem_type TEXT,
    storage_type TEXT,
    total_gb REAL,
    used_gb REAL,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);