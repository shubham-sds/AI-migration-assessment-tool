CREATE TABLE IF NOT EXISTS performance_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    alias TEXT,
    instance_name TEXT,
    value REAL,
    unit TEXT,
    description TEXT,
    threshold REAL,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);