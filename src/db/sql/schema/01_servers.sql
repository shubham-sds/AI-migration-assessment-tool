CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT,
    ip_address TEXT UNIQUE,
    os_name TEXT,
    os_version TEXT,
    cpu_cores INTEGER,
    total_memory_gb REAL,
    last_discovered TIMESTAMP
);