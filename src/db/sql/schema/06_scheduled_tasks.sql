CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    name TEXT,
    command TEXT,
    schedule TEXT,
    enabled BOOLEAN,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);