CREATE TABLE IF NOT EXISTS config_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    file_path TEXT,
    content TEXT,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);