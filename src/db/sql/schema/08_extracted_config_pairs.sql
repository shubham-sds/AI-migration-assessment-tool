CREATE TABLE IF NOT EXISTS extracted_config_pairs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    file_path TEXT,
    config_key TEXT,
    config_value TEXT,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);