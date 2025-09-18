CREATE TABLE IF NOT EXISTS process_open_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    pid INTEGER,
    file_path TEXT,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);