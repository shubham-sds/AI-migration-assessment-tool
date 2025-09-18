CREATE TABLE IF NOT EXISTS docker_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    container_id TEXT,
    container_names TEXT,
    container_status TEXT,
    ports TEXT,
    image_repository TEXT,
    image_tag TEXT,
    image_id TEXT,
    command TEXT,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);