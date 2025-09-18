CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    protocol TEXT,
    state TEXT,
    local_address TEXT,
    local_port INTEGER,
    peer_address TEXT,
    peer_port INTEGER,
    process_name TEXT,
    pid INTEGER,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);