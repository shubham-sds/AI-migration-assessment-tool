CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    process_name TEXT,
    pid INTEGER,
    user TEXT,
    state TEXT,
    command_line TEXT,
    listening_ports TEXT,
    owning_package TEXT,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);