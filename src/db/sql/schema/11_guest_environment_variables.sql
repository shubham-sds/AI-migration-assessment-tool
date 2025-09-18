CREATE TABLE IF NOT EXISTS guest_environment_variables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    variable_name TEXT,
    variable_value TEXT,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);