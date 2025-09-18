INSERT INTO servers (hostname, ip_address, os_name, os_version, cpu_cores, total_memory_gb, last_discovered)
VALUES (?,?,?,?,?,?,?)
ON CONFLICT(ip_address) DO UPDATE SET
    hostname=excluded.hostname,
    os_name=excluded.os_name,
    os_version=excluded.os_version,
    cpu_cores=excluded.cpu_cores,
    total_memory_gb=excluded.total_memory_gb,
    last_discovered=excluded.last_discovered;