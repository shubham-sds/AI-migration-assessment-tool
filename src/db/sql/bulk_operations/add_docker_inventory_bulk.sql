INSERT INTO docker_inventory (
    server_id, container_id, container_names, container_status, ports,
    image_repository, image_tag, image_id, command
) VALUES (?,?,?,?,?,?,?,?,?);