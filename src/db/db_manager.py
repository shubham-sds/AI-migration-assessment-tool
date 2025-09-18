import sqlite3
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s')

class DBManager:
    """
    Manages all interactions with the SQLite database, including schema creation,
    and bulk data insertion.
    """

    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = None
        self.sql_base_path = Path(__file__).parent / "sql"
        self.queries = self._load_all_queries()
        try:
            self.conn = sqlite3.connect(db_file, check_same_thread=False)
            self.conn.execute("PRAGMA foreign_keys = ON;")
            logging.info(f"Successfully connected to database: {db_file}")
            self._create_tables()
            # The call to _create_discovery_status_table() has been removed.
        except (sqlite3.Error, FileNotFoundError) as e:
            logging.error(f"Error initializing database manager: {e}")

    def _load_query(self, filepath: Path) -> str:
        with open(filepath, 'r') as f:
            return f.read()

    def _load_all_queries(self) -> dict:
        queries = {}
        if not self.sql_base_path.is_dir():
            raise FileNotFoundError(f"SQL directory not found: {self.sql_base_path}")
        for path in self.sql_base_path.rglob("*.sql"):
            key = path.stem
            if key in queries:
                logging.warning(f"Duplicate query key '{key}' found. Overwriting.")
            queries[key] = self._load_query(path)
        return queries

    def close(self):
        if self.conn:
            self.conn.close()
            logging.info("Database connection closed.")

    def _create_tables(self):
        if not self.conn:
            return
        cursor = self.conn.cursor()
        schema_keys = sorted([key for key in self.queries if key.startswith(('0', '1', '2'))])
        for key in schema_keys:
            query = self.queries.get(key)
            if query:
                cursor.executescript(query)
                self.conn.commit()
        logging.info("All tables created or verified successfully.")

    # --- All discovery status methods have been removed ---

    def clear_snapshot_data_for_server(self, server_id):
        if not self.conn: return
        cursor = self.conn.cursor()
        tables_to_clear = [
            "applications", "network_connections", "installed_software",
            "storage_mounts", "scheduled_tasks", "config_files",
            "extracted_config_pairs", "process_open_files", "performance_metrics",
            "guest_environment_variables", "docker_inventory"
        ]
        for table in tables_to_clear:
            cursor.execute(f"DELETE FROM {table} WHERE server_id =?", (server_id,))
        self.conn.commit()
        logging.info(f"Cleared snapshot data for server_id: {server_id}")

    def get_server_ips_to_ids(self):
        if not self.conn: return {}
        cursor = self.conn.cursor()
        cursor.execute(self.queries['get_server_ips_to_ids'])
        return {ip: id for id, ip in cursor.fetchall()}

    def clear_snapshot_data_for_vcenter(self, vcenter_ip):
        if not self.conn: return
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM vsphere_vms WHERE vcenter_ip =?", (vcenter_ip,))
        cursor.execute("DELETE FROM vsphere_hosts WHERE vcenter_ip =?", (vcenter_ip,))
        cursor.execute("DELETE FROM vsphere_clusters WHERE vcenter_ip =?", (vcenter_ip,))
        cursor.execute("DELETE FROM vsphere_datastores WHERE vcenter_ip =?", (vcenter_ip,))
        cursor.execute("DELETE FROM vsphere_performance_metrics WHERE vcenter_ip =?", (vcenter_ip,))
        self.conn.commit()
        logging.info(f"Cleared previous vSphere snapshot data for vCenter: {vcenter_ip}")

    # --- VSPHERE LOOKUP METHODS ---

    def get_vsphere_cluster_ids(self, vcenter_ip):
        if not self.conn: return {}
        cursor = self.conn.cursor()
        cursor.execute(self.queries['get_vsphere_cluster_ids'], (vcenter_ip,))
        return {name: id for id, name in cursor.fetchall()}

    def get_vsphere_host_ids(self, vcenter_ip):
        if not self.conn: return {}
        cursor = self.conn.cursor()
        cursor.execute(self.queries['get_vsphere_host_ids'], (vcenter_ip,))
        return {name: id for id, name in cursor.fetchall()}

    def get_vsphere_vm_ids(self, vcenter_ip):
        if not self.conn: return {}
        cursor = self.conn.cursor()
        cursor.execute(self.queries['get_vsphere_vm_ids'], (vcenter_ip,))
        return {name: id for id, name in cursor.fetchall()}

    # --- BULK INSERTION METHODS ---

    def _execute_bulk_operation(self, query_key, data):
        if not self.conn or not data: return
        query = self.queries.get(query_key)
        if query:
            self.conn.cursor().executemany(query, data)
        else:
            logging.error(f"Query key '{query_key}' not found.")

    def add_servers_bulk(self, server_data):
        self._execute_bulk_operation('add_servers_bulk', server_data)

    def add_applications_bulk(self, app_data):
        self._execute_bulk_operation('add_applications_bulk', app_data)

    def add_network_connections_bulk(self, conn_data):
        self._execute_bulk_operation('add_network_connections_bulk', conn_data)

    def add_installed_software_bulk(self, software_data):
        self._execute_bulk_operation('add_installed_software_bulk', software_data)

    def add_storage_mounts_bulk(self, mount_data):
        self._execute_bulk_operation('add_storage_mounts_bulk', mount_data)

    def add_scheduled_tasks_bulk(self, task_data):
        self._execute_bulk_operation('add_scheduled_tasks_bulk', task_data)

    def add_config_files_bulk(self, file_data):
        self._execute_bulk_operation('add_config_files_bulk', file_data)

    def add_extracted_config_pairs_bulk(self, pair_data):
        self._execute_bulk_operation('add_extracted_config_pairs_bulk', pair_data)

    def add_process_open_files_bulk(self, file_data):
        self._execute_bulk_operation('add_process_open_files_bulk', file_data)

    def add_performance_metrics_bulk(self, metric_data):
        self._execute_bulk_operation('add_performance_metrics_bulk', metric_data)

    def add_environment_variables_bulk(self, env_data):
        self._execute_bulk_operation('add_environment_variables_bulk', env_data)

    def add_docker_inventory_bulk(self, docker_data):
        self._execute_bulk_operation('add_docker_inventory_bulk', docker_data)

    def add_vsphere_clusters_bulk(self, cluster_data):
        self._execute_bulk_operation('add_vsphere_clusters_bulk', cluster_data)

    def add_vsphere_cluster_rules_bulk(self, rule_data):
        self._execute_bulk_operation('add_vsphere_cluster_rules_bulk', rule_data)

    def add_vsphere_hosts_bulk(self, host_data):
        self._execute_bulk_operation('add_vsphere_hosts_bulk', host_data)

    def add_vsphere_vms_bulk(self, vm_data):
        self._execute_bulk_operation('add_vsphere_vms_bulk', vm_data)

    def add_vsphere_snapshots_bulk(self, snapshot_data):
        self._execute_bulk_operation('add_vsphere_snapshots_bulk', snapshot_data)

    def add_vsphere_virtual_disks_bulk(self, disk_data):
        self._execute_bulk_operation('add_vsphere_virtual_disks_bulk', disk_data)

    def add_vsphere_networks_bulk(self, network_data):
        self._execute_bulk_operation('add_vsphere_networks_bulk', network_data)

    def add_vsphere_tags_bulk(self, tag_data):
        self._execute_bulk_operation('add_vsphere_tags_bulk', tag_data)

    def add_vsphere_datastores_bulk(self, datastore_data):
        self._execute_bulk_operation('add_vsphere_datastores_bulk', datastore_data)

    def add_vsphere_performance_metrics_bulk(self, perf_data):
        self._execute_bulk_operation('add_vsphere_performance_metrics_bulk', perf_data)
