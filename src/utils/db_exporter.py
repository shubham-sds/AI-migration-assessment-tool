# src/utils/db_exporter.py

import json
import logging
import sqlite3

from src.db.db_manager import DBManager

logger = logging.getLogger(__name__)

class DBExporter:
    """Handles the logic for exporting the SQLite database to other formats."""

    def __init__(self, db_manager: DBManager):
        """Initializes the exporter with a DBManager instance."""
        self.db_manager = db_manager

    def export_to_json(self, output_path: str) -> bool:
        """
        Reads all tables from the database and exports them to a single JSON file.

        Args:
            output_path: The file path where the JSON output will be saved.

        Returns:
            True if the export was successful, False otherwise.
        """
        if not self.db_manager.conn:
            logger.error("Database connection is not available for exporting.")
            return False

        all_data = {}
        try:
            cursor = self.db_manager.conn.cursor()

            # Get a list of all tables in the database
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [table[0] for table in cursor.fetchall()]

            # Filter out internal sqlite tables
            tables_to_export = [t for t in tables if not t.startswith('sqlite_')]
            logger.info(f"Found tables to export: {', '.join(tables_to_export)}")

            for table_name in tables_to_export:
                # Get the column names for the current table
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [col[1] for col in cursor.fetchall()]

                # Fetch all rows from the table
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()

                # Convert the list of tuples (rows) into a list of dictionaries
                # for proper JSON formatting.
                table_data = [dict(zip(columns, row)) for row in rows]
                all_data[table_name] = table_data

            # Write the structured dictionary to a JSON file with pretty-printing
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(all_data, f, indent=4, ensure_ascii=False)

            logger.info(f"Database successfully exported to {output_path}")
            return True

        except (sqlite3.Error, IOError) as e:
            logger.exception(f"An error occurred during the database export process: {e}")
            return False
