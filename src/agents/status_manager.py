# src/agents/status_manager.py

import pandas as pd
import threading
from datetime import datetime
from pathlib import Path

class StatusManager:
    """
    Manages discovery status in a CSV, assigning a unique run_id to each host entry.
    This class is thread-safe.
    """
    def __init__(self, status_file="data/discovery_status.csv"):
        self.status_file_path = Path(status_file)
        self.columns = ['run_id', 'ip', 'os_type', 'user', 'status', 'last_update']
        self._lock = threading.Lock()
        
        self.status_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        if not self.status_file_path.exists():
            pd.DataFrame(columns=self.columns).to_csv(self.status_file_path, index=False)

    def _read_status_file(self) -> pd.DataFrame:
        """Reads the status CSV, ensuring correct data types."""
        try:
            dtype_map = {'run_id': 'Int64', 'ip': str, 'os_type': str, 'user': str, 'status': str}
            df = pd.read_csv(self.status_file_path, dtype=dtype_map)
            return df
        except (pd.errors.EmptyDataError, FileNotFoundError):
            return pd.DataFrame(columns=self.columns)

    def _write_status_file(self, df: pd.DataFrame) -> None:
        """Writes a DataFrame to the status CSV."""
        if 'run_id' in df.columns:
            df['run_id'] = df['run_id'].astype('Int64')
        df.to_csv(self.status_file_path, index=False)

    def _get_next_run_id(self) -> int:
        """Determines the next available run_id."""
        df = self._read_status_file()
        if df.empty or df['run_id'].dropna().empty:
            return 1
        return int(df['run_id'].max()) + 1

    def add_hosts_from_inventory(self, inventory_df: pd.DataFrame):
        """Adds hosts from a new inventory, assigning unique, sequential run_ids."""
        with self._lock:
            if inventory_df.empty:
                return

            next_id = self._get_next_run_id()
            
            new_hosts_df = inventory_df[['ip', 'os_type', 'user']].copy()
            # Assign a unique, incrementing run_id to each new host
            new_hosts_df['run_id'] = range(next_id, next_id + len(new_hosts_df))
            new_hosts_df['status'] = 'pending'
            new_hosts_df['last_update'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            new_hosts_df = new_hosts_df[self.columns]

            existing_df = self._read_status_file()
            combined_df = pd.concat([existing_df, new_hosts_df], ignore_index=True)
            self._write_status_file(combined_df)

    def update_host_status(self, run_id: int, status: str):
        """Updates the status for a specific run_id."""
        with self._lock:
            df = self._read_status_file()
            
            mask = (df['run_id'] == run_id)
            if mask.any():
                df.loc[mask, 'status'] = status
                df.loc[mask, 'last_update'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._write_status_file(df)

    def get_incomplete_hosts(self) -> pd.DataFrame:
        """Gets a DataFrame of all hosts that are not in 'completed' status."""
        with self._lock:
            df = self._read_status_file()
            if df.empty:
                return pd.DataFrame(columns=self.columns)
            
            return df[df['status'] != 'completed'].copy()
