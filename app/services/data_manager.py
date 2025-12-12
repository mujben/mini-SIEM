import pandas as pd
from pathlib import Path
from datetime import datetime

class DataManager:
    STORAGE_DIR = Path.cwd() / "storage" # Path to storage directory (Path object)

    @staticmethod
    def ensure_storage() -> None:
        """
        Creates storage folder if it does not exist
        """
        DataManager.STORAGE_DIR.mkdir(exist_ok=True) # exist_ok=True ensures no error if folder exists

    @staticmethod
    def save_logs_to_parquet(log_list, host_id) -> tuple:
        """
        Saves list of logs to a '.parquet' file
        """
        DataManager.ensure_storage()
        
        if not log_list:
            return None, 0
            
        # 1. Make DataFrame
        df = pd.DataFrame(log_list)
        
        # 2. Fill missing columns
        expected_cols = ['timestamp', 'source_ip', 'alert_type', 'user', 'message', 'raw_log']
        for col in expected_cols:
            if col not in df.columns:
                df[col] = None

        # 3. Generate filename
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"logs_{host_id}_{timestamp_str}.parquet"
        
        file_path = DataManager.STORAGE_DIR / filename
        
        # 4. Write to Parquet
        try:
            df.to_parquet(file_path, engine='pyarrow', index=False)
            return filename, len(df)
        except Exception as e:
            print(f"Parquet write error: {e}")
            raise e

    @staticmethod
    def load_logs(filename) -> pd.DataFrame:
        """
        Loads Parquet file to DataFrame.
        """
        DataManager.ensure_storage()
        
        file_path = DataManager.STORAGE_DIR / filename
        
        if not file_path.exists():
            print(f"Warning: File {filename} does not exist.")
            return pd.DataFrame()
        
        try:
            df = pd.read_parquet(file_path, engine='pyarrow')
            return df
        
        except Exception as e:
            print(f"Parquet file {filename} read error: {e}")
            return pd.DataFrame()