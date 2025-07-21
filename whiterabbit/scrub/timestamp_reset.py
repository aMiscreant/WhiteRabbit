import os
import time

def reset_timestamps(file_path: str, timestamp: float = None) -> None:
    """
    Reset file timestamps (access and modification time).

    Args:
        file_path (str): Path to the file.
        timestamp (float, optional): Unix timestamp to set; defaults to current time.
    """
    if timestamp is None:
        timestamp = time.time()
    try:
        os.utime(file_path, (timestamp, timestamp))
    except Exception as e:
        raise RuntimeError(f"Failed to reset timestamps for {file_path}: {e}")

