import os

def shred_file(file_path: str, passes: int = 3) -> None:
    """
    Securely overwrite a file multiple times to prevent recovery.

    Args:
        file_path (str): Path to file to shred.
        passes (int): Number of overwrite passes.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    length = os.path.getsize(file_path)
    with open(file_path, "r+b") as f:
        for pass_num in range(passes):
            f.seek(0)
            # On odd passes write random bytes, even passes write zeros
            if pass_num % 2 == 0:
                data = os.urandom(length)
            else:
                data = b'\x00' * length
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    # Finally, remove the file
    os.remove(file_path)
