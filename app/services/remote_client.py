import paramiko

class RemoteClient:
    """
    Wrapper around paramiko.SSHClient.
    Supports context manager (with ... as ...).
    """
    def __init__(self, host, user, port=22, password=None, key_file=None) -> None:
        self.host = host
        self.user = user
        self.port = port
        self.password = password
        self.key_file = key_file
        self.client = None
        self.sftp = None

    def __enter__(self):
        """Establishing a connection"""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            print(f"Connecting to {self.user}@{self.host}:{self.port}...")
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.user,
                password=self.password,
                key_filename=self.key_file,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            self.sftp = self.client.open_sftp()
            print(f"Connected with {self.host}")
        except Exception as e:
            print(f"No connection: {e}")
            raise e # raise again to notify a script using this class
            
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Closing a connection"""
        if self.sftp: self.sftp.close()
        if self.client: self.client.close()
        print("Disconnected.")

    def run(self, command) -> tuple:
        """Executes a command and returns (stdout, stderr)"""
        if not self.client:
            raise ConnectionError("Brak połączenia SSH")
        
        stdin, stdout, stderr = self.client.exec_command(command)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        return out, err

    def get_file(self, remote_path, local_path) -> bool:
        """Saves a file from the remote server to the local machine."""
        if self.sftp:
            try:
                self.sftp.get(remote_path, local_path)
                print(f"Downloaded: {remote_path} to {local_path}")
                return True
            except IOError as e:
                print(f"Error downloading a file: {e}")
                return False
        return False