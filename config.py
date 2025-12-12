import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-very-secret')
    
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///../instance/project.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SSH_DEFAULT_USER = os.getenv('SSH_DEFAULT_USER', 'vagrant')
    SSH_DEFAULT_PORT = int(os.getenv('SSH_DEFAULT_PORT', 2222))
    SSH_KEY_FILE = os.getenv('SSH_KEY_FILE', '')

    #default log storage folder
    STORAGE_FOLDER = Path.cwd() / 'storage'