
from pathlib import Path

from dotenv import load_dotenv


# Project root
BASE_DIR = Path(__file__).resolve().parents[2]

# Load root .env
ENV_FILE = BASE_DIR / ".env"
load_dotenv(ENV_FILE)


