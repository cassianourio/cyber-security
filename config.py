import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env
load_dotenv(BASE_DIR / ".env")

# Google Cloud settings
GCP_PROJECT = os.getenv("GCP_PROJECT", "cyber-security-cassi-9")
GCP_LOCATION = os.getenv("GCP_LOCATION", "us-central1")

# Vertex AI Model selection
# We use gemini-2.5-flash as default as it has been tested successfully
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# Reports output directory
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
