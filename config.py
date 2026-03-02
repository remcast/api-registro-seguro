import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent

# Carga las variables del archivo .env que está en la raíz del proyecto
load_dotenv(BASE_DIR / ".env")

# Clave secreta de Flask (cookies de sesión, etc.)
SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# Clave y algoritmo para firmar/verificar JWT
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# Ruta de la base de datos SQLite
DATABASE_PATH = os.getenv("DATABASE_PATH", "database.db")

