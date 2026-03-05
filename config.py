import os

from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")

# Carga las variables desde el archivo .env
load_dotenv(ENV_PATH)

# Clave usada por Flask y por JWT
SECRET_KEY = os.getenv("SECRET_KEY", "clave secreta")

# Algoritmo para firmar/verificar JWT
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# Ruta de la base de datos SQLite
DATABASE_PATH = os.getenv(
    "DATABASE_PATH",
    os.path.join(BASE_DIR, "database.db"),
)
