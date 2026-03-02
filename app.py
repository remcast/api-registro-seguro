from datetime import datetime, timedelta
import sqlite3

import bcrypt
from flask import Flask, jsonify, request
from functools import wraps
import jwt

from config import DATABASE_PATH, JWT_ALGORITHM, SECRET_KEY


app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY


# Función auxiliar para conectar a la BD
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crea/ajusta la tabla y columnas necesarias."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Asegurar tabla base
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL
        )
        """
    )

    # Asegurar columnas adicionales
    cursor.execute("PRAGMA table_info(usuarios)")
    columnas = [row[1] for row in cursor.fetchall()]
    if "saldo" not in columnas:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN saldo REAL DEFAULT 1000.0")
    if "rol" not in columnas:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN rol TEXT DEFAULT 'usuario'")

    # Asegurar valores por defecto para registros existentes
    cursor.execute("UPDATE usuarios SET saldo = 1000.0 WHERE saldo IS NULL")
    cursor.execute(
        "UPDATE usuarios SET rol = 'usuario' WHERE rol IS NULL OR rol = ''"
    )

    conn.commit()
    conn.close()


@app.route("/registro", methods=["POST"])
def registro():
    data = request.get_json()

    try:
        email = data.get("email")
        password = data.get("password")

        # VALIDACIÓN 1: Datos presentes
        if not email or not password:
            return jsonify({"error": "Faltan datos"}), 400

        # VALIDACIÓN 2: Longitud estricta (Mayor a 8 y Menor a 10)
        # Esto significa que la contraseña SOLO puede tener 9 caracteres.
        if not (8 < len(password) < 10):
            return (
                jsonify(
                    {
                        "error": "Credenciales Invalidas: La contraseña debe ser mayor a 8 y menor a 10 caracteres"
                    }
                ),
                400,
            )

        conn = get_db_connection()
        cursor = conn.cursor()

        # VALIDACIÓN 3: Duplicados
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "El usuario ya existe"}), 409

        # HASHING: Cifrar contraseña
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # INSERTAR: Guardar en BD (saldo y rol por defecto)
        cursor.execute(
            "INSERT INTO usuarios (email, password, saldo, rol) VALUES (?, ?, ?, ?)",
            (email, hashed_password, 1000.0, "usuario"),
        )
        conn.commit()
        conn.close()

        return jsonify({"mensaje": "Usuario Registrado"}), 201

    except Exception as e:
        return jsonify({"error": f"Error del servidor: {str(e)}"}), 500


@app.route("/cambiar-contrasena", methods=["PUT"])
def cambiar_contrasena():
    try:
        data = request.get_json()
        email = data.get("email")
        password_actual = data.get("password_actual")
        password_nueva = data.get("password_nueva")

        # 1. Validar que lleguen los datos
        if not email or not password_actual or not password_nueva:
            return (
                jsonify(
                    {
                        "error": "Faltan datos (email, password_actual, password_nueva)"
                    }
                ),
                400,
            )

        # 2. Validar longitud de la NUEVA contraseña
        if not (8 < len(password_nueva) < 10):
            return (
                jsonify(
                    {
                        "error": "La nueva contraseña debe ser mayor a 8 y menor a 10 caracteres"
                    }
                ),
                400,
            )

        conn = get_db_connection()
        cursor = conn.cursor()

        # 3. Buscar al usuario y obtener su hash actual
        cursor.execute("SELECT password FROM usuarios WHERE email = ?", (email,))
        usuario = cursor.fetchone()

        if not usuario:
            conn.close()
            return jsonify({"error": "Usuario no encontrado"}), 404

        hash_guardado = usuario[0]

        # 4. Verificar que la contraseña ACTUAL sea correcta
        if not bcrypt.checkpw(password_actual.encode("utf-8"), hash_guardado):
            conn.close()
            return jsonify({"error": "La contraseña actual es incorrecta"}), 401

        # 5. Si todo está bien, hashear la NUEVA contraseña
        nuevo_hash = bcrypt.hashpw(password_nueva.encode("utf-8"), bcrypt.gensalt())

        # 6. Actualizar en la Base de Datos (UPDATE)
        cursor.execute(
            "UPDATE usuarios SET password = ? WHERE email = ?", (nuevo_hash, email)
        )
        conn.commit()
        conn.close()

        return jsonify({"mensaje": "Contraseña actualizada con éxito"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# FLUJO DE AUTENTICACIÓN JWT
# =============================================================================
@app.route("/validar", methods=["POST"])
def validar_usuario():
    """Valida credenciales y genera JWT."""
    try:
        # PASO 1-2: Recibe credenciales, valida datos y busca el usuario en BD (obtiene su hash)
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Faltan datos"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password, rol FROM usuarios WHERE email = ?", (email,)
        )
        usuario = cursor.fetchone()

        if not usuario:
            conn.close()
            return jsonify({"error": "Usuario no encontrado"}), 404

        hash_guardado = usuario[0]
        rol = usuario[1]

        if bcrypt.checkpw(password.encode("utf-8"), hash_guardado):
            conn.close()

            # Crear y firmar JWT (API)
            payload = {
                "email": email,
                "rol": rol,
                "exp": datetime.utcnow() + timedelta(hours=24),
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)

            # Guardar el token
            return jsonify({"mensaje": "Credenciales válidas", "token": token}), 200
        else:
            conn.close()
            return jsonify({"error": "Credenciales inválidas"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def requiere_token(f):
    """Protege endpoints con JWT."""

    @wraps(f)
    def decorador(*args, **kwargs):
        # Enviar JWT en header Authorization: Bearer <token> (cliente)
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return (
                jsonify(
                    {
                        "error": "Falta el token. Envía: Authorization: Bearer <token>"
                    }
                ),
                401,
            )

        token = auth_header.split(" ")[1]

        try:
            # Verificar JWT y permitir acceso (API)
            payload = jwt.decode(
                token, SECRET_KEY, algorithms=[JWT_ALGORITHM]
            )
            request.usuario_actual = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido o firma incorrecta"}), 401

    return decorador


@app.route("/saldo", methods=["GET"])
@requiere_token
def ver_saldo():
    """Endpoint protegido (ejemplo)."""
    usuario = request.usuario_actual
    email = usuario.get("email")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT saldo FROM usuarios WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Usuario no encontrado"}), 404

    return (
        jsonify(
            {
                "mensaje": "Acceso concedido",
                "email": email,
                "saldo": float(row["saldo"]),
            }
        ),
        200,
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)

from flask import Flask, request, jsonify
import sqlite3
import bcrypt
from functools import wraps
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)

# Variable para firmar y verificar JWT
clave_secreta = "clave secreta"


# Función auxiliar para conectar a la BD (para que tu compañero la use)
def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crea/ajusta la tabla y columnas necesarias."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Asegurar tabla base
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL
        )
        """
    )

    # Asegurar columnas adicionales
    cursor.execute("PRAGMA table_info(usuarios)")
    columnas = [row[1] for row in cursor.fetchall()]
    if "saldo" not in columnas:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN saldo REAL DEFAULT 1000.0")
    if "rol" not in columnas:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN rol TEXT DEFAULT 'usuario'")

    # Asegurar valores por defecto para registros existentes
    cursor.execute("UPDATE usuarios SET saldo = 1000.0 WHERE saldo IS NULL")
    cursor.execute(
        "UPDATE usuarios SET rol = 'usuario' WHERE rol IS NULL OR rol = ''"
    )

    conn.commit()
    conn.close()


@app.route("/registro", methods=["POST"])
def registro():
    data = request.get_json()

    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        # VALIDACIÓN 1: Datos presentes
        if not email or not password:
            return jsonify({"error": "Faltan datos"}), 400

        # VALIDACIÓN 2: Longitud estricta (Mayor a 8 y Menor a 10)
        # Esto significa que la contraseña SOLO puede tener 9 caracteres.
        if not (8 < len(password) < 10):
            return jsonify(
                {
                    "error": "Credenciales Invalidas: La contraseña debe ser mayor a 8 y menor a 10 caracteres"
                }
            ), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # VALIDACIÓN 3: Duplicados
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "El usuario ya existe"}), 409

        # HASHING: Cifrar contraseña
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # INSERTAR: Guardar en BD (saldo y rol por defecto)
        cursor.execute(
            "INSERT INTO usuarios (email, password, saldo, rol) VALUES (?, ?, ?, ?)",
            (email, hashed_password, 1000.0, "usuario"),
        )
        conn.commit()
        conn.close()

        return jsonify({"mensaje": "Usuario Registrado"}), 201

    except Exception as e:
        return jsonify({"error": f"Error del servidor: {str(e)}"}), 500


# Endpoint para cambiar contraseña
@app.route("/cambiar-contrasena", methods=["PUT"])
def cambiar_contrasena():
    try:
        data = request.get_json()
        email = data.get("email")
        password_actual = data.get("password_actual")
        password_nueva = data.get("password_nueva")

        # 1. Validar que lleguen los datos
        if not email or not password_actual or not password_nueva:
            return (
                jsonify(
                    {
                        "error": "Faltan datos (email, password_actual, password_nueva)"
                    }
                ),
                400,
            )

        # 2. Validar longitud de la NUEVA contraseña (la misma regla de antes)
        if not (8 < len(password_nueva) < 10):
            return (
                jsonify(
                    {
                        "error": "La nueva contraseña debe ser mayor a 8 y menor a 10 caracteres"
                    }
                ),
                400,
            )

        conn = get_db_connection()
        cursor = conn.cursor()

        # 3. Buscar al usuario y obtener su hash actual
        cursor.execute("SELECT password FROM usuarios WHERE email = ?", (email,))
        usuario = cursor.fetchone()

        if not usuario:
            conn.close()
            return jsonify({"error": "Usuario no encontrado"}), 404

        hash_guardado = usuario[0]  # El hash está en la primera columna

        # 4. Verificar que la contraseña ACTUAL sea correcta
        # (Comparamos lo que escribió con el hash de la BD)
        if not bcrypt.checkpw(password_actual.encode("utf-8"), hash_guardado):
            conn.close()
            return jsonify({"error": "La contraseña actual es incorrecta"}), 401

        # 5. Si todo está bien, Hashear la NUEVA contraseña
        nuevo_hash = bcrypt.hashpw(password_nueva.encode("utf-8"), bcrypt.gensalt())

        # 6. Actualizar en la Base de Datos (UPDATE)
        cursor.execute(
            "UPDATE usuarios SET password = ? WHERE email = ?", (nuevo_hash, email)
        )
        conn.commit()
        conn.close()

        return jsonify({"mensaje": "Contraseña actualizada con éxito"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# FLUJO DE AUTENTICACIÓN JWT
# =============================================================================
@app.route("/validar", methods=["POST"])
def validar_usuario():
    """Valida credenciales y genera JWT."""
    try:
        # PASO 1-2: Recibe credenciales, valida datos y busca el usuario en BD (obtiene su hash)
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Faltan datos"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password, rol FROM usuarios WHERE email = ?", (email,)
        )
        usuario = cursor.fetchone()

        if not usuario:
            conn.close()
            return jsonify({"error": "Usuario no encontrado"}), 404

        hash_guardado = usuario[0]
        rol = usuario[1]

        if bcrypt.checkpw(password.encode("utf-8"), hash_guardado):
            conn.close()

            # Crear y firmar JWT (API)
            payload = {
                "email": email,
                "rol": rol,
                "exp": datetime.utcnow() + timedelta(hours=24),  # expira en 24 horas
            }
            token = jwt.encode(payload, clave_secreta, algorithm="HS256")

            # Guardar el token
            return jsonify({"mensaje": "Credenciales válidas", "token": token}), 200
        else:
            conn.close()
            return jsonify({"error": "Credenciales inválidas"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def requiere_token(f):
    """Protege endpoints con JWT."""

    @wraps(f)
    def decorador(*args, **kwargs):
        # Enviar JWT en header Authorization: Bearer <token> (cliente)
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return (
                jsonify(
                    {
                        "error": "Falta el token. Envía: Authorization: Bearer <token>"
                    }
                ),
                401,
            )

        token = auth_header.split(" ")[1]

        try:
            # Verificar JWT y permitir acceso (API)
            payload = jwt.decode(token, clave_secreta, algorithms=["HS256"])
            request.usuario_actual = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido o firma incorrecta"}), 401

    return decorador


@app.route("/saldo", methods=["GET"])
@requiere_token
def ver_saldo():
    """Endpoint protegido (ejemplo)."""
    usuario = request.usuario_actual
    email = usuario.get("email")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT saldo FROM usuarios WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Usuario no encontrado"}), 404

    return (
        jsonify(
            {
                "mensaje": "Acceso concedido",
                "email": email,
                "saldo": float(row["saldo"]),
            }
        ),
        200,
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)

from flask import Flask, request, jsonify
import sqlite3
import bcrypt
from functools import wraps
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)

# Variable para firmar y verificar JWT
clave_secreta = "clave secreta"

# Función auxiliar para conectar a la BD (para que tu compañero la use)
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crea/ajusta la tabla y columna necesarias."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Asegurar tabla base
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL
        )
    """)

    # Asegurar columna saldo
    cursor.execute("PRAGMA table_info(usuarios)")
    columnas = [row[1] for row in cursor.fetchall()]
    if "saldo" not in columnas:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN saldo REAL DEFAULT 1000.0")

    # Asegurar saldo para registros existentes
    cursor.execute("UPDATE usuarios SET saldo = 1000.0 WHERE saldo IS NULL")

    conn.commit()
    conn.close()

@app.route('/registro', methods=['POST'])
def registro():
    data = request.get_json()

    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        # VALIDACIÓN 1: Datos presentes
        if not email or not password:
            return jsonify({"error": "Faltan datos"}), 400

        # VALIDACIÓN 2: Longitud estricta (Mayor a 8 y Menor a 10)
        # Esto significa que la contraseña SOLO puede tener 9 caracteres.
        if not (8 < len(password) < 10):
            return jsonify({"error": "Credenciales Invalidas: La contraseña debe ser mayor a 8 y menor a 10 caracteres"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # VALIDACIÓN 3: Duplicados
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "El usuario ya existe"}), 409

        # HASHING: Cifrar contraseña
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # INSERTAR: Guardar en BD (saldo por defecto)
        cursor.execute(
            "INSERT INTO usuarios (email, password, saldo) VALUES (?, ?, ?)",
            (email, hashed_password, 1000.0)
        )
        conn.commit()
        conn.close()

        return jsonify({"mensaje": "Usuario Registrado"}), 201

    except Exception as e:
        return jsonify({"error": f"Error del servidor: {str(e)}"}), 500
    
# Endpoint para cambiar contraseña

@app.route('/cambiar-contrasena', methods=['PUT'])
def cambiar_contrasena():
    try:
        data = request.get_json()
        email = data.get('email')
        password_actual = data.get('password_actual')
        password_nueva = data.get('password_nueva')

        # 1. Validar que lleguen los datos
        if not email or not password_actual or not password_nueva:
            return jsonify({"error": "Faltan datos (email, password_actual, password_nueva)"}), 400

        # 2. Validar longitud de la NUEVA contraseña (la misma regla de antes)
        if not (8 < len(password_nueva) < 10):
            return jsonify({"error": "La nueva contraseña debe ser mayor a 8 y menor a 10 caracteres"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # 3. Buscar al usuario y obtener su hash actual
        cursor.execute("SELECT password FROM usuarios WHERE email = ?", (email,))
        usuario = cursor.fetchone()

        if not usuario:
            conn.close()
            return jsonify({"error": "Usuario no encontrado"}), 404
        
        hash_guardado = usuario[0] # El hash está en la primera columna

        # 4. Verificar que la contraseña ACTUAL sea correcta
        # (Comparamos lo que escribió con el hash de la BD)
        if not bcrypt.checkpw(password_actual.encode('utf-8'), hash_guardado):
            conn.close()
            return jsonify({"error": "La contraseña actual es incorrecta"}), 401

        # 5. Si todo está bien, Hashear la NUEVA contraseña
        nuevo_hash = bcrypt.hashpw(password_nueva.encode('utf-8'), bcrypt.gensalt())

        # 6. Actualizar en la Base de Datos (UPDATE)
        cursor.execute("UPDATE usuarios SET password = ? WHERE email = ?", (nuevo_hash, email))
        conn.commit()
        conn.close()

        return jsonify({"mensaje": "Contraseña actualizada con éxito"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# =============================================================================
# FLUJO DE AUTENTICACIÓN JWT
# =============================================================================

@app.route('/validar', methods=['POST'])
def validar_usuario():
    """Valida credenciales y genera JWT."""
    try:
        # PASO 1-2: Recibe credenciales, valida datos y busca el usuario en BD (obtiene su hash)
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Faltan datos"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT password FROM usuarios WHERE email = ?", (email,))
        usuario = cursor.fetchone()

        if not usuario:
            conn.close()
            return jsonify({"error": "Usuario no encontrado"}), 404

        hash_guardado = usuario[0]

        if bcrypt.checkpw(password.encode('utf-8'), hash_guardado):
            conn.close()

            # Crear y firmar JWT (API)
            payload = {
                "email": email,
                "exp": datetime.utcnow() + timedelta(hours=24)  # expira en 24 horas
            }
            token = jwt.encode(payload, clave_secreta, algorithm="HS256")

            # Guardar el token
            return jsonify({
                "mensaje": "Credenciales válidas",
                "token": token
            }), 200
        else:
            conn.close()
            return jsonify({"error": "Credenciales inválidas"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def requiere_token(f):
    """Protege endpoints con JWT."""
    @wraps(f)
    def decorador(*args, **kwargs):
        # Enviar JWT en header Authorization: Bearer <token> (cliente)
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Falta el token. Envía: Authorization: Bearer <token>"}), 401

        token = auth_header.split(' ')[1]

        try:
            # Verificar JWT y permitir acceso (API)
            payload = jwt.decode(token, clave_secreta, algorithms=["HS256"])
            request.usuario_actual = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido o firma incorrecta"}), 401

    return decorador


@app.route('/saldo', methods=['GET'])
@requiere_token
def ver_saldo():
    """Endpoint protegido (ejemplo)."""
    usuario = request.usuario_actual
    email = usuario.get("email")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT saldo FROM usuarios WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Usuario no encontrado"}), 404

    return jsonify({
        "mensaje": "Acceso concedido",
        "email": email,
        "saldo": float(row["saldo"])
    }), 200


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

