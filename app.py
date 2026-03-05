from flask import Flask, request, jsonify
import sqlite3
import bcrypt
from functools import wraps
import jwt
from datetime import datetime, timedelta
import re

# 1. Importamos las variables seguras desde config.py
from config import SECRET_KEY, JWT_ALGORITHM, DATABASE_PATH

app = Flask(__name__)

# Función auxiliar para conectar a la BD
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/registro', methods=['POST'])
def registro():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Faltan datos"}), 400

        # Validación de Formato de Email
        patron_correo = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(patron_correo, email):
            return jsonify({"error": "El formato del correo electrónico no es válido"}), 400

        # Validación de Longitud (Entre 8 y 10 caracteres)
        if len(password) < 8 or len(password) > 10:
            return jsonify({"error": "La contraseña debe tener al menos 8 y no mayor a 10 caracteres"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "El usuario ya existe"}), 409

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor.execute(
            "INSERT INTO usuarios (email, password, saldo, rol) VALUES (?, ?, ?, ?)",
            (email, hashed_password, 1000.0, 'cliente')
        )
        conn.commit()
        conn.close()

        return jsonify({"mensaje": "Usuario Registrado"}), 201

    except Exception as e:
        return jsonify({"error": f"Error del servidor: {str(e)}"}), 500

@app.route('/cambiar-contrasena', methods=['PUT'])
def cambiar_contrasena():
    try:
        data = request.get_json()
        email = data.get('email')
        password_actual = data.get('password_actual')
        password_nueva = data.get('password_nueva')

        if not email or not password_actual or not password_nueva:
            return jsonify({"error": "Faltan datos"}), 400

        # Validación de Longitud (Entre 8 y 10 caracteres)
        if len(password_nueva) < 8 or len(password_nueva) > 10:
            return jsonify({"error": "La nueva contraseña debe tener al menos 8 y no mayor a 10 caracteres"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT password FROM usuarios WHERE email = ?", (email,))
        usuario = cursor.fetchone()

        if not usuario:
            conn.close()
            return jsonify({"error": "Usuario no encontrado"}), 404
        
        hash_guardado = usuario['password']

        if not bcrypt.checkpw(password_actual.encode('utf-8'), hash_guardado):
            conn.close()
            return jsonify({"error": "La contraseña actual es incorrecta"}), 401

        nuevo_hash = bcrypt.hashpw(password_nueva.encode('utf-8'), bcrypt.gensalt())

        cursor.execute("UPDATE usuarios SET password = ? WHERE email = ?", (nuevo_hash, email))
        conn.commit()
        conn.close()

        return jsonify({"mensaje": "Contraseña actualizada con éxito"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/validar', methods=['POST'])
def validar_usuario():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Faltan datos"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT password, rol FROM usuarios WHERE email = ?", (email,))
        usuario = cursor.fetchone()

        if not usuario:
            conn.close()
            return jsonify({"error": "Usuario no encontrado"}), 404

        hash_guardado = usuario['password']
        rol = usuario['rol']

        if bcrypt.checkpw(password.encode('utf-8'), hash_guardado):
            conn.close()

            # Usamos SECRET_KEY de config.py
            payload = {
                "email": email,
                "rol": rol,
                "exp": datetime.utcnow() + timedelta(hours=24)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)

            return jsonify({"mensaje": "Credenciales válidas", "token": token}), 200
        else:
            conn.close()
            return jsonify({"error": "Credenciales inválidas"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# FUNCION PARA PROTEGER RUTAS (Debe ir antes de los endpoints protegidos)
def requiere_token(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Falta el token. Envía: Authorization: Bearer <token>"}), 401

        token = auth_header.split(' ')[1]

        try:
            # Usamos SECRET_KEY de config.py
            payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
            request.usuario_actual = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido o firma incorrecta"}), 401

    return decorador

# ENDPOINTS CENTRALES DEL PROYECTO (Compras, Publicar Artículo, Crear Reserva)
@app.route('/comprar', methods=['POST'])
@requiere_token
def comprar():
    data = request.get_json()
    articulo = data.get('articulo')
    cantidad = data.get('cantidad')
    precio_unitario = 150.0

    if not articulo or cantidad is None:
        return jsonify({"error": "Faltan datos (articulo, cantidad)"}), 400

    if not isinstance(cantidad, int) or cantidad <= 0:
        return jsonify({"error": "La cantidad debe ser un número entero mayor a cero"}), 400

    if '<' in str(articulo) or '>' in str(articulo):
        return jsonify({"error": "Caracteres no permitidos. Peligro de inyección HTML."}), 400

    usuario = request.usuario_actual
    email = usuario.get("email")
    costo_total = cantidad * precio_unitario

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT saldo FROM usuarios WHERE email = ?", (email,))
    row = cursor.fetchone()

    if not row or row['saldo'] < costo_total:
        conn.close()
        return jsonify({"error": "Saldo insuficiente para esta compra o usuario no encontrado"}), 400

    nuevo_saldo = row['saldo'] - costo_total
    
    cursor.execute("UPDATE usuarios SET saldo = ? WHERE email = ?", (nuevo_saldo, email))
    conn.commit()
    conn.close()

    return jsonify({"mensaje": f"Compra exitosa de {cantidad} {articulo}(s).", "saldo_restante": nuevo_saldo}), 200

@app.route('/publicar_articulo', methods=['POST'])
@requiere_token
def publicar_articulo():
    data = request.get_json()
    titulo = data.get('titulo')
    contenido = data.get('contenido')

    if not titulo or not contenido:
        return jsonify({"error": "Faltan datos (titulo, contenido)"}), 400

    patron_html = re.compile(r'<[^>]+>')
    if patron_html.search(titulo) or patron_html.search(contenido):
        return jsonify({"error": "No se permiten etiquetas HTML por seguridad."}), 400

    usuario = request.usuario_actual
    email = usuario.get("email")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO articulos (usuario_email, titulo, contenido) VALUES (?, ?, ?)", 
                (email, titulo, contenido))
    conn.commit()
    conn.close()

    return jsonify({"mensaje": "Artículo publicado con éxito"}), 201

@app.route('/crear_reserva', methods=['POST'])
@requiere_token
def crear_reserva():
    data = request.get_json()
    fecha = data.get('fecha')
    personas = data.get('personas')

    if not fecha or personas is None:
        return jsonify({"error": "Faltan datos (fecha, personas)"}), 400

    if not isinstance(personas, int) or personas <= 0:
        return jsonify({"error": "El número de personas debe ser mayor a cero"}), 400

    if len(str(fecha)) > 20 or '<' in str(fecha):
        return jsonify({"error": "Formato de fecha inválido o peligroso"}), 400

    usuario = request.usuario_actual
    email = usuario.get("email")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO reservas (usuario_email, fecha, personas) VALUES (?, ?, ?)", 
                (email, fecha, personas))
    conn.commit()
    conn.close()

    return jsonify({"mensaje": f"Reserva creada para {personas} personas el {fecha}"}), 201

if __name__ == '__main__':
    app.run(debug=True, port=5000)