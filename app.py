from flask import Flask, request, jsonify
import sqlite3
import bcrypt

app = Flask(__name__)

# Función auxiliar para conectar a la BD (para que tu compañero la use)
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

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

        # INSERTAR: Guardar en BD
        cursor.execute("INSERT INTO usuarios (email, password) VALUES (?, ?)", (email, hashed_password))
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


if __name__ == '__main__':
    app.run(debug=True, port=5000)

