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
    
    # ---------------------------------------------------
    # Aqui te toca a ti victor :p
    # Aquí debes implementar:
    # 1. Validaciones (Pass > 8 y < 10) -> Error 400
    # 2. Verificar duplicados (Email) -> Error 409
    # 3. Hash de contraseña con Bcrypt
    # 4. Insertar en BD -> Success 201
    # ---------------------------------------------------

    return jsonify({"mensaje": "Endpoint creado. Falta implementar lógica."}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)