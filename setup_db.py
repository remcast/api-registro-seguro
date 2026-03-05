import sqlite3

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # 1. Crear tabla usuarios CON SALDO Y ROL
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            saldo REAL DEFAULT 1000.0,
            rol TEXT DEFAULT 'cliente'
        )
    ''')
    
    # 2. Crear tabla reservas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reservas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_email TEXT NOT NULL,
            fecha TEXT NOT NULL,
            personas INTEGER NOT NULL
        )
    ''')

    # 3. Crear tabla articulos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS articulos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_email TEXT NOT NULL,
            titulo TEXT NOT NULL,
            contenido TEXT NOT NULL
        )
    ''')
    
    print("Base de datos y tablas creadas perfectamente con todas las columnas.")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()