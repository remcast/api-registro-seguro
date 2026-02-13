import sqlite3

# Conexión y creación de tabla
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Crear tabla usuarios con los requisitos específicos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'cliente'
        )
    ''')
    
    print("Base de datos creada exitosamente.")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()