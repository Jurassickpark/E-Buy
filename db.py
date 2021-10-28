
#Conexion a la base de datos
import sqlite3

from flask import current_app, g
from werkzeug.security import check_password_hash
from sqlite3 import Error

def get_db():
    try:
        if 'db' not in g:
            g.db = sqlite3.connect('data.db')          #Conexion a la base de datos
            #Trae las filas
            g.db.row_factory = sqlite3.Row  #Debuelve las filas que estan en tuplas permite acceder a las columnas llamdas por el nombre
        return g.db
    except Error:
        print(Error)
   

def close_db():
    if g.db is not None:
        g.db.close()

        