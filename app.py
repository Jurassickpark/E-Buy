import os
from flask import Flask, render_template, flash, request, redirect, url_for, jsonify, session, g, send_file, make_response, abort
from werkzeug.datastructures import Authorization
from werkzeug.security import generate_password_hash, check_password_hash
from os import getenv

import utils
from db import get_db
from formulario import Contactenos
import pathlib
from werkzeug.exceptions import abort


import requests
# from flask import Flask, session, abort, redirect
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests


# # from authlib.flask.client import OAuth
# from dotenv import load_dotenv
# from os import getenv

# -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


app = Flask( __name__ )
app.secret_key = os.urandom( 24 )


# ------------------------------------------------------------------------------------------Index---------------------------------------------------------------------------------------------------------------



# @app.route( '/' )
# def index():
#     if g.user:
#         return redirect( url_for( 'producto' ) )
#     return render_template( 'Login.html' )


@app.route( '/' )
def index():
    return redirect('/Administrador')
    
# -----------------------------------------------------------------------------------------Registro------------------------------------------------------------------------------------------------------------



@app.route( '/Registro', methods=('GET', 'POST') )
def registro():
    try:
        if request.method == 'POST':
      
            name= request.form['nombre']
            apellido = request.form['apellido']
            password = request.form['password']
            email = request.form['correo']
            error = None
            db = get_db()  
            
            if not utils.isUsernameValid( apellido ):
                error = "El apellido es necesario"
                flash( error )
                return render_template( 'Registro.html' )


            if not utils.isPasswordValid( password ):
                error = 'La contraseña debe contenir al menos una minúscula, una mayúscula, un número y 8 caracteres'
                flash( error )
                return render_template( 'Registro.html' )

            if not utils.isEmailValid( email ):
                error = 'El correo debe contener @'
                flash( error )
                return render_template( 'Registro.html' )


            cur = db.execute('SELECT * FROM usuario WHERE correo = ?', (email,)).fetchone()
          
            
            
            if cur is None:
                error = "El correo no existe"
                password = generate_password_hash(password) 
                db = get_db()       
                cur = db.cursor()   
                cur.executescript("INSERT INTO usuario (nombre, apellido, correo, contraseña, Rol) VALUES ('%s', '%s', '%s', '%s', '%s')" % (name, apellido, email, password, 'User',)) 
                db.commit()
                flash('Registrado exitosamente')

                return render_template('Login.html')
            else:
                
                error ="El correo ya existe"
        
            flash(error)
        

        return render_template( 'Registro.html' )
        
    except:
        flash('aqui estamos')
        return render_template( 'Registro.html' )


# -------------------------------------------------------------------------------------Login----------------------------------------------------------------------------------------------------------------


@app.route('/Login', methods=('GET', 'POST'))
def login():
   
    try:
        if request.method == 'POST':
            db = get_db()       
            error = None
            username = request.form['correoEmail']
            password = request.form['password']

            
            if not username:
                error = 'El correo electronico es requerido'
                flash(error)
                return render_template('Login.html')

            if not password:
                error = 'La contraseña es requerida'
                flash(error)
                return render_template('Login.html')


            cur = db.execute('SELECT * FROM usuario WHERE correo = ?', (username,)).fetchone()
          
            
            """ print(cur[0])
            print(cur[1])
            print(cur[2])
            print(cur[3])
            print(cur[4]) """
            
            if cur is None:
                error = "El correo no existe"
            else:
                
                if check_password_hash(cur['contraseña'], password): 
                    session.clear()
                    session['user_id'] = cur[0] 
                    
                    resp = make_response( redirect( url_for('producto')))
                    resp.set_cookie('correoEmail', username ) #Se guarda
                    return resp
                    
                else:
                    error ="La contraseña no es valida"
                    

            flash(error)
           
        return render_template('Login.html')
    except:
        return render_template('Login.html')


# ------------------------------------------------------------------------------SesionA-----------------------------------------------------------------------------------------------------------------------


@app.before_request
def logged():
    user_id = session.get( 'user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM usuario WHERE id=?', (user_id,)).fetchone()
        
    # print(g.user)

# -------------------------------------------------------------------------------Google----------------------------------------------------------------------------------------------------------------------


@app.route('/Google')
def goo():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    print(authorization_url)
    return redirect(authorization_url)




GOOGLE_CLIENT_ID = "494550765014-uj9nn1n20g87p59ov6e59tkfong98sit.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")


flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)
    

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"




@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)
    
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    # return id_info
    # return id_info["name"]
    #return id_info.get("email")

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    g.goo = None
    flash(id_info.get("name"))
    flash(id_info.get("email"))
    return redirect("/Product")





def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()
    
    return wrapper


# --------------------------------------------------------------------------------------------PaginaPrincipal----------------------------------------------------------------------------------------------------


@app.route('/Producto', methods=['GET', 'POST'])
def producto(): 
    if g.user:
        db = get_db()       
        # error = None
        cookie = request.cookies.get('correoEmail')  # Obtener, leer cookie
        print(cookie)
        cur = db.execute('SELECT * FROM usuario WHERE correo = ?', (cookie,)).fetchone()
        #consulta
        flash(cur[1] + " " + cur[2])
        flash(cookie)
    else:
        return render_template('Producto.html')
    return render_template('Producto.html')





@app.route('/Product', methods=['GET', 'POST'])
@login_is_required
def product():
    return render_template('Producto.html')

# ----------------------------------------------------------------------------------------CerrarSesion--------------------------------------------------------------------------------------------------------


@app.route( '/logout')
def logout():
    session.clear()
    return redirect(url_for('login')) # o return redirect("/")



# ---------------------------------------------------------------------------------------------db-----------------------------------------------------------------------------------------------------------


@app.route('/db', methods=('GET', 'POST'))
def base():
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT * FROM  Producto')
    data = cur.fetchall()
    print(data)
    return render_template( 'db.html', datoss = data) #Se pasa un parametro para ver los datos

# -----------------------------------------------------------------------------------------Search-----------------------------------------------------------------------------------------------------------

@app.route('/buscar', methods=['GET', 'POST'])
def buscar():

    if request.method == 'POST':
      
            name= request.form['producto']
            db = get_db()
            consulta = db.execute('SELECT * FROM Producto WHERE name = ?', (name,)).fetchone()

            if consulta is None:
                flash('no existe ese nombre en el inventario')
                return redirect('/buscar')
            else:              
                return render_template('buscar.html', datos = consulta)      
    
    return render_template('buscar.html')


# ----------------------------------------------------------------------------------Añadir-------------------------------------------------------------------------------------------------------------------

@app.route('/Anadir', methods=('GET', 'POST'))
def anadir():
    try:
        if request.method == 'POST':
      
            name= request.form['producto']
            precio = request.form['precio']
            comentario = request.form['comment']
            stock = request.form['stock']
            error = None
            print(name)
            print(precio)
            print(comentario)
            db = get_db()  
            
            
    
            cur = None
            cur = db.execute('SELECT * FROM Producto WHERE name = ?', (name,)).fetchone()
            
            if cur is None:
                error = "El producto no existe"
                db = get_db()       
                cur = db.cursor()   
                cur.executescript("INSERT INTO Producto (name, Descripcion, Price, Stock) VALUES ('%s', '%s', '%s', '%s')" % (name, comentario, precio, stock)) 
                db.commit()
                flash('Registrado exitosamente')

                return render_template('Anadir.html')
            else:
                
                error ="El Producto ya existe"
        
            flash(error)
        
        return render_template( 'Anadir.html')
        
    except:
        flash('aqui esta')
        return render_template( 'Anadir.html' )


# -----------------------------------------------------------------------------------Eliminar-----------------------------------------------------------------------------------------------------------------


@app.route('/Delete/<int:id>', methods=['GET', 'POST'])
def delete(id):

    db = get_db()
    cur = db.cursor()  #Apuntamos a la base de datos
    cur.execute('DELETE FROM Producto WHERE Id = {}'.format(id))
    db.commit()
    return redirect('/Administrador')




# -------------------------------------------------------------------------------------Editar----------------------------------------------------------------------------------------------------------------

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    db = get_db() 
    cur = db.cursor()  #Apuntamos a la base de datos
    cur.execute('SELECT * FROM Producto WHERE Id = {}'.format(id))
    data = cur.fetchone()
    cur.close()
    print(data)
    return render_template('edit.html', datos = data)

# ---------------------------------------------------------------------------------------Administrador-----------------------------------------------------------------------------------------------------

@app.route('/Administrador')
def admin():
    return render_template('principal.html')

# --------------------------------------------------------------------------------------Editar---------------------------------------------------------------------------------------------------------------



@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    if request.method == 'POST':
            db = get_db()
            name= request.form['producto']
            precio = request.form['precio']
            comentario = request.form['comment']
            stock = request.form['stock']
            cur = db.cursor()
            consulta = "UPDATE Producto SET name = ?, Descripcion = ?, Price = ?, Stock = ? WHERE Id = ?"
            cur.execute(consulta, [name, comentario, precio, stock, id])
            print(consulta)
            db.commit()
            db.close()
            flash('ha sido actualizado exitosamente')
            # return redirect('/Administrador')
            return redirect('/buscar')
    
        


# -----------------------------------------------------------------------------------------Mapa--------------------------------------------------------------------------------------------------------------

@app.route('/Mapa')
def mapa():
    return render_template("Mapa.html")

# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


if __name__ == "__main__":
    app.run(debug=True)

# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


