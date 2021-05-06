from cryptography.fernet import Fernet
from flask import Flask, render_template, url_for, request, session, redirect
from flask_pymongo import PyMongo
from pymongo import MongoClient
import json

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'Login'
app.config['MONGO_URI'] = 'mongodb+srv://dbadmin:adminuser@logindetails.qx1k3.mongodb.net/Login?retryWrites=true&w=majority'

mongo = PyMongo(app)

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key","wb") as key_file:
        key_file.write(key)
        print("Key is generated")

def load_key():
    return open("secret.key","rb").read()

def encrypt_message(message):
    key = load_key()
    encoded_msg = message.encode()
    f = Fernet(key)
    encrypted_msg = f.encrypt(encoded_msg)
    return encrypted_msg

# print(encrypt_message("Hello world"))

def decrypt_message(enc_msg):
    key = load_key()
    f = Fernet(key)
    dec_msg = f.decrypt(enc_msg)
    return dec_msg.decode()

# enc = encrypt_message('hello')
# print(enc)
# dec = decrypt_message(enc)
# print(dec)

@app.route('/')
def index():
    if 'username' in session:
        return 'Logged in as '+ session['username'] + '<br>' + "<b><a href = '/logout'>click here to log out</a></b>"

    return render_template('index.html')
 

@app.route('/login', methods=['POST'])
def login():
    users = mongo.db.users
    login_user = users.find_one({'name' : request.form['username']})
    # hashpass = encrypt_message(users.find_one({'pass' : request.form['pass']}))
    Passkey = 'passs' 
    dec_passkey = 'Example'
    if login_user['password'] is not None:
        Passkey = login_user['password'] 
        dec_passkey = decrypt_message(Passkey) 
        print(Passkey,' ',dec_passkey)

    if login_user:
        if dec_passkey == request.form['pass']:
            session['username'] = request.form['username']
            return redirect(url_for('index'))

    return 'Invalid username/password combination'

@app.route('/logout')
def logout():
   # remove the username from the session if it is there
   session.pop('username', None)
   return redirect(url_for('index'))

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        users = mongo.db.users
        existing_user = users.find_one({'name' : request.form['username']})

        if existing_user is None:
            key = load_key()
            # encoded_msg = message.encode()
            f = Fernet(key)
            # encrypted_msg = f.encrypt(encoded_msg)
            hashpass = f.encrypt(request.form['pass'].encode('utf-8'))
            users.insert({'name' : request.form['username'], 'password' : hashpass, 'key': key})
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        
        return 'That username already exists!'

    return render_template('register.html')

if __name__ == '__main__':
    app.secret_key = 'mysecret'
    app.run(debug=True)
