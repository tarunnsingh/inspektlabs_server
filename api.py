from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import datetime
from functools import wraps
import os
import glob
from os import listdir
from os.path import isfile, join

UPLOAD_FOLDER = './image_uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})


@app.route('/api/user/register', methods=['GET', 'POST'])
def register():
    auth = request.authorization
    print(auth.username, auth.password)
    if not auth or not auth.username or not auth.password:
        return make_response('Username and/or Password missing', 401, {'WWW-Authenticate' : 'Basic realm="Missing Credentials"'})
    
    user = User.query.filter_by(name=auth.username).first()
      
    if user:
        return make_response('Username Taken!', 401, {'WWW-Authenticate' : 'Basic realm="Username Taken Already"'})

    hashed_password = generate_password_hash(auth.password, 'sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=auth.username, password=hashed_password, admin=False)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'Regestered Successfully, Login to Continue!'})


@app.route('/api/user/login', methods=['GET', 'POST'])
def login():
    auth = request.authorization
    print(auth)
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        resp = make_response('Login Success', {'login': 'SuccessFul', 'user' : user.name})
        resp.set_cookie('x-access-token', token)
        return resp
        
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/api/user/logout', methods=['GET', 'POST'])
def logout():
    resp = make_response('Logged Out')
    resp.set_cookie('x-access-token', '', expires=0)
    return resp


@app.route('/api/user/authenticated', methods=['GET', 'POST'])
def isauthenticated():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    if not token:
        print("NO token")
        return jsonify({'message' : 'Token is missing!'}), 401
    # print ("TOKEN FOUND", token)

    try: 
        data = jwt.decode(token, app.config['SECRET_KEY'])
        current_user = User.query.filter_by(public_id=data['public_id']).first()
    except:
        return jsonify({'message' : 'Token is invalid!'}), 401

    return jsonify({"user" : current_user.name, "isAuthenticated" : True})

@app.route('/api/image/upload', methods=['GET', 'POST'])
# @token_required
def upload_image():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return jsonify({"message" : "Image Uploaded Successfully!"})

@app.route('/api/image/name_list', methods=['GET', 'POST'])
def list_image():
    name_list = [f for f in listdir(UPLOAD_FOLDER) if isfile(join(UPLOAD_FOLDER, f))]
    print(name_list)
    return jsonify({
        "name_list": name_list
    })


if __name__ == '__main__':
    app.run(debug=True)