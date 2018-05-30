from functools import wraps
from flask import *
import jwt
import httplib2
from models import User
from controllers.app_core import app, db
from pymongo import MongoClient
import gridfs
import json, pickle
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
from bson import ObjectId
from werkzeug.wrappers import Response

def validate(self, form, extra_validators=tuple()):
    self.errors = list(self.process_errors)

app = Flask(__name__)

bcrypt = Bcrypt(app)
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, '../database/database.db')
db_uri = 'sqlite:///{}'.format(db_path)

app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

#client = MongoClient('10.34.216.102')
client = MongoClient('159.65.1.111', 29027,
                        username='mongostorage',
                        password='iotdatastr',
                        authSource='admin',
                        authMechanism='SCRAM-SHA-1')


def validate_token(request,is_admin=False):

    auth_header = request.headers.get('Authorization')

    if not auth_header or 'Bearer' not in auth_header:
        return {'message': 'Bad authorization header!'}

    split = auth_header.split(' ')

    try:
        decode_data = jwt.decode(split[1], app.config['SECRET_KEY'])
        user = User.query.filter_by(mac_address=decode_data.get('user_id')).first()

        if not user:
            return {'message': 'User not found'}
        if is_admin and not user.is_admin:
            return {'messgage': 'Not admin token'}

        return {'user': user.as_dict()}

    except Exception as error:
        return {'message': 'Token is invalid'}

def token_required(is_admin=False):
    def token_required_inner(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            res = validate_token(request, is_admin)
            if not res.get('user'):
                return jsonify(res.get('message')), 401
            return f(res.get('user'), *args, **kwargs)
        return decorated
    return token_required_inner


@app.route("/logout")
def api_logout():

    return render_template('Login.html')

@app.route("/login", methods=["POST", "GET"])
def api_login():
    if request.method == "POST":
        try:
            if  not request.form['username'] or not request.form['password']:
                return jsonify({
                    'message': 'No login data found'
                })
            user = User.query.filter_by(username=request.form['username']).first()

            if user and user.check_password(request.form['password']):
                token_data = {
                    'user_id': user.mac_address
                }

                token = jwt.encode(token_data, app.config['SECRET_KEY'])
                session['token'] = token.decode('UTF-8')
                session['username'] = user.username
                return redirect('/home')

            return jsonify({'message': 'invalid login'}), 401

        except Exception as error:
            print(error)
            return jsonify({'message': 'something went wrong'}), 400
    return render_template('Login.html')

@app.route("/users")
@token_required(is_admin=True)
def api_get_users(current_user):

    data = User.query.all()
    users = [user.as_dict() for user in data]
    return jsonify(users)

@app.route("/register", methods=["POST", "GET"])
def api_create_users():
    if request.method == "POST":
        #req = request.get_json(silent=True)
        if not request.form['username'] or not request.form['password']:
            return jsonify({
                'message': 'No json data found'
            })
        try:
            user = User(request.form['username'] , request.form['password'], request.form['mac_address'])
            db.session.add(user)
            db.session.commit()

            return redirect('/login')

        except Exception as error:
            print(error)
            return jsonify({
                'message': 'Something went wrong'
            }),400
    return render_template('Register.html')

@app.route('/home', methods=["POST", "GET"])
def tampilan():
    if request.method == "GET":
        if session['username'] == "admin":
            data = User.query.all()
            users = [user.as_dict() for user in data]
            print(users)
        return render_template('Home.html', User=users)
    else:
        if request.form["action"]=="delete" and session['username'] == "admin":
            db.session.query(User).filter(User.id==request.form["id"]).delete()
            db.session.commit()
            print(session['username'])
            return redirect("/home")
        token = "Bearer " + request.form['Token']
        tipedata = request.form['Tipedata']
        conn = httplib2.HTTPConnectionWithTimeout("localhost:5001")
        headers = {
            "Authorization": token
        }
        conn.putrequest("GET", "/api/getdata" + tipedata)
        conn.putheader("Authorization", token)
        conn.endheaders()
        response = conn.getresponse()
        Data = response.read()
        print (Data)
        return render_template('Home.html', Data=Data)


@app.route('/api/getdata',methods=['GET'])
@token_required()
def getdata(self):
    db_ = client.test
    data = []
    if request.args.get('topic') :
        if request.args.get('topic')=="gambar":
            fs = gridfs.GridFS(db_)
            for data_ in fs.find():
                data.append("https://iot.belajardisini.com:5001/api/getgambar/"+str(data_._id))
        else:
            for data_ in db_.testH__130.find({"topic": request.args.get('topic')},{"_id":0}):
                data.append(data_)
    else:
        for data_ in db_.testH__130.find({}, {"_id": 0}):
            data.append(data_)
    return json.dumps(data, sort_keys=True)

@app.route('/api/post', methods=['POST'])
@token_required()
def post(self):
    db = client.test
    fs = gridfs.GridFS(db)
    for data in request.get_json():
        if "Data" in data or request.content_length >= (800*1024):
            print(gridfs, data["Name"])
            gambar = pickle.loads(data["Data"].encode('utf-8'),encoding='latin1')
            fs.put(gambar,filename=data["Name"], encoding='latin1')
        else :
            db['testH__130'].insert_one(data)
    return "DATA TEST TERKIRIM"

@app.route('/api/getgambar/<string:oid>/')
def getGambar(oid):
    db = client.test
    fs = gridfs.GridFS(db)
    file = fs.get(ObjectId(oid))
    print(file.upload_date)
    res = make_response(file.read())
    res.mimetype = "image/jpg"
    return res
    #return Response(file, mimetype=file.content_type, direct_passthrough=True)

#if __name__ == '__main__':
 #       app.run(debug=True, threaded=True, port=5001,host='127.0.0.1')