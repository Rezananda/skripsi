from functools import wraps
from flask import jsonify, request, Flask, make_response
import jwt
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

client = MongoClient('10.34.216.102')


def validate_token(request):

    auth_header = request.headers.get('Authorization')

    if not auth_header or 'Bearer' not in auth_header:
        return {'message': 'Bad authorization header!'}

    split = auth_header.split(' ')

    try:
        decode_data = jwt.decode(split[1], app.config['SECRET_KEY'])
        user = User.query.filter_by(mac_address=decode_data.get('user_id')).first()

        if not user:
            return {'message': 'User not found'}

        return {'user': user.as_dict()}

    except Exception as error:
        return {'message': 'Token is invalid'}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        res = validate_token(request)
        if not res.get('user'):
            return jsonify(res.get('message')), 401
        return f(res.get('user'), *args, **kwargs)
    return decorated


"""@app.route("/")
def root():
    return jsonify({'message': 'API Root'})
"""
"""@app.route("/current-user")
def api_get_current_user():
    auth_header = request.headers.get('Authorization')

    if not auth_header or 'Bearer' not in auth_header:
        return jsonify({'message': 'Bad authorization header!'}), 400

    split = auth_header.split(' ')
    
    try:
        decode_data = jwt.decode(split[1], app.config['SECRET_KEY'])
        user = User.query.filter_by(public_id=decode_data.get('user_id')).first()
        print(user)

        if not user:
            return jsonify({'message': 'Token is invalid'}), 401
        return jsonify({
            'message': 'User is authenticated',
            'user': user.as_dict()
        })
    except Exception as error:
        return jsonify({'message': 'Token is invalid'}), 401
"""
@app.route("/login", methods=["POST"])
def api_login():
    try:
        req = request.get_json(silent=True)
        if not req or not req.get('username') or not req.get('password'):
            return jsonify({
                'message': 'No login data found'
            })
        user = User.query.filter_by(username=req.get('username')).first()

        if user and user.check_password(req.get('password')):
            token_data = {
                'user_id': user.mac_address
            }

            token = jwt.encode(token_data, app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')})

        return jsonify({'message': 'invalid login'}), 401

    except Exception as error:
        print(error)
        return jsonify({'message': 'something went wrong'}), 400


@app.route("/users")
@token_required
def api_get_users(current_user):

    data = User.query.all()
    users = [user.as_dict() for user in data]
    return jsonify(users)

#@app.route("/user/<int:user_id>")
#@token_required
'''
def api_get_users(current_user, user_id):

    data = User.query.filter_by(mac_address=user_id)
    users = [user.as_dict() for user in data]
    return jsonify(users)
'''
@app.route("/users", methods=['POST'])
def api_create_users():
    req = request.get_json(silent=True)
    if not req:
        return jsonify({
            'message': 'No json data found'
        })
    try:
        user = User(**req)
        db.session.add(user)
        db.session.commit()

        return jsonify({
            'message':'User with id {user.mac_address} created successfully',
            'user': user.as_dict()
        })
    except Exception as error:
        print(error)
        return jsonify({
            'message': 'Something went wrong'
        }),400

@app.route('/api/getdata',methods=['GET'])
@token_required
def getdata(self):
    db_ = client.test
    data = []
    if request.args.get('topic') :
        if request.args.get('topic')=="gambar":
            fs = gridfs.GridFS(db_)
            for data_ in fs.find():
                data.append({"_id": str(data_._id), "filename": data_.filename, "md5":data_.md5})
        else:
            for data_ in db_.testH__130.find({"topic": request.args.get('topic')},{"_id":0}):
                data.append(data_)
    else:
        for data_ in db_.testH__130.find({}, {"_id": 0}):
            data.append(data_)
    return json.dumps(data, indent=4, sort_keys=True)

@app.route('/api/post', methods=['POST'])
@token_required
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