from pymongo import MongoClient
import gridfs
from controllers.app_core import app
from functools import wraps
from flask import jsonify, request, Flask
import jwt
from models import User
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os

#from bson import ObjectId
#from werkzeug import Response
import json, pickle
from flask import request,jsonify

client = MongoClient('10.34.216.102')
bcrypt = Bcrypt(app)
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, '../database/database.db')
db_uri = 'sqlite:///{}'.format(db_path)

app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
db.create_all()

def validate_token(request):
    try:
        auth_header = request.headers.get('Authorization')

        if not auth_header or 'Bearer' not in auth_header:
            return {'message': 'Bad authorization header!'}

        split = auth_header.split(' ')

        if not len(split) == 2:
           return {'message': 'Bad authorization header!'}

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

@app.route("/login", methods=["POST"])
def api_login():
    try:
        req = request.get_json(silent=True)
        if not req or not req.get('username') or not req.get('password'):
            return jsonify({
                'message': 'No login data found'
            })
        user = User.query.filter_by(email=req.get('username')).first()

        if user and user.check_password(req.get('password')):
            token_data = {
                'user_id': user.mac_address
            }

            token = jwt.encode(token_data, app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')})

        return jsonify({'message': 'invalid login'}), 401

    except Exception as error:
        return jsonify({'message': 'something went wrong'}), 400

@app.route("/users")
@token_required
def api_get_users(current_user):

    data = User.query.all()
    users = [user.as_dict() for user in data]
    return jsonify(users)

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

#POST DATA CO
@app.route('/api/postdata', methods=['POST'])
def postdataco():
    db = client.test
    fs = gridfs.GridFS(db)
    string = ""
    for data in request.get_json():
        if "Data" in data :
            fs.put(pickle.loads(data["Data"]), filename=data["Name"])
            string += data["Name"] + " berhasil masuk gridfs\n"
        else:
            db.data__355.insert_one(data)
            string += "data json berhasil masuk mongodb\n"
        return string
        # data = request.get_json()
        # db = client.dataCO
        # db.dataCO.insert_many(data)
        # return "DATA CO TERKIRIM"
#POST DATA COBA
@app.route('/api/post/<string:num>', methods=['POST'])
def post(num):
    db = client.test
    fs = gridfs.GridFS(db)
    for data in request.get_json():
        if "Data" in data :
            fs.put(pickle.loads(data["Data"]),filename=data["Name"])
        else :
            db[num].insert_one(data)
    return "DATA TEST TERKIRIM"

#GET DATA
@app.route('/api/getdata',methods=['GET'])
def get():
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

@app.route('/api/getdata/<string:topic>',methods=['GET'])
def getByTopic(topic):
    db_ = client.test
    data = []
    if topic == "gambar" :
        string = "<ul style='list-style:none'>"
        fs = gridfs.GridFS(db_)
        for data_ in fs.find():
            string+="<h1><li>_id : <a href='../getgambar/"+str(data_._id)+"'>"+str(data_._id)+"</a></li></h1><li>filename : "+data_.filename+"</li><li>md5 : "+data_.md5+"</li><li>"+data_.size()+"</li>"
        string+="</ul>"
    else :
        for data_ in db_.testH__130.find({"topic":"office/"+topic},{"_id":0}):
            data.append(data_)
        string = jsonify(data)
    return string

@app.route('/api/stat',methods=['GET'])
def getStat():
    db_ = client.test
    data = []
    data = db_.command('collstats','testH__130')
    return "<pre>"+json.dumps(data, indent=4, sort_keys=True)+"</pre>"

"""@app2.route('/api/getgambar/<string:oid>/')
def getGambar(oid):
    db = client.test
    fs = gridfs.GridFS(db)
    file = fs.get(ObjectId(oid))
    return Response(file, mimetype=file.content_type, direct_passthrough=True)
"""
if __name__ ==  '__main__':
    app.run(debug=True,port=5001,host='127.0.0.1')

