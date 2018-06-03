from functools import wraps
from flask import *
from flask_cors import CORS, cross_origin
from flask_marshmallow import Marshmallow
from models import user_schema, users_schema
import jwt
import httplib2
from models import User
from pymongo import MongoClient
import gridfs
import json, pickle
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_bcrypt import Bcrypt
import os
from bson import ObjectId
from werkzeug.wrappers import Response
from app_core import app, db, ma

def validate(self, form, extra_validators=tuple()):
    self.errors = list(self.process_errors)

client = MongoClient('10.34.216.102')

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

    except jwt.ExpiredSignatureError:
        return {'message' :'Signature expired. Please log in again.'}
    except jwt.InvalidTokenError:
        return {'message': 'Invalid token. Please log in again.'}

def token_required(is_admin=False):
    def token_required_inner(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            print('decorator call')
            if request.method != 'OPTIONS':
                res = validate_token(request, is_admin)
                if not res.get('user'):
                    return jsonify(res.get('message')), 401
                return f(*args, **kwargs)
        return decorated
    return token_required_inner


@app.route("/")
def index():
    print(session)
    if 'admin' in session:
        if session['admin'] == True:
            return redirect('/admin')
        else:
            return redirect('/home')
    else:
        return render_template('Login.html')


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
@app.route("/api/login", methods=["POST", "GET"])
def api_login():
    if request.method == "POST":
        
        try:
            #req = request.get_json(silent=True)
            if  not request.form['username'] or not request.form['password']:
                return jsonify({
                    'message': 'No login data found'
                })
            user = User.query.filter_by(username=request.form['username']).first()
            
            if user and user.check_password(request.form['password']):
                if user.is_admin:
                    token_data = {
                        'user_id': user.mac_address,
                        'username': user.username,
                        'role': 'admin'
                    }
                else:
                    token_data = {
                        'user_id': user.mac_address,
                        'username': user.username,
                        'role': 'user'
                    }

                token = jwt.encode(token_data, app.config['SECRET_KEY'])
                session['token'] = token.decode('UTF-8')
                session['username'] = user.username
                session['admin'] = user.is_admin
                print(session)
                #return redirect('/home')
                return jsonify({'token': token.decode('UTF-8'), 'username': user.username, 'admin': user.is_admin}), 200

            return jsonify({'message': 'invalid login'}), 401

        except Exception as error:
            print(error)
            return jsonify({'message': 'something went wrong'}), 400
    #return render_template('Login.html')

# Route for getting js file
@app.route('/js/<path:path>')
def send_js(path):
    return send_from_directory('templates/js', path)
@app.route("/register")
def view_register():
    return render_template('Register.html')

@app.route("/logout")
def logout():
    session.clear()
    print(session)
    return redirect('/')

@app.route("/admin", methods=["POST", "GET"])
def view_admin():
    if request.method == "GET":
        return render_template('Admin.html')
    else:
        data = User.query.all()
        users = [user.as_dict() for user in data]
        print (users)
        return render_template('Admin.html', User=users)


@app.route("/api/users", methods=["GET"])
@token_required(is_admin=True)
def api_get_users():
    data = User.query.all()
    result = users_schema.dump(data)
    print(result)
    return jsonify(result.data)

# endpoit to update user
@app.route("/api/user/<int:id>", methods=["PUT"])
@token_required(is_admin=True)
def user_update(id):
    try:
        user = User.query.get(id)

        if user:
            username = request.form['username']
            mac_address = request.form['mac_address']
            is_admin = True if request.form['is_admin'] == 'true' else False

            user.username = username
            user.mac_address = mac_address
            user.is_admin = is_admin

            db.session.commit()
            return jsonify({'message': 'success'}), 200
        else:
            return jsonify({'message': 'user not exists'}), 400
    except Exception as error:
        print(error)
        return jsonify({'message': 'something went wrong'}), 400


# endpoint to delete user
@app.route("/api/user/<int:id>", methods=["DELETE"])
@token_required(is_admin=True)
def user_delete(id):
    try:
        user = User.query.get(id)
        if user:
            db.session.delete(user)
            db.session.commit()

            return jsonify({'message': 'success'}), 200
        else:
            return jsonify({'message': 'user not exists'}), 400

    except Exception as error:
        print(error)
        return jsonify({'message': 'something went wrong'}), 400


@app.route("/api/datatables/users")
def api_datatables_get_users():
    # Store request query string
    requestData = request.args

    #datatables column index => database column name
    columns = {
        0: 'username',
        1: 'mac_address',
        2: 'is_admin'
    }
    
    #getting total number records without any search
    totalData = User.query.count()
    #when there is no search parameter then total number rows = total number filtered rows.
    totalFiltered = totalData;   

    
    if requestData['search[value]']:
        sql = "SELECT * FROM user  "
        sql += "WHERE username LIKE '" + requestData['search[value]'] + "%' "
        sql += "OR mac_address LIKE '" + requestData['search[value]'] + "%' "
        sql += "OR is_admin LIKE '" + requestData['search[value]'] + "%' "

        query = text(sql)
        result = db.engine.execute(sql).fetchall()
        #result = users_schema.dump(result)
        totalFiltered = len(result)

        sql += " ORDER BY " + columns[int(requestData['order[0][column]'])] + " " + requestData['order[0][dir]'] + " " + " LIMIT " + requestData['start'] + " ," + requestData['length'] + " "
        query = text(sql)
    else:
        sql = "SELECT * FROM user "
        sql += " ORDER BY " + columns[int(requestData['order[0][column]'])] + " " + requestData['order[0][dir]'] + " " + " LIMIT " + requestData['start'] + " ," + requestData['length'] + " "
        query = text(sql)
    
    result = db.engine.execute(query)
    data = []

    while True:
        row = result.fetchone()

        if row == None:
            break

        nestedData = {}
        user = user_schema.dump(row).data
        nestedData['DT_RowId'] = user['id']
        nestedData['username'] = user['username']
        nestedData['mac_address'] = user['mac_address']
        nestedData['is_admin'] = user['is_admin']
        nestedData['action'] = '<button class="btn btn-success" data-toggle="modal" data-target="#update-user-modal" data-id="' + str(user['id']) + '"><span class="glyphicon glyphicon-pencil"></span></button><button class="btn btn-danger" data-toggle="modal" data-target="#confirm-delete" data-id="' + str(user['id']) + '"><span class="glyphicon glyphicon-trash"></span></button>'
        data.append(nestedData)

    return jsonify({
        'draw' : int(requestData['draw']),
        'recordsTotal' : int(totalData),
        'recordsFiltered': int(totalFiltered),
        'data': data
    })


#@app.route("/user/<int:user_id>")
#@token_required
'''
def api_get_users(current_user, user_id):

    data = User.query.filter_by(mac_address=user_id)
    users = [user.as_dict() for user in data]
    return jsonify(users)
'''
@app.route("/api/register", methods=["POST", "GET"])
def api_create_users():
    if request.method == "POST":
        #req = request.get_json(silent=True)
        if not request.form['username'] or not request.form['password']:
            return jsonify({
                'message': 'No json data found'
            })
        try:
            username = request.form['username']
            password = request.form['password']
            mac_address = request.form['mac_address']

            if User.query.filter_by(username=username).first():
                return jsonify({ 'message': 'Username already exsist'}), 400
            else:
                user = User(username , password, mac_address)
                db.session.add(user)
                db.session.commit()
                return jsonify({
                    "message": "success"
                }), 200

        except Exception as error:
            print(error)
            return jsonify({
                'message': 'Something went wrong'
            }),400
    return render_template('Register.html')

@app.route('/home', methods=["POST", "GET"])
def tampilan():
    if request.method == "GET":
        return render_template('Home.html')
    else:
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
def getdata():
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
def post():
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