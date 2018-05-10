from pymongo import MongoClient
import gridfs
from app_core import app

#from bson import ObjectId
#from werkzeug import Response
import json,datetime,pickle
from flask import Flask,request,jsonify

client = MongoClient('10.34.216.102')

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

