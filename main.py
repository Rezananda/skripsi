from routes import *
from models import *
#from controllers.app_core import app, db

db.create_all()

app.run(debug=True, threaded=True, port=5001,host='127.0.0.1')