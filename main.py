from app_core import app, db
from routes import *
from models import *

db.create_all()

if __name__ == '__main__':
    app.run(debug=True, threaded=True, port=5001,host='127.0.0.1')