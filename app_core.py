from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_marshmallow import Marshmallow
import os

app = Flask(__name__)
CORS(app)

bcrypt = Bcrypt(app)
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'database/database.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SECRET_KEY'] = 'awefawefawefawef'
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
ma = Marshmallow(app)
