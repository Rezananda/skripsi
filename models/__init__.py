from uuid import uuid4
from controllers.app_core import db, bcrypt

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(500), unique=True, nullable=True)
    username = db.Column(db.String(500), unique=True, nullable=True)
    password = db.Column(db.String(1000), nullable=True)

    def __init__(self, username, password, is_admin=False):
        self.mac_address = str(uuid4())
        self.username = username
        self.password = bcrypt.generate_password_hash(password)


    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def as_dict(self):
        return {
            'id': self.mac_address,
            'username': self.username,
            'password': self.password
        }