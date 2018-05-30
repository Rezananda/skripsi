#from uuid import uuid4
from app_core import db, ma, bcrypt

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(500), unique=True, nullable=True)
    username = db.Column(db.String(500), unique=True, nullable=True)
    password = db.Column(db.String(1000), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, username, password, mac_address, is_admin=False):
        #self.mac_address = str(uuid4())
        self.mac_address = mac_address
        self.username = username
        self.password = bcrypt.generate_password_hash(password)
        self.is_admin = is_admin

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def as_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'password': self.password,
            'mac_address': self.mac_address,
            'is_admin': self.is_admin
        }

class UserSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('id', 'username', 'mac_address', 'is_admin')


user_schema = UserSchema()
users_schema = UserSchema(many=True)