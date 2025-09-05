from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255))
    role = db.Column(db.String(32), default="prover")  # 'prover', 'verifier', 'admin'
    eth_address = db.Column(db.String(255), nullable=True)  # optional
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Document(db.Model):
    __tablename__ = "documents"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(512))
    stored_filename = db.Column(db.String(512))  # encrypted file name on server
    filesize = db.Column(db.Integer)
    # We store only the commitment/public fields. Do NOT store plaintext SHA if privacy required.
    commitment = db.Column(db.String(128))  # e.g., keccak256(owner || fileHash || salt)
    salt = db.Column(db.String(128), nullable=True)   # optional — be careful with privacy
    cid = db.Column(db.String(512), nullable=True)    # optional IPFS CID if used
    status = db.Column(db.String(32), default="uploaded")  # uploaded|proof_in_progress|proven
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship('User', backref='documents')
