import os
import uuid
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_from_directory, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ----------------------------
# Flask App Config
# ----------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key"   # change in production
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'docuaudit.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ----------------------------
# Database Models
# ----------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255))
    role = db.Column(db.String(32), default="prover")  # prover, verifier, admin
    eth_address = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Document(db.Model):
    __tablename__ = "documents"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    filename = db.Column(db.String(512))
    stored_filename = db.Column(db.String(512))  # encrypted file name on server
    filesize = db.Column(db.Integer)
    commitment = db.Column(db.String(128))  # keccak256(owner || fileHash || salt)
    salt = db.Column(db.String(128), nullable=True)
    cid = db.Column(db.String(512), nullable=True)  # optional IPFS CID
    status = db.Column(db.String(32), default="uploaded")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship("User", backref="documents")

# ----------------------------
# Initialize Database
# ----------------------------
with app.app_context():
    db.create_all()

# ----------------------------
# User Loader
# ----------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------------
# Role Decorator
# ----------------------------
def require_role(role):
    def inner(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role != role and current_user.role != "admin":
                flash("Insufficient permissions", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapped
    return inner

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].lower().strip()
        name = request.form.get("name", "")
        password = request.form["password"]
        role = request.form.get("role", "prover")

        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)
        user = User(email=email, name=name, password_hash=pw_hash, role=role)
        db.session.add(user)
        db.session.commit()
        flash("Account created — please log in", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].lower().strip()
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    docs = Document.query.filter_by(owner_id=current_user.id).order_by(Document.created_at.desc()).all()
    return render_template("dashboard.html", docs=docs)

@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    doc = Document.query.filter_by(stored_filename=filename).first()
    if not doc:
        abort(404)
    if doc.owner_id != current_user.id and current_user.role != "admin":
        abort(403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if current_user.role not in ("prover", "admin"):
        flash("Your role can't upload documents", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        f = request.files.get("file")
        if not f:
            flash("No file provided", "danger")
            return redirect(url_for("upload"))

        orig_filename = request.form.get("orig_filename", secure_filename(f.filename))
        commitment = request.form.get("commitment")
        salt = request.form.get("salt") or None
        cid = request.form.get("cid") or None

        if not commitment:
            flash("Missing commitment (public metadata). Upload aborted.", "danger")
            return redirect(url_for("upload"))

        ext = os.path.splitext(orig_filename)[1]
        stored_name = f"{uuid.uuid4().hex}{ext}.enc"
        stored_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
        f.save(stored_path)
        filesize = os.path.getsize(stored_path)

        doc = Document(
            owner_id=current_user.id,
            filename=orig_filename,
            stored_filename=stored_name,
            filesize=filesize,
            commitment=commitment,
            salt=salt,
            cid=cid,
            status="uploaded"
        )
        db.session.add(doc)
        db.session.commit()
        flash("Encrypted file uploaded and metadata recorded.", "success")
        return redirect(url_for("dashboard"))

    return render_template("upload.html")

@app.route("/api/documents")
@login_required
def api_documents():
    if current_user.role not in ("verifier", "admin"):
        return jsonify({"error": "Unauthorized"}), 403
    docs = Document.query.order_by(Document.created_at.desc()).limit(100).all()
    out = []
    for d in docs:
        out.append({
            "id": d.id,
            "owner_email": d.owner.email,
            "commitment": d.commitment,
            "status": d.status,
            "created_at": d.created_at.isoformat(),
            "cid": d.cid
        })
    return jsonify(out)

# ----------------------------
# Run the App
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)
