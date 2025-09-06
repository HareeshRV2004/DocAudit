import os
import uuid
import qrcode
import io
import base64
import json
from datetime import datetime
from functools import wraps
from PIL import Image
from pyzbar import pyzbar

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
# Helper Functions
# ----------------------------
def generate_qr_code(data):
    """Generate QR code and return as base64 string"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return img_base64

def create_document_qr_data(doc):
    """Create QR code data for a document"""
    return {
        "doc_id": doc.id,
        "commitment": doc.commitment,
        "filename": doc.filename,
        "owner_email": doc.owner.email,
        "created_at": doc.created_at.isoformat(),
        "status": doc.status
    }

def scan_qr_from_image(image_file):
    """Scan QR code from uploaded image file"""
    try:
        # Read the image
        image = Image.open(image_file)
        
        # Convert to RGB if necessary
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Scan for QR codes
        qr_codes = pyzbar.decode(image)
        
        if not qr_codes:
            return None, "No QR code found in the image"
        
        # Get the first QR code data
        qr_data = qr_codes[0].data.decode('utf-8')
        
        # Try to parse as JSON
        try:
            qr_info = json.loads(qr_data)
            return qr_info, None
        except json.JSONDecodeError:
            return qr_data, None
            
    except Exception as e:
        return None, f"Error scanning QR code: {str(e)}"

def log_verification(verifier_id, document_id, verification_type, verification_data, result, request):
    """Log verification attempt"""
    log = VerificationLog(
        verifier_id=verifier_id,
        document_id=document_id,
        verification_type=verification_type,
        verification_data=verification_data,
        result=result,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(log)
    db.session.commit()

def check_user_access(user):
    """Check if user has access based on status and approval"""
    if user.status == "blocked":
        return False, "Account is blocked"
    if user.status == "suspended":
        return False, "Account is suspended"
    if not user.is_approved and user.role != "admin":
        return False, "Account pending approval"
    return True, None

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
    status = db.Column(db.String(32), default="active")  # active, pending, blocked, suspended
    is_approved = db.Column(db.Boolean, default=False)  # admin approval required
    last_login = db.Column(db.DateTime, nullable=True)
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
    qr_code_data = db.Column(db.Text, nullable=True)  # base64 encoded QR code
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship("User", backref="documents")

class VerificationLog(db.Model):
    __tablename__ = "verification_logs"
    id = db.Column(db.Integer, primary_key=True)
    verifier_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    document_id = db.Column(db.Integer, db.ForeignKey("documents.id"), nullable=True)
    verification_type = db.Column(db.String(32), nullable=False)  # commitment, qr_code
    verification_data = db.Column(db.Text, nullable=True)  # commitment hash or QR data
    result = db.Column(db.String(32), nullable=False)  # verified, tampered, not_found
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    verifier = db.relationship("User", backref="verification_logs")
    document = db.relationship("Document", backref="verification_logs")

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
    if current_user.is_authenticated:
        # Redirect based on user role
        if current_user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        elif current_user.role == "verifier":
            return redirect(url_for("verifier_dashboard"))
        else:
            return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("login"))

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
        # New users need admin approval unless they're registering as admin
        is_approved = (role == "admin")
        user = User(email=email, name=name, password_hash=pw_hash, role=role, is_approved=is_approved)
        db.session.add(user)
        db.session.commit()
        
        if is_approved:
            flash("Account created — please log in", "success")
        else:
            flash("Account created — pending admin approval", "warning")
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

        # Check user access
        has_access, error_msg = check_user_access(user)
        if not has_access:
            flash(error_msg, "danger")
            return redirect(url_for("login"))

        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()

        login_user(user)
        
        # Redirect based on user role
        if user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        elif user.role == "verifier":
            return redirect(url_for("verifier_dashboard"))
        else:
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
        db.session.flush()  # Get the doc ID
        
        # Generate QR code
        qr_data = create_document_qr_data(doc)
        qr_json = jsonify(qr_data).get_data(as_text=True)
        doc.qr_code_data = generate_qr_code(qr_json)
        
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
# Verifier Routes
# ----------------------------
@app.route("/verifier")
@login_required
def verifier_dashboard():
    if current_user.role not in ("verifier", "admin"):
        flash("Access denied. Verifier role required.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("verifier.html")

@app.route("/verify/upload", methods=["GET", "POST"])
@login_required
def verify_upload():
    if current_user.role not in ("verifier", "admin"):
        flash("Access denied. Verifier role required.", "danger")
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        commitment = request.form.get("commitment", "").strip()
        if not commitment:
            flash("Please provide a commitment hash", "danger")
            return redirect(url_for("verify_upload"))
        
        # Find document with matching commitment
        doc = Document.query.filter_by(commitment=commitment).first()
        
        if doc:
            # Log successful verification
            log_verification(current_user.id, doc.id, "commitment", commitment, "verified", request)
            flash("✅ Document Verified - Commitment matches stored hash", "success")
            return render_template("verify_result.html", 
                                 verified=True, 
                                 doc=doc, 
                                 commitment=commitment)
        else:
            # Log failed verification
            log_verification(current_user.id, None, "commitment", commitment, "not_found", request)
            flash("❌ Document Tampered - No matching commitment found", "danger")
            return render_template("verify_result.html", 
                                 verified=False, 
                                 commitment=commitment)
    
    return render_template("verify_upload.html")

@app.route("/verify/qr", methods=["GET", "POST"])
@login_required
def verify_qr():
    if current_user.role not in ("verifier", "admin"):
        flash("Access denied. Verifier role required.", "danger")
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        qr_data = request.form.get("qr_data", "").strip()
        qr_file = request.files.get("qr_file")
        
        qr_info = None
        error_msg = None
        
        # Handle image upload
        if qr_file and qr_file.filename:
            qr_info, error_msg = scan_qr_from_image(qr_file)
            if error_msg:
                flash(f"❌ {error_msg}", "danger")
                return redirect(url_for("verify_qr"))
        # Handle text input
        elif qr_data:
            try:
                qr_info = json.loads(qr_data)
            except json.JSONDecodeError:
                flash("Invalid QR code data format", "danger")
                return redirect(url_for("verify_qr"))
        else:
            flash("Please provide QR code data or upload an image", "danger")
            return redirect(url_for("verify_qr"))
        
        if not qr_info:
            flash("No valid QR code data found", "danger")
            return redirect(url_for("verify_qr"))
        
        # Extract document info
        if isinstance(qr_info, dict):
            doc_id = qr_info.get("doc_id")
            commitment = qr_info.get("commitment")
        else:
            # If it's raw text, try to extract info differently
            flash("QR code contains raw text, not document data", "danger")
            return redirect(url_for("verify_qr"))
        
        if not doc_id or not commitment:
            flash("Invalid QR code data format - missing doc_id or commitment", "danger")
            return redirect(url_for("verify_qr"))
        
        # Find document
        doc = Document.query.get(doc_id)
        if not doc:
            # Log failed verification
            log_verification(current_user.id, None, "qr_code", str(qr_info), "not_found", request)
            flash("❌ Document not found", "danger")
            return render_template("verify_result.html", 
                                 verified=False, 
                                 qr_data=qr_data,
                                 qr_info=qr_info)
        
        # Verify commitment matches
        if doc.commitment == commitment:
            # Log successful verification
            log_verification(current_user.id, doc.id, "qr_code", str(qr_info), "verified", request)
            flash("✅ Document Verified - QR code authentic", "success")
            return render_template("verify_result.html", 
                                 verified=True, 
                                 doc=doc, 
                                 qr_data=qr_data,
                                 qr_info=qr_info)
        else:
            # Log failed verification
            log_verification(current_user.id, doc.id, "qr_code", str(qr_info), "tampered", request)
            flash("❌ Document Tampered - QR code data doesn't match", "danger")
            return render_template("verify_result.html", 
                                 verified=False, 
                                 doc=doc,
                                 qr_data=qr_data,
                                 qr_info=qr_info)
    
    return render_template("verify_qr.html")

@app.route("/qr/<int:doc_id>")
@login_required
def download_qr(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    # Check if user owns the document or is admin/verifier
    if doc.owner_id != current_user.id and current_user.role not in ("admin", "verifier"):
        abort(403)
    
    if not doc.qr_code_data:
        flash("QR code not available for this document", "danger")
        return redirect(url_for("dashboard"))
    
    # Return QR code as image
    from flask import Response
    qr_data = base64.b64decode(doc.qr_code_data)
    return Response(qr_data, mimetype="image/png", 
                   headers={"Content-Disposition": f"attachment; filename=qr_{doc.filename}.png"})

# ----------------------------
# Admin Routes
# ----------------------------
@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Access denied. Admin role required.", "danger")
        return redirect(url_for("dashboard"))
    
    # Get all documents with owner info
    documents = db.session.query(Document, User).join(User, Document.owner_id == User.id)\
        .order_by(Document.created_at.desc()).all()
    
    # Get verification logs
    verification_logs = db.session.query(VerificationLog, User, Document)\
        .join(User, VerificationLog.verifier_id == User.id)\
        .outerjoin(Document, VerificationLog.document_id == Document.id)\
        .order_by(VerificationLog.created_at.desc()).limit(50).all()
    
    # Get pending users
    pending_users = User.query.filter_by(is_approved=False, status="active").all()
    
    # Get blocked users
    blocked_users = User.query.filter_by(status="blocked").all()
    
    # Statistics
    total_docs = Document.query.count()
    total_users = User.query.count()
    total_verifications = VerificationLog.query.count()
    verified_docs = VerificationLog.query.filter_by(result="verified").count()
    
    return render_template("admin_dashboard.html", 
                         documents=documents,
                         verification_logs=verification_logs,
                         pending_users=pending_users,
                         blocked_users=blocked_users,
                         stats={
                             "total_docs": total_docs,
                             "total_users": total_users,
                             "total_verifications": total_verifications,
                             "verified_docs": verified_docs
                         })

@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.role != "admin":
        flash("Access denied. Admin role required.", "danger")
        return redirect(url_for("dashboard"))
    
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=users)

@app.route("/admin/user/<int:user_id>/approve", methods=["POST"])
@login_required
def admin_approve_user(user_id):
    if current_user.role != "admin":
        flash("Access denied. Admin role required.", "danger")
        return redirect(url_for("dashboard"))
    
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    user.status = "active"
    db.session.commit()
    
    flash(f"User {user.email} has been approved", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/block", methods=["POST"])
@login_required
def admin_block_user(user_id):
    if current_user.role != "admin":
        flash("Access denied. Admin role required.", "danger")
        return redirect(url_for("dashboard"))
    
    user = User.query.get_or_404(user_id)
    user.status = "blocked"
    user.is_approved = False
    db.session.commit()
    
    flash(f"User {user.email} has been blocked", "warning")
    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/unblock", methods=["POST"])
@login_required
def admin_unblock_user(user_id):
    if current_user.role != "admin":
        flash("Access denied. Admin role required.", "danger")
        return redirect(url_for("dashboard"))
    
    user = User.query.get_or_404(user_id)
    user.status = "active"
    user.is_approved = True
    db.session.commit()
    
    flash(f"User {user.email} has been unblocked", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/suspend", methods=["POST"])
@login_required
def admin_suspend_user(user_id):
    if current_user.role != "admin":
        flash("Access denied. Admin role required.", "danger")
        return redirect(url_for("dashboard"))
    
    user = User.query.get_or_404(user_id)
    user.status = "suspended"
    db.session.commit()
    
    flash(f"User {user.email} has been suspended", "warning")
    return redirect(url_for("admin_users"))

@app.route("/admin/verification-logs")
@login_required
def admin_verification_logs():
    if current_user.role != "admin":
        flash("Access denied. Admin role required.", "danger")
        return redirect(url_for("dashboard"))
    
    logs = db.session.query(VerificationLog, User, Document)\
        .join(User, VerificationLog.verifier_id == User.id)\
        .outerjoin(Document, VerificationLog.document_id == Document.id)\
        .order_by(VerificationLog.created_at.desc()).all()
    
    return render_template("admin_verification_logs.html", logs=logs)

# ----------------------------
# Run the App
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)
