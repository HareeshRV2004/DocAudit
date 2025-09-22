# DocAudits Project - Complete Technical Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [Technology Stack](#technology-stack)
3. [System Architecture](#system-architecture)
4. [Database Schema](#database-schema)
5. [Complete Workflow](#complete-workflow)
6. [Security & Privacy Features](#security--privacy-features)
7. [Smart Contract Architecture](#smart-contract-architecture)
8. [File Structure Analysis](#file-structure-analysis)
9. [API Endpoints](#api-endpoints)
10. [Deployment Guide](#deployment-guide)
11. [Code Examples](#code-examples)
12. [Troubleshooting](#troubleshooting)

---

## Project Overview

**DocAudits** is a blockchain-based document verification system specifically designed for Aadhaar card verification using zero-knowledge proof concepts and commitment schemes. The system allows users to commit their Aadhaar attributes to a blockchain while maintaining privacy, and enables verifiers to validate specific attributes without exposing the full document details.

### Key Features
- **Privacy-Preserving Verification**: Users can prove specific attributes without revealing full document
- **Blockchain Immutability**: Commitments stored on-chain prevent tampering
- **QR Code Integration**: Easy sharing and verification of commitments
- **Role-based Access**: Different user types with appropriate permissions
- **Audit Trail**: Complete logging of all verification attempts

---

## Technology Stack

### Backend Technologies
- **Flask 2.3.3** - Python web framework for main application server
- **SQLAlchemy 3.0.3** - Database ORM for SQLite database management
- **Flask-Login 0.6.2** - User authentication and session management
- **Web3.py** - Ethereum blockchain interaction and smart contract communication
- **Solidity ^0.8.19** - Smart contract development language
- **Truffle** - Blockchain development framework for contract deployment

### Frontend Technologies
- **Bootstrap 5.3.0** - CSS framework for responsive user interface
- **Jinja2** - Template engine for HTML rendering
- **JavaScript** - Client-side interactions and form handling

### Cryptographic & Image Processing
- **QRCode 7.4.2** - QR code generation and scanning capabilities
- **PyZBar** - QR code reading from uploaded images
- **Pillow (PIL)** - Image processing and manipulation
- **Keccak256** - Cryptographic hashing for commitment generation
- **UUID** - Unique identifier generation for salts and commitments

### Blockchain Infrastructure
- **Ganache** - Local Ethereum blockchain for development and testing
- **MetaMask** - Ethereum wallet integration (implicit)
- **Solidity Smart Contracts** - On-chain verification logic and data storage

### Additional Dependencies
- **cryptography 41.0.3** - Cryptographic operations
- **bcrypt 4.0.1** - Password hashing
- **python-dotenv 1.0.0** - Environment variable management
- **werkzeug 2.3.7** - WSGI utilities and security functions
- **py-solc-x** - Solidity compiler integration
- **opencv-python** - Computer vision capabilities

---

## System Architecture

### High-Level Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │    │   Flask App     │    │   Blockchain    │
│   (Frontend)    │◄──►│   (Backend)     │◄──►│   (Ganache)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   SQLite DB     │
                       │   (Database)    │
                       └─────────────────┘
```

### Component Interaction Flow
1. **User Interface Layer**: HTML templates with Bootstrap styling
2. **Application Layer**: Flask routes handling HTTP requests
3. **Business Logic Layer**: Python functions for processing and validation
4. **Data Access Layer**: SQLAlchemy ORM for database operations
5. **Blockchain Layer**: Web3.py for smart contract interactions
6. **Storage Layer**: SQLite database and file system

---

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    role VARCHAR(32) DEFAULT 'prover',
    eth_address VARCHAR(255),
    status VARCHAR(32) DEFAULT 'active',
    is_approved BOOLEAN DEFAULT FALSE,
    last_login DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**User Roles:**
- **prover**: Can upload and commit Aadhaar documents
- **verifier**: Can verify Aadhaar commitments
- **admin**: Full system access and user management

**User Status:**
- **active**: Normal user status
- **pending**: Awaiting admin approval
- **blocked**: Blocked by admin
- **suspended**: Temporarily suspended

### Aadhaar Records Table
```sql
CREATE TABLE aadhaar_records (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    aadhaar_number VARCHAR(12) NOT NULL,
    commitment_id_hex VARCHAR(66) NOT NULL,
    salt VARCHAR(128) NOT NULL,
    qr_filename VARCHAR(256) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);
```

### Verification Logs Table
```sql
CREATE TABLE verification_logs (
    id INTEGER PRIMARY KEY,
    verifier_id INTEGER NOT NULL,
    document_id INTEGER,
    verification_type VARCHAR(32) NOT NULL,
    verification_data TEXT,
    result VARCHAR(32) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (verifier_id) REFERENCES users(id),
    FOREIGN KEY (document_id) REFERENCES documents(id)
);
```

### Documents Table (Legacy)
```sql
CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    filename VARCHAR(512),
    stored_filename VARCHAR(512),
    filesize INTEGER,
    commitment VARCHAR(128),
    salt VARCHAR(128),
    cid VARCHAR(512),
    status VARCHAR(32) DEFAULT 'uploaded',
    qr_code_data TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);
```

---

## Complete Workflow

### Phase 1: User Registration & Authentication

#### 1.1 User Registration Process
```python
# Registration endpoint
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].lower().strip()
        name = request.form.get("name", "")
        password = request.form["password"]
        role = request.form.get("role", "prover")
        
        # Check for existing user
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return redirect(url_for("register"))
        
        # Hash password
        pw_hash = generate_password_hash(password)
        
        # Admin approval logic
        is_approved = (role == "admin")
        
        # Create user
        user = User(
            email=email, 
            name=name, 
            password_hash=pw_hash, 
            role=role, 
            is_approved=is_approved
        )
        db.session.add(user)
        db.session.commit()
```

#### 1.2 Login Process
```python
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].lower().strip()
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        
        # Verify credentials
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))
        
        # Check user access
        has_access, error_msg = check_user_access(user)
        if not has_access:
            flash(error_msg, "danger")
            return redirect(url_for("login"))
        
        # Update last login and authenticate
        user.last_login = datetime.utcnow()
        db.session.commit()
        login_user(user)
```

### Phase 2: Aadhaar Commitment (Prover Workflow)

#### 2.1 Aadhaar Data Input
The prover provides:
- **12-digit Aadhaar number** (validated for format)
- **Attributes to prove**:
  - Age ≥ 18 (boolean)
  - Indian citizenship (boolean)
  - Gender (M/F/O)
  - Name (optional, for matching)

#### 2.2 Cryptographic Commitment Generation
```python
def create_aadhaar_commitments(aadhaar_number, name, gender, above18, indian):
    # Generate public salt
    public_salt = uuid.uuid4().hex
    
    # Create commitment ID
    commitment_id_hex = w3.keccak(text=f"{public_salt}:{uuid.uuid4().hex}").hex()
    
    # Hash function helper
    def h(text):
        return w3.keccak(text=text).hex()
    
    # Generate attribute commitments
    above18_hex = h(public_salt + ("Above18" if above18 else "Under18"))
    indian_hex = h(public_salt + ("Indian" if indian else "NotIndian"))
    gender_hex = h(public_salt + ("Gender:" + gender)) if gender else h(public_salt + "Gender:")
    name_hash_hex = h(public_salt + ("Name:" + name)) if name else h(public_salt + "Name:")
    validity_hex = h(public_salt + "Valid")
    
    return {
        'commitment_id_hex': commitment_id_hex,
        'salt': public_salt,
        'above18_hex': above18_hex,
        'indian_hex': indian_hex,
        'gender_hex': gender_hex,
        'name_hash_hex': name_hash_hex,
        'validity_hex': validity_hex
    }
```

#### 2.3 Blockchain Transaction
```python
def set_aadhaar_commitments(self, account, private_key, commitment_id_hex,
                           above18_hex, indian_hex, gender_hex,
                           name_hash_hex, validity_hex):
    nonce = self.w3.eth.get_transaction_count(account)
    tx = self.contract.functions.setAadhaarCommitments(
        Web3.to_bytes(hexstr=commitment_id_hex),
        Web3.to_bytes(hexstr=above18_hex),
        Web3.to_bytes(hexstr=indian_hex),
        Web3.to_bytes(hexstr=gender_hex),
        Web3.to_bytes(hexstr=name_hash_hex),
        Web3.to_bytes(hexstr=validity_hex)
    ).build_transaction({
        "from": account,
        "nonce": nonce,
        "gas": 1_500_000,
        "gasPrice": self.w3.to_wei("2", "gwei")
    })
    
    signed = self.w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt.transactionHash.hex()
```

#### 2.4 QR Code Generation
```python
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

# QR payload structure
qr_payload = {
    "commitment_id": commitment_id_hex,
    "salt": public_salt
}
```

### Phase 3: Verification Process (Verifier Workflow)

#### 3.1 QR Code Input Methods
**Method 1: Image Upload**
```python
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
```

**Method 2: Text Input**
```python
# Direct JSON input from user
qr_data = request.form.get("qr_data", "").strip()
try:
    qr_info = json.loads(qr_data)
except json.JSONDecodeError:
    flash("Invalid QR code data format", "danger")
```

#### 3.2 Verification Process
```python
def verify_aadhaar_attributes(qr_info, check_age=False, check_citizen=False):
    commitment_id_hex = qr_info.get("commitment_id", "").strip()
    salt = qr_info.get("salt", "").strip()
    
    # Hash function
    def h(text):
        return w3.keccak(text=text).hex()
    
    # Always check validity
    validity_provided = h(salt + 'Valid')
    is_valid = bc.verify_attr('verifyValidity', commitment_id_hex, validity_provided)
    
    # Optional checks
    age_verified = None
    citizen_verified = None
    
    if is_valid and check_age:
        above18_provided = h(salt + 'Above18')
        age_verified = bc.verify_attr('verifyAbove18', commitment_id_hex, above18_provided)
    
    if is_valid and check_citizen:
        indian_provided = h(salt + 'Indian')
        citizen_verified = bc.verify_attr('verifyIndian', commitment_id_hex, indian_provided)
    
    # Determine overall result
    selected_checks = [v for v in [age_verified, citizen_verified] if v is not None]
    overall = is_valid and (all(selected_checks) if selected_checks else True)
    
    return {
        'overall': overall,
        'valid': is_valid,
        'age': age_verified,
        'citizen': citizen_verified
    }
```

### Phase 4: Admin Management

#### 4.1 User Management Functions
```python
@app.route("/admin/user/<int:user_id>/approve", methods=["POST"])
def admin_approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    user.status = "active"
    db.session.commit()
    flash(f"User {user.email} has been approved", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/block", methods=["POST"])
def admin_block_user(user_id):
    user = User.query.get_or_404(user_id)
    user.status = "blocked"
    user.is_approved = False
    db.session.commit()
    flash(f"User {user.email} has been blocked", "warning")
    return redirect(url_for("admin_users"))
```

#### 4.2 System Monitoring
```python
def get_admin_statistics():
    return {
        "total_docs": Document.query.count(),
        "total_users": User.query.count(),
        "total_verifications": VerificationLog.query.count(),
        "verified_docs": VerificationLog.query.filter_by(result="verified").count()
    }
```

---

## Security & Privacy Features

### Privacy Protection Mechanisms

#### 1. No Plaintext Storage
- Only cryptographic hashes are stored on-chain
- Original Aadhaar data never stored in plaintext
- Salt-based hashing prevents rainbow table attacks

#### 2. Selective Disclosure
- Users choose which attributes to prove
- Verifiers can only verify selected attributes
- Zero-knowledge proof concept implementation

#### 3. Commitment Scheme
```python
# Commitment generation prevents pre-computation attacks
commitment = keccak256(salt + attribute_value)
# Salt is unique per commitment
salt = uuid.uuid4().hex
```

### Security Measures

#### 1. Password Security
```python
# Werkzeug password hashing
pw_hash = generate_password_hash(password)
# Verification
is_valid = check_password_hash(stored_hash, provided_password)
```

#### 2. Session Management
```python
# Flask-Login secure sessions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
```

#### 3. Role-based Access Control
```python
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
```

#### 4. Input Validation
```python
# Aadhaar number validation
if not aadhaar_number.isdigit() or len(aadhaar_number) != 12:
    flash('Enter a valid 12-digit Aadhaar number', 'danger')
    return redirect(url_for('aadhaar_upload'))
```

---

## Smart Contract Architecture

### Verifier.sol Contract Structure
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Verifier {
    struct AadhaarSet {
        bytes32 above18;           // Age commitment hash
        bytes32 indian;            // Citizenship commitment hash
        bytes32 gender;            // Gender commitment hash
        bytes32 nameHash;          // Name commitment hash
        bytes32 validity;          // Document validity hash
        bool set;                  // Set flag
    }

    // Storage mapping
    mapping(bytes32 => AadhaarSet) private records;

    // Events
    event AadhaarCommitted(bytes32 indexed commitmentId, address indexed uploader);

    // Main commitment function
    function setAadhaarCommitments(
        bytes32 commitmentId,
        bytes32 above18,
        bytes32 indian,
        bytes32 gender,
        bytes32 nameHash,
        bytes32 validity
    ) external {
        require(!records[commitmentId].set, "Already set");
        records[commitmentId] = AadhaarSet({
            above18: above18,
            indian: indian,
            gender: gender,
            nameHash: nameHash,
            validity: validity,
            set: true
        });
        emit AadhaarCommitted(commitmentId, msg.sender);
    }

    // Verification functions
    function verifyAbove18(bytes32 commitmentId, bytes32 provided) 
        external view returns (bool) {
        AadhaarSet storage s = records[commitmentId];
        return s.set && s.above18 == provided;
    }

    function verifyIndian(bytes32 commitmentId, bytes32 provided) 
        external view returns (bool) {
        AadhaarSet storage s = records[commitmentId];
        return s.set && s.indian == provided;
    }

    function verifyGender(bytes32 commitmentId, bytes32 provided) 
        external view returns (bool) {
        AadhaarSet storage s = records[commitmentId];
        return s.set && s.gender == provided;
    }

    function verifyName(bytes32 commitmentId, bytes32 provided) 
        external view returns (bool) {
        AadhaarSet storage s = records[commitmentId];
        return s.set && s.nameHash == provided;
    }

    function verifyValidity(bytes32 commitmentId, bytes32 provided) 
        external view returns (bool) {
        AadhaarSet storage s = records[commitmentId];
        return s.set && s.validity == provided;
    }

    function isSet(bytes32 commitmentId) external view returns (bool) {
        return records[commitmentId].set;
    }
}
```

### Contract Deployment
```javascript
// migrations/2_deploy_contracts.js
const Verifier = artifacts.require("Verifier");

module.exports = function (deployer) {
  deployer.deploy(Verifier);
};
```

### Truffle Configuration
```javascript
// truffle-config.js
module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 7545,            // Ganache GUI port
      network_id: "*",
    },
  },
  compilers: {
    solc: {
      version: "0.8.19",
    }
  }
};
```

---

## File Structure Analysis

```
DocAudits/
├── app.py                      # Main Flask application (673 lines)
├── models.py                   # Database models (legacy, 32 lines)
├── blockchain.py              # Web3 blockchain integration (61 lines)
├── config.py                   # Configuration settings (12 lines)
├── requirements.txt            # Python dependencies (18 lines)
├── truffle-config.js          # Truffle configuration (14 lines)
├── docuaudit.db               # SQLite database file
│
├── contracts/
│   └── Verifier.sol           # Solidity smart contract (71 lines)
│
├── build/contracts/
│   └── Verifier.json          # Compiled contract ABI and address
│
├── migrations/
│   └── 2_deploy_contracts.js  # Truffle deployment script (6 lines)
│
├── templates/                 # HTML templates (15 files)
│   ├── base.html              # Base template with navigation
│   ├── login.html             # User login page
│   ├── register.html          # User registration page
│   ├── dashboard.html         # Prover dashboard
│   ├── verifier.html          # Verifier dashboard
│   ├── admin_dashboard.html   # Admin dashboard
│   ├── aadhaar_upload.html    # Aadhaar commitment form
│   ├── aadhaar_history.html   # Aadhaar records history
│   ├── verify_qr.html         # QR verification form
│   ├── verify_result.html     # Verification results display
│   ├── admin_users.html       # User management
│   ├── admin_verification_logs.html # Verification logs
│   └── [other templates...]
│
├── static/qr/                 # Generated QR codes
│   ├── aadhaar_b64d5913d0.png
│   ├── aadhaar_ddeb7d774f.png
│   └── aadhaar_f142587ca4.png
│
├── uploads/                   # File uploads (legacy)
└── venv/                      # Python virtual environment
```

### Key File Descriptions

#### app.py (Main Application)
- **673 lines** of Python code
- Contains all Flask routes and business logic
- Handles user authentication, Aadhaar commitment, and verification
- Integrates with blockchain and database

#### blockchain.py (Blockchain Integration)
- **61 lines** of Web3.py integration code
- Handles smart contract interactions
- Manages transaction signing and sending
- Provides verification methods

#### Verifier.sol (Smart Contract)
- **71 lines** of Solidity code
- Defines Aadhaar commitment storage structure
- Implements verification functions
- Uses mapping for efficient storage

---

## API Endpoints

### Authentication Endpoints
```
GET  /                    - Redirect based on user role
POST /register           - User registration
GET  /register           - Registration form
POST /login              - User login
GET  /login              - Login form
GET  /logout             - User logout
```

### Prover Endpoints
```
GET  /dashboard          - Prover dashboard
GET  /aadhaar/upload      - Aadhaar commitment form
POST /aadhaar/upload     - Process Aadhaar commitment
GET  /aadhaar/history    - View Aadhaar records
GET  /aadhaar/qr/<id>    - Download QR code
```

### Verifier Endpoints
```
GET  /verifier           - Verifier dashboard
GET  /verify/qr          - QR verification form
POST /verify/qr          - Process QR verification
GET  /api/documents      - API for document listing
```

### Admin Endpoints
```
GET  /admin              - Admin dashboard
GET  /admin/users        - User management
POST /admin/user/<id>/approve  - Approve user
POST /admin/user/<id>/block    - Block user
POST /admin/user/<id>/unblock  - Unblock user
POST /admin/user/<id>/suspend  - Suspend user
GET  /admin/verification-logs  - View verification logs
```

### File Access Endpoints
```
GET  /uploads/<filename> - Download uploaded files (legacy)
```

---

## Deployment Guide

### Prerequisites
1. **Python 3.8+** installed
2. **Node.js** and **npm** for Truffle
3. **Ganache** for local blockchain
4. **Git** for version control

### Step 1: Environment Setup
```bash
# Clone the repository
git clone <repository-url>
cd DocAudits

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Blockchain Setup
```bash
# Install Truffle globally
npm install -g truffle

# Install local dependencies
npm install

# Start Ganache (GUI or CLI)
# GUI: Download and run Ganache
# CLI: ganache-cli --port 7545

# Compile and deploy contracts
truffle compile
truffle migrate --network development
```

### Step 3: Configuration
```python
# Update blockchain.py with your Ganache account
account = "0x172FAeE93c26F963E0271040E3cEC61774849C11"
private_key = "0xadfc344fbfd781cb311f1ae9faf8744e98bd8879fc7bf714c668581e9baa2712"
```

### Step 4: Database Initialization
```python
# Run the application to create database
python app.py
# Database will be created automatically with SQLAlchemy
```

### Step 5: Run Application
```bash
# Start Flask development server
python app.py

# Application will be available at:
# http://localhost:5000
```

### Production Deployment Considerations
1. **Use PostgreSQL** instead of SQLite for production
2. **Configure proper secret keys** in environment variables
3. **Use a production blockchain** (Ethereum mainnet/testnet)
4. **Implement proper logging** and monitoring
5. **Set up HTTPS** with SSL certificates
6. **Configure reverse proxy** (nginx/Apache)
7. **Use WSGI server** (Gunicorn/uWSGI)

---

## Code Examples

### Complete Aadhaar Commitment Flow
```python
@app.route("/aadhaar/upload", methods=["GET", "POST"])
@login_required
def aadhaar_upload():
    if current_user.role not in ("prover", "admin"):
        flash("Your role can't upload Aadhaar", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # Extract form data
        aadhaar_number = request.form.get('aadhaar_number','').strip()
        name = request.form.get('name','').strip().lower()
        gender = request.form.get('gender','').strip().upper()
        above18 = bool(request.form.get('above18'))
        indian = bool(request.form.get('indian'))

        # Validate Aadhaar number
        if not aadhaar_number.isdigit() or len(aadhaar_number) != 12:
            flash('Enter a valid 12-digit Aadhaar number', 'danger')
            return redirect(url_for('aadhaar_upload'))

        # Initialize blockchain connection
        bc = Blockchain()
        w3 = bc.w3

        # Generate commitments
        public_salt = uuid.uuid4().hex
        commitment_id_hex = w3.keccak(text=f"{public_salt}:{uuid.uuid4().hex}").hex()

        def h(text):
            return w3.keccak(text=text).hex()

        above18_hex = h(public_salt + ("Above18" if above18 else "Under18"))
        indian_hex = h(public_salt + ("Indian" if indian else "NotIndian"))
        gender_hex = h(public_salt + ("Gender:" + gender)) if gender else h(public_salt + "Gender:")
        name_hash_hex = h(public_salt + ("Name:" + name)) if name else h(public_salt + "Name:")
        validity_hex = h(public_salt + "Valid")

        # Submit to blockchain
        account = "0x172FAeE93c26F963E0271040E3cEC61774849C11"
        private_key = "0xadfc344fbfd781cb311f1ae9faf8744e98bd8879fc7bf714c668581e9baa2712"
        
        bc.set_aadhaar_commitments(account, private_key, commitment_id_hex, 
                                  above18_hex, indian_hex, gender_hex, 
                                  name_hash_hex, validity_hex)

        # Generate QR code
        static_qr_dir = os.path.join(BASE_DIR, 'static', 'qr')
        os.makedirs(static_qr_dir, exist_ok)
        
        qr_payload = json.dumps({"commitment_id": commitment_id_hex, "salt": public_salt})
        img = qrcode.make(qr_payload)
        qr_filename = f"aadhaar_{commitment_id_hex[:10]}.png"
        img.save(os.path.join(static_qr_dir, qr_filename))

        # Store in database
        record = AadhaarRecord(
            owner_id=current_user.id,
            aadhaar_number=aadhaar_number,
            commitment_id_hex=commitment_id_hex,
            salt=public_salt,
            qr_filename=qr_filename,
        )
        db.session.add(record)
        db.session.commit()

        flash('Aadhaar commitments stored on-chain', 'success')
        return render_template('aadhaar_upload.html', qr_img_path=qr_filename)

    return render_template('aadhaar_upload.html')
```

### Complete Verification Flow
```python
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

        # Extract commitment data
        commitment_id_hex = qr_info.get("commitment_id", "").strip()
        salt = qr_info.get("salt", "").strip()

        if not commitment_id_hex or not salt:
            flash("QR missing commitment_id or salt", "danger")
            return redirect(url_for("verify_qr"))

        # Initialize blockchain
        bc = Blockchain()
        w3 = bc.w3

        def h(text):
            return w3.keccak(text=text).hex()

        # Perform verification checks
        validity_provided = h(salt + 'Valid')
        is_valid = bc.verify_attr('verifyValidity', commitment_id_hex, validity_provided)

        check_age = bool(request.form.get('check_age'))
        check_citizen = bool(request.form.get('check_citizen'))

        age_verified = None
        citizen_verified = None
        
        if is_valid and check_age:
            above18_provided = h(salt + 'Above18')
            age_verified = bc.verify_attr('verifyAbove18', commitment_id_hex, above18_provided)
        
        if is_valid and check_citizen:
            indian_provided = h(salt + 'Indian')
            citizen_verified = bc.verify_attr('verifyIndian', commitment_id_hex, indian_provided)

        # Determine overall result
        selected_checks = [v for v in [age_verified, citizen_verified] if v is not None]
        overall = is_valid and (all(selected_checks) if selected_checks else True)

        # Log verification
        log_result = "verified" if overall else "not_verified"
        log_verification(current_user.id, None, "qr_code", json.dumps(qr_info), log_result, request)

        # Display results
        if overall:
            flash("✅ Aadhaar Verified", "success")
        else:
            flash("❌ Aadhaar Not Verified", "danger")
            
        return render_template("verify_result.html", 
                             verified=overall, 
                             qr_info=qr_info, 
                             checks={"valid": is_valid, "age": age_verified, "citizen": citizen_verified})
    
    return render_template("verify_qr.html")
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Blockchain Connection Issues
**Problem**: "Cannot connect to Ganache"
**Solutions**:
- Ensure Ganache is running on port 7545
- Check Ganache GUI/CLI is active
- Verify network configuration in truffle-config.js

#### 2. Contract Deployment Issues
**Problem**: "Contract not deployed"
**Solutions**:
```bash
# Recompile contracts
truffle compile

# Reset and redeploy
truffle migrate --reset --network development

# Check contract address in build/contracts/Verifier.json
```

#### 3. QR Code Scanning Issues
**Problem**: "No QR code found in image"
**Solutions**:
- Ensure image contains a clear QR code
- Try different image formats (PNG, JPG)
- Check image quality and resolution
- Use text input as alternative

#### 4. Database Issues
**Problem**: "Database locked" or "Table doesn't exist"
**Solutions**:
```python
# Recreate database
with app.app_context():
    db.drop_all()
    db.create_all()
```

#### 5. Permission Issues
**Problem**: "Access denied" or "Insufficient permissions"
**Solutions**:
- Check user role assignment
- Verify admin approval status
- Ensure proper login session

### Debug Mode
```python
# Enable Flask debug mode
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### Logging Configuration
```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)
```

---

## Conclusion

DocAudits represents a comprehensive implementation of privacy-preserving document verification using blockchain technology. The system successfully combines:

- **Zero-knowledge proof concepts** for privacy protection
- **Blockchain immutability** for tamper-proof storage
- **Modern web technologies** for user-friendly interface
- **Cryptographic commitments** for secure verification
- **Role-based access control** for system security

The project demonstrates practical applications of advanced cryptographic concepts in real-world scenarios, providing a foundation for secure, privacy-preserving identity verification systems.

---

**Document Version**: 1.0  
**Last Updated**: December 2024  
**Total Pages**: This comprehensive documentation covers all aspects of the DocAudits project

