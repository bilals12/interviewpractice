# general AppSec Engineering coding exercises


**1. implement a function to sanitize user input to prevent XSS in a web application.**

```python
import html

def sanitize_input(input):
    """
    sanitizes input to prevent XSS by escaping special HTML characters.

    args:
    - input (str): input string to be sanitized

    returns:
    - str: sanitized version of input string where special chars are escaped

    using the `html.escape` method from the standard library, it replaces chars like '<', '>', '&', '"', ''' with corresponding escape codes.
    """
    return html.escape(input)

# example
if __name__ == "__main__":
    unsanitized_input = "<script>alert('XSS!')</script>"
    sanitized_input = sanitize_input(unsanitized_input)
    print(f"sanitized input: {sanitized_input}")
```

the output of this program would now be: `&lt;script&gt;alert(&#x27;XSS!&#x27;)&lt;/script&gt;`. [escapes `<`, `>`, `'` into `&lt;`, `&gt;`, `&#x27;`]

**2. develop a script to simulate a SQLi attack on a sample db, and propose a solution to prevent such attacks.**

we'll develop the attack using python and SQLite (disk-based db that doesn't require separate server process) then create a prevention technique using parametrized queries.

```python
# sample db + table setup
conn = sqlite3.connect(':memory:') # creates in-memory db 
cursor = conn.cursor()
cursor.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
cursor.execute("INSERT INTO users(username, password) VALUES ('admin', 'adminpass'), ('user', 'userpass')")

# SQLi attack
def SQLi(username):
    """
    args:
    - username (str): username input that contains the SQLi code

    the input is concatenated directly into the SQL query. 
    """
    query = f"SELECT  * FROM users WHERE username = '{username}'"
    print(f"executing query: {query}")
    try:
        cursor.execute(query)
        return cursor.fetchall()
        except sqlite3.OperationalError as e:
            return f"SQL error: {e}"
# example of SQLi
mal_input = "admin' --"
result = SQLi(mal_input)
print(f"Result: {result}")
```

this would execute the query successfully and return the admin user's details.

to prevent this, use parametrized queries.

```python
def secure(username):
    """
    args:
    - username (str): input from user
    """
    query = "SELECT * FROM users WHERE username = ?"
    print(f"executing secure query: {query}")
    cursor.execute(query, (username,))
    return cursor.fetchall()
# usage
result = secure_query("admin")
print(f"secure result: {result}")
```

this code ensures that user input is treated as data, not as part of the SQL command. 

**3. write code to generate/validate JSON Web Tokens (JWT) for secure authentication in a web app.**

JWT is used for secure auth by transmitting information between parties as a JSON object. it's good for securing RESTful APIs and single-page apps (SPAs).

first install `PyJWT`.

```bash
pip install PyJWT
```

then:

```python
import jwt
import datetime

# secret key for signing the JWT. keep secure!
# you can store it as either an environment variable, in a config file (away from source repo and guarded by ACL), use secret management tools (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)
SECRET_KEY = "your_key"

def generate_jwt(payload, lifetime_minutes=30):
    """
    args:
    - payload (dict): dict containing the payload data for the JWT
    - lifetime_minutes (int): lifetime of token (minutes)
    returns:
    - str: JWT token
    """
    # setting expiration time
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=lifetime_minutes)
    payload.update({"exp": expire})

    # generate JWT
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def validate_jwt(token):
    """
    args: 
    - token (str): JWT to validate
    returns:
    - dict: payload of token if validation is successful
    - none: if validation fails
    """
    try:
        # decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        print("token expired!")
    except jwt.InvalidTokenError:
        print("invalid token!")
    return None

# example
if __name__ = "__main__":
    user_data = {"user_id": 123, "username": "testuser"}
    token = generate_jwt(user_data)
    print(f"generated JWT: {token}")
    # simulate delay to test expiration (uncomment to simulate expiration)
    # time.sleep(31*60)

    validated_data = validate_jwt(token)
    if validated_data:
        print(f"token is valid. payload: {validated_data}")
    else:
        print("token validation failed!")
```

examples of output would be like this:

```bash
generated JWT: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInVzZXJuYW1lIjoidGVzdHVzZXIiLCJleHAiOjE3MDg4MDIyNTR9.DBUpSzf9fllwG_ygC3NvILdDdrRS8gOykUixN1wsdKU'

token is valid. payload: {'user_id': 123, 'username': 'testuser', 'exp': 1708802254}
```

**4. create a secure password hashing function using `bcrypt` or `PBKDF2` to store passwords securely in a db.**

`bcrypt` automatically handles salt generation + storage as part of the hashed password (makes each hash unique even for identical passwords).

```bash
pip install bcrypt
```

```python
import bcrypt

def hash_password(password):
    """
    args:
    - password (str): plaintext password to hash
    returns:
    - bytes: hashed password
    """

    # convert password to bytes then hash it
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed

def verify_password(password, hashed):
    """
    args:
    - password (str): plaintext password to verify
    - hashed (bytes): hashed password to compare against
    returns:
    - bool: true if password matches hash, false otherwise
    """

    password_bytes = password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed)

# example
if __name__ = "__main__":
    original_password = "securePassword123!"
    hashed_password = hash_password(original_password)
    print(f"hashed password: {hashed_password}")

    # verify password
    verification_result = verify_password("securePassword123!", hashed_password)
    print(f"verification result: {verification_result}")

    # verify with wrong password
    wrong_verification = verify_password("wrongPassword!", hashed_password)
    print(f"verification result: {wrong_verification}")
```

example outputs:

```bash
hashed password: $2b$12$k60XBq/8L20b/8y/1bBzceVYiAIx0z2QMtJMnCpZFJ3ZkRWll5RvO

verification result: True

verification result: False
```

some notes:

- only hashed passwords should be stored in db. never store plaintext passwords!

- `bcrypt` automatically generates and applies a new salt for each password hashed. this is crucial for protecting against [rainbow table attacks](https://www.beyondidentity.com/glossary/rainbow-table-attack)

- `bcrypt.checkpw` is specifically designed to be secure against timing attacks (inferring information based on time taken by comparisons).

**5. implement a script to scan a piece of code for potential vulns like hardcoded credentials or sensitive data exposure.**

basic script (python) that scans files for patterns of hardcoded secrets (passwords, API keys, tokens). 

use regex to search for common patterns. can extend `PATTERNS` list based on specific patterns relevant to codebase/environment.

read file line-by-line, applying each pattern to find matches. when pattern matches, it records line number + content for reporting.

can expand search to multiple files, directories, or file types. integrating with syntax trees (ASTs) can provide more accurate detection.

integrate with SAST tools. and watch out for false positives!

```python
import os
import re

# patterns to search for potential sensitive data
# adjust to fit different contexts

patterns = {
    'hardcoded_ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'api_key': r'(api_key|apikey|API_KEY|APIKEY)[\s]*=[\s]*["\']?[A-Za-z0-9]{20,}["\']?',
    'password': r'(password|PASSWORD)[\s]*=[\s]*["\']?[^\s,"\'\n]+["\']?'
}

# file extensions
file_extensions = ['.py', '.txt', '.cfg', '.config', '.yml', '.yaml', '.json']

def scan_file(file_path):
    """
    scan single file.
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()
        for pattern_name, pattern in patterns.items():
            if re.search(pattern, content):
                print(f"potential sensitive data ({pattern_name})) found in {file_path}")

def scan_directory(directory):
    """
    recursively scan directory for files with specific extensions + check for sensitive data.
    """
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in file_extensions):
                scan_file(os.path.join(root, file))

# example
if __name__ = "__main__":
    directory_to_scan = '.' # current directory. can change if needed.
    scan_directory(directory_to_scan)
```

examples of output:

```bash
potential sensitive data (api_key) found in /path/to/project/settings.py
```

```bash
potential sensitive data (password) found in /path/to/project/config.yaml
```

```bash
potential sensitive data (email) found in /path/to/project/docs/contacts.txt
```

```bash
potential sensitive data (hardcoded_ip) found in /path/to/project/deploy/config.json
```

**6. develop a secure file upload feature that includes checks for file type, size, and content to prevent malicious file uploads.**

python + flask (WSGI web app framework).

```bash
pip install flask
```

then create flask app with an upload route that performs the checks.

```python
from flask import Flask, request, flash, redirect, url_for
import os
import magic

app = Flask(__name__)
app.secret_key = 'secret_key'

# upload parameters
upload_folder = '/path/to/uploads'
allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
max_file_size = 1024 * 1024 * 5 # 5MB

app.config['UPLOAD_FOLDER'] = upload_folder
app.config['MAX_CONTENT_LENGTH'] = max_file_size

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions
           # checks for '.' in filename (must be at least one)
           # filename.rsplit('.', 1) splits filename string from the right at the first '.' it encounters
           # [1] accesses second element of list (file extension)
           # .lower() converts extension to lowercase
           # checks extension against whitelist (allowed_extensions)

def is_safe_content(file_path):
    # magic lib checks file's MIME type
    mime = magic.Magic(mime=True)
    file_mime_type = mime.from_file(file_path)
    # add/modify MIME types per requirements
    safe_mime_types = {'text/plain', 'application/pdf', 'image/png', 'image/jpeg', 'image/gif'}
    return file_mime_type in safe_mime_types

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('no file part!')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('no selected file!')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        if is_safe_content(file_path):
            flash('file successfully uploaded!')
            return redirect(url_for('upload_file'))
        else:
            os.remove(file_path) # remove file if it doesn't meet content check
            flash('file content not allowed!')
            return redirect(request.url)
    else:
        flash('file type not allowed!')
        return redirect(request.url)
if __name__ = '__main__':
    app.run(debug=True)
```

- `allowed_file` function checks file extension against whitelist

- `MAX_CONTENT_LENGTH` in flask automatically rejects uploads exceeding a size limit.

- `is_safe_content` used `python-magic` to inspect file's MIME type. this looks for files that have a misleading extension.

- `secure_filename` (imported from `werkzeug.utils`) sanitizes filename to prevent directory traversal attacks. 


**7. write code to implement role-based access control (RBAC) in an application to restrict user permissions based on their roles.**

define roles, perms, and associating the roles with specific perms. assign roles to users that determine what actions they can perform.

define permissions and roles first.

```python
class Permission:
    def __init__(self, name):
        self.name = name

class Role:
    def __init__(self, name):
        self.name = name
        self.permissions = []

    def add_permission(self, permission):
        self.permissions.append(permission)
    
    def has_permission(self, permission_name):
        return any(permission.name == permission_name for permission in self.permissions)
```

then define users and assign roles.

```python
class User:
    def __init__(self, username):
        self.username = username
        self.roles = []

    def assign_role(self, role):
        self.roles.append(role)
    
    def has_permission(self, permission_name):
        return any(role.has_permission(permission_name) for role in self.roles)
```

implement RBAC in app logic

```python
# define permissions
read_permission = Permission("read")
write_permission = Permission("write")
delete_permission = Permission("delete")

# define roles
admin_role = Role("admin")
admin_role.add_permission(read_permission)
admin_role.add_permission(write_permission)
admin_role.add_permission(delete_permission)

editor_role = Role("editor")
editor_role.add_permission(read_permission)
editor_role.add_permission(write_permission)

viewer_role = Role("viewer")
viewer_role.add_permission(read_permission)

# create users + assign roles
admin_user = User("admin_user")
admin_user.assign_role(admin_role)

editor_user = User("editor_user")
editor_user.assign_role(editor_role)

viewer_user = User("viewer_user")
viewer_user.assign_role(viewer_role)

# example (check if user has a specific permission)
print(admin_user.has_permission("write")) # should return True
print(viewer_user.has_permission("write")) # should return False
```

**8. build a script to automate the process of scanning dependencies for known vulnerabilities using tools like OWASP Dependency-Check.**

identify project dependencies + check if there are known, publicly disclosed vulns.

can run tool from CLI, but integrate into automation script (as part of CI/CD pipeline).

install from github first, then write automation script in python.

```python
import subprocess
import os

# config
dependency_check_path = 'dependency-check/bin/dependency-check.sh' # path to Dependency-Check CLI
project_path = '/path/to/project' # path to project that needs to be scanned
report_output_path = 'path/to/output/report' # where to save report
report_format = 'HTML' # format can be HTML, XML, CSV, JSON, etc.

def run_dependency_check():
    # check if output path exists
    if not os.path.exists(report_output_path):
        os.makedirs(report_output_path)

    # construct command to run Dependency-Check
    command = [
        dependency_check_path,
        '--project', 'project name',
        '--scan', project_path,
        '--out', report_output_path,
        '--format', report_format,
        '--enableExperimental', # additional experimental analyzers
        # add flags here
    ]

    # execute command
    try:
        print("starting Dependency-Check scan...")
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print("scan completed successfully!")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("error during the scan:")
        print(e.output)
if __name__ == '__main__':
    run_dependency_check()
```

this tool relies on NVD. 

**9. create a secure login mechanism using multi-factor authentication (MFA) with time-based one-time passwords (TOTP) for enhanced security.**

integrate secure password storage with `bcrypt`, secure TOTP secure storage, rate limit login attempts + TOTP verification.

```bash
pip install pyotp bcrypt
```

modify user model to store hashed passwords + store TOTP.

```python
import bcrypt
import pyotp

class User:
    def __init__(self, username, hashed_password, totp_secret):
        self.username = username
        self.hashed_password = hashed_password # stores hashed password
        self.totp_secret = totp_secret # can be encrypted
```

hash password and generate TOTP secret when registering a new user

```python
def hashed_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def register_user(username, password):
    hashed_password = hash_password(password)
    totp_secret = pyotp.random_base32()
    user = User(username, hashed_password, totp_secret)
    # store this user object in the user management system

    # generate + display TOTP URI for QR code generation
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="APP")
    print("register your TOTP with this URI:", totp_uri)
    return user
```

for login, verify hashed password + TOTP code. implement some basic rate limiting by tracking login attempts.

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# assume a flask app for rate limiting
app = Flask(__name__)
limiter = Limiter(
    app,
    key_func = get_remote_address,
    default_limits = ["5 per minute", "100 per day"]
)

def verify_password(stored_hash, password_attempt):
    return bcrypt.checkpw(password_attempt.encode('utf-8'), stored_hash)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute") # rate limiting login attempts
def login():
    username = request.form['username']
    password = request.form['password']
    totp_code = request.form['totp_code']
    user = get_user_by_username(username)

    if not user or not verify_password(user.hashed_password, password):
        return "login failed: incorrect username/password", 401
    
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(totp_code):
        return "login failed: invalid TOTP code", 401
    
    # login success
    return "login successful!", 200
```

**10. develop a script to encrypt sensitive data at rest using AES encryption and securely store the encryption keys.**

use `cryptography` library, include functions to generate encryption key, encrypt data using AES, decrypt data, and store encryption key using a key management solution.

```bash
pip install cryptography
```

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PNKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# keygen + storage
def generate_key(password_provided, salt=os.urandom(16)):
    password = password_provided.encode() # convert from string to bytes
    kdf = Scrypt(
        salt=salt, # salt used to prevent rainbow table attacks
        length=32, # length of derived key (AES-256 requires 32-byte key)
        n=2**14, # CPU/mem cost factor
        r=8, # block size param (affects mem/CPU usage)
        p=1, # parallelization param
        backend=default_backend() # default crypto backend
    )
    key = kdf.derive(password) # derive secure key from password
    return key, salt # return generated key + salt

# encrypt data using AES
def encrypt(data, key):
    iv = os.urandom(16) # random initialization vector for AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) # create cipher object for AES in CBC mode
    encryptor = cipher.encryptor() # encryptor instance
    padder = padding.PKCS7(128).padder() # padder for block size of 128 bits (AES block size)
    padded_data = padder.update(data.encode()) + padder.finalize() # pad data to be multiple of block size
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize() # encrypt padded data
    return encrypted_data, iv # return encrypted data + IV

# decrypt data
def decrypt(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize() # remove padding
    return unpadded_data.decode() # convert bytes back to string and return

# example
if __name__ = "__main__":
    password = "secure_password" # define password for keygen
    data_to_encrypt = "sensitive data!!!" # data to be encrypted

    key, salt = generate_key(password) # generate encryption key using password
    encrypted_data, iv = encrypt(data_to_encrypt, key) # encrypt data using generated key
    decrypted_data = decrypt(encrypt_data, key, iv) # decrypt
    
    print(f"encrypted data: {encrypted_data}") # print encrypted data (bytes)
    print(f"decrypted data: {decrypted_data}")
```

- generation of secure key from password using `Scrypt` (a key derivation function resistant to brute-force and rainbow table attacks by using a salt)

- encryption/decryption uses AES in CBC mode (requires IV for added security)

- padding applied to data before encryption to ensure it fits AES block size, and removed after decryption

**11. find out where soft deleted items are stored and write a script to pull them from local dbs**

SQLite:

```python
import sqlite3
from datetime import datetime, timedelta

# db connection
db_path = 'path.db'
conn = sqlite3.connect(db_path)
# mysql
conn = mysql.connector.connect(
    host="localhost",
    user="your_username",
    password="your_password",
    database="your_database"
)
# postgreSQL
conn = psycopg2.connect(
    host="localhost",
    user="your_username",
    password="your_password",
    database="your_database"
)
cursor = conn.cursor()

# retrieve soft deleted items (last 30 days)
def retrieve_soft_deleted_items(table_name):
    # calculate date
    thirty_days_ago = datetime.now() - timedelta(days=30)
    thirty_days_ago_str = thirty_days_ago.strftime('%Y-%m-%d %H:%M:%S')

    # query to select items marked deleted within 30 days ago
    query = f"""
    SELECT * FROM {table_name} WHERE deleted_at IS NOT NULL AND deleted_at > ?
    """

    # execute
    cursor.execute(query, (thirty_days_ago_str,))

    # return
    return cursor.fetchall()

# example
if __name__ == '__main__':
    table_name = 'table' # replace with table name
    deleted_items = retrieve_soft_deleted_items(table_name)
    for item in deleted_items:
        print(item) # print each item
```

mongoDB:

```python
from pymongo import MongoClient
from datetime import datetime, timedelta

# connection setup
client = MongoClient('mongodb://localhost:27017/')
db = client['your_db'] # replace with db
collection = db['collection'] # replace with your collection

# retriever
def retrieve_soft_deleted_items():
    thirty_days_ago = datetime.now() - timedelta(days=30)
    query = {'deleted_at': {'$gt': thirty_days_ago}}
    deleted_items = collection.find(query)
    return list(deleted_items)

# example
if __name__ == '__main__':
    deleted_items = retrieve_soft_deleted_items()
    for item in deleted_items:
        print(item)
```

**12. Write a mini forensics tool to collect identifying information from PDF metadata.**

```python
import PyPDF2

def extract_pdf_metadata(pdf_path):
    """
    args:
    - pdf_path (str): path to the pdf file.
    returns:
    - dict: dict containing PDF metadata
    """
    try:
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfFileReader(file)
            metadata = pdf_reader.getDocumentInfo()
            return metadata
    except Exception as e:
        print(f"error reading metadata: {e}")
        return None

def print_pdf_metadata(metadata):
    """
    args:
    - metadata (dict): dict containing PDF metadata
    """
    if metadata:
        print("PDF metadata:")
        for key, value in metadata.items():
            print(f"{key}: {value}")
    else:
        print("no metadata found")
# example
if __name__ == "__main__":
    pdf_path = "path.pdf"
    metadata = extract_pdf_metadata(pdf_path)
    print_pdf_metadata(metadata)
```

**13. Design a script to implement Cross-Site Request Forgery (CSRF) protection in a web application using token-based validation.**

use token-based validation (generate unique token for each user session, use token in each state-change request)

```python
from flask import Flask, request, session, abort
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.urandom(24) # random secret key gen (keep secure!)

# generate CSRF token + store it in user session
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(64).hex() # generate random token
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token # make csrf_token available in templates

def csrf_protect(f):
    # decorator to enforce CSRF protection
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            # verify token
            token = session.pop('csrf_token', None)
            request_token = request.form.get('csrf_token')
            if not token or token != request_token:
                abort(403) # forbidden if tokens don't match
        return f(*args, **kwargs)
    return decorated_function

@app.route('/form', methods=['GET'])
def form():
    # render form for POST request (must include CSRF token)
    return '''
    <form action="/submit" method="post">
        <input type="hidden" name="csrf_token" value="{csrf_token}" />
        <input type="submit" value="Submit" />
    </form>
    '''.format(csrf_token=generate_csrf_token())

@app.route('/submit', methods=['POST'])
@csrf_protect
def submit():
    # form submission logic
    return "form submitted!"

if __name__ == "__main__":
    app.run(debug=True)
```

- unique CSRF token generated + stored in user session when accessing a form

- CSRF token included in hidden field in each form that submits state-change request

- `csrf_protect` decorator used to wrap routes handling POST requests. it extracts the token from session and form, comparing them to ensure they match. request aborted (403) if token is missing or they don't match.

- token regenerated for each session to ensure uniqueness and is removed from session after verification (prevents reuse).

**14. Develop a function to validate and sanitize user input to prevent XML External Entity (XXE) attacks in an XML parsing module.**

XXE attacks exploit XML parsers by tricking them into executing unauthorized actions (accessing local/remote files). 

```python
from lxml import etree
from io import StringIO

def safe_parse(xml_input):
    """
    args:
    - xml_input (str): string containing XML data to be parsed

    returns:
    - object: lxml.etree object if parse is successful (None, otherwise)
    """
    try:
        # config XML parser to disable document type definitions (DTDs) + external entities
        parser = etree.XMLParser(no_network=True, dtd_validation=False, load_dtd=False)
        parser.resolvers.add(BlockExternalEntitiesResolver()) # custom resolver to block external entities

        # parse XML
        tree = etree.parse(StringIO(xml_input), parser)
        return tree
    except etree.XMLSyntaxError as e:
        print(f"XML parsing error: {e}")
        return None

class BlockExternalEntitiesResolver(etree.Resolver):
    """
    custom revolver that prevents external entity resolution
    """
    def resolve(self, url, public_id, context):
        return self.resolve_string("", context) # return empty string for external entity
    
# example
if __name__ == "__main__":
    xml_input = """<?xml version="1.0"?>
    <!DOCTYPE data [
    <!ENTITY example SYSTEM "file:///etc/passwd">
    ]>
    <data>&example;</data>"""
    result = safe_parse(xml_input)
    if result is not None:
        print("XML parsed without XXE!")
    else:
        print("failed to parse XML")
```

**15. Write code to implement secure cookie attributes such as HttpOnly and Secure flags to enhance session security in a web application.**

the flags help mitigate risks of client-side script access to protected cookie data and ensure cookies are sent over HTTPS. 

```python
from flask import Flask, request, make_response
app = Flask(__name__)

@app.route('/')
def index():
    # create response object
    resp = make_response("hello, world!")

    # set secure cookie on response
    resp.set_cookie(
        'session_id',
        'secure_session_id',
        secure=True, # cookie sent over HTTPS
        httponly=True, # prevent access to cookie via client-side script (XSS)
        samesite='Lax' # Strict/Lax restricts cross-site sharing
    )
    return resp
if __name__ == "__main__":
    app.run(ssl_context='adhoc') # testing with self-signed cert
```

**16. Create a script to detect and prevent Insecure Direct Object References (IDOR) vulnerabilities in an API endpoint.**

IDOR occurs when an app provides direct access to objects based on user input. 
validate current user's perms to access requested object. 
assume there's a user auth system and each object (profile) has an associated user ID to check against.

```python
from flask import Flask, request, jsonify, abort
from functools import wraps

app = Flask(__name__)

# function that fetches user ID from session
def get_user_id():
    # in a real app, return auth user ID from session or token
    return 1 # assuming user with ID 1 is current user

# db of user profiles
user_profiles = {
    1: {"id": 1, "name": "john", "email": "john@example.com"},
    2: {"id": 2, "name": "jane", "email": "jane@example.com"},
}

def access_require(f):
    """
    decorator that checks if current user has access to requested user object
    """
    @wraps(f)
    def decorated(user_id, *args, **kwargs):
        current_id = get_user_id()
        if current_id != user_id:
            abort(403) # if IDs don't match
        return f(user_id, *args, **kwargs)
    return decorated

@app.route('/api/user/<int:user_id>', methods=['GET'])
@access_require
def get_profile(user_id):
    """
    API endpoint that gets user profile
    access restricted to profile owner!
    """
    user_profile = user_profiles.get(user_id)
    if user_profile:
        return jsonify(user_profile)
    else:
        abort(404) # if profile doesn't exist
    
if __name__ == "__main__":
    app.run(debug=True)
```

**17. Implement a secure password policy enforcement mechanism that includes complexity requirements and password expiration in a user authentication system.**

**18. Develop a function to securely handle error messages to prevent information leakage that could be exploited by attackers.**

**19. Design a script to enforce Content-Type validation for file uploads to prevent MIME sniffing attacks in a web application.**

**20. Write code to implement data encryption at the field level using format-preserving encryption (FPE) techniques for sensitive information storage.**

this allows output (encrypted) to be in the same format as input (original, unencrypted). useful for encrypting stuff like credit card numbers, social security numbers, other PII.

```python
import pyffx

def encrypt_data(secret_key, data, domain=None):
    """
    args:
    - secret_key (str): used for encryption
    - data (str): data to be encrypted
    - domain (tuple): tuple defining domain of chars for encryption 
    returns:
    - str: encrypted data
    """
    # determine domain based on data type if not specified
    if not domain:
        if data.isdigit():
            domain = ('0123456789', len(data)) # numeric
        else:
            raise ValueError("domain must be specified for non-numeric data")
    
    # init FPE object with secret key + domain
    e = pyffx.Integer(secret_key, domain[0], length=domain[1])

    # encrypt data
    encrypted_data = e.encrypt(int(data))

    # return encrypted data (padded to maintain format)
    return str(encrypted_data).zfill(domain[1])

def decrypt_data(secret_key, encrypted_data, domain=None):
    if not domain:
        if encrypted_data.isdigit():
            domain = ('0123456789', len(encrypted_data))
        else:
            raise ValueError("domain must be specified for non-numeric data")
    
    # init FPE object
    d = pyffx.Integer(secret_key, domain[0], length=domain[1])

    # decrypt data
    decrypted_data = d.decrypt(int(encrypted_data))

    return str(decrypted_data).zfill(domain[1])

# example
if __name__ == "__main__":
    secret_key = "secret"
    original_data = "1234567890123456" # example data (credit card number etc)

    encrypted_data = encrypt_data(secret_key, original_data)
    decrypted_data = decrypt_data(secret_key, encrypted_data)

    print(f"original data: {original_data}")
    print(f"encrypted data: {encrypted_data}")
    print(f"decrypted data: {decrypted_data}")
```



**21. Create a function to securely handle user sessions by implementing session fixation prevention measures in a stateful web application.**

**22. Develop a script to perform input/output validation on external system calls to prevent Command Injection vulnerabilities in an application.**

sanitize user input!

assume a feature that allows users to ping a specified host check its availability

```python
import subprocess
import re

def valid_hostname(hostname):
    """
    validates hostname using regex to ensure it consists of alphanumeric chars, hyphens, periods. very basic validation!
    """
    pattern = r'^[a-zA-Z0-9.-]+$'
    if re.match(pattern, hostname):
        return True
    else:
        return False

def safe_ping(hostname):
    """
    ping host by validating hostname before executing system command
    args:
    - hostname (str)
    returns:
    - str: result of ping
    """

    # validate hostname
    if not valid_hostname(hostname):
        return "error: invalid hostname"
    
    # construct command with validated input
    command = ["ping", "-c", "4", hostname]

    # execute command without shell
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"command execution failed: {e.output}"

# example
if __name__ == "__main__":
    hostname = input("enter hostname to ping: ").strip()
    result = safe_ping(hostname)
    print(result)
```

# hard questions!

**23. Develop a script to implement a custom cryptographic protocol for secure communication between two endpoints, ensuring confidentiality, integrity, and authenticity.**

AES for symmetric encryption
HMAC for integrity check, RSA for digital signatures

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import os

# keygen for RSA
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

# symmetric keygen for AES
symmetric_key = Fernet.generate_key()
cipher = Fernet(symmetric_key)

# encrypt message using fernet (AES)
def encrypt_message(message):
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

# decrypt message
def decrypt_message(encrypted_message):
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()

# sign message using private RSA key
def sign_message(message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# verify signature using public RSA key
def verify_signature(message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

# example
if __name__ == "__main__":
    original_message = "message!"
    encrypted_message = encrypt_message(original_message)
    decrypted_message = decrypt_message(encrypted_message)
    signature = sign_message(encrypted_message)

    print(f"original: {original_message}")
    print(f"encrypted: {encrypted_message}")
    print(f"decrypted: {decrypted_message}")
    print(f"verification: ", verify_signature(encrypted_message, signature))
```

**24. Design a function to detect and mitigate Blind SQL Injection vulnerabilities in a complex database query system with limited error-based feedback.**

```python
import sqlite3

def safe_query(db_path, query, params):
    """
    args:
    - db_path (str): path to db
    - query (str): query to execute, with placeholders for params
    - params (tuple): params to safely inject into query
    returns:
    - list: query results
    """

    # connect
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # execute query safely
    try:
        cursor.execute(query, params)
        results = cursor.fetchall()
        return results
    except sqlite3.Error as e:
        print(f"db error: {e}")
        return []
    finally:
        # close connection
        conn.close()

# example
if __name__ = "__main__":
    db_path = 'path/to/db.db'
    # parametrized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    params = ('exampleUser', 'examplePass') # user input should be sanitized and passed here
    results = safe_query(db_path, query, params)
    for row in results:
        print(row)

```


**25. Write code to implement a secure sandbox environment for executing untrusted code snippets while preventing code injection and privilege escalation.**

use `subprocess` to exec untrusted code in a separate process with restricted privs
irl: use isolated containers or VMs

```python
import subprocess
import os

def run_untrusted(code_snippet, timeout=5):
    # exec code snippet in separate process
    # code_snippet: string containing the code
    # timeout: max exec time (s)

    # path to temp file to store code
    code_file = "/tmp/untrusted.py"

    # write code to temp file
    with open(code_file, "w") as f:
        f.write(code_snippet)

    # define command to run python code in restricted env
    # "nobody" user (drop privs)
    command = ["sudo", "-u", "nobody", "python3", code_file]

    try:
        # exec command with time limit
        result = subprocess.run(command, capture_output=True, text=True, timeout=timepout)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return "", "execution timed out!"
    finally:
        # cleanup: remove temp file
        os.remove(code_file)

# example
if __name__ == "__main__":
    code_snippet = """
    print("hello, sandbox!")
    """
    stdout, stderr = run_untrusted(code_snippet)
    print("STDOUT:", stdout)
    print("STDERR:", stderr)
```

**26. Create a script to perform runtime memory analysis and exploit detection to identify and prevent buffer overflow vulnerabilities in a C/C++ application.**

**27. Develop a function to implement dynamic taint analysis for tracking user-controlled input flow through the application's data flow paths to prevent data leakage.**



**28. Design a secure logging mechanism that includes log integrity verification, log encryption, and tamper-evident logging to ensure data confidentiality and integrity.**

encrypt logs (AES-256)

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib
import os

# secure encryption key
def gen_key(password: str, salt=os.urandom(16)):
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key, salt

# encrypt
def encrypt_message(message: str, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# decrypt
def decrypt_message(encrypted_message: str, key):
    b64 = base64.b64decode(encrypted_message.encode('utf-8'))
    nonce, tag, ciphertext = b64[:16], b64[16:32], b64[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')
```

log integrity verification + tamper-evident logging
compute secure hash for each log entry (incorporate content of log and hash of previous log entry)
append new log entry with hash to a log file
this is a simple demo of a blockchain like structure

```python
import hashlib
import json
import os

LOG_FILE_PATH = 'secure_log.json'

def get_last_hash():
    # hash of last log entry from file
    try:
        with open(LOG_FILE_PATH, 'r') as log_file:
            # go to last line of file to get latest entry
            for line in reversed(list(log_file)):
                last_log = json.loads(line)
                return last_log['hash']
    except (FileNotFoundError, JSONDecodeError, KeyError):
        # if file not found or empty, start with no prev hash
        return ''

def hash_log_entry(entry: str, previous_hash: str) -> str:
    # generate sha-256 hash of log entry + previous log's hash
    hasher = hashlib.sha256()
    hasher.update(f'{entry}{previous_hash}'.encode('utf-8'))
    return hasher.hexdigest()

def append_log(entry: str):
    # append new log entry to file, including hash of prev entry
    previous_hash = get_last_hash()
    new_hash = hash_log_entry(entry, previous_hash)
    log_entry = {
        'log': entry,
        'hash': new_hash
    }

    # append
    with open(LOG_FILE_PATH, 'a') as log_file:
        log_file.write(json.dumps(log_entry) + '\n')

# example
if __name__ == "__main__":
    append_log("user login attempt successful")
    append_log("user accessed confidential document")
```


**29. Write code to implement a secure key management system using Hardware Security Modules (HSMs) for storing and protecting cryptographic keys.**

**30. Develop a script to perform automated security fuzz testing on API endpoints with mutation-based fuzzing techniques to uncover hidden vulnerabilities.**

mutation based fuzzing: inputs systematically modified (mutated) to generate test cases

`@given` used to generate test inputs (`data`) which are mutated strings of at least 1 character

`strategies` module defines type/characteristics of test data

script makes POST request to specified endpoint with mutated data.

any status code outside common codes might indicate a potential vuln.

```python
import requests
from hypothesis import given, strategies as st

API_ENDPOINT = 'http://example.com/api/v1/endpoint'

@given(data=st.text(min_size=1)) # generating random strings
def fuzz_endpoint(data):
    try:
        response = requests.post(API_ENDPOINT, data={'data': data}, timeout=5) # assuming POST request
        # analyze response
        if response.status_code not in [200, 400, 401, 403, 404]:
            print(f"potential vuln found with input '{data}'")
            print(f"status code: {response.status_code}, response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"request failed: {e}")

# example
if __name__ == "__main__":
    fuzz_endpoint()
```

**31. Create a function to implement runtime code integrity checks using Control Flow Integrity (CFI) mechanisms to prevent code-reuse attacks like Return-Oriented Programming (ROP).**

potential whiteboard exercise. 

CFI prevents code-reuse (like ROP) by validating target of each indirect function call at runtime. it points to a valid entry of allowed control flow transfers. these CFI mechanisms are implemented at compiler or OS level.

some notes:

- compiler level CFI options like Clang's `-fsanitize=cfi` or OS stuff designed for this purpose that analyze program's control flow graph at compile time (or enforce policies at runtime)

- compiler-inserted checks are optimized for performance

- irl CFI involves shadow stacks, indirect call site protections, fine-grain control flow graphs. 

here's some python pseudocode.

```python
# dict to hold mapping of valid func calls
# rudimentary CFI table where predefined func calls are allowed
valid_func_calls = {
    'func_a':['func_b', 'func_c'],
    'func_b':['func_a'],
    # other func relationships here
}

def func_a():
    print("executing func_a")
    # some condition/input to call func b or func c
    cfi_check('func_b')

def func_b():
    print("executing func_b")
    # per valid_func_calls table
    cfi_check('func_a')

def cfi_check(target_func, caller_func):
    # simulate CFI check
    # ensure target func is an allowed call
    if target_func in valid_func_calls.get(caller_func, []):
        # execute target func if it's valid
        globals()[target_func]()
    else:
        print(f"CFI violation: {caller_func} is not allowed to call {target_func}")

# example
if __name__ == "__main__":
    func_a() # start program
```

**32. Design a secure microservices architecture with end-to-end encryption, mutual TLS authentication, and distributed access control policies for inter-service communication in a cloud-native environment.**

**33. Design a secure API authentication mechanism using OAuth 2.0 with JWT tokens, token revocation, and token introspection for secure authorization and access control.**

- `/token` issues JWT tokens to authenticated users

- `/revoke` revokes tokens (use a db/cache irl)

- `/introspect` checks if token is active (not expired/revoked)

```python
from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)

SECRET_KEY = "secret_key"

# store revoked tokens here (should be a more persistent storage in prod)
REVOKED_TOKENS = set()

@app.route('/token', methods=['POST'])
def token_gen():
    # simulated OAuth 2.0 token endpoint that issues JWT tokens
    # irl, validate authorization grant here
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "missing user_id"}), 400

    # generate token
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30) # token expiry
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})

@app.route('/revoke', methods=['POST'])
def token_rev():
    # token revoke
    token = request.json.get('token')
    if not token:
        return jsonify({"error": "missing token"}), 400

    # add token to set of revoked tokens
    REVOKED_TOKENS.add(token)
    return jsonify({"message": "token revoked"})

@app.route('/introspect', methods=['POST'])
def token_intro():
    # token introspection
    token = request.json.get('token')
    if not token:
        return jsonify({"error": "missing token"}), 400

    # check if token is in revoked set
    if token in REVOKED_TOKENS:
        return jsonify({"active": False})

    # verify + decode
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"active": True, "user_id": payload["user_id"]})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 401

if __name__ == "__main__":
    app.run(debug=True)
```

can also use `Authlib` with Flask to create a simple OAuth 2.0 server that issues JWT tokens.

**34. Design a function to perform runtime code obfuscation techniques such as control flow flattening and string encryption to deter reverse engineering of critical application logic.**

```python
import random

# add random if-else statements to flatten control flow
def flow_flat(code):
    obfusc_code = ""
    for line in code.split('\n'):  # check if line is not empty
        if line.strip():
            obfusc_code += f"if random.choice([True, False]):\n {line}\n"
        else:
            obfusc_code += '\n'
    return obfusc_code

# caesar cipher encryption to obfuscate strings in code
def string_encr(code):
    encr_code = ""
    for char in code:
        encr_code += chr(ord(char) + 1) # caesar cipher encryption
    return encr_code

# example
orig_code = """
def main():
    print("hello, world!")
"""
obfusc_code = flow_flat(orig_code)
encr_code = string_encr(obfusc_code)

print(f"original code: {orig_code}")
print(f"\nobfuscated code: {obfusc_code}")
print(f"\nencrypted code: {encr_code}")
```

given the example original code here:

```python
def main():
    print("hello, world!")
```

the output would then be

```python
"obfuscated code": if random.choice([True, False]):
def main():
    print("hello, world!")
```

```python
"encrypted code": ef!nboj"!qpxfs
```

**35. Design a secure data encryption scheme using homomorphic encryption techniques for performing computations on encrypted data without decrypting it, ensuring data privacy and confidentiality.**

HE (homomorphic encryption): allows computations on ciphertexts. results in an encrypted result which matches the result of operations performed on the plaintext.

PHE (partially homomorphic encryption): supports unlimited operations of 1 type (addition/multiplication)

SWHE (somewhat homomorphic): supports limited number of addition and multiplication operations

FHE (fully homomorphic): unlimited numbers of addition and multiplication

use `PySEAL` (python wrapper around Microsoft SEAL library - a C++ lib that supports HE)

setting up SEAL context involves defining polynomial modulus degree and coefficient modulus (security + efficiency of encryption)

plaintext data must be encoded into a format suitable for homomorphism and then encrypted

`evaluator` class is used to perform encrypted computations

encrypted data must then be decrypted and decoded

notes:

- HE operations are computationally intensive. params chosen impact performance + security (tradeoff)

- HE is good for implementing secure data processing without revealing it to the computing party


```python
import seal
from seal import CKKSEncoder, Encryptor, Decryptor, Evaluator, SEALContext
from seal import CoeffModulus, SchemeType, EncryptionParameters

def seal_context(poly_modulus_degree=8192):
    params = EncryptionParameters(SchemeType.CKKS)
    params.set_poly_modulus_degree(poly_modulus_degree)
    params.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))
    context = SEALContext.Create(params)
    return context

def HE_ex():
    context = seal_context()
    encoder = CKKSEncoder(context)
    encryptor = Encryptor(context, context.key_context_data().public_key())
    decryptor = Decryptor(context, context.key_context_data().secret_key())
    evaluator = Evaluator(context)

    # encode + decrypt 2 numbers
    num1, num2 = 5.0, 10.0
    ptext1 = encoder.encode(num1, scale=2**40)
    ptext2 = encoder.encode(num2, scale=2**40)
    ctext1 = encryptor.encrypt(ptext1)
    ctext2 = encryptor.encrypt(ptext2)

    # homomorphically compute the sum
    evaluator.add_inplace(ctext1, ctext2)

    # decrypt + decode result
    decr_result = decryptor.decrypt(ctext1)
    deco_result = encoder.decode(decr_result)
    print(f"result of homomorphic computation: {deco_result}")

if __name__ == "__main__:
    HE_ex()

```

**36. Write code to implement runtime memory protection mechanisms like Address Space Layout Randomization (ASLR) and Data Execution Prevention (DEP) to mitigate memory-based attacks.**

these are usually implemented by the OS and the compiler of the app.

ASLR: randomizes memory addresses used by sys/app processes. typically enabled at OS level.

- windows: `/DYNAMICBASE` option with linker

- linux: compilers like GCC enable ASLR by default, but make sure executable is not compiled with `-no-pie` (disables position independence) option. to enable: `gcc -o my_app my_app.c -fPIE -pie`

DEP: prevents code from being executed in certain regions of mem, like stack/heap. 

- windows: DEP enabled by default. use `/NXCOMPAT` linker to ensure.

- linux: DEP aka NX (No-Execute) managed by OS. check if it's supported by looking for `nx` flag: `grep nx /proc/cpuinfo`

here's some simplistic code

```python
import ctypes

# ASLR
try:
    # set ADDR_NO_RANDOMIZE flag using personality
    try:
        result = ctypes.CDLL("libc.so.6").personality(0x004000)
        if result == -1:
            print("could not change process personality")
        else:
            print("ASLR disabled for process)
    except Exception as e:
        print(f"error altering ASLR setting: {e}")

# DEP
try:
    if ctypes.windll.kernel32.SetProcessDEPPolicy(0x00000001):
        print("DEP enabled")
    else:
        print("DEP could not be enabled")
except Exception as e:
    print("error enabling DEP:", e)
```

can also check if DEP is enabled like this

```c
#include <stdio.h>
#include <windows.h>

int main() {
    DWORD dwFlags;
    BOOL bRet = GetProcessDEPPolicy(GetCurrentProcess(), &dwFlags, NULL);
    if (bRet) {
        if (dwFlags & PROCESS_DEP_ENABLE) {
            printf("DEP enabled for process\n");
        } else {
            printf("DEP not enabled for process\n");
        }
    } else {
        printf("failed to retrieve DEP policy for process\n");
    }
    return 0;
}
```

**37. Develop a script to implement a secure data masking algorithm for sensitive information in a database to protect privacy and comply with data protection regulations.**

simple masking technique for emails and phone numbers

```python
import sqlite3
import re

def mask_email(email):
    # email masker that keeps domain part intact
    user, domain = email.split('@')
    return f"{user[0]}***@{domain}"

def mask_phone(phone):
    # hide middle part of phone number
    return f"{phone[:3]}***{phone[-3:]}"

def update_data(db_path):
    # connect to db and update info with masked values
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # fetch
        cursor.execute("SELECT id, email, phone FROM users")
        users = cursor.fetchall()

        for user in users:
            user_id, email, phone = user
            # apply mask
            masked_email = mask_email(email)
            masked_phone = mask_phone(phone)

            # update db with masked vals
            cursor.execute("UPDATE users SET email = ?, phone = ?, WHERE id = ?", (masked_email, masked_phone, user_id))

        conn.commit()
        print("data mask successful!")
    except sqlite3.Error as e:
        print(f"db error: {e}")
    
    finally:
        if conn:
            conn.close()

# example
if __name__ == "__main__:
    db_path = "path/to/db.db"
    update_data(db_path)
```

notes: 

- irreversible. consider encryption

- execute in secure manner if integrating with web apps/APIs

- make sure it's compliant

- backup first

**38. Write code to implement a secure session hijacking detection mechanism using behavioral analysis and anomaly detection algorithms.**

use heuristics here: IP address consistency + user agent string matching to flag potential hijacking attempts

irl use stuff like session duration, request patterns, geolocation, etc.

```python
import hashlib

class Session:
    def __init__(self, user_id, ip_addr, user_agent):
        self.user_id = user_id
        self.ip_addr = ip_addr
        self.user_agent = user_agent
        self.session_token = self.generate_session_token()

    def session_token_gen(self):
        hash_input = (self.user_id + self.ip_addr + self.user_agent).encode()
        return hashlib.sha256(hash_input).hexdigest()

    def validate_session(self, ip_addr, user_agent):
        # if IP or user agent changes, flag as potential hijack
        if self.ip_addr != ip_addr or self.user_agent != user_agent:
            return False # potential hijacking detected
        return True # session may be legit
# example
orig_session = Session("user123", "192.168.1.1", "Mozilla/5.0")

# simulate request from same user but different IP + UA
req_ip = "192.168.1.2" # changed network
req_ua = "Mozilla/5.0" # same browser

if orig_session.validate_session(req_ip, req_ua):
    print("session valid")
else:
    print("potential session hijack")
```



**39. Create a script to automate the process of identifying and patching known vulnerabilities in third-party libraries and dependencies using vulnerability databases like NVD.**

**40. Develop a function to implement secure deserialization practices to prevent deserialization vulnerabilities like remote code execution in Java or .NET applications.**

this occurs when ana app deserializes untrusted data, leading to execution of malicious code.

java:

- libraries like Jackon/Gson for JSON parsing provide more control (don't automatically execute methods on deserialized objects)

- custom `readObject` methods to validate/sanitize before deserialization

- serialization filters like `java.io.ObjectInputFilter` specify criteria for incoming data

```java
import java.io.*;
public class SafeDeserialization {
    public static void setupSerializationFilter() {
        ObjectInputFilter filter = info -> {
            if (info.depth() > 5) {
                // limit depth to prevent complex data structures
                return ObjectInputFilter.Status.REJECTED;
            }
            if (info.references() > 1000) {
                // limit references to prevent reference flooding
                return ObjectInputFilter.Status.REJECTED;
            }
            return ObjectInputFilter.Status.ALLOWED;
        };
        ObjectInputFilter.Config.setSerialFilter(filter);
    }
    public static Object safelyDeserialization(byte[] data) throws IOException, ClassNotFoundException {
        setupSerializationFilter();

        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        } catch (InvalidClassException | StreamCorruptedException | ClassNotFoundException e) {
            // handle exception
            throw e;
        }
    }
    public static void main(String[] args) {
        // code code code
    }
}
```

in .NET:

```csharp
using System;
using System.Runtime.Serialization;
using System.IO;
using Newtonsoft.Json;

[DataContract]
public class SafeObject {
    [DataMember]
    public string Data { get; set; }
}

public class SafeDeserialization {
    public static T Deserialize<T>(string json) {
        // additional validation logic here
        return JsonConvert.DeserializeObject<T>(json);
    }

    public static void Main(string[] args) {
        // example
        string safeJson = "{\"Data\":\"Safe Data\"}";
        var safeObject = Deserialize<SafeObject>(safeJson);
        Console.WriteLine(safeObject.Data);
    }
}
```






**41. Develop a script to perform static code analysis on source code files to identify security vulnerabilities such as buffer overflows, injection flaws, and insecure cryptographic practices.**

scan source code files based on pattern matching
irl tools: SonarQube, Fortify, Brakeman (Ruby on Rails), Bandit (Python)

using basic pattern matching to identify insecure crypto (weak hashing):

```python
import re
import os

# define patterns
patterns = {
    'md5': re.compile(r'\bmd5\b'),
    'sha1': re.compile(r'\bsha1\b'),
}

# list of files/dirs to exclude
excludes = ['venv', 'node_modules', '.git']

def is_excluded(path):
    for exclude in excludes:
        if exclude in path:
            return True
    return False

def scan_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()
        for key, pattern in patterns.items():
            if pattern.search(content):
                print(f"insecure usage of {key.upper()} found in {file_path}")

def scan_directory(directory):
    for root, dirs, files in os.walk(directory):
        # filter out excluded
        dirs[:] = [d for d in dirs if not is_excluded(d)]
        for file in files:
            if file.endswith(('.py', '.js', '.java', '.c', '.cpp')):
                scan_file(os.path.join(root, file))

if __name__ == "__main__":
    directory_to_scan = '.' # current dir
    scan_directory(directory_to_scan)
```


**42. Create a function to implement secure cross-origin resource sharing (CORS) policies with fine-grained access controls and preflight request handling in a web application.**

**43. Implement a cypher which converts text to emoji or something.**

```python
def text_emoji(text):
    char_emoji = {
        'a': '😀', 'b': '😃', 'c': '😄', 'd': '😁', 'e': '😆',
        'f': '😅', 'g': '😂', 'h': '🤣', 'i': '😊', 'j': '😇',
        'k': '🙂', 'l': '🙃', 'm': '😉', 'n': '😌', 'o': '😍',
        'p': '🥰', 'q': '😘', 'r': '😗', 's': '😙', 't': '😚',
        'u': '😋', 'v': '😛', 'w': '😝', 'x': '😜', 'y': '🤪',
        'z': '😏', ' ': '👻', '1': '1️⃣',
        '2': '2️⃣', '3': '3️⃣', '4': '4️⃣', '5': '5️⃣',
        '6': '6️⃣', '7': '7️⃣', '8': '8️⃣', '9': '9️⃣',
        '0': '0️⃣'
    }

    # convert each char in input to emoji
    emoji_mess = ''.join([char_emoji.get(char, '?') for char in text.lower()])

    return emoji_mess

# example
input_t = "helloworld"
emoji_t = text_emoji(input_t)
print(f"original: {input_t}\nemoji: {emoji_t}")
```

**44. Write code to enforce transport layer security (TLS) for all traffic and implement certificate pinning to prevent man-in-the-middle attacks.**

use `requests` library and `certifi` to enforce TLS and implement cert pinning. 

need server's expected cert fingerprint (use browser or OpenSSL: `openssl s_client -connect yourdomain.com:443 -servername yourdomain.com | openssl x509 -noout -fingerprint -sha256`)

output of fingerprint is like this:

```bash
SHA256 Fingerprint=12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0
```

```python
import hashlib
import requests
from requests.exceptions import SSLError

# SHA256 fingerprint
exp_fingerprint = '12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0' # remove colons

def get_fingerprint(url):
    # get actual fingerprint of cert
    try:
        # make request to fetch
        response = requests.get(url, timeout=5)
        # access server cert
        cert = response.raw.connection.sock.getpeercert(binary_form=True)
        # calculate
        sha256_fingerprint = hashlib.sha256(cert).hexdigest()
        return sha256_fingerprint
    except SSLError as e:
        print(f"SSL error: {e}")
        return None

def verify_cert(url):
    # verify cert matches fingerprint
    fingerprint = get_fingerprint(url)
    if fingerprint == exp_fingerprint:
        print("cert verification successful")
        return True
    else:
        print("cert verification failed!")
        return False

# verify with url
url = 'https://yourdomain.com'

if verify_cert(url):
    # request logic
    response = requests.get(url)
    # response logic
else:
    # verification failure logic
    print("aborting!")
```






