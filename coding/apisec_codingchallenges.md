# API Security coding challenges

# important

## storing creds as env variables

### linux/macOS

temporary (current terminal session):

```bash
export VARIABLE_NAME='value'
```

permanent:

```bash
nano ~/.bash_profile
nano ~/.bashrc
nano ~/.zshrc
```

add following line at the end of the file:

```bash
export VARIABLE_NAME='value'
```

restart terminal or source profile file:

```bash
source ~/.bash_profile
source ~/.bashrc
source ~/.zshrc
```

### windows

temporary:

```cmd
set VARIABLE_NAME=value
```

permanent:

edit system environment variables
under "user variables" or "system variables" click "new"
enter the name of variable and value, click OK

## calling env variables in python

```python
import os
VARIABLE_NAME = os.getenv('VARIABLE_NAME')
```

# some basic questions

**Implement a simple API endpoint in Flask/Django that requires an API key validation before responding. The candidate should check for the presence of the API key in headers or parameters, validate it against pre-shared values in code/db, return 401 unauthorized response if invalid key.**

create flask app, define API endpoint that checks for API key, validate key against pre-shared value, return 401 (unauthorized) if key is invalid

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

# pre-shared API key
VALID_KEY = {'hfhfhfhfhf'}

@app.route('/data', methods=['GET'])
def secure_data():
    # extract API key from headers
    api_key = request.headers.get('x-api-key')

    # validate key
    if api_key in VALID_KEY:
        # some logic here for authorized users
        return jsonify({"message": "access granted!"}), 200
    else:
        # API key not present or invalid
        return jsonify({"error": "unauthorized"}), 401

if __name__ == '__main__':
    app.run(debug=True)
```


**Write a script that fetches data from a public API like weather/news API. The code should use requests library to make the API call over HTTPS, handle authentication if required in the form of API keys and validate the SSL certificates to prevent MITM attacks.**

`requests` library supports HTTPS and validates SSL by default

```python
import requests

def fetch_data(api_key, city):
    # returns dict containing weather data
    base_url = "https://api.openweathermap.org/data/2.5/weather"
    params = {
        "q": city,
        "appid": api_key,
        "units": "metric" # celsius
    }
    try:
        response = requests.get(base_url, params=params)
        # validate response
        response.raise_for_status() # HTTPError if status is 4xx/5xx
        return response.json() # parse + return JSON response
    except requests.exceptions.HTTPError as errh:
        return {"error": f"HTTP error: {errh}"}
    except requests.exception.ConnectionError as errc:
        return {"error": f"connection error: {errc}"}
    except requests.exceptions.Timeout as errt:
        return {"error": f"timeout error: {errt}"}
    except requests.exceptions.RequestException as err:
        return {"error": f"unexpected error: {err}"}
    
# example
api_key = "hfhfhfhfhfhf" # replace with OpenWeatherMap API key
city = "Toronto"
weather_data = fetch_data(api_key, city)
print(weather_data)
```



**Create a basic REST API in Python that requires JWT token based authentication. The candidate should implement JWT generation with claims, signature using HS256 and validate JWT token in the request before returning the response.**

implement API with JWT auth

```python
from flask import Flask, jsonify, request, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# setup extension
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
jwt = JWTManager(app)

# mock db of registered users
users = {"user1": "password"}

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    # validate user creds
    if username not in users or users[username] != password:
        return jsonify({"msg": "bad username/password"}), 401

    # create JWT token
    access_token = create_access_token(identity=username)
    return jsonify({access_token=access_token})

@app.route('/protected', methods=['GET'])
@jwt_required() # protect route with JWT
def protected():
    # access identity of current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True)
```

- `JWT_SECRET_KEY` used to sign JWT tokens

- `/login` endpoint accepts username:password, validates, returns JWT token

- `/protected` is a protected route that requires a valid JWT token to access. `@jwt_required()` ensures that requests include a valid JWT token in Authorization header

- `create_access_token()` generates JWT token with identity

- send `POST` request to `/login` with JSON body containing username:password

- send `GET` request to `/protected` with JWT token included in Authorization header as `Bearer <token>`

**Develop code to upload a file to a cloud storage API like S3/Cloudinary/Azure Blob Storage by making proper access key based authenticated requests for secure file transfer over TLS.**

upload file to S3
use `boto3` library

```bash
pip install boto3
```

configure AWS creds 
create cred file (`~/.aws/credentials` on unix, `%UserProfile\.aws\credentials` on windows)

```java
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
```

now upload file using python

```python
import boto3
from botocore.exceptions import NoCredentialsError

def upload(file_name, bucket_name, object_name=None):
    # if S3 object name not specified, use file_name
    if object_name is None:
        object_name = file_name

    # upload file
    s3_client = boto3.client('s3')
    try:
        s3_client.upload_file(file_name, bucket_name, object_name)
    except NoCredentialsError:
        print("creds not available")
        return False
    return True

# example
file_name = 'path/to/file'
bucket_name = 's3-bucket'
object_name = 'object-name' # optional

success = upload(file_name, bucket_name, object_name)
if success:
    print("file uploaded!")
else:
    print("upload failed.")
```

**Write a script to access and manipulate remote database like MongoDB Atlas by connecting using SRV connection strings from python application, handling TLS/SSL to encrypt traffic between app and database.**

```bash
pip install pymongo
```

the connection string

```php
mongodb+srv://<username>:<password>@<cluster-url>/test?retryWrites=true&w=majority
```

atlas automatically uses TLS/SSL as long as you use SRV connection string

```python
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# connection string
uri = "mongodb+srv://<username>:<password>@<cluster-url>/test?retryWrites=true&w=majority"

# connect to cluster
client = MongoClient(uri)

try:
    # ismaster command doesn't require auth
    client.admin.command('ismaster')
    print("connection successful!")
except ConnectionFailure:
    print("connection failed.")

# specify db/collection
db = client['db_name']
collection = db['coll_name']

# insert document
insert_result = collection.insert_one({"name": "john doe", "email": "john@example.com"})
print(f"inserted document id: {insert_result.inserted_id})

# find document
found_document = collection.find_one({"name": "john doe"})
print(f"found document: {found_document}")

# close connection
client.close()
```

**Create a simple microservice that fetches data from another microservice by making an internal API call. The code should implement mutual TLS authentication between the services to establish identity and secure communication.**

mTLS: both client + server authenticate each other

## flask

setting up server
set up a simple Flask app with 1 route (`/data`). 
configured to use SSL with `ssl_context`, which is set up to require client certs (`ssl.CERT_REQUIRED`)

```python
from flask import Flask, jsonify
import ssl

app = Flask(__name__)

@app.route('/data')
def get_data():
    return jsonify({'message': 'secure data from microservice'})

if __name__ == '__main__':
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    context.load_verify_locations(cafile='ca.crt')
    context.verify_mode = ssl.CERT_REQUIRED
    app.run(port=5001, ssl_context=context)
```

setting up client

```python
import requests
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

# custom ssl context to enforce client cert
ssl_context = create_urllib3_context(
    cert_reqs='CERT_REQUIRED',
    ca_certs='ca.crt', # path to CA cert
    keyfile='client.key', # path to client's priv key
    certfile='client.crt' # path to client's cert
)
def fetch_data():
    # fetch data from microservice
    response = requests.get('https://localhost:5001/data', verify='ca.crt', cert=('client.crt', 'client.key'), # client cert for authentication
    proxies={'https': None}) # avoid proxies in local setup

    print(response.json())
if __name__ == '__main__':
    fetch_data()
```

## fastAPI

server setup

```python
from fastapi import FastAPI
app = FastAPI()

@app.get("/data")
async def get_data():
    return {"message": "secure data from microservice"}
```

to enforce mTLS, run uvicorn with SSL configs pointing to server cert, private key and CA cert for client auth
run server from command line

```bash
uvicorn app:app --host 0.0.0.0 --port 5001 --ssl-keyfile=./server.key --ssl-certfile=./server.crt --ssl-ca-certs=./ca.crt --ssl-cert-reqs=2
```

setting up client
use `httpx` which is async

```python
import httpx

async def fetch_data():
    async with httpx.AsyncClient(verify='ca.crt', cert=('client.crt', 'client.key')) as client:
        response = await client.get('https://localhost:5001/data')
        print(response.json())
```

server managed by ASGI server (uvicorn) command line options for SSL

## without flask/FastAPI

1. generate cert using OpenSSL

2. server.py

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'hello!!!!')

def run(server_class=HTTPServer, handler_class=SimpleHandler, port=4443):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile='server.crt', keyfile='server.key', ssl_version=ssl.PROTOCOL_TLS, ca_certs='ca.crt', cert_reqs=ssl.CERT_REQUIRED)
    print(f'starting httpd on port {port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run()
```

3. client.py

```python
import http.client
import ssl

def make_request(host='localhost', port=4443):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='ca.crt')
    context.load_cert_chain(certfile='client.crt', keyfile='client.key')

    connection = http.client.HTTPSConnection(host, port, context=context)
    connection.request('GET', '/')
    response = connection.getresponse()
    print(f'status: {response.status}, reason: {response.reason}')
    data = response.read()
    print(data.decode())

if __name__ == '__main__':
    make_request
```

**Implement a rate limiting logic for an API endpoint that uses a token bucket algorithm to allow only a certain number of requests per minute from an API consumer. The code should check the token count before processing request and return 429 Too Many Requests response if rate limit exceeds.**

track number of available tokens for each API consumer, replenish tokens at fixed rate
if bucket runs out, reqs denied until tokens replenished

```python
from flask import Flask, jsonify, request
import time

app = Flask(__name__)

# config rate limiting
RATE_LIMIT = 5 # 5 reqs per min
REFILL_TIME = 60 # refill rate (s)
buckets = {} # dict to keep track of buckets for each consumer

def get_bucket(ip):
    # get current state of bucket
    # create new bucket if it doesn't exist
    if ip not in buckets:
        # each bucket is a list: [available tokens, last refill timestamp]
        buckets[ip]: [RATE_LIMIT, time.time()]
    return buckets[ip]

def refill_tokens(bucket):
    # refill bucket based on elapsed time since last refill
    now = time.time()
    elapsed = now - bucket[1] # time since last refill
    # calculate how many tokens to add
    tokens_add = (elapsed // REFILL_TIME) * RATE_LIMIT
    if tokens_add > 0:
        bucket[0] = min(bucket[0] + tokens_add, RATE_LIMIT) # don't exceed RATE_LIMIT
        bucket[1] = now

@app.route('/api/resource')
def protected_resource():
    client_ip = request.remote_addr # use client IP as API consumer ID
    bucket = get_bucket(client_ip)
    # refill bucket based on elapsed
    refill_tokens(bucket)
    if bucket[0] > 0:
        bucket[0] -= 1 # consume 1 token
        return jsonify({'message': 'request successful'}), 200
    else:
        # no tokens available (rate limit exceeded)
        return jsonify({'error': 'too many requests'}), 429

if __name__ == '__main__':
    app.run(debug=True)
```

- `RATE_LIMIT` defines max number of reqs allowed per minute (per consumer)

- `REFILL_TIME` defines how often tokens are replenished

- `buckets` dict tracks token buckets for each consumer, id'd by IP address. each bucket contains number of available tokens, and timestamp of last refill

- per req, script checks if there are available tokens in the bucket. if tokens are available, it takes 1 token and allows req. otherwise: 429

- `refill_tokens` calculates number of tokens to add based on elapsed time. makes sure bucket's token count does not exceed rate limit

- irl, using API keys or some other form of authentication besides IP address

- use Redis for prod environments (manage rate limiting across multiple server instances)

### without flask:

define token bucket rate limiter

```python
import time

class TokenBucket:
    def __init__(self, tokens, fill_rate):
        self.capacity = tokens
        self._tokens = tokens
        self.fill_rate = fill_rate
        self.timestamp = time.time()
    
    def consume(self, tokens=1):
        # consume tokens from bucket
        now = time.time()
        elapsed = now - self.timestamp
        self._tokens += elapsed * self.fill_rate
        self.timestamp = now

        # bucket should not exceed cap
        if self._tokens > self.capacity:
            self._tokens = self.capacity

        # consume only if there are enough
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False
```

server with rate limiting:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

# init global rate limiter
# 5 tokens + refill 5 tokens per min (5/60 per s)
rate_limiter = TokenBucket(tokens=5, fill_rate=5/60)

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # check if req is allowed by rate limiter
        if not rate_limiter.consume():
            self.send_response(429, "too many reqs")
            self.end_headers()
            self.wfile.write(b"rate limit exceeded. try again later!")
            return
        
        # handle allow
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello!")

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"starting httpd on port {port}")
    httpd.serve_forever()

if __name__ == '__main__':
    # run server in separate thread (concurrency)
    server_thread = threading.Thread(target=run)
    server_thread.daemon = True
    server_thread.start()

    input("press enter to stop server\n")
```

**Write code to call an API that requires OAuth 2.0 authentication. The script should implement authorization code grant type flow - make a token endpoint call to get access token by passing client ID, secret and then use the access token to call the API.**

redirect user to authorization server
get authorization code
exchange code for token

```python
from flask import Flask, request, redirect
import requests

app = Flask(__name__)

client_id = 'client_id'
client_secret = 'client_secret'
redirect_uri = 'http://localhost:5000/callback'
authorization_url = 'https://authorization-server.com/auth'
token_url = 'https://authorization-server.com/token'
scope = 'read'

@app.route('/login')
def login():
    auth_url = f"{authorization_url}?response_type=code?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}"
    return redirect{auth_url}

@app.route('/callback')
def callback():
    code = request.args.get('code')
    access_token = get_access_token(code)
    # use access_token to call API
    return 'API call response'

def get_access_token(code):
    payload = {
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'redirect_uri': redirect_uri
    }
    response = requests.post(token_url, data=payload)
    response_data = response.json()
    return response_data['access_token']

if __name__ == '__main__':
    app.run(debug=True)
```

### without flask:

```python
import requests
# if storing creds as env variables:
# import os

# OAuth2.0 endpoint
token_url = 'https://authorization-server.com/oauth/token'
api_url = 'https://api.example.com/data'

# client creds (obtain from OAuth provider)
client_id = 'client_id'
client_secret = 'client_secret'
# if storing creds as env variables:
# client_id = os.getenv('CLIENT_ID')
# client_secret = os.getenv('CLIENT_SECRET')

# get access token
def get_token(client_id, client_secret):
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }
    response = requests.post(token_url, data=payload)
    # check for valid resp
    if response.status_code == 200:
        return response.json()['access_token']
    else:
        raise Exception("failed to obtain access token")

# call API with access token (authenticated req)
def call_api(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(api_url, headers=headers)
    return response.json()

# example
try:
    # if calling creds from env variables:
    # if not client_id or not client_secret:
        # raise Exception("Client ID or Client Secret not set in environment variables")
    access_token = get_token(client_id, client_secret)
    api_response = call_api(access_token)
    print(api_response)
except Exception as e:
    print(f"error: {e}")
```

- `/login` route constructs authorization URL and redirects user to it

- 

**Create an API endpoint that fetches data from a database and returns response in JSON format. The code should sanitize any user input parameters before using them in database queries to prevent SQL injection attacks.**

assume we create an app: `app.py`
assume we have a SQLite db named `example.db`: table `users` with cols `id`, `name`, `email`

```python
from flask import Flask, request, jsonify, g
import sqlite3

DATABASE = 'example.db'
app = Flask(__name__)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_conn(exception):
    # close db connection automatically when app context ends
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    # execute queries with params
    # uses parametrized queries (query, args) to prevent SQLi by separating query structure from data
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def sanitize_input(user_input):
    # basic implementation: remove non-alphanumeric chars from input
    # use 'bleach' for more complex data
    return ''.join(e for e in user_input if e.isalnum())

@app.route('/api/users', methods=['GET'])
# accepts 'id' param, sanitizes it, uses it in parametrized query to fetch user data
def get_users():
    user_id = request.args.get('id', '')
    user_id = sanitize_input(user_id) # sanitize input
    if user_id:
        # using parametrized queries
        user = query_db('select * from users where id = ?', [user_id], one=True)
    else:
        user = query_db('select * from users')
    return jsonify(user)

if __name__ == '__main__':
    app.run(debug=True)
```

executing script: `python app.py`

access API endpoint: `https://127.0.0.1:5000/api/users?id=1`


**Develop a script to upload a file to an API endpoint that accepts multipart encoded file data. The code should check the uploaded file content type, size as per application logic requirements, scan contents for viruses/malware before storing on the server to prevent file based attacks.**

```python
from flask import Flask, request, jsonify
import magic
import os

app = Flask(__name__)

upload_folder = '/path/to/directory'
allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
max_file_size = 1024 * 1024 * 10 #10MB

app.config['UPLOAD_FOLDER'] = upload_folder

def allowed_file(filename):
    # check if file extension allowed
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def check_file(file_stream):
    # check file content type
    mime = magic.Magic(mime=True)
    file_mime_type = mime.from_buffer(file_stream.read(1024))
    file_stream.seek(0) # reset file stream position
    return file_mime_type in ['text/plain', 'application/pdf', 'image/png', 'image/jpeg', 'image/gif']

def scan_file(file_path):
    # scans file for virus/malware
    # this should be replaced with an actual scan implementation
    return True # if file is clean

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'no file part'}), 400
    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'no selected file'}), 400

    if file and allowed_file(file.filename):
        if file.mimetype not in allowed_extensions:
            return jsonify({'error': 'file type not allowed'}), 400
        if file.content_length > max_file_size:
            return jsonify({'error': 'file size exceeds limit'}), 400
        if not check_file(file.stream):
            return jsonify({'error': 'file content does not match type'}), 400
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        if not scan_file(filepath):
            os.remove(filepath) # remove file if it's flagged
            return jsonify({'error': 'file infected'}), 403
        
        return jsonify({'message': 'file upload successful'}), 200
    
    return jsonify({'error': 'file type not allowed'}), 400

if __name__ == '__main__':
    app.rub(debug=True)
```

- can use ClamAV tool

- or use some of the following methods: checksums, 


# some more complicated questions


**A. Develop a script to implement OAuth 2.0 authentication with JWT tokens for securing access to an API endpoint.**

need:

- OAuth 2.0 server for token issuance

- resource server (RS) that hosts protected API endpoints

- client app that makes request to access user's resources

script should simulate issuing a JWT token upon successful login then require token for accessing protected endpoint

```bash
pip install Flask PyJWT
```

```python
from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)

# secret key (keep secret irl)
SECRET_KEY = "secret!"

# dummy user data
USERS = {
    "user1": "password1",
    "user2": "password2"
}

# grabbing token from /login endpoint
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if username in USERS and USERS[username] == password:
        # create JWT token
        token = jwt.encode({
            'sub': username,
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, SECRET_KEY, algorithm='HS256')
        return jsonify({'token': token})
    else:
        return jsonify({'message': 'invalid username/password'}), 401

# using token to access /protected endpoint
@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if token is None:
        return jsonify({'message': 'missing token'}), 401

    try:
        # attempt to decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'message': f'access granted for {payload["sub"]}'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'invalid token'}), 401

if __name__ == '__main__':
    app.run(debug=True)
```

`/login` endpoint simulates the login process. it accepts username/password, verifies against `USERS` dict, issues JWT token if auth is a success. `sub` is username, `iat` is issued at time, `exp` is expiration time.

`/protected` endpoint requires a valid JWT token to access. client must send token in the `Authorization` header. server decodes and verifies token using secret key. 

JWT tokens are encoded using the `SECRET_KEY`. 

**B. Create a function to enforce rate limiting and request throttling mechanisms on API endpoints to prevent abuse and DoS attacks.**

**Develop a Python function to implement rate limiting on API endpoints based on user authentication tokens to prevent abuse and ensure fair usage of resources**

track requests per token with specified time window. use Redis in prod environments

```python
from flask import Flask, request, jsonify
from functools import wraps
import time

app = Flask(__name__)

# store request count for each token in dict
request_count = {}

# max number of reqs allowed per period per token
req_limit = 5

# time window for rate limit (s)
time_window = 60

def rate_limiter(func):
    # decorator to enforce rate limits on API endpoints
    # use request token to track + limit reqs
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')

        # ensure token exists
        if not token:
            return jsonify({'message': 'missing/invalid token'}), 403

        current_time = time.time()
        # init/update request_count + timestamp of token
        if token not in request_count or current_time = request_count[token][1] > time_window:
            request_count[token] = [1, current_time] # reset count + update timestamp
        else:
            request_count[token][0] += 1 # increment request_count

            # check if req limit exceeded
            if request_count[token][0] > req_limit:
                return jsonify({'message': 'rate limit exceeded. try again later.'}), 429
        return func(*args, **kwargs)
    return wrapper

@app.route('/protected', methods=['GET'])
@rate_limiter
def protected():
    # protected endpoint that applies rate limiting based on user token
    return jsonify({'message': 'rate limited resource. access granted'})

if __name__ == "__main__":
    app.run(debug=True)
```

- `rate_limiter` is a decorator applied to any Flask route that requires rate limiting. it'll check + enforce rate limit based on the `Authorization` token provided in request headers.

**C. Implement TLS/SSL encryption for secure communication between clients and the API server, ensuring data confidentiality and integrity.**

set up SSL cert for server and configure server to use HTTPS instead.

generating a self signed SSL cert:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

creates a 4096-bit RSA key and cert valid for 365 days.

enable HTTPS in app:

```python
from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({'message': 'hello HTTPS!'})
if __name__ == "__main__":
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
```

test via curl:

```bash
curl -k https://localhost:5000/
```

**D. Design a script to manage API keys securely, including key generation, rotation, and revocation mechanisms for access control.**

store/manage API keys using simple storage system (irl use db or KMS)

```python
import os
import uuid
import json

# file to store API keys
api_file = 'api_keys.json'

def load_keys():
    if not os.path.exists(api_file):
        return {}
    with open(api_file, 'r') as file:
        return json.load(file)

def save_keys(keys):
    with open(api_file, 'w') as file:
        json.dump(keys, file, indent=4)

def gen_key(description):
    keys = load_keys()
    new_key = str(uuid.uuid4())
    keys[new_key] = {'description': description, 'revoked': False}
    save_keys(keys)
    return new_key

def revoke_key(api_key):
    keys = load_keys()
    if api_key in keys:
        keys[api_key]['revoked'] = True
        save_keys(keys)
        return True
    return False

def rotate_key(old_key, description):
    if revoke_key(old_key):
        return gen_key(description)
    return None

def list_keys():
    keys = load_keys()
    return keys

# example
if __name__ == '__main__':
    # gen new key
    key = gen_key('example key')
    print(f"generated API key: {key}")

    # list API keys
    print("current API keys:")
    for key, details in list_keys().items():
        print(f"key: {key}, description: {details['description']}, revoked: {details['revoked']}")

    # revoke key
    if revoke_key(key):
        print(f"API key revoked: {key}")

    # rotate key
    new_key = rotate_key(key, 'rotated key')
    print(f"new rotated key: {new_key}")
```

notes:

- use secure db to store keys

- ensure keys have limited access rights (least privilege)

- use environment vars or secure vaults

- track creation, usage, rotation, revocation


**E. Develop a logging mechanism to record API requests, responses, and errors for auditing purposes, along with real-time monitoring of API traffic.**

log requests (request path, method, payload)

log responses (status codes, content)

log exceptions/errors

```python
from flask import Flask, request, jsonify
import logging
from logging.handlers import RotatingFieldHandler
import time

app = Flask(__name__)

# logging config
# create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # set log level to INFO

# file handler that logs messages to file with rotation
handler = RotatingFileHandler('api_logs.log', maxBytes=10000, backupCount=3)

# define format for logging messages
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter) # set formatter for file handler

logger.addHandler(handler) # add file handler to logger

# create console handler
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(formatter)
logger.addHandler(consoleHandler) # add console handler to logger

@app.before_request
def before_log():
    # log details of each incoming request before processing
    data = request.get_json() if request.is_json else request.data
    logger.info(f"request: {request.path} method: {request.method} payload: {data}")

@app.after_request
def after_log(response):
    # log details of each response during processing
    logger.error(f"error: {str(e)}", exc_info=True)
    return jsonify(error=str(e)), 500

# demo with sample API
@app.route('/api/test', methods=['GET', 'POST'])
def test():
    # test endpoint to demo GET/POST handling
    if request.method == 'POST':
        # return message indicating data was received for POST
        return jsonify({"message": "data received"}), 200
    else:
        # message for GET
        return jsonify({"message": "welcome!"}), 200

if __name__ == "__main__":
    app.run(debug=True)
```

- sets up logger

- configs logger to write logs to a rotating file (avoid indefinite growth) and console (RTM)

- `RotatingFileHandler` writes logs to file `api_logs.log`, rotating when size `maxBytes=10000` is reached, keeping up to 3 old log files (`backupCount=3`)

- uses Flask's `before_request` and `after_request` decorators

- `handle_exception` catches exceptions and logs error details

**F. Write code to hash API secrets and encrypt database credentials for secure storage and access in API backend code.**

use SHA-256 for hashing API secrets

use `cryptography` library to encrypt db creds

```python
from hashlib import sha256
from cryptography.fernet import Fernet
import base64
import os

# hashing secrets using sha-256
def hash_secret(secret):
    return sha256(secret.encode()).hexdigest()

# encryption/decryption of db creds
def gen_key():
    # encryption key
    return base64.urlsafe_b64encode(os.urandom(32))

def encrypt_data(data, key):
    # encryption method
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    # decryption method
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

# example
if __name__ == "__main__":
    # hashing API secret
    api_secret = "super secret key"
    hashed_secret = hash_secret(api_secret)
    print(f"hashed API secret: {hashed_secret}")

    # encrypting
    db_creds = "user:password"
    key = gen_key()
    encrypted_creds = encrypt_data(db_creds, key)
    print(f"encrypted db creds: {encrypted_creds}")

    # decrypting
    decrypted_creds = decrypt_data(encrypted_creds, key)
    print(f"decrypted db creds: {decrypted_creds}")
```

**G. Develop automated API schema validation checks to prevent data type mismatches and enforce size limits, precision for numeric fields.**

use `pydantic` or `marshmallow` for schema validation (define schema validation)

```python
from pydantic import BaseModel, Field, ValidationError
from typing import List, Optional

class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    age: Optional[int] = Field(None, ge=18, le=120) # between 18 and 120
    email: str
    roles: List[str] = [] # list of roles
    salary: Optional[float] = Field(None, gt=0, le=1000000.00) # greater than 0, less than/equal to 1,000,000

def validate_input(user_data: dict):
    try:
        user = User(**user_data)
        print(f"valid input: {user}")
        return True
    except ValidationError as e:
        print(f"validation error: {e}")
        return False

# example (valid)
valid = {
    "username": "john",
    "age": 30,
    "email": "john@example.com",
    "roles": ["admin", "user"],
    "salary": 50000.90
}

# example (invalid)
invalid = {
    "username": "j",
    "age": 17,
    "email": "john@example.com",
    "roles": ["admin", "user"],
    "salary": 100000000
}

# validation
validate_input(valid) # should pass
validate_input(invalid) # should fail
```

**H. Develop a script to perform automated security fuzz testing on API endpoints with mutation-based fuzzing techniques to uncover hidden vulnerabilities.**

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

**I. Write code to add CORS origins, headers for cross-origin resource sharing configuration in Flask/Django REST framework based APIs.**

## flask

```bash
pip install flask-cors
```

```python
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# config CORS globally (all routes)
CORS(app)

# config CORS for specific routes/origins
cors = CORS(app, resources={r"/api/*": {"origins": "*"}}, supoorts_credentials=True)

@app.route('/api/example')
def example():
    return 'CORS-enabled route'

if __name__ == "__main__":
    app.run(debug=True)
```

## django

```bash
pip install django-cors-headers
```

add `corsheaders` to `INSTALLED_APPS` in `settings.py`:

```python
INSTALLED_APPS = [
    'corsheaders',
    ...
]
```

add `CorsMiddleware` to `MIDDLEWARE` (place it before middleware that can generate responses (`CommonMiddleware` or `WhiteNoiseMiddleware`))

```python
MIDDLEWARE =  [
    'corsheaders.middleware.CorsMiddleware,
    ...
]
```

configure in `settings.py`:

```python
CORS_ALLOW_ALL_ORIGINS = True # allow all origins (not good for prod)

CORS_ALLOWED_ORIGINS = [
    "https://example.com",
    "https://another.com",
]
```

if API needs to accept cookies or auth headers from frontend, add following:

```python
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = ['content-type', 'authorization']
```

**Create a function to implement secure cross-origin resource sharing (CORS) policies with fine-grained access controls and preflight request handling in a web application.**

specify origins, HTTP methods, headers are allowed for cross-origin requests

handling preflight (HTTP OPTIONS) is essential to see if request can be safely made

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

def custom_resp(response, origin, methods=['GET'], allow_credentials=True, max_age=86400, allowed_headers=['Content-Type', 'Authorization']):
    # add CORS headers to response object
    # response: flask response object
    # origin: allowed origin(s) for request
    # methods: list of allowed methods
    # allow_credentials: request can include user creds
    # max_age: how long results of preflight req can be cached
    # allowed_headers: allowed req headers
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Methods'] = ', '.join(methods)
    response.headers['Access-Control-Allow-Headers'] = ', '.join(allowed_headers)
    response.headers['Access-Control-Allow-Credentials'] = 'true' if allow_credentials else 'false'
    response.headers['Access-Control-Max-Age'] = str(max_age)
    return response

@app.before_request
def preflight_handle():
    if request.method == 'OPTIONS':
        preflight_response = jsonify({'status': 'OK'})
        origin = request.headers.get('Origin')
        # add validation logic here
        # for example purposes, allow all origins + methods
        if origin:
            return custom_cors_response(preflight_response, origin=origin)
        else:
            # if origin header missing/not allowed, block request
            return jsonify({'error': 'missing or not allowed origin header'}), 403

@app.after_request
def add_cors_headers(response):
    # add CORS headers to every response
    origin = request.headers.get('Origin')
    # origin validation logic here
    if origin:
        return custom_cors_response(response, origin=origin)
    return response

# example: protected route
@app.route('/protected-resource', methods=['GET', 'POST'])
def protected_resource():
    return jsonify({'message': 'protected resource!'})

if __name__ == "__main__":
    app.run(debug=True)
```

- `custom_cors_reponse` sets CORS headers on response object based on allowed origins, methods, headers

- `handle_preflight_request` intercepts HTTP OPTIONS and applies necessary CORS headers (necessary for browsers to determine whether to proceed with request)


**J. Develop a script to dynamically scan an OpenAPI spec for security misconfigurations and provide remediations.**

look for stuff like missing auth, lack of rate limits, poor validation

```python
import yaml
import requests

def load_spec(file_path):
    # load OpenAPI spec from YAML file
    with open(file_path, 'r') as file:
        spec = yaml.safe_load(file)
    return spec

def check_security(spec):
    if 'components' in spec and 'securitySchemes' in spec['components']:
        print("security definitions found")
    else:
        print("warning: no security definitions found")
    
    for path, operations in spec['paths'].items():
        for operation in operations.values():
            if 'security' not in operation:
                print(f"warning: operation {operation.get('operationId', path)} does not specify security requirements")

def check_rate_limit(spec):
    # rate limiting often defined in infrastructure or app logic

def check_validation(spec):
    for path, operations in spec['paths'].items():
        for operation in operations.values():
            if 'parameters' in operation:
                for param in operation['parameters']:
                    if param.get('required', False) and 'schema' in param:
                        print(f"input validation found for parameter {param['name']} in operation {operation.get('operationId', path)}")
                    else:
                        print(f"warning: no input validation for parameter {param['name']} in operation {operation.get('operationId', path)}")

            if 'requestBody' in operation:
                if 'content' in operation['requestBody']:
                    print(f"input validation found for request body in operation {operation.get('operationId', path)}")
                else:
                    print(f"warning: no input validation for request body in operation {operation.get('operationId', path)}")

def scan_spec(file_path):
    # scan spec for common misconfigs
    spec = load_spec(file_path)
    check_security(spec)
    check_rate_limit(spec)
    check_validation(spec)

# example
if __name__ == "__main__":
    file_path = 'spec.yml'
    scan_spec(file_path)
```


