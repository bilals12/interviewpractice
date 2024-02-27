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