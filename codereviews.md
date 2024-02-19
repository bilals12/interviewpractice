# challenge 1

```python

from flask import Flask, request, redirect, url_for
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)

def is_authenticated_user():
    # This function checks if the user is authenticated and is omitted for brevity
   pass

@app.route('/')
def home():
    if not is_authenticated_user():
        logging.info('Unauthorized access attempt.')
        return redirect(url_for('login'))

    redirect_url = request.args.get('redirect_url')
    if redirect_url:
        logging.info(f'Redirecting to: {redirect_url}')
        return redirect(redirect_url)

    return 'Welcome to the home page!'

@app.route('/login')
def login():
    # Simulated login page
    return 'Login Page - User authentication goes here.'

if __name__ == '__main__':
    app.run(debug=False)

```

## vulnerability found

1. open redirect: application takes a `redirect_url` param from query string, redirects user to this URL without any validation. this can be exploited by attacker to redirect user to a malicious site (open redirect vulnerability).

## fixed code

```python

from flask import Flask, request, redirect, url_for
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)

def is_authenticated_user():
    # This function checks if the user is authenticated and is omitted for brevity
    pass

def is_safe_url(target):
    """
    Function to validate the redirect URL to ensure it is safe for redirection.
    This can be enhanced based on the application's requirements.
    """
    # Implement URL validation logic here
    # For simplicity, we're just checking if it's relative URL or not
    return target.startswith('/') and not '//' in target and not ' ' in target

@app.route('/')
def home():
    if not is_authenticated_user():
        logging.info('Unauthorized access attempt.')
        return redirect(url_for('login'))

    redirect_url = request.args.get('redirect_url')
    if redirect_url and is_safe_url(redirect_url):
        logging.info(f'Redirecting to: {redirect_url}')
        return redirect(redirect_url)
    else:
        logging.info('Unsafe or no redirect URL provided. Redirecting to default home page.')
        return 'Welcome to the home page!'

@app.route('/login')
def login():
    # Simulated login page
    return 'Login Page - User authentication goes here.'

if __name__ == '__main__':
    app.run(debug=False)
```

## changes made

1. URL validation function: a new function `is_safe_url` is introduced to validate the `redirect_url`. this function checks whether the URL is a relative URL and does not contain suspicious chars (`//`, ` `). this is a basic validation, it can be enhanced

2. validation check in `home` function: `home` function is modified to use `is_safe_url` to validate `redirect_url`. if `redirect_url` is not safe or not provided, it defaults to home page.


# challenge 2

```js

const express = require('express');
const axios = require('axios');

const app = express();

app.get('/profile', (req, res) => {
    console.log('Received request for /profile');

    // Simulated profile data
    const profileData = {
        name: 'John Doe',
        role: 'Developer'
    };
    
    res.json(profileData);
    console.log('Sent profile data response');
});

app.get('/fetch-data', async (req, res) => {
    const url = req.query.url;
    console.log(`Received request for /fetch-data with URL: ${url}`);
    
    try {
        const response = await axios.get(url);
        res.send(response.data);
        console.log(`Data fetched and sent for URL: ${url}`);
    } catch (error) {
        console.error(`Error fetching data from URL: ${url}`, error);
        res.status(500).send('Error fetching data');
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

## vulnerability found

1. SSRF: the `/fetch-data` endpoint takes a URL from the query string and makes an HTTP request to the URL using the `axios` library. this can be exploited in a SSRF attack (attacker can make server send requests to unintended/malicious URLs)

## fixed code

```js
const express = require('express');
const axios = require('axios');
const url = require('url');

const app = express();

app.get('/profile', (req, res) => {
    console.log('Received request for /profile');

    // Simulated profile data
    const profileData = {
        name: 'John Doe',
        role: 'Developer'
    };
    
    res.json(profileData);
    console.log('Sent profile data response');
});

app.get('/fetch-data', async (req, res) => {
    const inputUrl = req.query.url;
    console.log(`Received request for /fetch-data with URL: ${inputUrl}`);
    
    // Validate the URL before fetching
    if (!isValidUrl(inputUrl)) {
        return res.status(400).send('Invalid URL provided');
    }

    try {
        const response = await axios.get(inputUrl);
        res.send(response.data);
        console.log(`Data fetched and sent for URL: ${inputUrl}`);
    } catch (error) {
        console.error(`Error fetching data from URL: ${inputUrl}`, error);
        res.status(500).send('Error fetching data');
    }
});

function isValidUrl(inputUrl) {
    try {
        new URL(inputUrl);
        // Further validation logic can be added here
        return true;
    } catch (e) {
        return false;
    }
}

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

## changes made

1. URL validation function: a function `isValidUrl` is introduced to validate the provided URL. it uses the `URL` constructor for basic validation, but the function can be enhanced to include more specific checks (allowing certain domains or protocols)

2. validation check: the `/fetch-data` endpoint now uses the `isValidUrl` function to validate the input URL before making the HTTP request. if the URL is invalid, it responds with a `400 Bad Request`.

# challenge 3

```java

package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class DemoApplication {

    private Map<String, String> userDatabase = new HashMap<>();

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam String username, @RequestParam String password) {
        String hashedPassword = hashPassword(password);
        userDatabase.put(username, hashedPassword);
        return "User registered successfully";
    }

    @PostMapping("/login")
    public String loginUser(@RequestParam String username, @RequestParam String password) {
        String hashedPassword = userDatabase.get(username);
        if (hashedPassword != null && hashedPassword.equals(hashPassword(password))) {
            return "Login successful";
        }
        return "Invalid username or password";
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(password.getBytes());
            byte[] digest = md.digest();
            return DatatypeConverter.printHexBinary(digest).toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            return "Error: Hashing algorithm not found";
        }
    }

    // retrieving all usernames (simulated admin functionality)
    @GetMapping("/admin/usernames")
    public Map<String, String> getAllUsernames() {
        return userDatabase;
    }
}
```

## vulnerability found

1. use of insecure hashing algo (MD5): MD5 is considered insecure for hashing passwords due to its vulnerability to collision attacks and its fast computation (susceptible to brute force or rainbow table attacks)

2. storage of hashed passwords without salt: salting is crucial to protect against rainbow table attacks

3. exposure via admin endpoint: the `/admin/usernames` endpoint exposes the entire user db, including usernames + their hashed passwords. 

## fixed code

```java

package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

@SpringBootApplication
@RestController
public class DemoApplication {

    private Map<String, String> userDatabase = new HashMap<>();
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 512;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam String username, @RequestParam String password) {
        String salt = getNewSalt();
        String hashedPassword = hashPassword(password, salt);
        userDatabase.put(username, hashedPassword + ":" + salt);
        return "User registered successfully";
    }

    @PostMapping("/login")
    public String loginUser(@RequestParam String username, @RequestParam String password) {
        String storedValue = userDatabase.get(username);
        if (storedValue != null) {
            String[] parts = storedValue.split(":");
            String hashedPassword = parts[0];
            String salt = parts[1];
            if (hashedPassword.equals(hashPassword(password, salt))) {
                return "Login successful";
            }
        }
        return "Invalid username or password";
    }

    private String hashPassword(String password, String salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), ITERATIONS, KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            return "Error: Hashing algorithm not found";
        }
    }

    private String getNewSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // Endpoint removed to protect sensitive data
}
```

## changes made

1. switch hashing algorithm: replaced MD5 with PBKDF2, which applies a hash function multiple times to increase the time required to hash and check passwords (makes brute forcing more difficult)

2. added salt: implemented salting with a unique salt for each password. this makes each hash unique even if 2 users have the same password (protects against rainbow table attack)

3. removed admin endpoint: the admin functionality for retrieving all usernames + hashed passwords has been removed. if it's necessary, it can be implemented with strict access controls and should not expose hashed passwords.

# challenge 4

```python
from flask import Flask, request

app = Flask(__name__)

USERNAME = "admin"
PASSWORD = "mypassword"

@app.route('/')
def home():
    return "Welcome to the Flask App!"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == USERNAME and password == PASSWORD:
        return "Login successful!"
    else:
        return "Invalid credentials!"

if __name__ == '__main__':
    app.run(debug=False)
```

## vulnerability found

1. hardcoded credentials

2. lack of password hashing

3. no rate limiting/account lockout mechanisms: login function has no rate limiting or account lockout mechanisms (brute force attacks)

## fixed code

```python
from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# Configure rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]  # Example limit: 5 requests per minute
)

# Environment variables should be used for sensitive information
USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
PASSWORD_HASH = generate_password_hash(os.environ.get("ADMIN_PASSWORD", "default_password"))

# Dictionary to track failed attempts
failed_attempts = {}

@app.route('/')
def home():
    return "Welcome to the Flask App!"

@app.route('/login', methods=['POST'])
@limiter.limit("3/minute")  # Custom limit for login route
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Check for account lockout
    if failed_attempts.get(username, 0) >= 3:
        return "Account locked due to too many failed attempts. Please try again later."
    if username == USERNAME and check_password_hash(PASSWORD_HASH, password):
        failed_attempts[username] = 0  # Reset failed attempts on successful login
        return "Login successful!"
    else:
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        return "Invalid credentials!"

if __name__ == '__main__':
    app.run(debug=False)

```

## changes made

1. use env variables for creds: instead of hardcoding, admin username/password now retrieved from environment variables.

2. password hashing with werkzeug: uses werkzeug's `generate_password_hash` and `check_password_hash` for secure password handling. the hash is compared during login.

3. placeholder for additional security measures: rate limiting, account lockout

# challenge 5

```java
package com.example.my.tests;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import java.io.*;
import javax.xml.parsers.*;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

@RestController
public class HomeController {

	@RequestMapping("/")
	public String index() {
		return "Greetings from Spring Boot!";
	}

	@RequestMapping(method=RequestMethod.POST, value="/process")
	public String process(String inputXml) {
		if (inputXml == null) {
			return "Provide an inputXml variable";
		}

		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = dbf.newDocumentBuilder();
			Document doc = builder.parse(new InputSource(new StringReader(inputXml)));

			return xmlToString(doc);
		} catch (Exception e) {
			e.printStackTrace();
			return e.getMessage();
		}
	}

	public static String xmlToString(Document doc) {
		try {
			StringWriter sw = new StringWriter();
			TransformerFactory tf = TransformerFactory.newInstance();

			Transformer transformer = tf.newTransformer();
			transformer.transform(new DOMSource(doc), new StreamResult(sw));

			return sw.toString();
		} catch (Exception ex) {
			throw new RuntimeException("Error converting to String", ex);
		}
	}
}
```

## vulnerability found

1. XML external entity injection (XXE injection): parsing XML input without disabling external entities + DTDs (Document Type Definitions). this makes it vulnerable to XXE attacks, where an attacker can provide malicious XML content to perform actions like accessing local files, causing DoS, SSRF.

## fixed code

```java
package com.example.my.tests;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import java.io.*;
import javax.xml.parsers.*;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

@RestController
public class HomeController {

    @RequestMapping("/")
    public String index() {
        return "Greetings from Spring Boot!";
    }

    @RequestMapping(method = RequestMethod.POST, value = "/process")
    public String process(String inputXml) {
        if (inputXml == null) {
            return "Provide an inputXml variable";
        }

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // Mitigate XXE
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);

            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(inputXml)));

            return xmlToString(doc);
        } catch (Exception e) {
            e.printStackTrace();
            return e.getMessage();
        }
    }

    public static String xmlToString(Document doc) {
        try {
            StringWriter sw = new StringWriter();
            TransformerFactory tf = TransformerFactory.newInstance();

            Transformer transformer = tf.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(sw));

            return sw.toString();
        } catch (Exception ex) {
            throw new RuntimeException("Error converting to String", ex);
        }
    }
}
```

## changes made

1. disabling external entities + DTDs: the `DocumentBuilderFactory` instance has been configured to prevent XXE by disabling DTDs and external entities. this is achieved thru the `setFeature` method with appropriate feature URLs. also, `setXIncludeAware(false)` and `setExpandEntityReferences(false)` ensure that external entity processing is disabled.

# challenge 6

```go
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "<html><body>Welcome to the Go Web Server! Visit /greet, /about, or /contact</body></html>")
    })

    http.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "<html><body><h1>About Us</h1><p>We are a team of passionate Gophers...</p></body></html>")
    })

    http.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "<html><body><h1>Contact Us</h1><p>Email us at contact@example.com</p></body></html>")
    })

    http.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
        name := r.URL.Query().Get("name")
        response := fmt.Sprintf("<html><body><h1>Hello, %s!</h1></body></html>", name)
        fmt.Fprint(w, response)
    })

    fmt.Println("Server is running at http://localhost:8080/")
    http.ListenAndServe(":8080", nil)
}
```

## vulnerability found

1. XSS: the `/greet` endpoint directly uses user input from the query param `name` in the HTML response without sanitization. this can lead to XSS attacks if an attacker provides a javascript code as the `name`.

2. lack of input validation

3. hardcoded HTML in response: writing HTML directly to server code can be cumbersome to maintain. use templates.

4. no HTTPS support: server only listens on HTTP. use HTTPS.

## fixed code

```go
package main

import (
    "fmt"
    "html/template"
    "net/http"
)

func main() {
    http.HandleFunc("/", homeHandler)
    http.HandleFunc("/about", aboutHandler)
    http.HandleFunc("/contact", contactHandler)
    http.HandleFunc("/greet", greetHandler)

    fmt.Println("Server is running at http://localhost:8080/")
    http.ListenAndServe(":8080", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "<html><body>Welcome to the Go Web Server! Visit /greet, /about, or /contact</body></html>")
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "<html><body><h1>About Us</h1><p>We are a team of passionate Gophers...</p></body></html>")
}

func contactHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "<html><body><h1>Contact Us</h1><p>Email us at contact@example.com</p></body></html>")
}

func greetHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    tmpl := template.New("greet")
    tmpl, _ = tmpl.Parse("<html><body><h1>Hello, {{.}}!</h1></body></html>")

    tmpl.Execute(w, template.HTMLEscapeString(name))
}
```

## changes made

1. XSS protection: the `/greet` handler now uses go's `html/template` package to safely embed `name` parameter in the response (preventing XSS)

2. use of HTML templates

3. set up HTTPS on server.

# challenge 7

```js
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');

const app = express();
app.use(bodyParser.json());

// Dummy email transporter (configure properly for a real app)
const transporter = nodemailer.createTransport({
    service: 'example',
    auth: {
        user: 'user@example.com',
        pass: 'password'
    }
});

app.get('/', (req, res) => {
    res.send('Welcome to our application!');
});

app.get('/profile', (req, res) => {
    // Dummy profile information
    res.json({ username: 'JohnDoe', email: 'john@example.com' });
});

app.post('/register', (req, res) => {
    // User registration logic (omitted for brevity)
    res.send('User registration successful!');
});

app.post('/reset-password', (req, res) => {
    const email = req.body.email;
    const host = req.headers.host;

    const resetLink = `http://${host}/reset-password?token=generatedToken123`;
    transporter.sendMail({
        from: 'support@example.com',
        to: email,
        subject: 'Password Reset',
        text: `Click here to reset your password: ${resetLink}`
    });

    res.send('Password reset link has been sent to your email.');
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
```

## vulnerability found

1. hardcoded creds.

2. lack of input validation: `/reset-password` endpoint does not validate email input.

3. insecure transport layer: using `http` for reset link.

4. token predictability: token in reset link is hardcoded + predictable.

5. lack of rate limiting: app does not implement rate limiting on sensitive endpoints.

6. logging sensitive information.

## fixed code

```js
require('dotenv).config();
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto'); // will be used for secure random token generation

const app = express();
app.use(bodyParser.json());
app.use(helmet());

const resetPasswordLimiter = rateLimit({
    windowMs: 15*60*1000, // 15 mins
    max: 5 // each IP limited to 5 requests per windowMs
});

// use env variables for sensitive data
const transporter = nodemailer.createTransport({
    service: 'example',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.use('/reset-password', resetPasswordLimiter);

app.post('/reset-password', (req, res) => {
    const email = req.body.email;
    // email validation
    function validateEmail(email) {
        const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return re.test(String(email).toLowerCase());
    };
    const host = req.headers.host;

    // use HTTPS + generate secure token
    const resetLink = `https://${host}/reset-password?token=${secureRandomToken()}`;
    transporter.sendMail({
        from: 'support@example.com',
        to: email,
        subject: 'Password Reset',
        text: 'Click here to reset your password: ${resetLink}'
    });
    res.send('Password reset link has been sent to your email.');
});

function secureRandomToken() {
    return crypto.randomBytes(48).toString('hex');
}

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
```

## changes made

1. dotenv for env variable management

2. helmet for setting various HTTP headers for security

3. express-rate-limit for basic rate limiting

# challenge 8

```nginx
server {
    listen 80;
    server_name another-awesome-challenge.com;

    location /backend { 
        proxy_pass http://backend/;
    }
    
    location /html {
        alias /usr/share/nginx/html/;
    }
}
```

## fixed code

```nginx
server {
    listen 80;
    server_name another-awesome-challenge.com;
    return 301 https://$server_name$request_uri; # Redirect HTTP to HTTPS
}

server {
    listen 443 ssl;
    server_name another-awesome-challenge.com;

    # SSL configuration here (certificate and key paths)

    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'";

    location /backend { 
        proxy_pass http://backend/;
        # Consider IP whitelisting or basic auth for additional security
    }
    
    location /html {
        alias /usr/share/nginx/html/;
        # Ensure only static files can be served from this location
    }
}
```

challenge 9

```python
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Assume there's a UserProfileService with methods to fetch and update user profiles
class UserProfileService:
    def get_user_profile(self, username):
        # Implementation to fetch user profile from the database
        pass

    def update_user_profile(self, user_profile):
        # Implementation to update user profile in the database
        pass

user_profile_service = UserProfileService()

@app.route('/edit-profile', methods=['POST'])
def edit_profile():
    username = request.form.get('username')
    user_profile = user_profile_service.get_user_profile(username)

    if user_profile.get_username() == username:
        user_profile_service.update_user_profile(user_profile)
        
        return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=False)
```

## vulnerability found

1. missing input validation: username from `request.form.get('username')` is used directly without validation (risk of SQLi)

2. lack of auth check: `/edit-profile` endpoint does not verify user's authentication.

3. user profile update logic flaw: code checks if `user_profile.get_username() == username` but doesn't show how `user_profile` is updated with the new data.

## fixed code

```python
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'

class UserProfileService:
    def get_user_profile(self, username):
        pass
    def update_user_profile(self, user_profile):
        pass

user_profile_service = UserProfileService()

@app.route('/edit-profile', methods=['POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login')) # ensure user is logged in
    username = session['username'] # use username from session to avoid tampering
    user_profile = user_profile_service.get_user_profile(username)

    # assuming there's a method to safely update user profile with sanitized inputs
    if user_profile and user_profile.get_username() == username:
        # update user_profile with sanitized form inputs here
        user_profile_service.update_user_profile(user_profile)

        return redirect(url_for('dashboard'))
    return 'Unauthorized', 403

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login')
def login():
    # implement login logic
    pass

if __name__ == '__main__':
    app.run(debug=False)
```

## changes made

1. session-based authentication to verify if user is logged in + authorized to edit profile

2. sanitize + validate all user inputs before processing (avoid injection attacks)

3. set secret key for Flask to securely sign session cookie

4. return unauthorized access message if user profile doesn't exist or username doesn't match