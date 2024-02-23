1. implement a function to sanitize user input to prevent XSS in a web application.

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

2. develop a script to simulate a SQLi attack on a sample db, and propose a solution to prevent such attacks.

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