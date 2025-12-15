
# config.py - Updated for DVWA on port 8088
TARGET_URL = "http://localhost:8088"
LOGIN_URL = "http://localhost:8088/login.php"
LOGIN_CREDENTIALS = {
    "username": "admin",
    "password": "password",
    "Login": "Login"
}

# Scanner settings
MAX_DEPTH = 2
MAX_PAGES = 20
REQUEST_DELAY = 0.5
USER_AGENT = "WebScanPro/1.0"

# Output settings
OUTPUT_DIR = "output"