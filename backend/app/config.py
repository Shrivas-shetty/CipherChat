HOST = "0.0.0.0"
PORT = 8000
MAX_USERS = 2
DISPLAY_NAME_MIN = 1
DISPLAY_NAME_MAX = 20
CHAT_TEXT_MIN = 1
CHAT_TEXT_MAX = 2000
PROTOCOL_VERSION = 1

# localhost + RFC1918 private ranges, any port
CORS_ORIGIN_REGEX = (
    r"^https?://("
    r"localhost"
    r"|127\.0\.0\.1"
    r"|10(?:\.\d{1,3}){3}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r")(:\d+)?$"
)
