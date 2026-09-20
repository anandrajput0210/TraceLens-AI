from flask import Flask
from flask_cors import CORS
from services.users import get_users


app = Flask(__name__)


@app.get("/api/users")
def users():
    return {
        "users": get_users()
    }


app.run(
    host="0.0.0.0",
    port=5000
)
app.config["DEBUG"] = True


CORS(app, origins="*")