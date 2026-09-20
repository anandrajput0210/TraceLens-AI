from flask import Flask

app = Flask(__name__)


@app.get("/api/users")
def users():
    return {"users": []}


app.run(host="0.0.0.0", port=5000)