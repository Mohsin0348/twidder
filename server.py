# server.py
from flask import Flask, request, jsonify, render_template, abort
from flask_sock import Sock
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from dotenv import load_dotenv
import click
import re
import hmac
import hashlib
import time
import os

from database_helper import (
    initialize_database,
    find_user_by_email,
    create_user,
    create_token,
    create_recovery_token,
    find_user_by_token,
    find_user_by_recovery_token,
    delete_token,
    delete_recovery_token,
    update_password,
    get_messages,
    create_message,
)

app = Flask(__name__)
sock = Sock(app)
bcrypt = Bcrypt(app)
initialize_database()

SECRET_KEY = os.getenv("SECRET_KEY").encode()

active_connections = {}

# Configure your email server settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'      # e.g., Gmail SMTP
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")

mail = Mail(app)


def send_email_from_template(recipient, subject, body):
    if not recipient:
        return jsonify({"error": "Recipient email is required"}), 400

    try:
        msg = Message(subject, recipients=[recipient])
        msg.html = body
        mail.send(msg)
        return jsonify({"message": "Email sent successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- Helpers ----------------

def response(message, status_code, data=None):
    res = {"message": message}
    if data is not None:
        res["data"] = data
    return jsonify(res), status_code


def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)


def get_token():
    return request.headers.get("Authorization")


def get_token_user():
    token = get_token()
    if not token:
        return None
    return find_user_by_token(token)

def get_recovery_token_user(token):
    if not token:
        return None
    return find_user_by_recovery_token(token)


def verify_request():

    signature = request.headers.get("X-Signature")
    timestamp = request.headers.get("X-Timestamp")

    if not signature or not timestamp:
        return False

    try:
        timestamp = int(timestamp)
    except:
        return False

    if abs(time.time() - timestamp) > 30:
        return False

    message = f"{request.path}:{timestamp}".encode()

    expected = hmac.new(
        SECRET_KEY,
        message,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected)


# ---------------- Routes ----------------

@app.route("/")
def index():
    return render_template("client.html")


# ---------------- SIGN UP ----------------

@app.route("/sign_up", methods=["POST"])
def sign_up():

    data = request.get_json()

    required = ["email","password","firstname","familyname","gender","city","country"]

    if not data or not all(data.get(f) for f in required):
        return response("invalid_fields", 400)

    if not is_valid_email(data["email"]):
        return response("invalid_email", 400)

    password = data.get('password', "")
    if len(password) < 6:
        return response("password_short", 400)

    if find_user_by_email(data["email"]):
        return response("user_exists", 409)

    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
    data["password"] = hashed

    create_user(data)

    return response("user_created", 201)


# ---------------- SIGN IN ----------------

@app.route("/sign_in", methods=["POST"])
def sign_in():

    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return response("missing_credentials", 400)

    user = find_user_by_email(data["username"])

    if not user or not bcrypt.check_password_hash(user["password"], data["password"]):
        return response("invalid_login", 401)

    token = create_token(user["email"])

    user_data = dict(user)
    user_data.pop("password")

    return response("login_success", 200, {"token":token,"user":user_data})


# ---------------- SIGN OUT ----------------

@app.route("/sign_out", methods=["DELETE"])
def sign_out():

    if not verify_request():
        return response("invalid_signature",403)

    token_data = get_token_user()

    if not token_data:
        return response("invalid_token",401)

    delete_token(get_token())

    return response("logout_success",200)


# ---------------- CHANGE PASSWORD ----------------

@app.route("/change_password", methods=["PUT"])
def change_password():

    if not verify_request():
        return response("invalid_signature",403)

    token_data = get_token_user()

    if not token_data:
        return response("invalid_token",401)

    data = request.get_json()

    user = find_user_by_email(token_data["email"])

    if not bcrypt.check_password_hash(user["password"], data["oldpassword"]):
        return response("wrong_old_password",401)

    new_hash = bcrypt.generate_password_hash(data["newpassword"]).decode("utf-8")

    update_password(token_data["email"], new_hash)

    return response("password_updated",200)


# ---------------- Password Recovery ----------------

@app.route("/request_password_recovery", methods=["POST"])
def request_password_recovery():
    data = request.get_json()
    email = data.get("email", "")
    user = find_user_by_email(email)
    if not user:
        return response("invalid_email",400)
    
    token = create_recovery_token(email)
    recovery_link = f"{request.host_url}password_recovery?token={token}"
    mail_subject = "Password recovery mail"
    mail_body = render_template(
        "recovery_mail.html",
        name=f"{user['firstname']} {user['familyname']}",
        recovery_link=recovery_link
    )
    send_email_from_template(email, mail_subject, mail_body)
    return response("Password recovery link sent successfully.", 200)


@app.route("/password_recovery", methods=["GET"])
def get_password_recovery():
    token = request.args.get("token")

    token_data = get_recovery_token_user(token)

    if not token_data:
        abort(404)
    return render_template("client.html")


@app.route("/password_recovery", methods=["POST"])
def password_recovery():
    data = request.get_json()
    print(data)
    token = data.get("token", "")
    password = data.get('password', "")

    token_data = get_recovery_token_user(token)

    if not token_data:
        return response("invalid_token",401)

    if not data or not password:
        return response("invalid_fields", 400)

    if len(password) < 6:
        return response("password_short", 400)

    new_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    update_password(token_data["email"], new_hash)
    delete_recovery_token(token)

    return response("recovery_success", 200)


# ---------------- USER DATA ----------------

@app.route("/get_user_data_by_token")
def get_user_data_by_token():

    if not verify_request():
        return response("invalid_signature",403)

    token_data = get_token_user()

    if not token_data:
        return response("invalid_token",401)

    user = find_user_by_email(token_data["email"])

    return response("user_found",200,dict(user))


@app.route("/get_user_data_by_email/<email>")
def get_user_data_by_email(email):

    if not verify_request():
        return response("invalid_signature",403)

    if not get_token_user():
        return response("invalid_token",401)

    user = find_user_by_email(email)

    if not user:
        return response("user_not_found",404)

    return response("user_found",200,dict(user))


# ---------------- MESSAGES ----------------

@app.route("/get_user_messages_by_token")
def get_user_messages_by_token():

    if not verify_request():
        return response("invalid_signature",403)

    token_data = get_token_user()

    if not token_data:
        return response("invalid_token",401)

    messages = get_messages(token_data["email"])

    return response("messages_found",200,[dict(m) for m in messages])


@app.route("/get_user_messages_by_email/<email>")
def get_user_messages_by_email(email):

    if not verify_request():
        return response("invalid_signature",403)

    if not get_token_user():
        return response("invalid_token",401)

    messages = get_messages(email)

    return response("messages_found",200,[dict(m) for m in messages])


@app.route("/post_message",methods=["POST"])
def post_message():

    if not verify_request():
        return response("invalid_signature",403)

    token_data = get_token_user()

    if not token_data:
        return response("invalid_token",401)

    data = request.get_json()

    create_message(
        data["message"],
        token_data["email"],
        data.get("email") or token_data["email"],
        latitude=data.get("latitude"),
        longitude=data.get("longitude")
    )

    return response("message_created", 201)


# ---------------- WebSocket ----------------

@sock.route("/ws")
def websocket(ws):

    print("Active connections: ", active_connections)
    token = request.args.get("token")
    token_data = find_user_by_token(token)

    if not token_data:
        ws.close()
        return

    email = token_data["email"]
    if email in active_connections:
        try:
            active_connections[email].send("logout")
        except:
            pass

    active_connections[email] = ws
    print("Active connections: ", active_connections)

    try:
        while True:
            if ws.receive() is None:
                break
    finally:
        active_connections.pop(email,None)


if __name__ == "__main__":
    app.run(debug=True)