from datetime import timedelta
from functools import wraps
from os import environ

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    verify_jwt_in_request,
    get_jwt,
)
from flask_migrate import Migrate
from flask_socketio import SocketIO, join_room, emit
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields, post_dump
from sqlalchemy import func, and_, or_
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = (
    environ.get("SECRET_KEY")
    or "0ac1faff41cfe21eda735af6dfe29e9727a75dbbd88f82c9f66115cd44ca6399"
)
app.config["JWT_SECRET_KEY"] = (
    environ.get("JWT_SECRET_KEY")
    or "cfad2708c23ab3bb4da83f489eb3bb2a3f12066350b20e8862157cca33b9334a"
)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=365)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    environ.get("DATABASE_URL") or "sqlite:///chatapp.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

cors = CORS(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, async_mode="eventlet", logger=True)

users = []

users_conversations = db.Table(
    "users_conversations",
    db.Column("user_id", db.Integer, db.ForeignKey("users.id")),
    db.Column(
        "conversation_id",
        db.Integer,
        db.ForeignKey("conversations.id"),
    ),
)


def admin_only(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        verify_jwt_in_request()
        username = get_jwt()["sub"]

        if username != "admin":
            # checks if it isn't a socketio connection
            if not hasattr(request, "sid"):
                return jsonify(status="error", msg="Only admins allowed!"), 403
            return socketio.disconnect()
        return f(*args, **kwargs)

    return decorator


def not_banned(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        verify_jwt_in_request()
        username = get_jwt()["sub"]
        user = User.query.filter_by(username=username).first()
        if user.is_banned:
            # checks if it isn't a socketio connection
            if not hasattr(request, "sid"):
                return (
                    jsonify(status="error", msg="Sorry, your account has been banned!"),
                    403,
                )
            return socketio.disconnect()
        return f(*args, **kwargs)

    return decorator


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False, unique=True)
    ip_address = db.Column(db.String(16), nullable=False)
    is_banned = db.Column(db.Boolean, default=False)
    messages = db.relationship("Message", backref="sender", lazy="dynamic")
    date_joined = db.Column(db.DateTime, default=func.now())

    def __init__(self, username, ip, password):
        self.username = username
        self.ip_address = ip
        self.password_hash = generate_password_hash(password)


class UserSerializer(Schema):
    id = fields.Int()
    username = fields.Str()
    password_hash = fields.Str(load_only=True)
    ip_address = fields.Str()
    is_banned = fields.Bool()
    date_joined = fields.DateTime()


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    conversation_id = db.Column(
        db.Integer, db.ForeignKey("conversations.id"), nullable=False
    )
    content = db.Column(db.LargeBinary(), nullable=False)
    timestamp = db.Column(db.DateTime, default=func.now())


class MessageSerializer(Schema):
    id = fields.Int()
    content = fields.Str()
    timestamp = fields.DateTime()

    @post_dump(pass_original=True)
    def add_sender(self, data, original_data, **kwargs):
        sender = UserSerializer().dump(original_data.sender)
        data["sender"] = sender
        return data


class Conversation(db.Model):
    __tablename__ = "conversations"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)
    is_private = db.Column(db.Boolean, default=False)
    created_on = db.Column(db.DateTime, default=func.now())
    participants = db.relationship(
        "User",
        secondary=users_conversations,
        backref=db.backref("conversations", lazy="dynamic"),
        lazy="dynamic",
    )
    messages = db.relationship("Message", backref="conversation", lazy="dynamic")


class ConversationSerializer(Schema):
    id = fields.Int()
    name = fields.Str()
    is_private = fields.Bool()
    created_on = fields.DateTime()
    participants = fields.Nested(UserSerializer(many=True))
    messages = fields.Nested(MessageSerializer(many=True))


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(username=identity).first()


@app.route("/")
def index():
    return jsonify({"message": "Welcome to Chatapp"}), 200


@app.route("/registration", methods=["POST"])
def registration():
    req_data = request.get_json(force=True)
    if not req_data["username"] or not req_data["password"]:
        return jsonify(status="error", message="Invalid"), 400

    user = User.query.filter_by(username=req_data["username"]).first()
    if user:
        return jsonify(status="error", message="Username already in use"), 400

    new_user = User(
        username=req_data["username"],
        password=req_data["password"],
        ip=request.remote_addr,
    )
    db.session.add(new_user)
    db.session.commit()
    return (
        jsonify(
            {
                "status": "success",
                "message": "Your account has been created successfully!",
            }
        ),
        201,
    )


@app.route("/login", methods=["POST"])
def login():
    req_data = request.get_json(force=True)
    if not req_data["username"] or not req_data["password"]:
        return jsonify({"status": "error", "message": "Invalid"}), 400

    user = User.query.filter_by(username=req_data["username"]).first()
    if not user or not check_password_hash(user.password_hash, req_data["password"]):
        return jsonify(status="error", message="Invalid credentials"), 400

    if user.is_banned:
        return (
            jsonify(status="error", message="Sorry, your account has been banned!"),
            403,
        )

    access_token = create_access_token(identity=user.username)
    return (
        jsonify(
            status="success",
            username=user.username,
            access_token=access_token,
            message="Logged in successfully!",
        ),
        200,
    )


@app.route("/channels")
@not_banned
def channels():
    all_channels = Conversation.query.filter_by(is_private=False).all()
    schema = ConversationSerializer(many=True)
    result = schema.dump(all_channels)
    return jsonify(status="success", data=result), 200


@app.route("/channels/<name>")
@not_banned
def channel(name):
    _channel = Conversation.query.filter(
        and_(Conversation.name == name, Conversation.is_private == False)
    ).first()

    user = User.query.filter_by(username=get_jwt_identity()).first()

    schema = ConversationSerializer()
    if not _channel:
        new_channel = Conversation(name=name)
        user = User.query.filter_by(username=get_jwt_identity()).first()
        new_channel.participants.append(user)

        db.session.add(new_channel)
        db.session.commit()

        result = schema.dump(new_channel)
        return jsonify(status="success", data=result), 200

    if not _channel.participants.filter(User.id == user.id).count() > 0:
        _channel.participants.append(user)
        db.session.commit()

    result = schema.dump(_channel)
    return jsonify(status="success", data=result), 200


@app.route("/privates")
@not_banned
def privates():
    user = User.query.filter_by(username=get_jwt_identity()).first()
    private_chats = user.conversations.filter_by(is_private=True).all()

    schema = ConversationSerializer(many=True)
    data = schema.dump(private_chats)
    return jsonify(status="success", data=data), 200


@app.route("/privates/<username>")
@not_banned
def private(username):
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify(status="error", msg="User not found!"), 404

    current_user = User.query.filter_by(username=get_jwt_identity()).first()

    private_chat = Conversation.query.filter(
        Conversation.is_private == True,
        or_(
            Conversation.name == f"{current_user.username}-{user.username}",
            Conversation.name == f"{user.username}-{current_user.username}",
        ),
    ).first()

    schema = ConversationSerializer()
    if private_chat:
        data = schema.dump(private_chat)
        return jsonify(status="success", data=data), 200

    new_private_chat = Conversation(
        name=f"{user.username}-{current_user.username}", is_private=True
    )
    new_private_chat.participants.extend([user, current_user])

    db.session.add(new_private_chat)
    db.session.commit()

    data = schema.dump(new_private_chat)
    return jsonify(status="success", data=data), 200


@app.route("/ban/username/<username>")
@admin_only
def ban_username(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return (
            jsonify(status="error", msg="No user is associated with that username!"),
            404,
        )

    if user.username == "admin":
        return (
            jsonify(status="error", msg="You cannot ban an admin!"),
            400,
        )
    user.is_banned = True
    db.session.commit()
    return jsonify(status="success", msg=f"{username} banned!"), 200


@app.route("/ban/ip/<ip_addr>")
@admin_only
def ban_ip_addr(ip_addr):
    _users = User.query.filter_by(ip_address=ip_addr).all()
    if not _users:
        return (
            jsonify(status="error", msg="IP Address not associated with any user!"),
            404,
        )

    for user in _users:
        if user.username == "admin":
            continue
        user.is_banned = True

    db.session.commit()
    return jsonify(status="success", msg=f"{ip_addr} banned!"), 200


@app.route("/stats")
@admin_only
def stats():
    _users = User.query.all()
    schema = UserSerializer(many=True)

    data = schema.dump(_users)

    return jsonify(status="success", data=data)


@app.route("/search")
@admin_only
def search_channels():
    query = request.args.get("q")
    _channel = Conversation.query.filter(
        Conversation.is_private == False, Conversation.name == query
    ).first()
    if not _channel:
        return jsonify(status="error", msg="Channel not found!"), 404

    schema = ConversationSerializer()
    data = schema.dump(_channel)
    return jsonify(status="success", data=data), 200


@socketio.on("connect")
@not_banned
def connect():
    print(f"Connecting: {get_jwt_identity()}, {request.sid}")
    users.append({"sid": request.sid, "user_id": get_jwt_identity()})
    print(users)


@socketio.on("disconnect")
def disconnect():
    print(f"Disconnecting: {request.sid}")
    global users
    users = list(filter(lambda user: user.get("sid") != request.sid, users))

    print(users)


@socketio.on("join-channel")
@not_banned
def join_channel(data):
    room = data["channel_name"]
    username = data["username"]
    join_room(room=room)
    emit(
        "joined-channel",
        {"msg": f"{username} just joined the room."},
        room=room,
        include_self=False,
    )


@socketio.on("join-private-chat")
@not_banned
def join_private_chat(data):
    room = data["chat_name"]
    username = data["username"]
    join_room(room=room)
    emit(
        "joined-private-chat",
        {"msg": f"{username} is now online."},
        room=room,
        include_self=False,
    )


@socketio.on("new-private-message")
@not_banned
def new_private_message(data):
    room = data["chat_name"]
    sender = data["from"]
    message = data["msg"]

    user = User.query.filter_by(username=sender).first()
    conversation = Conversation.query.filter(
        and_(Conversation.name == room, Conversation.is_private == True)
    ).first()

    new_message = Message(
        sender_id=user.id, conversation_id=conversation.id, content=message
    )
    db.session.add(new_message)
    db.session.commit()

    data = MessageSerializer().dump(new_message)
    emit("private-messages", data, room=room)


@socketio.on("new-channel-message")
@not_banned
def new_channel_message(data):
    room = data["channel"]
    sender = data["from"]
    message = data["msg"]

    user = User.query.filter_by(username=sender).first()
    conversation = Conversation.query.filter(
        and_(Conversation.name == room, Conversation.is_private == False)
    ).first()

    new_message = Message(
        sender_id=user.id, conversation_id=conversation.id, content=message
    )
    db.session.add(new_message)
    db.session.commit()

    data = MessageSerializer().dump(new_message)
    emit("channel-messages", data, room=room)


@app.cli.command("run:socketio")
def run_socketio():
    """
    Run the eventlet server.
    """
    import eventlet

    eventlet.monkey_patch()
    socketio.run(app)
