import json
import os
from getpass import getpass

import click
import requests
import socketio
from cryptography.fernet import Fernet

URL = "https://cli-chatapp.herokuapp.com"

# Encryption Key for messages and secret
ENCRYPTION_KEY = b"r33YpSlDxWaRVYUA1quBSv8wezWfOwVt-zcJw2PvpVI="

# Secrets Storage Location
separator = os.sep
PATH = os.path.expanduser(f"~{separator}.chatapp_secret")

# SocketIO client instantiation
sio = socketio.Client()

# Encryption
f = Fernet(ENCRYPTION_KEY)


def store_secrets(jwt: str, username: str):
    """
    Encrypt and JWT Token and username for use
    """

    jwt = f.encrypt(jwt.encode())
    username = f.encrypt(username.encode())

    with open(PATH, "wb") as file:
        file.write(jwt)
        file.write("\n".encode())
        file.write(username)


def delete_secrets():
    if os.path.exists(PATH):
        os.remove(PATH)


def get_secrets() -> list or None:
    """
    Get stored secrets
    """

    # check if path exists
    if not os.path.exists(PATH):
        return None

    # check if file is empty
    if os.path.getsize(PATH) == 0:
        return None

    with open(PATH, "rb") as file:
        content = file.readlines()
        return [f.decrypt(secret).decode("utf-8") for secret in content]


@click.group()
def chatapp():
    """
    Chat App CLI.
    """
    pass


@chatapp.command()
def register():
    """
    Create an account on Chat App
    """
    while True:
        username = input("Username: ")
        if len(username) < 2:
            click.secho(
                "・Username must be at least two characters",
                err=True,
                fg="red",
                bold=True,
            )
            continue
        break

    while True:
        password = getpass(prompt="Password: ")
        if len(password) < 4:
            click.secho(
                "・Password must be at least four characters",
                err=True,
                fg="red",
                bold=True,
            )
            continue
        break
    # request body
    data = json.dumps(dict(username=username, password=password))

    # request headers
    headers = {"content-type": "application/json"}
    r = requests.post(f"{URL}/registration", data=data, headers=headers, timeout=15)
    if r.status_code > 201:
        click.secho(f'・{r.json()["message"]}', err=True, fg="red", bold=True)
    else:
        click.secho(f'・{r.json()["message"]}', fg="green", bold=True)


@chatapp.command()
def login():
    """
    Login to Chat App
    """
    while True:
        username = input("Username: ")
        if len(username) < 2:
            click.secho(
                "・Username must be at least two characters",
                err=True,
                fg="red",
                bold=True,
            )
            continue
        break

    while True:
        password = getpass(prompt="Password: ")
        if len(password) < 4:
            click.secho(
                "・Password must be at least four characters",
                err=True,
                fg="red",
                bold=True,
            )
            continue
        break

    # request body
    data = json.dumps(dict(username=username, password=password))

    # request header
    headers = {"content-type": "application/json"}

    r = requests.post(f"{URL}/login", data=data, headers=headers, timeout=15)
    if r.status_code > 201:
        click.secho(f'・{r.json()["message"]}', err=True, fg="red", bold=True)
    else:
        store_secrets(r.json()["access_token"], r.json()["username"])
        click.secho(f'・{r.json()["message"]}', fg="green", bold=True)


@chatapp.command()
def logout():
    """
    Logout of Chat App CLI
    """
    confirmation = input("Are you sure you want to logout? [y/n]: ")
    if confirmation.lower() == "y":
        delete_secrets()
        click.secho("・You have been logged out successfully!", fg="green", bold=True)
    elif confirmation.lower() == "n":
        pass
    else:
        click.secho("・Command not recognised!", fg="red", bold=True)


@chatapp.command()
def channels():
    """
    List all public channels
    """
    if not get_secrets():
        click.secho(
            "・You need to be logged in to view all channels",
            err=True,
            fg="red",
            bold=True,
        )
    else:
        jwt, _ = get_secrets()
        headers = {"Authorization": f"Bearer {jwt}"}
        r = requests.get(f"{URL}/channels", headers=headers)
        if r.status_code > 200:
            click.secho(
                f"・{r.json()['msg']}",
                err=True,
                fg="red",
                bold=True,
            )
            return

        # get all public channels available
        data = r.json()["data"]
        if len(data) < 1:
            click.secho("・No channels available at the moment!", fg="blue", bold=True)
        else:
            click.secho("---------- AVAILABLE PUBLIC CHANNELS ----------", bold=True)
            for _channel in data:
                click.secho(
                    f'{_channel["name"]}: {len(_channel["participants"])} participant(s)',
                    fg="blue",
                    bold=True,
                )


@chatapp.command()
@click.argument("name", type=click.STRING)
def channel(name):
    """
    Join a public channel or create a new channel if it's non-existent
    """
    if not get_secrets():
        click.secho(
            "・You need to be logged in to view a channel",
            err=True,
            fg="red",
            bold=True,
        )
        return

    jwt, username = get_secrets()
    headers = {"Authorization": f"Bearer {jwt}"}
    r = requests.get(f"{URL}/channels/{name}", headers=headers)

    if r.status_code > 200:
        click.secho(
            f"・{r.json()['msg']}",
            err=True,
            fg="red",
            bold=True,
        )
        return

    data = r.json()["data"]
    click.secho(
        f'-------------- Welcome to {data["name"]} channel ----------------', bold=True
    )

    # SocketIO connection
    sio.connect(URL, headers=headers, transports="polling")

    for _message in data["messages"]:
        if _message["sender"]["username"] == "admin":
            click.secho(
                f'[{_message["timestamp"]}] {_message["sender"]["username"]}: {f.decrypt(_message["content"].encode()).decode()}',
                bold=True,
                fg="yellow",
            )
        else:
            click.secho(
                f'[{_message["timestamp"]}] {_message["sender"]["username"]}: {f.decrypt(_message["content"].encode()).decode()}',
                bold=True,
                fg="green",
            )

    sio.sleep(10)
    sio.emit("join-channel", {"username": username, "channel_name": name})

    while True:
        new_message = (input("Enter a message (max of 155 characters): ")).strip()
        if 156 > len(new_message) > 0:
            new_message = f.encrypt(new_message.encode())
            sio.emit(
                "new-channel-message",
                {"msg": new_message, "from": username, "channel": name},
            )
        else:
            click.secho(
                "・You cannot send an empty text",
                err=True,
                fg="red",
                bold=True,
            )
        sio.sleep(1)


@chatapp.command()
def privates():
    """
    View all private conversations with users
    """

    if not get_secrets():
        click.secho(
            "・You need to be logged in to view all private chats!",
            err=True,
            fg="red",
            bold=True,
        )
        return

    jwt, username = get_secrets()
    headers = {"Authorization": f"Bearer {jwt}"}
    r = requests.get(f"{URL}/privates", headers=headers)

    if r.status_code > 200:
        click.secho(
            f"・{r.json()['msg']}",
            err=True,
            fg="red",
            bold=True,
        )
        return

        # get all private chats available
    data = r.json()["data"]
    if len(data) < 1:
        click.secho("・No private chats available at the moment!", fg="blue", bold=True)
    else:
        click.secho("---------- PRIVATE CHATS ----------", bold=True)
        for _channel in data:
            click.secho(
                f'・{_channel["name"]}',
                fg="blue",
                bold=True,
            )


@chatapp.command()
@click.argument("username", type=click.STRING)
def private(username):
    """
    Start a private chat with a user.
    """
    if not get_secrets():
        click.secho(
            "・You need to be logged in to start/continue a private chat!",
            err=True,
            fg="red",
            bold=True,
        )
        return

    jwt, my_username = get_secrets()

    # check if username equals to yours
    if username == my_username:
        click.secho(
            "・You cannot have a private chat with yourself!",
            err=True,
            fg="red",
            bold=True,
        )
        return

    headers = {"Authorization": f"Bearer {jwt}"}
    r = requests.get(f"{URL}/privates/{username}", headers=headers)

    if r.status_code > 200:
        click.secho(
            f"・{r.json()['msg']}",
            err=True,
            fg="red",
            bold=True,
        )
        return

    data = r.json()["data"]
    click.secho(
        f'-------------- Private Chat -> {" and ".join(data["name"].split("-"))} ----------------',
        bold=True,
    )

    # SocketIO connection
    sio.connect(URL, headers=headers)

    for _message in data["messages"]:
        click.secho(
            f'[{_message["timestamp"]}] {_message["sender"]["username"]}: {f.decrypt(_message["content"].encode()).decode()}',
            bold=True,
            fg="magenta",
        )

    sio.sleep(10)

    sio.emit("join-private-chat", {"username": my_username, "chat_name": data["name"]})

    while True:
        new_message = (input("Enter a message (max of 155 characters): ")).strip()
        if 156 > len(new_message) > 0:
            new_message = f.encrypt(new_message.encode())
            sio.emit(
                "new-private-message",
                {"msg": new_message, "from": my_username, "chat_name": data["name"]},
            )
        else:
            click.secho(
                "・You cannot send an empty text ",
                err=True,
                fg="red",
                bold=True,
            )
        sio.sleep(1)


@chatapp.command()
def stat():
    """
    View currently logged in users
    """
    if not get_secrets():
        click.secho(
            "・You need to be logged in to view all channels",
            err=True,
            fg="red",
            bold=True,
        )
        return

    jwt, username = get_secrets()
    headers = {"Authorization": f"Bearer {jwt}"}
    r = requests.get(f"{URL}/stats", headers=headers)

    if r.status_code > 200:
        click.secho(
            f"・{r.json()['msg']}",
            err=True,
            fg="red",
            bold=True,
        )
        return

    data = r.json()["data"]
    click.secho(f"-------------- Users ----------------", bold=True)
    if not data:
        click.secho("No user logged in at the moment!", bold=True)
    else:
        for user in data:
            click.secho(
                f'Username: {user["username"]} -> IP Address: {user["ip_address"]}',
                bold=True,
            )


@chatapp.command()
@click.argument("channel_name")
def warn(channel_name):
    """
    Send a warning to a public channel
    """
    if not get_secrets():
        click.secho(
            "・You need to be logged in!",
            err=True,
            fg="red",
            bold=True,
        )
        return

    jwt, username = get_secrets()
    headers = {"Authorization": f"Bearer {jwt}"}
    r = requests.get(f"{URL}/search?q={channel_name}", headers=headers)
    if r.status_code > 200:
        click.secho(
            f"・{r.json()['msg']}",
            err=True,
            fg="red",
            bold=True,
        )
        return

    data = r.json()["data"]

    # SocketIO connection
    sio.connect(URL, headers=headers, transports="polling")

    while True:
        warning_message = (
            input(f"Enter a warning message to send to {channel_name} channel: ")
        ).strip()
        if not len(warning_message) > 0:
            click.secho(
                "・You cannot send an empty text ",
                err=True,
                fg="red",
                bold=True,
            )
            continue
        break

    sio.sleep(1)

    msg = f.encrypt(warning_message.encode())

    sio.emit(
        "new-channel-message",
        {"msg": msg, "from": username, "channel": channel_name},
    )

    click.secho(
        f"・Warning sent to {channel_name} channel successfully!", bold=True, fg="green"
    )

    sio.wait()

    return


@chatapp.command()
@click.argument("ip_addr")
def ban_ip(ip_addr):
    """
    Ban users using IP Address
    """
    if not get_secrets():
        click.secho(
            "・You need to be logged in!",
            err=True,
            fg="red",
            bold=True,
        )
        return

    jwt, username = get_secrets()
    headers = {"Authorization": f"Bearer {jwt}"}
    r = requests.get(f"{URL}/ban/ip/{ip_addr}", headers=headers)

    if r.status_code > 200:
        click.secho(
            f"・{r.json()['msg']}",
            err=True,
            fg="red",
            bold=True,
        )
        return

    msg = r.json()["msg"]
    click.secho(f"・{msg}", bold=True, fg="green")


@chatapp.command()
@click.argument("username")
def ban_username(username):
    """
    Ban user using their username
    """
    if not get_secrets():
        click.secho(
            "・You need to be logged in!",
            err=True,
            fg="red",
            bold=True,
        )
        return

    jwt, my_username = get_secrets()
    headers = {"Authorization": f"Bearer {jwt}"}
    r = requests.get(f"{URL}/ban/username/{username}", headers=headers)

    if r.status_code > 200:
        click.secho(
            f"・{r.json()['msg']}",
            err=True,
            fg="red",
            bold=True,
        )
        return

    msg = r.json()["msg"]
    click.secho(f"・{msg}", bold=True, fg="green")


@sio.on("connect")
def connect():
    pass


@sio.on("disconnect")
def disconnect():
    pass


@sio.on("channel-messages")
def channel_messages(data):
    if data["sender"]["username"] == "admin":
        click.secho(
            f'[{data["timestamp"]}] {data["sender"]["username"]}: {f.decrypt(data["content"].encode()).decode()}',
            bold=True,
            fg="yellow",
        )
    else:
        click.secho(
            f'[{data["timestamp"]}] {data["sender"]["username"]}: {f.decrypt(data["content"].encode()).decode()}',
            bold=True,
            fg="green",
        )


@sio.on("private-messages")
def private_messages(data):
    click.secho(
        f'[{data["timestamp"]}] {data["sender"]["username"]}: {f.decrypt(data["content"].encode()).decode()}',
        bold=True,
        fg="magenta",
    )


@sio.on("joined-channel")
def joined_channel(data):
    click.secho(f'{data["msg"]}', bold=True)


@sio.on("joined-private-chat")
def joined_private_chat(data):
    click.secho(f'{data["msg"]}', bold=True)


if __name__ == "__main__":
    chatapp()
