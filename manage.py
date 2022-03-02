import json
import time
import socket
from flask import Flask, request, session, jsonify, make_response, send_from_directory, abort
import os
from functools import wraps
from config import my_secretKey
import jwt
import requests
app = Flask(__name__)
app.config["SECRET_KEY"] = "SECRET_KEY"

OAUTH_REST_URL = "http://oauth-rest"
GET_USER_INFO = "/api/api_isSuperUser"

def get_host_ip():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip=s.getsockname()[0]
    finally:
        s.close()
    return ip


def get_username_by_auth(token):
    dict = jwt.decode(token, my_secretKey, algorithms=['HS256'])
    return dict['username']


def check_auth(token):
    dict = jwt.decode(token, my_secretKey, algorithms=['HS256'])
    print("decode token", dict)
    envRest, envWeb, username = dict['portal_rest'], dict['portal_web'], dict['username']
    matchRest = "A"
    matchWeb = "A"
    res = requests.get(OAUTH_REST_URL+GET_USER_INFO, params={"username": username})
    print(res.json())
    print(res.json()["superUser"])
    if res.json()["superUser"]:
        matchRest = "B"
        matchWeb = "B"
    if envRest != matchRest or envWeb != matchWeb or matchRest != os.environ["APP_ENV"]:
        return False
    return True


def authenticate():
    msg = "need authentication"
    resp = jsonify(code="-1", data={"msg": msg})
    return resp


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization')
        print("auth", auth)
        if not auth or not check_auth(auth):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/index')
@requires_auth
def hello():
    auth = request.headers.get('Authorization')
    msg = "token match env"
    ip = get_host_ip()
    resp = jsonify(code="0", data={"msg": msg, "ip": ip, "username": get_username_by_auth(auth)})
    return resp


@app.route('/test')
def test():
    return jsonify(code="0", data={"msg": "succeeded"})


def equal(b: bytes):
    """用来补齐被JWT去掉的等号"""
    rest = len(b) % 4
    return b + '='*rest


if __name__ == '__main__':
    app.run(debug=True)

    # key = "secret"
    # token = jwt.encode({"test": "100"}, key, "HS256")
    # header, payload, signature = token.split(".")
    #
    # print("header=",base64.urlsafe_b64decode(equal(header)))
    # print("payout=", base64.urlsafe_b64decode(equal(payload)))
    # print("signature", base64.urlsafe_b64decode(equal(signature)))

