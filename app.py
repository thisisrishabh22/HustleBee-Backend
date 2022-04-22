from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from decouple import config
from flask_cors import CORS, cross_origin
import json

# Prod Or Dev
ENV = config("ENV")

# Getting Production or Development DB Credentials
def env_config():
    if ENV == "DEV":
        URI = config("LOCAL_URI")
        DB_NAME = config("LOCAL_DB_NAME")
        return {"URI": URI, "DB_NAME": DB_NAME}
    if ENV == "PROD":
        URI = config("URI")
        DB_NAME = config("DB_NAME")
        return {"URI": URI, "DB_NAME": DB_NAME}


DB_CREDS = env_config()

app = Flask(__name__)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# Making a Connection with MongoClient
app.client = MongoClient(host=DB_CREDS["URI"],connect=False)
# database
app.db = app.client[DB_CREDS["DB_NAME"]]

# collections
user = app.db["users"]
profile = app.db["profiles"]

# JWT Config
app.config["JWT_SECRET_KEY"] = "OizT0h_e6wDiIBlAX2s"
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'


@cross_origin()
@app.route("/dashboard")
@jwt_required
def dasboard():
    return jsonify(msg="Welcome!")

@cross_origin(origin='*')
@app.route("/register", methods=["POST"])
def register():
    if request.is_json:
        email = request.json["email"]
        name = request.json["name"]
        password = request.json["password"]
    else:
        email = request.form["email"]
        name = request.form["name"]
        password = request.form["password"]
    
    resp_user = user.find_one({"email": email})
    if resp_user:
        return jsonify(msg="User Already Exist")
    else:
        pw_hash = bcrypt.generate_password_hash(password)
        user_info = dict(name=name, email=email, password=pw_hash, token="")
        user.insert_one(user_info)
        return jsonify(msg="User added sucessfully")

@cross_origin(origin='*')
@app.route("/login", methods=["POST"])
def login():
    if request.is_json:
        email = request.json["email"]
        password = request.json["password"]
    else:
        email = request.form["email"]
        password = request.form["password"]

    resp_user = user.find_one({"email": email})
    if resp_user:
        pass_is_valid = bcrypt.check_password_hash(
            resp_user["password"], password)
        if pass_is_valid:
            access_token = create_access_token(identity=email)
            user.update_one({"email": email}, {
                            "$set": {"token": access_token}})
            return jsonify(msg="Login Succeeded!", accessToken=access_token)
        else:
            return jsonify(msg="Password Incorrect")
    else:
        return jsonify(msg="Not Registered")

@cross_origin(origin='*')
@app.route("/user", methods=["get"])
def get_user():
    if 'token' in request.headers:
        token = request.headers.get('token')
        resp_user = user.find_one({"token": token})
        if resp_user:
            user_data = {}
            user_data["_id"] = str(resp_user['_id'])
            user_data["email"] = resp_user["email"]
            user_data["name"] = resp_user["name"]
            return jsonify(msg="user found", user=user_data)
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")

@cross_origin(origin='*')
@app.route("/users", methods=["get"])
def get_users():
    if 'token' in request.headers:
        token = request.headers.get('token')
        resp_user = user.find_one({"token": token})
        if resp_user:
            fin_all_users = []
            all_users = user.find()
            for i in all_users:
                fin_all_users.append({"name": i["name"], "email": i["email"]})
            return jsonify(msg="users", users=fin_all_users)
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")

@cross_origin(origin='*')
@app.route("/create-profile", methods=["POST"])
def create_profile():
    if 'token' in request.headers:
        token = request.headers.get('token')
        if request.is_json:
            role =  request.json["role"]
            position = request.json["position"]
        else:
            role =  request.form["role"]
            position = request.form["position"]
    
        resp_user = user.find_one({"token": token})
        if resp_user:
            resp_profile = profile.find_one({"email" : resp_user["email"]})

            if resp_profile:
                return jsonify(msg="Profile already exist")
            else:
                prof_info = dict(name=resp_user["name"], email=resp_user["email"], role=role, position=position)
                profile.insert_one(prof_info)
                return jsonify(msg="Profile created sucessfully")
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")