from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from decouple import config
from flask_cors import CORS, cross_origin
from bson.objectid import ObjectId

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
app.client = MongoClient(host=DB_CREDS["URI"], connect=False)
# database
app.db = app.client[DB_CREDS["DB_NAME"]]

# collections
user = app.db["users"]
profile = app.db["profiles"]
job = app.db["jobs"]

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
        access_token = create_access_token(identity=email)
        user_info = dict(name=name, email=email,
                         password=pw_hash, token=access_token)
        user.insert_one(user_info)
        return jsonify(msg="User added sucessfully", accessToken=access_token)


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
            user_data = resp_user
            id = str(resp_user['_id'])
            user_data["_id"] = id
            user_data.pop("password")
            user_data.pop("token")
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
                fin_all_users.append(
                    {"_id": str(i["_id"]), "name": i["name"], "email": i["email"]})
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
            role = request.json["role"]
            position = request.json["position"]
            location = request.json["location"]
        else:
            role = request.form["role"]
            position = request.form["position"]
            location = request.form["location"]

        resp_user = user.find_one({"token": token})
        if resp_user:
            resp_profile = profile.find_one({"email": resp_user["email"]})

            if resp_profile:
                return jsonify(msg="Profile already exist")
            else:
                prof_info = dict(
                    name=resp_user["name"], email=resp_user["email"], role=role, position=position, location=location)
                profile.insert_one(prof_info)
                return jsonify(msg="Profile created sucessfully")
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")


@cross_origin(origin='*')
@app.route("/profile", methods=["get"])
def get_profile():
    if 'token' in request.headers:
        token = request.headers.get('token')
        resp_user = user.find_one({"token": token})
        if resp_user:
            resp_profile = profile.find_one({"email": resp_user["email"]})
            if resp_profile:
                profile_data = {}
                profile_data = resp_profile
                id = str(resp_profile["_id"])
                profile_data["_id"] = id
                profile_data = {**resp_profile}
                return jsonify(msg="profile found", profile=profile_data)
            else:
                return jsonify(msg="Profile not created!")
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")


@cross_origin(origin='*')
@app.route("/profiles", methods=["get"])
def get_profiles():
    if 'token' in request.headers:
        token = request.headers.get('token')
        resp_user = user.find_one({"token": token})
        if resp_user:
            fin_all_profiles = []
            all_profiles = profile.find()
            for i in all_profiles:
                fin_all_profiles.append({"_id": str(i["_id"]), "name": i["name"], "email": i["email"],
                                        "role": i["role"], "position": i["position"], "location": i["location"]})
            return jsonify(msg="profiles", profiles=fin_all_profiles)
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")


@cross_origin(origin='*')
@app.route("/create-job", methods=["post"])
def create_jobs():
    if 'token' in request.headers:
        token = request.headers.get('token')
        resp_user = user.find_one({"token": token})
        if resp_user:
            if request.is_json:
                title = request.json["title"]
                content = request.json["content"]
                salary = request.json["salary"]
                experience = request.json["experience"]
                location = request.json["location"]
                category = request.json["category"]
                type = request.json["type"]
                industry_category = request.json["industry_category"]
            else:
                title = request.form["title"]
                content = request.form["content"]
                salary = request.form["salary"]
                experience = request.form["experience"]
                location = request.form["location"]
                category = request.form["category"]
                type = request.form["type"]
                industry_category = request.form["industry_category"]

            job_info = dict(employer=resp_user["email"], title=title, content=content, salary=salary,
                            experience=experience, location=location, category=category, type=type,
                            industry_category=industry_category, applicants=[], published=0)
            job.insert_one(job_info)
            return jsonify(msg="job created successfully")
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")


@cross_origin(origin='*')
@app.route("/publish-job", methods=["get"])
def publish_jobs():
    if 'token' in request.headers:
        token = request.headers.get('token')
        job_id = request.headers.get('jobid')
        resp_user = user.find_one({"token": token})
        if resp_user:
            resp_job = job.find_one(
                {"employer": resp_user["email"], "_id": ObjectId(job_id)})
            print(resp_job)
            if resp_job["published"] == 1:
                return jsonify(msg="job already pubished")
            else:
                job.update_one({"employer": resp_user["email"], "_id": ObjectId(job_id)}, {
                               "$set": {"published": 1}})
                return jsonify(msg="job published")
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")


@cross_origin(origin='*')
@app.route("/unpublish-job", methods=["get"])
def unpublish_jobs():
    if 'token' in request.headers:
        token = request.headers.get('token')
        job_id = request.headers.get('jobid')
        resp_user = user.find_one({"token": token})
        if resp_user:
            resp_job = job.find_one(
                {"employer": resp_user["email"], "_id": ObjectId(job_id)})
            if resp_job["published"] == 1:
                job.update_one({"employer": resp_user["email"], "_id": ObjectId(job_id)}, {
                               "$set": {"published": 0}})
                return jsonify(msg="job unpublished")
            else:
                return jsonify(msg="job already unpublished")
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")


@cross_origin(origin='*')
@app.route("/jobs", methods=["get"])
def get_jobs():
    if 'token' in request.headers:
        token = request.headers.get('token')
        resp_user = user.find_one({"token": token})
        if resp_user:
            resp_job = job.find({"published": 1})
            fin_jobs = []
            for i in resp_job:
                data = i
                data["_id"] = str(data["_id"])
                fin_jobs.append(data)
            if len(fin_jobs) > 0:
                return jsonify(msg="jobs", jobs=fin_jobs)
            else:
                return jsonify(msg="no jobs")
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")


@cross_origin(origin='*')
@app.route("/apply", methods=["post"])
def apply_jobs():
    if 'token' in request.headers:
        token = request.headers.get('token')
        job_id = request.headers.get('jobid')
        resp_user = user.find_one({"token": token})
        if resp_user:
            resp_job = job.find_one(
                {"published": 1, "_id": ObjectId(job_id)})
            if resp_user["email"] in resp_job["applicants"]:
                return jsonify(msg="already applied to the job")
            else:
                new_applicants = resp_job["applicants"]
                new_applicants.append(resp_user["email"])
                job.update_one({"published": 1, "_id": ObjectId(job_id)}, {
                               "$set": {"applicants": new_applicants}})
                return jsonify(msg="applied to the job")
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")


@cross_origin(origin='*')
@app.route("/my-posted-jobs", methods=["get"])
def get_my_posted_jobs():
    if 'token' in request.headers:
        token = request.headers.get('token')
        resp_user = user.find_one({"token": token})
        if resp_user:
            resp_job = job.find({"employer": resp_user["email"]})
            fin_jobs = []
            for i in resp_job:
                data = i
                data["_id"] = str(data["_id"])
                fin_jobs.append(data)
            if len(fin_jobs) > 0:
                return jsonify(msg="my posted jobs", my_posted_jobs=fin_jobs)
            else:
                return jsonify(msg="you have no jobs posted")
        else:
            return jsonify(msg="not authorized")
    else:
        return jsonify(msg="not authorized")
