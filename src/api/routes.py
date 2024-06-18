"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200


@api.route("/signup", methods=["POST"])
def handle_signup():

    request_body_user = request.get_json()
    user=User.query.filter_by(email=request_body_user["email"],password=request_body_user["password"]).first()

    if user:
        return jsonify({"msg":"el usuario ya existe"})
    new_user=User(email=request_body_user["email"],password=request_body_user["password"])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg":"nuevo usuario registrado"}), 200


@api.route("/login", methods=["POST"])
def handle_login():

    request_data = request.get_json()
    email=request_data.get("email")
    password=request_data.get("password")

    if not email or not password:
        return jsonify({"mgs":"email y password requeridos"})
    user=User.query.filter_by(email=email, password=password).first()
    if not user:
        return jsonify({"msg":"email y password incorrectos"})
    token=create_access_token(identity=user.id)
    return jsonify({"msg":token,"user_id":user.id})




