#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource, Api

from config import app, db, bcrypt
from models import User

class ClearSession(Resource):

    def delete(self):
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204


class Signup(Resource):
    def post(self):
        json = request.get_json()
        user = User(
            username=json['username']
        )
        user.password_hash = bcrypt.generate_password_hash(json['password']).decode('utf-8')
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id

        return {'id': user.id, 'username': user.username}, 201  # Return user object in JSON response



class CheckSession(Resource):

    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = User.query.get(user_id)
            return user.to_dict()

        return None, 204

class Login(Resource):

    def post(self):
        json = request.get_json()
        user = User.query.filter_by(username=json['username']).first()

        if user and bcrypt.check_password_hash(user.password_hash, json['password']):  # Change here
            session['user_id'] = user.id
            return {'id': user.id, 'username': user.username}, 200  # Change here

        return {}, 401



class Logout(Resource):

    def delete(self):
        session['user_id'] = None

        return {}, 204

api = Api(app)
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)