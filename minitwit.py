# -*- coding: utf-8 -*-
"""
	MiniTwit
	~~~~~~~~

	A microblogging application written with Flask and sqlite3.

	:copyright: (c) 2015 by Armin Ronacher.
	:license: BSD, see LICENSE for more details.
"""

import time
import json
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
	 render_template, abort, g, flash, _app_ctx_stack, jsonify, Response
from werkzeug import check_password_hash, generate_password_hash
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from bson import json_util

# configuration
DATABASE = '/tmp/minitwit.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

# create our little application :)
app = Flask('minitwit')
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)
mongo = PyMongo(app)

@app.cli.command('populatedb')
def populatedb_command():
	populate_db()
	print('Populated the database.')

def get_user_id(username):
	"""Convenience method to look up the id for a username."""
	rv = mongo.db.user.find_one({'username': username}, {'_id': 1})
	return rv['_id'] if rv else None


def format_datetime(timestamp):
	"""Format a timestamp for display."""
	return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
	"""Return the gravatar image for the given email address."""
	return 'https://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
		(md5(email.strip().lower().encode('utf-8')).hexdigest(), size)

def populate_db():
	result = mongo.db.message.delete_many({})
	print result.deleted_count , "messages deleted"
	mongo.db.user.drop()
	print result.deleted_count , "users deleted"
	mongo.db.follower.drop()
	#password = asd
	#pbkdf2:sha256:50000$VkXoNh0W$74f25225aab278pbkdf2:sha256:50000$VkXoNh0W$74f25225aab278bf3ba83921af34604574d5246993429ec26903f5b9875ac18fbf3ba83921af34604574d5246993429ec26903f5b9875ac18f
	result = mongo.db.user.insert(
				{'username': 'testuser1',
				 'email': 'test1@email.com',
				 'pw_hash': 'pbkdf2:sha256:50000$OsYsSQ2F$be40fe67dc85114d7de5dcafa66df7fbdfdee5ab89c7609cc8455e79564eab1b'})
	mongo.db.message.insert(
			{'author_id': ObjectId(result),
			 'email': 'test1@email.com',
			 'username': 'testuser1',
			 'text': 'I LOVE THIS PROJECT!',
			 'pub_date': int(time.time())})
	result = mongo.db.user.insert(
				{'username': 'testuser2',
				 'email': 'test2@email.com',
				 'pw_hash': 'pbkdf2:sha256:50000$OsYsSQ2F$be40fe67dc85114d7de5dcafa66df7fbdfdee5ab89c7609cc8455e79564eab1b'})
	mongo.db.message.insert(
			{'author_id': ObjectId(result),
			 'email': 'test2@email.com',
			 'username': 'testuser2',
			 'text': 'I DON\'T LIKE THIS PROJECT!',
			 'pub_date': int(time.time())})
	result = mongo.db.user.insert(
				{'username': 'testuser3',
				 'email': 'test3@email.com',
				 'pw_hash': 'pbkdf2:sha256:50000$OsYsSQ2F$be40fe67dc85114d7de5dcafa66df7fbdfdee5ab89c7609cc8455e79564eab1b'})
	mongo.db.message.insert(
			{'author_id': ObjectId(result),
			 'email': 'test3@email.com',
			 'username': 'testuser3',
			 'text': 'IDK WHAT IM TYPING!',
			 'pub_date': int(time.time())})
	result = mongo.db.user.insert(
				{'username': 'testuser4',
				 'email': 'test4@email.com',
				 'pw_hash': 'pbkdf2:sha256:50000$OsYsSQ2F$be40fe67dc85114d7de5dcafa66df7fbdfdee5ab89c7609cc8455e79564eab1b'})
	mongo.db.message.insert(
			{'author_id': result,
			 'email': 'test4@email.com',
			 'username': 'testuser4',
			 'text': 'I DON\'T MIND THIS PROJECT!',
			 'pub_date': int(time.time())})

@app.before_request
def before_request():
	g.user = None
	if 'user_id' in session:
		g.user = mongo.db.user.find_one({'_id': ObjectId(session['user_id'])})

@app.route('/api/statuses/public_timeline', methods=['GET'])
def publicTimeline():
	messages = list(mongo.db.message.find().sort('pub_date', -1))
	#print messages[1].keys()
	return json.dumps(messages, sort_keys = False, indent = 4, default=json_util.default)


@app.route('/api/statuses/home_timeline', methods=['GET'])
def homeTimeline():
	if not session['user_id']:
		return jsonify({"error" : "Unauthorized"}), 401
	user = mongo.db.user.find_one({'_id': ObjectId(session['user_id'])})

	#handle users that arent following anyone - will error out otherwise
	try:
		following = user['following_id']
	except: 
		following = []

	messages = list(mongo.db.message.find(
		{'$or': [
			{'author_id': ObjectId(session['user_id'])},
			{'author_id': {'$in': following}}
		]}).sort('pub_date', -1))

	return json.dumps(messages,sort_keys = False, indent = 4, default=json_util.default)

@app.route('/api/statuses/user_timeline/<username>', methods=['GET'])
def userTimeline(username):
	profile_user = mongo.db.user.find_one({'username': username})
	whom_id = get_user_id(username)

	if profile_user is None:
		return jsonify({"status": "Not Found"}), 404

	messages = list(mongo.db.message.find(
		{'author_id': ObjectId(profile_user['_id'])}).sort('pub_date', -1))

	return json.dumps(messages,sort_keys = False, indent = 4, default=json_util.default)

@app.route('/api/friendships/create', methods=['POST'])
def create_friendship():
	if request.method == 'POST':
		content = request.get_json()
		whom = content.get("username")
		whom_id = get_user_id(whom)

		if session['user_id'] is None:
			return jsonify({"status: Unauthorized"}), 401
		if whom_id is None:
			return jsonify({"status: Not Found"}), 404

		mongo.db.user.update(
			{'_id': ObjectId(session['user_id'])},
			{'$push': {'following_id': whom_id}}, upsert=True)

	else:
	   return jsonify({"status: Method Not Allowed"}), 405

	return jsonify({"username": whom, "followed" : "True"}),200

@app.route('/api/friendships/delete/<username>', methods=['DELETE'])
def delete_friendship(username):
	if request.method == 'DELETE':
		whom_id = get_user_id(username)

		if session[user_id] is None:
			return jsonify({"status: Unauthorized"}), 401
		if whom_id is None:
			return jsonify({"status: Not Found"}), 404

		mongo.db.user.update(
			{'_id': ObjectId(session['user_id'])},
			{'$pull': {'following_id': whom_id}})
	else:
		return jsonify({"status: Method Not Allowed"}), 405

	return jsonify({"username" : username, "followed" : "False"}), 200

@app.route('/api/statuses/update', methods=['POST'])
def addMessage():
	content = request.get_json()
	message = content.get('text')
	user = mongo.db.user.find_one({'_id': ObjectId(session['user_id'])})

	if user is None:
		return jsonify({"status: Not Found"}), 404
	if session['user_id'] is None:
		return jsonify({"status: Unauthorized"}), 401

	mongo.db.message.insert(
            {'author_id': ObjectId(session['user_id']),
             'email': user['email'],
             'username': user['username'],
             'text': message,
             'pub_date': int(time.time())})

	return jsonify({"message" : message}), 200

@app.route('/api/account/verify_credentials', methods=['GET', 'DELETE'])
def verifyCredentials():
	if (request.method =='GET'):
		username = request.args.get('username',default=" ",type=str)
		user_id = get_user_id(username)
		password = request.args.get('password',default="asd",type=str)
				
		user = mongo.db.user.find_one({'username': username})

		if user is None:
			error = 'Invalid username'
			return jsonify({"status" : "Bad Request"}, 400)
		elif not check_password_hash(user['pw_hash'], password):
			error = 'Invalid password'
			return jsonify({"status" : "Unauthorized"}, 401)
		else:
			session['user_id'] = str(user_id)
			return jsonify({"username": username, "password":password}), 200
			
	elif (request.method == 'DELETE'):
		print session['user_id']
		session.pop('user_id', None)
		return jsonify({"status" : "deleted"}), 200
	else:
		return jsonify({"status" : "Method Not Allowed"}), 405


@app.route('/')
def timeline():
	if not g.user:
		return redirect(url_for('public_timeline'))
	user = mongo.db.user.find_one({'_id': ObjectId(session['user_id'])})
	#handle users that arent following anyone
	try:
		following = user['following_id']
	except: 
		following = []
	
	
	if following is None:
		following = {'whom_id': []}
	messages = list(mongo.db.message.find(
		{'$or': [
			{'author_id': ObjectId(session['user_id'])},
			{'author_id': {'$in': following}}
		]}).sort('pub_date', -1))
	return render_template('timeline.html', messages=messages)


@app.route('/public')
def public_timeline():
	result = list(mongo.db.follower.find({}))
	print(json.dumps(result, sort_keys = False, indent = 4, default=json_util.default))
	"""Displays the latest messages of all users."""
	messages = list(mongo.db.message.find().sort('pub_date', -1))
	return render_template('timeline.html', messages=messages)


@app.route('/<username>')
def user_timeline(username):
	"""Display's a users tweets."""
	profile_user = mongo.db.user.find_one({'username': username})

	if profile_user is None:
		abort(404)
	followed = False
	if g.user:
		following = mongo.db.user.find_one(
			{'_id': ObjectId(session['user_id']),
			 'following_id': {'$in': [ObjectId(profile_user['_id'])]}}) is not None
	messages = mongo.db.message.find(
		{'author_id': ObjectId(profile_user['_id'])}).sort('pub_date', -1)
	return render_template('timeline.html', messages=messages,
						   followed=following, profile_user=profile_user)


@app.route('/<username>/follow')
def follow_user(username):
	"""Adds the current user as follower of the given user."""
	if not g.user:
		abort(401)
	whom_id = get_user_id(username)
	if whom_id is None:
		abort(404)
	mongo.db.user.update(
		{'_id': ObjectId(session['user_id'])},
		{'$push': {'following_id': whom_id}}, upsert=True)

	result = mongo.db.user.find_one({'_id': ObjectId(session['user_id'])})
	print(json.dumps(result, sort_keys = False, indent = 4, default=json_util.default))
	flash('You are now following "%s"' % username)


	return redirect(url_for('user_timeline', username=username))

@app.route('/<username>/unfollow')
def unfollow_user(username):
	"""Removes the current user as follower of the given user."""
	if not g.user:
		abort(401)
	whom_id = get_user_id(username)
	if whom_id is None:
		abort(404)
	mongo.db.user.update(
		{'_id': ObjectId(session['user_id'])},
		{'$pull': {'following_id': whom_id}})
	flash('You are no longer following "%s"' % username)
	
	return redirect(url_for('user_timeline', username=username))

@app.route('/add_message', methods=['POST'])
def add_message():
	"""Registers a new message for the user."""
	if 'user_id' not in session:
		abort(401)
	if request.form['text']:
		mongo.db.message.insert(
			{'author_id': ObjectId(session['user_id']),
			 'email': g.user['email'],
			 'username': g.user['username'],
			 'text': request.form['text'],
			 'pub_date': int(time.time())})
		flash('Your message was recorded')
	return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
	"""Logs the user in."""
	if g.user:
		return redirect(url_for('timeline'))
	error = None
	if request.method == 'POST':
		user = mongo.db.user.find_one({'username': request.form['username']})
		if user is None:
			error = 'Invalid username'
		elif not check_password_hash(user['pw_hash'], request.form['password']):
			error = 'Invalid password'
		else:
			flash('You were logged in')
			session['user_id'] = str(user['_id'])
			return redirect(url_for('timeline'))
	return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
	"""Registers the user."""
	if g.user:
		return redirect(url_for('timeline'))
	error = None
	if request.method == 'POST':
		if not request.form['username']:
			error = 'You have to enter a username'
		elif not request.form['email'] or '@' not in request.form['email']:
			error = 'You have to enter a valid email address'
		elif not request.form['password']:
			error = 'You have to enter a password'
		elif request.form['password'] != request.form['password2']:
			error = 'The two passwords do not match'
		elif get_user_id(request.form['username']) is not None:
			error = 'The username is already taken'
		else:
			mongo.db.user.insert(
				{'username': request.form['username'],
				 'email': request.form['email'],
				 'pw_hash': generate_password_hash(request.form['password'])})
			flash('You were successfully registered and can login now')
			return redirect(url_for('login'))
	return render_template('register.html', error=error)


@app.route('/logout')
def logout():
	"""Logs the user out."""
	flash('You were logged out')
	session.pop('user_id', None)
	return redirect(url_for('public_timeline'))

# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url