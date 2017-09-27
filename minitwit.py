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
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack, jsonify

from werkzeug import check_password_hash, generate_password_hash


# configuration
DATABASE = '/tmp/minitwit.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

# create our little application :)
app = Flask('minitwit')
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)

#tested
@app.route('/api/statuses/home_timeline', methods=['GET'])
def homeTimeline():
	print(session.get('user_id'))
	if not g.user:
		return jsonify({"error" : "Unauthorized"}), 401

	rv=query_db('''select message.*, user.* from message, user where message.author_id = user.user_id and 
			(user.user_id = ? or user.user_id in (select whom_id from follower where who_id = ?)) 
			order message.pub_date desc limit ?''', [session['user_id'], session['user_id'], PER_PAGE])
	result = ([tuple(row) for row in rv])
	return jsonify(result), 200

#tested
@app.route('/api/statuses/public_timeline', methods=['GET'])
def publicTimeline():
	rv = query_db('select message.*, user.* from message, user where message.author_id = user.user_id order by message.pub_date desc limit ?', [PER_PAGE])
	return jsonify([tuple(row) for row in rv]), 200

#tested
@app.route('/api/statuses/user_timeline/<username>', methods=['GET'])
def userTimeline(username):
	profile_user = query_db('select * from user where username = ?', [username])
	whom_id = get_user_id(username)

	if profile_user is None:
		return jsonify({"error: Not Found"}), 404
	if not g.user:
		return jsonify({"error: Unauthorized"}), 401

	followed = query_db('select 1 from follower where follower.who_id = ? and follower.whom_id = ?', [session['user_id'], whom_id], one=True)
	rv = query_db('select message.*, user.* from message, user where user.user_id = message.author_id and user.user_id = ? order by message.pub_date desc limit ?', [whom_id, PER_PAGE])
	return jsonify([tuple(row) for row in rv]), 200

#tested
@app.route('/api/friendships/create', methods=['POST'])
def create_friendship():
	if request.method == 'POST':
		db = get_db()
		content = request.get_json()
		whom = content.get("username")
		whom_id = get_user_id(whom)

		if not g.user:
			return jsonify({"error: Unauthorized"}), 401
		if whom_id is None:
			return jsonify({"error: Not Found"}), 404

		db.execute('insert into follower (who_id, whom_id) values (?, ?)', [session['user_id'], whom_id])
		db.commit()
	else:
		return jsonify({"error: Method Not Allowed"}), 405
	
	return jsonify({"username": whom, "followed" : "True"}),200

#tested
@app.route('/api/friendships/delete/<username>', methods=['DELETE'])
def delete_friendship(username):
	if request.method == 'DELETE':
		db = get_db()
		whom_id = get_user_id(username)

		if not g.user:
			return jsonify({"error: Unauthorized"}), 401
		if whom_id is None:
			return jsonify({"error: Not Found"}), 404

		db.execute('delete from follower where who_id=? and whom_id=?', [session['user_id'], whom_id])
		db.commit()
	else:
		return jsonify({"error: Method Not Allowed"}), 405

	return jsonify({"username" : username, "followed" : "False"}), 200

#tested
@app.route('/api/statuses/update', methods=['POST'])
def addMessage():

	db = get_db()
	content = request.get_json()
	message = content.get('text')

	db.execute('insert into message (author_id, text, pub_date) values (?, ?, ?)', [session['user_id'], message, int(time.time())])
	db.commit()

	return jsonify({"message" : message}), 200

#tested
#FIX SESSION POP ---- CAN STILL ACCESS USER AFTER POPPING
@app.route('/api/account/verify_credentials', methods=['GET', 'DELETE'])
def verifyCredentials():
	db = get_db()
	if (request.method =='GET'):
		username = request.args.get('username',default=" ",type=str)
		user_id = get_user_id(username)
		print(user_id)
		password = request.args.get('password',default=" ",type=str)

		user = query_db('''select * from user where username = ?''', [username], one=True)
		if user is None:
			error = 'Invalid username'
			return jsonify({"error" : "Bad Request"}, 400)
		elif not check_password_hash(user['pw_hash'], password):
			error = 'Invalid password'
			return jsonify({"error" : "Unauthorized"}, 401)
		else:
			session['user_id'] = user_id
			session.modified = True
 			return jsonify({"username": username, "password":password}), 200
		
	elif (request.method == 'DELETE'):
		session.pop('user_id', None)

		return jsonify({"status" : "deleted"}), 200
	else:
		return jsonify({"error" : "Method Not Allowed"}), 405

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db


@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()


def init_db():
    """Initializes the database."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Initialized the database.')

def populate_db():
	db = get_db()
	with app.open_resource('population.sql', mode='r') as f:
		db.cursor().executescript(f.read())
	db.commit()

@app.cli.command('populatedb')
def populatedb_command():
	populate_db()
	print('Populated the databse.')

def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('select user_id from user where username = ?',
                  [username], one=True)
    return rv[0] if rv else None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'https://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']], one=True)


@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))
    return render_template('timeline.html', messages=query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id and (
            user.user_id = ? or
            user.user_id in (select whom_id from follower
                                    where who_id = ?))
        order by message.pub_date desc limit ?''',
        [session['user_id'], session['user_id'], PER_PAGE]))


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    return render_template('timeline.html', messages=query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id
        order by message.pub_date desc limit ?''', [PER_PAGE]))


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    profile_user = query_db('select * from user where username = ?',
                            [username], one=True)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_db('''select 1 from follower where
            follower.who_id = ? and follower.whom_id = ?''',
            [session['user_id'], profile_user['user_id']],
            one=True) is not None
    return render_template('timeline.html', messages=query_db('''
            select message.*, user.* from message, user where
            user.user_id = message.author_id and user.user_id = ?
            order by message.pub_date desc limit ?''',
            [profile_user['user_id'], PER_PAGE]), followed=followed,
            profile_user=profile_user)


@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    db = get_db()
    db.execute('insert into follower (who_id, whom_id) values (?, ?)',
              [session['user_id'], whom_id])
    db.commit()
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
    db = get_db()
    db.execute('delete from follower where who_id=? and whom_id=?',
              [session['user_id'], whom_id])
    db.commit()
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        db = get_db()
        db.execute('''insert into message (author_id, text, pub_date)
          values (?, ?, ?)''', (session['user_id'], request.form['text'],
                                int(time.time())))
        db.commit()
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where
            username = ?''', [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'], request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
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
        elif not request.form['email'] or \
                '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            db = get_db()
            db.execute('''insert into user (
              username, email, pw_hash) values (?, ?, ?)''',
              [request.form['username'], request.form['email'],
               generate_password_hash(request.form['password'])])
            db.commit()
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

