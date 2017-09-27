# -*- coding: utf-8 -*-
"""
    MiniTwit Tests
    ~~~~~~~~~~~~~~

    Tests the MiniTwit application.

    :copyright: (c) 2015 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import os
import tempfile
import pytest
import flask
from minitwit import minitwit
import requests

@pytest.fixture
def client():
    db_fd, minitwit.app.config['DATABASE'] = tempfile.mkstemp()
    client = minitwit.app.test_client()
    with minitwit.app.app_context():
        minitwit.init_db()

    yield client

    os.close(db_fd)
    os.unlink(minitwit.app.config['DATABASE'])


def register(client, username, password, password2=None, email=None):
	"""Helper function to register a user"""
	if password2 is None:
		password2 = password
	if email is None:
		email = username + '@example.com'
	return client.post('/register', data={
		'username':     username,
		'password':     password,
		'password2':	password2,
		'email':        email,
	}, follow_redirects=True)


def login(client, username, password):
	"""Helper function to login"""
#	return requests.get('http://0.0.0.0:5000/api/account/verify_credentials?username=danial&possword=danial')
	myParams = {"username":username,
				"password":password}
	return requests.get('http://0.0.0.0:5000/api/account/verify_credentials', params=myParams)
	#return client.get('/api/account/verify_credentials?username=foo&password=default', [username, password])
	#return client.get('/api/account/verify_credentials?username=<username>&password=<password>', [username, password])

def register_and_login(client, username, password):
	"""Registers and logs in in one go"""
	register(client, username, password)
	return login(client, username, password)

def logout(client):
	"""Helper function to logout"""
	return requests.delete('http://0.0.0.0:5000/api/account/verify_credentials')

def add_message(client, text):
	"""Records a message"""
	r = client.post("http://0.0.0.0:5000/api/statuses/update", [{"text" : "added from tests"}])
#	rv = client.post('/api/statuses/update', data={ 'text': text })
	if text:
		#assert b'Your message was recorded' in r.data
		return r


def test_register(client):
    """Make sure registering works"""
    rv = register(client, 'test1', 'default')
    assert b'You were successfully registered ' \
           b'and can login now' in rv.data
    rv = register(client, 'test1', 'default')
    assert b'The username is already taken' in rv.data
    rv = register(client, '', 'default')
    assert b'You have to enter a username' in rv.data
    rv = register(client, 'meh', '')
    assert b'You have to enter a password' in rv.data
    rv = register(client, 'meh', 'x', 'y')
    assert b'The two passwords do not match' in rv.data
    rv = register(client, 'meh', 'foo', email='broken')
    assert b'You have to enter a valid email address' in rv.data


def test_login_logout(client):
	"""Make sure logging in and logging out works"""
	rv = register_and_login(client, 'user1', 'default')
	assert 'username' in rv.text
	rv = logout(client)
	assert 200 in rv.text
	rv = login(client, 'user1', 'wrongpassword')
	assert 'error' in rv.text
	rv = login(client, 'user2', 'wrongpassword')
	assert 'error' in rv.text


def test_message_recording(client):
    """Check if adding messages works"""
    register_and_login(client, 'foo', 'default')
    add_message(client,'test message 1')
    add_message(client, '<test message 2>')
    rv = client.get('/api/statuses/home_timeline')
    assert b'test message 1' in rv.data
    assert b'&lt;test message 2&gt;' in rv.data

def test_timelines(client):
	"""Make sure that timelines work"""
	register_and_login(client, 'foo', 'default')
	add_message(client, 'the message by foo')
	logout(client)
	register_and_login(client, 'bar', 'default')
	add_message(client, 'the message by bar')
	rv = client.get('/api/stauses/public_timeline')
	assert b'the message by foo' in rv.data
	assert b'the message by bar' in rv.data

	# bar's timeline should just show bar's message
	rv = client.get('/api/statuses/user_timeline/bar')
	assert b'the message by foo' in rv.data
	assert b'the message by bar' in rv.data

	# now let's follow foo
	rv = client.get('/api/friendships/create?username=foo', follow_redirects=True)
	assert b'You are now following &#34;foo&#34;' in rv.data

	# we should now see foo's message
	rv = client.get('/api/statuses/public_timeline')
	assert b'the message by foo' in rv.data
	assert b'the message by bar' in rv.data

	# but on the user's page we only want the user's message
	rv = client.get('/api/statuses/user_timeline/bar')
	assert b'the message by foo' not in rv.data
	assert b'the message by bar' in rv.data
	rv = client.get('/api/statuses/user_timeline/foo')
	assert b'the message by foo' in rv.data
	assert b'the message by bar' not in rv.data

	# now unfollow and check if that worked
	rv = client.delete('/api/friendships/delete/foo', follow_redirects=True)
	assert b'You are no longer following &#34;foo&#34;' in rv.data
	rv = client.get('/api/statuses/public_timeline')
	assert b'the message by foo' not in rv.data
	assert b'the message by bar' in rv.data
