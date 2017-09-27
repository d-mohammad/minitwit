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
import json

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
	myParams = {"username":username,
				"password":password}
	return requests.get('http://localhost:5000/api/account/verify_credentials', params=myParams)

def logout(client):
	requests.delete('http://localhost:5000/api/account/verify_credentials')
	return rv

#Test showing the timeline for authenticated user
def show_home_timeline(client):
	requests.get('http://localhost:5000/api/statuses/home_timeline')
#	return requests.get('http://localhost:5000/api/statuses/home_timeline')

#Test showing public timeline for everyone
def show_public_timeline(client):
	return requests.get('http://localhost:5000/api/statuses/public_timeline')

#Test showing message posted by user
def show_user_messages(client, username):
	return requests.get('http://localhost:5000/api/statuses/user_timeline/<username>', [username])

#Test adding authenticated user to the followers list of specified user
def add_auth_follower(client, username):
	myParams = {"username" : username}
	headers = {'Content-type': 'application/json'}
	return requests.post('http://localhost:5000/api/friendship/create', data=json.dumps(myParams), headers=headers)

#Test remove authenticated user from followers of 'username'
def remove_follower(client, username):
	return requests.delete('http://localhost:5000/api/friendships/delete/<username>', [username])

#Test posting a new message from authenticated user
def post_new_message(client, text):
	myParams = {"text" : "text"}
	headers = {'Content-type': 'application/json'}
	return requests..post('http://localhost:5000/api/statuses/update', data=json.dumps(myParams), headers=headers)

def test_register_login_logout(client):
#	result = register(client, "danial", "danial")
#	assert result.status_code == 200
	login(client, "danial", "danial")
#	assert result.status_code == 200
	result = show_home_timeline(client)
#	assert result.status_code == 200
#	result = logout(client)
#	assert result.status_code == 200

#def test_login_add_message(client):
#	result = login(client, "danial", "danial")
#	assert result.status_code == 200
#	result = post_new_message(client, "pyTest suite")
#	assert result.status_code == 200
#	result = show_home_timeline(client)
#	assert result.status_code == 200
#	result = show_public_timeline(client)
#	assert result.status_code == 200
#	result = logout(client)
#	assert result.status_code == 200

#def test_follow_unfollow(client):
#	result = login(client, "danial", "danial")
#	assert result.status_code == 200
#	result = add_auth_follower(client, 'user1')
#	assert result.status_code == 200
	
