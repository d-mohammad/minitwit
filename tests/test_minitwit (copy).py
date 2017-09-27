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

def login(client, username, password):
	myParams = {"username":username,"password":password}
	return requests.get('http://0.0.0.0:5000/api/account/verify_credentials', params=myParams)

def logout(client):
	return client.delete('http:0.0.0.0:5000/api/account/verify_credential')
#Test showing the timeline for authenticated user
def test_show_auth_timeline(client):
	return client.get('/api/statuses/home_timeline')

#Test showing public timeline for everyone
def test_show_public_timeline(client):
	return requests.get('http://0.0.0.0:5000/api/statuses/public_timeline')

#Test showing message posted by user
def test_show_messages(client, username):
	return requests.get('http://0.0.0.0:5000/api/statuses/user_timeline/<username>', [username])

#Test adding authenticated user to the followers list of specified user
def test_add_auth_follower(client, username):
	return requests.post('http://0.0.0.0:5000/api/friendship/create', data={"username" : username})	

#Test remove authenticated user from followers of 'username'
def test_remove_follower(client, username):
	return requests.delete('http://0.0.0.0:5000/api/friendships/delete/<username>', username)

#Test posting a new message from authenticated user
def test_post_new_message(client, text):
	return requests.post('http://0.0.0.0:5000/api/statuses/update', [{"text" : text}])
