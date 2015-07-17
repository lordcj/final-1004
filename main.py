#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import logging
from string import letters
from google.appengine.api import memcache
from google.appengine.ext import db
import re
import hmac

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
								autoescape = True)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

SECRET = "iamsosecret"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	r = USER_RE.match(username)
	if r:
		return username
	else:
		return None

PASS_RE = re.compile(r".{3,20}$")
def valid_key(password):
	r = PASS_RE.match(password)
	if r:
		return password
	else:
		return None

MAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")
def valid_mail(mail):
	r = MAIL_RE.match(mail)
	if r:
		return mail
	else:
		return None

def compare(password,c_password):
	if password == c_password:
		return True
	else:
		return None								

def signup_key(name = 'default'):
	return db.Key.from_path('signups',name)

def make_secure_val(user_id):
	return "%s|%s"%(user_id,hmac.new(SECRET,user_id).hexdigest())

def check_secure_val(s):
	r = s.split('|')[0]
	if s == make_secure_val(r):
		return r
	else:
		return False

def caching(refresh = False):
	key = "cache"	
	data = memcache.get(key)
	if not data or refresh:
		logging.error("DB QUERY")
		data = db.GqlQuery("SELECT * FROM Data ")
		data = list(data)
		memcache.set(key,data)
	return data

class Data(db.Model):
	username = db.StringProperty(required = True)
	password = db.TextProperty(required = True)
	write = db.TextProperty()

class Handler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.write(*a,**kw)

	def render_str(self,template,**params):
		t = jinja_env.get_template(template)
		return t.render(params)	

	def render(self,template,**kw):
		return self.write(self.render_str(template,**kw))
		
class MainHandler(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
    	username = self.request.get("username")
    	password = self.request.get("password")
    	c_password = self.request.get("c_password")
    	mail = self.request.get("mail")

    	v_user = valid_username(username)
    	v_pass = valid_key(password)
    	v_mail = valid_mail( mail)
    	match = compare(password,c_password)

    	direction = dict(username = username,mail = mail)

    	if not v_user:
    		direction["error1"] = "The username is not valid"

    	if not v_pass:
    		direction["error2"]	= "The password is not valid"

    	if not match:
    		direction["error3"] = "The passwords do not match"

    	if not v_mail:
    		direction["error4"] = "This is not a valid email"

    	if v_user and v_pass and match:
    		d = Data(parent = signup_key(),username = username,password = password)
    		d.put()
    		caching(True)
    		direction["message"] = "You have succesfully signed up"
    		self.render("signup.html",**direction)

    	else:
    		self.render("signup.html",**direction)				

class Login(Handler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")

		data = caching()
		direction = dict(username = username)
		for datas in data:
			if datas.username == username:
				if datas.password == password:
					key = str(datas.key().id())
					cookie_id = make_secure_val(key)
					self.response.headers.add_header('Set-Cookie','user_id=%s'%cookie_id)
					self.redirect('/')
					break
				else:
					direction["error2"] = "The password do not match"
					self.render("login.html",**direction)
					break
		else:
			direction["error1"] = "The username does not exist"
			self.render("login.html",**direction)

class Welcome(Handler):
	def get(self):
		user_id = self.request.cookies.get('user_id')
		if user_id:
				val = check_secure_val(user_id)
				if val:
					data = caching()
					for datas in data:
						if str(datas.key().id()) == val:
							username = datas.username
				self.render("main_page_e.html",username = username)
		else:
			self.render("main_page.html")
			
class Edit(Handler):
	def get(self):
		self.render("editing.html")

	def post(self):
		write = self.request.get("write")

		if write:
			user_id = self.request.cookies.get('user_id')
			val = check_secure_val(user_id)
			data = caching()
			for datas in data:
				if str(datas.key().id()) == val:
						username = datas.username
						password = datas.password
			d = Data(parent = signup_key(),write = write,username = username,password = password)
			caching(True)
			d.put()
			self.render('print.html',write = write,username = username)
		else:
			self.render("editing.html")

class Logout(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie','user_id = %s'%(""),path = '/')
		self.redirect('/')



app = webapp2.WSGIApplication([
    ('/signup',MainHandler),('/login',Login),('/', Welcome),('/edit',Edit),('/logout',Logout)
], debug=True)
