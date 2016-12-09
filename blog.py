import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'super-dooper_really-really_secretsecret'

### Steve Huffman's template framework

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

###

class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        # same as saying
        # if cookie_val and check_secure_val(cookie_val):
        #     return cookie_val
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):

    def get(self):
        self.render('enter.html')


### user stuff

def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)

# user object to be stored in db

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        # datastore procedural look up
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u



### blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)



class Post(db.Model):
    """define post class"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    name = db.ReferenceProperty(User)
    likes = db.IntegerProperty()
    # author = db.ReferenceProperty(Author)


    @property
    def like_count(likes):
        return likes.length

    # render the blog entry
    # replace \n with <br> makes the html not mess things up
    def render(self):
        # likes = self.post_likes(post_id)
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self) # likes=likes


class Likes(db.Model):
    name = db.StringProperty(required=True)
    post_id = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class Comment(db.Model):
    content = db.TextProperty(required = True)
    post_id = db.ReferenceProperty(Post)
    # post_id = db.IntegerProperty(required = True)
    name = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True )
    last_modified = db.DateTimeProperty(auto_now = True)
    likes = db.IntegerProperty(required = False)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", p = self)

###### moagm udacity mentor code

# class PostLike(db.Model):

#     like_user_id = db.StringProperty(required=True)


# parent=key of the post



class BlogFront(BlogHandler):
    """looks up all the blog posts by time created
    and renders front.html with result of post query"""

    def get(self):
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    """page for particular post"""

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(BlogHandler):
    """return new post html and verify the form,
    then redirect"""

    def get(self):
        self.render("newpost.html")

    def post(self):
        if not self.user:
            return self.redirect('/signup')
        subject = self.request.get('subject')
        content = self.request.get('content')
        # author = self.user.name
        likes = 0

        if subject and content:
            p = Post(parent=blog_key(), author=author,
                subject=subject, content=content, likes=likes)
            # p.put() to store p in the database
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'You did not enter subject or content!'
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


# sign up stuff

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):

    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class EditPost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("editpost.html", post=post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            return self.redirect('/signup')
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            # p = Post(parent=blog_key(), subject=subject, content=content)
            # p = db.get(post)
            post.subject = subject
            post.content = content
            post.put()

            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = 'You did not enter subject or content!'
            self.render("newpost.html", subject=subject, content=content,
                        error=error, likes=likes, author=author)


class DeletePost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/login")
        else:
            self.render('deletepost.html', post_id=id)

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)

            post.delete()
            self.redirect('/blog/')




class NewComment(BlogHandler):

    def get(self, post_id):
        if self.user:
            self.render("comment.html", postId= post_id)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
        content = self.request.get('content')
        name= self.request.get('name')
        created = self.request.get('created')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        posts = db.get(key)

        if posts == None:
            return self.redirecto('/blog')

        if content:
            c = Comment(content = content, name=name, post_id= posts)
            c.put()
            return self.redirect('/blog')
        else:
            error = "subject and content, please!"
            self.render("comment.html", content=content, error=error)




class LikePost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect("/login")
        else:
            self.redirect('/blog')


    def post(self, post_id):
        name = self.request.get('name')

        q = db.Query(Likes)
        q.filter('post_id =', post_id).filter('name =', name)
        created = ''
        for p in q.run():
            return self.redirect('/blog')
            return

        l = Likes(name = name, post_id=post_id)
        l.put()
        key = db.Key.from_path("Post", id, parent=blog_key())
        posts = db.get(key)
        if posts == None:
            return self.redirect('/blog')

        if posts.likes == None:
            posts.likes = 1
        else:
            posts.likes += 1
        posts.put()
        self.redirect('/blog')

        # post.likes = post.likes + 1
        # post.liked_by.append(self.user.name)

        # if self.user.name:
        #     post.put()
        #     self.redirect('/blog')

        # else:
        #     key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        #     post = db.get(key)
            # author = db.get(author_key)

            # logged_user = self.user.name

            # post.likes.name = self.user.name

            # post.put()
            # self.redirect('/blog')

# if author == logged_user or logged_user in post.liked_by
            #     self.redirect('/error')
            # else:
            #     post.likes += 1
            #     post.liked_by.append(logged_user)
            #     post.put()
            #     self.redirect('/blog')



class Login(BlogHandler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/blog')


class BlogWelcome(BlogHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')



app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/([0-9]+)/editpost', EditPost),
                               ('/blog/([0-9]+)/deletepost', DeletePost),
                               ('/blog/newcomment/([0-9]+)', NewComment),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/blog/welcome', BlogWelcome),
                               ],
                              debug=True)


# http://colorhunt.co/c/42254

