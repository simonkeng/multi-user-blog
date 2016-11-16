import os
import re
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

#### Steve Huffman's template framework
#### set up for use with jinja

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)



class MainPage(BlogHandler):
    def get(self):
        self.write('hello')



#### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    """define post class"""
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    # time stamp for date time of created post
    created = db.DateTimeProperty(auto_now_add = True)
    # time stamp to update the object, display last time updated
    last_modified = db.DateTimeProperty(auto_now = True)

    # render the blog entry
    # replace \n with <br> makes the html not mess things up
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BlogHandler):
    """looks up all the blog posts by time created
    and renders front.html with result of post query"""
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    """page for particular post"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    """return new post html and verify the form,
    then redirect"""
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            # p.put() to store p in the database
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'You did not enter subject or content!'
            self.render("newpost.html", subject = subject, content = content,
                        error = error)


# 0-9 + syntax is regular expression for describing a integer in app engine
# will be passed into PostPage as a integer

app = webapp2.WSGIApplication([('/', MainPage),
                                ('/blog/?', BlogFront),
                                ('/blog/([0-9]+)', PostPage),
                                ('/blog/newpost', NewPost),
                                ],
                                debug=True)
