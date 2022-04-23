from os import abort
from decouple import config
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, LoginForm, RegisterForm, CommentForm
from flask_gravatar import Gravatar
import sqlite3
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = config('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
db.create_all()


# ******************************** READ THE FOLLOWING LINK **********************************
# https://github.com/maxcountryman/flask-login

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    pass
 

@login_manager.user_loader
def user_loader(email):
    db = sqlite3.connect('blog.db')
    email_search = db.execute(f'''SELECT email FROM users WHERE email = '{email}' ''').fetchone()
    db.commit()
    db.close()
    if email_search == None:
        return email_search
    else:
        user = User()
        user.id = email
        return user


@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    db = sqlite3.connect('blog.db')
    email_search = db.execute(f'''SELECT email FROM users WHERE email = '{email}' ''').fetchone()
    db.commit()
    db.close()
    if email_search == None:
        return email_search
    else:
        user = User()
        user.id = email
        return user


# Decorator function
# Create admin-only decorator
def admin_only(function):
    @wraps(function)
    def decorator_function(*args, **kwargs):        
        try:
            db = sqlite3.connect('blog.db')

            user_id = db.execute(f''' SELECT id FROM users WHERE email = '{current_user.id}' ''').fetchone()
            user_id = int(user_id[0])
            print(user_id)
            db.commit()
            db.close()
        except:
            db.commit()
            db.close
            user_id = None

        finally:
            # Continue with the route function if id == 1
            if user_id == 1:
                print(f'user id: {user_id}')
                return function(*args, **kwargs)

            # If id is not 1 then return abort with 403 error
            else:
                print('aborted')
                return abort(403)
        
    return decorator_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    
    try:
        print(current_user.id)
        db = sqlite3.connect('blog.db')

        user_id = db.execute(f''' SELECT id FROM users WHERE email = '{current_user.id}' ''').fetchone()
        user_id = int(user_id[0])
        print(user_id)
        db.commit()
        db.close()
    except:
        user_id = None

    return render_template("index.html",user_id=user_id, all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(password=request.form['password'], method='pbkdf2:sha256', salt_length=8)
        name = request.form['name']
        # password = request.form['password']

        print(f'{email} - {name} - {password}')
        db = sqlite3.connect('blog.db')

        try:
            db.execute(f'''
                INSERT INTO users (email, name, password)
                VALUES ('{email}', '{name}', '{password}')
            ''')
            db.commit()
            db.close()

            user = User()
            user.id = email
            login_user(user)

            return redirect(url_for('get_all_posts'))
        except:
            print(f"'{email}' is already registered.")

            db.commit()
            db.close()
            flash("You've already signed up with that email. Log in instead!")
            return redirect(url_for('login'))

    else:
        form = RegisterForm()

        return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm()
    if request.method == 'POST':

        email_given = request.form['email']
        password_given = request.form['password']

        db = sqlite3.connect('blog.db')
        email_search = db.execute(f'''SELECT email FROM users WHERE email = '{email_given}' ''').fetchone()
        db.commit()

        password_search = db.execute(f'''SELECT password FROM users WHERE email = '{email_given}' ''').fetchone()
        db.commit() 
        db.close()

        if email_search == None:
            error = 'That email does not exist, please try again.'
              
        else:
            password_check = check_password_hash(pwhash=password_search[0], password=password_given)

            print(password_check)
            print(email_search)
            print(password_search)
            
            if password_check == True:
                user = User()
                user.id = email_given
                login_user(user)
                return redirect(url_for('get_all_posts'))

            else:
                error = 'Password incorrect, please try again.'

    return render_template("login.html", form=form, error=error, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():

    logout_user()
    print("Logged out!")

    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    try:
        print(current_user.id)
        db = sqlite3.connect('blog.db')

        user_id = db.execute(f''' SELECT id FROM users WHERE email = '{current_user.id}' ''').fetchone()
        user_id = int(user_id[0])
        print(user_id)
        db.commit()
        db.close()
    except:
        user_id = None


    # List comments
    db = sqlite3.connect('blog.db')
    db.row_factory = sqlite3.Row
    comments = db.execute(f''' SELECT * FROM comments WHERE post_id = {post_id} ''').fetchall()
    db.commit()
    db.close()

    for post in comments:
        print(post['comment'])

    form = CommentForm()

    if request.method == 'POST':
        comment = request.form['comment']
        author_id = user_id

        db = sqlite3.connect('blog.db')
        author = db.execute(f''' SELECT name FROM users WHERE email = '{current_user.id}' ''').fetchone()
        db.commit()  
        author = author[0]

        db.execute(f'''
            INSERT INTO comments (post_id, comment, author_id, author)
            VALUES ({post_id}, '{comment}', {author_id}, '{author}')
        ''')
        db.commit()
        db.close()
        return redirect(url_for('show_post', post_id=post_id))


    return render_template("post.html", comments=comments, user_id=user_id, form=form, post=requested_post, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    title = 'New Post'
    form = CreatePostForm()
    if request.method == 'POST':
        title = request.form['title']
        subtitle = request.form['subtitle']
        img_url = request.form['img_url']
        body = request.form['body']

        current_date = datetime.now()
        time_stamp = current_date.strftime('%B %d, %Y')

        print(f'this is the user_id : {current_user.id}')
        db = sqlite3.connect('blog.db')

        author = db.execute(f'''SELECT name FROM users WHERE email = '{current_user.id}' ''').fetchone()
        db.commit()
        author = author[0]

        author_id = db.execute(f'''SELECT id FROM users WHERE email = '{current_user.id}' ''').fetchone()
        db.commit()
        author_id = author_id[0]

        db.execute(f'''INSERT INTO blog_posts (author_id, title, date, body, author, img_url, subtitle)
                    VALUES ({author_id}, '{title}', '{time_stamp}', '{body}', '{author}', '{img_url}', '{subtitle}')
       ''')

        db.commit()
        db.close()
        return redirect(url_for('get_all_posts'))
    return render_template("make-post.html", title=title, form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    title_h1 = 'Edit Post'
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", title=title_h1, form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
