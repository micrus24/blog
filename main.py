import types
from datetime import date
from functools import wraps
import sqlalchemy.exc
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy import String, create_engine, Integer, Text, ForeignKey
from sqlalchemy.orm import DeclarativeBase, mapped_column, Session, relationship
from werkzeug.security import generate_password_hash, check_password_hash

from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)


# CONFIGURE TABLES
class Base(DeclarativeBase):
    pass


class User(Base, UserMixin):
    __tablename__ = "users"
    __allow_unmapped__ = True

    id = mapped_column(Integer, primary_key=True)
    name = mapped_column(String(250), nullable=False)
    password = mapped_column(String(250), nullable=False)
    email = mapped_column(String(250), nullable=False, unique=True)
    is_authenticated: False
    is_active: True
    is_anonymous: False

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(Base):
    __tablename__ = "blog_posts"

    author_id = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    id = mapped_column(Integer, primary_key=True)
    title = mapped_column(String(250), unique=True, nullable=False)
    subtitle = mapped_column(String(250), nullable=False)
    date = mapped_column(String(250), nullable=False)
    body = mapped_column(Text, nullable=False)
    img_url = mapped_column(String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")


class Comment(Base):
    __tablename__ = "comments"

    author_id = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")

    post_id = mapped_column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    id = mapped_column(Integer, primary_key=True)
    text = mapped_column(Text, nullable=False)


class UserNotFound(Exception):
    """Raised when user not found in query == query returned None type"""
    pass


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return function(*args, **kwargs)

    return wrapper


# CONNECT TO DB
engine = create_engine('sqlite:///blog.db')
Base.metadata.create_all(engine)
login_manager = LoginManager()
login_manager.init_app(app)

session = Session(engine, expire_on_commit=False)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return session.get(User, user_id)


@app.route('/')
def get_all_posts():
    posts = session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts, user=current_user)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User(email=form.email.data,
                        name=form.name.data,
                        password=generate_password_hash(password=form.password.data, method="pbkdf2:sha256",
                                                        salt_length=8))
        try:
            session.add(new_user)
            session.commit()
        except sqlalchemy.exc.IntegrityError:
            flash("Email already used to register. Log in instead.")
            return redirect(url_for("login"))
        else:
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, user=current_user)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user_to_login = session.query(User).filter_by(email=form.email.data).first()
            if isinstance(user_to_login, types.NoneType):
                raise UserNotFound
        except UserNotFound:
            flash('User not found in database')
            return redirect(url_for("login"))
        else:
            if check_password_hash(user_to_login.password, form.password.data):
                login_user(user_to_login)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password incorrect try again')
                return redirect(url_for("login"))
    return render_template("login.html", form=form, user=current_user)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    post = session.get(BlogPost, post_id)
    if form.validate_on_submit() and current_user.is_authenticated:
        new_comment = Comment(author_id=current_user.id,
                              author=current_user,
                              post_id=post.id,
                              parent_post=post,
                              text=form.comment.data)
        session.add(new_comment)
        session.commit()
    elif not current_user.is_authenticated and form.validate_on_submit():
        flash("Only logged-in users can comment. Please log in.")
        return redirect(url_for('login'))
    return render_template("post.html", post=post, user=current_user, form=form)


@app.route("/about")
def about():
    return render_template("about.html", user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", user=current_user)


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        session.add(new_post)
        session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, user=current_user)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = session.get(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post = session.get(BlogPost, post_id)
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = session.get(BlogPost, post_id)
    session.delete(post_to_delete)
    session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/admin")
@admin_only
def admin():
    all_users = session.query(User).all()
    all_posts = session.query(BlogPost).all()
    return render_template('admin.html', user=current_user, all_users=all_users, all_posts=all_posts)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
