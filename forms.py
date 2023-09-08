from builtins import type

import wtforms
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, EmailField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email Address", validators=[DataRequired()])
    password = wtforms.PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Create User")



# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = StringField("Email Address", validators=[DataRequired()])
    password = wtforms.PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    body = CKEditorField('comment')
    submit = SubmitField('Add Comment')

class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email Address", validators=[DataRequired()])
    phoneNumber = wtforms.StringField("Phone Number", validators=[DataRequired()])
    Message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Submit Message")