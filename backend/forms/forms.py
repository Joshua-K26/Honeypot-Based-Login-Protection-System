import re
from flask_wtf import FlaskForm
from sqlalchemy import func
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo, Regexp, ValidationError
)


def strong_password(form, field):
    pw = field.data or ""
    if not re.search(r"[A-Z]", pw):
        raise ValidationError("Password needs at least one uppercase letter.")
    if not re.search(r"[a-z]", pw):
        raise ValidationError("Password needs at least one lowercase letter.")
    if not re.search(r"\d", pw):
        raise ValidationError("Password needs at least one number.")
    if not re.search(r"[^A-Za-z0-9]", pw):
        raise ValidationError("Password needs at least one special character.")


class RegistrationForm(FlaskForm):

    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=50),
            Regexp(
                r"^[A-Za-z0-9_.-]+$",
                message="Username can only contain letters, numbers, dots, dashes and underscores."
            )
        ],
        render_kw={"maxlength": 50, "pattern": "[A-Za-z0-9_.\\-]+", "autocomplete": "username"}
    )

    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=120)],
        render_kw={"maxlength": 120, "autocomplete": "email"}
    )

    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=10, max=128), strong_password],
        render_kw={"minlength": 10, "maxlength": 128, "autocomplete": "new-password"}
    )

    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match")
        ],
        render_kw={"maxlength": 128, "autocomplete": "new-password"}
    )

    submit = SubmitField("Create Account")
    def validate_username(self, field):
        from models import User
        existing = User.query.filter(
            func.lower(User.username) == field.data.strip().lower()
        ).first()
        if existing:
            raise ValidationError("That username is not valid.")

    def validate_email(self, field):
        from models import User
        existing = User.query.filter(
            func.lower(User.email) == field.data.strip().lower()
        ).first()
        if existing:
            raise ValidationError("That email is not valid.")


class LoginForm(FlaskForm):

    username = StringField(
        "Username",
        validators=[DataRequired(), Length(max=120)],
        render_kw={"maxlength": 120, "autocomplete": "username"}
    )

    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(max=128)],
        render_kw={"maxlength": 128, "autocomplete": "current-password"}
    )

    submit = SubmitField("Login")