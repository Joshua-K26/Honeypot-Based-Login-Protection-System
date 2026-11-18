from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    trust_score = db.Column(db.Integer, default=100)
    account_status = db.Column(db.String(20), default="active")

    created_at = db.Column(
        db.DateTime,
        default=datetime.now
    )
    security_alert_read = db.Column(
    db.Boolean,
    default=False
)


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    attempt_id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=True
    )

    username_entered = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    attempt_status = db.Column(db.String(20))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(
        db.DateTime,
        default=datetime.now
    )
    fingerprint_id = db.Column(db.String(255))

class IPBehaviour(db.Model):
    __tablename__ = "ip_behaviour"

    behaviour_id = db.Column(
        db.Integer,
        primary_key=True
    )

    ip_address = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    failed_attempt_count = db.Column(
        db.Integer,
        default=0
    )

    request_rate = db.Column(
        db.Integer,
        default=0
    )

    request_interval = db.Column(
        db.Integer,
        default=0
    )

    unique_usernames_tested = db.Column(
        db.Integer,
        default=0
    )

    ip_reputation = db.Column(
        db.Integer,
        default=100
    )

    trust_score = db.Column(
        db.Integer,
        default=100
    )

    last_updated = db.Column(
        db.DateTime,
        default=datetime.now
    )

class DecoySession(db.Model):
    __tablename__ = "decoy_sessions"

    session_id = db.Column(
        db.Integer,
        primary_key=True
    )

    attempt_id = db.Column(db.Integer)

    fake_username = db.Column(
        db.String(50)
    )

    ip_address = db.Column(
        db.String(45)
    )

    entry_time = db.Column(
        db.DateTime

    )
    last_activity_time = db.Column(db.DateTime)


    exit_time = db.Column(
        db.DateTime
    )

    pages_visited = db.Column(
        db.Integer,
        default=0
    )

    actions_performed = db.Column(
        db.Integer,
        default=0
    )
    status = db.Column(
    db.String(20),
    default="Active",
    nullable=False
    ) 
    fingerprint_id = db.Column(db.String(255))

class DecoyInteraction(db.Model):

    __tablename__ = "decoy_interactions"

    interaction_id = db.Column(
        db.Integer,
        primary_key=True
    )

    session_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "decoy_sessions.session_id"
        ),
        nullable=False
    )

    action_type = db.Column(
        db.String(50),
        nullable=False
    )

    page_name = db.Column(
        db.String(100)
    )

    interaction_time = db.Column(
        db.DateTime,
        default=datetime.now
    )

class RiskEvaluation(db.Model):

    __tablename__ = "risk_evaluations"

    risk_id = db.Column(
        db.Integer,
        primary_key=True
    )

    attempt_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "login_attempts.attempt_id"
        )
    )

    risk_score = db.Column(
        db.Integer
    )

    risk_level = db.Column(
        db.String(20)
    )

    evaluation_reason = db.Column(
        db.Text
    )

    evaluated_at = db.Column(
        db.DateTime
    )

class Resource(db.Model):

    __tablename__ = "resources"

    resource_id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(255),
        nullable=False
    )

    category = db.Column(
        db.String(100),
        nullable=False
    )
    resource_type = db.Column(
    db.String(20),
    nullable=False,
    default="Article"
)

    description = db.Column(
        db.Text
    )

    file_url = db.Column(
        db.String(255)
    )

    access_level = db.Column(
        db.String(50)
    )
    created_at = db.Column(
        db.DateTime
    )
    author = db.Column(
        db.String(100)
    )
    read_time = db.Column(
        db.String(20)
    )

    published_date = db.Column(
        db.Date
    )

    hero_image = db.Column(
        db.String(255)
    )

    article_content = db.Column(
        db.Text
    )

    download_file = db.Column(
        db.String(255)
)

class BlockedIP(db.Model):

    __tablename__ = "blocked_ips"

    block_id = db.Column(
        db.Integer,
        primary_key=True
    )

    ip_address = db.Column(
        db.String(45),
        unique=True,
        nullable=False
    )

    reason = db.Column(
        db.String(255)
    )

    blocked_by = db.Column(
        db.String(100)
    )

    blocked_at = db.Column(
        db.DateTime,
        default=datetime.now
    )

class Notification(db.Model):

    __tablename__ = "notification"

    notification_id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    title = db.Column(
        db.String(100),
        nullable=False
    )

    message = db.Column(
        db.Text,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.now
    )

    is_read = db.Column(
        db.Boolean,
        default=False
    )
    
    
    