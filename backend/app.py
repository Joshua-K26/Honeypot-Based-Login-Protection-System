print("APP.PY LOADED SUCCESSFULLY")


from flask import Flask
from config import Config
from datetime import datetime, timedelta
from flask import send_from_directory
from sqlalchemy import func
from user_agents import parse
from functools import wraps

from models import (
    db,
    User,
    LoginAttempt,
    IPBehaviour,
    DecoySession,
    DecoyInteraction,
    RiskEvaluation,
    Resource,
    BlockedIP,
    Notification
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, request, session, flash, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from forms.forms import RegistrationForm, LoginForm
app = Flask(__name__)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.from_object(Config)

db.init_app(app)


ADMIN_USERNAME = "admin"

import os
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())
ADMIN_PASSWORD_HASH = os.environ["ADMIN_PASSWORD_HASH"]

def update_ip_behaviour(
    ip_address,
    username,
    success
):
    try:
        print("UPDATE IP BEHAVIOUR CALLED")
        print("IP:", ip_address, "SUCCESS:", success)

        behaviour = IPBehaviour.query.filter_by(
            ip_address=ip_address
        ).first()

        
        if not behaviour:
            print("CREATING NEW IP BEHAVIOUR ROW")
            behaviour = IPBehaviour(
                ip_address=ip_address
            )
            db.session.add(behaviour)
            db.session.commit()

        print("CURRENT TRUST SCORE:", behaviour.trust_score)   

        if not success:
            behaviour.failed_attempt_count += 1
           
        
        behaviour.unique_usernames_tested = (
    count_unique_usernames(ip_address)
)
        behaviour.request_rate = (
    calculate_request_rate(ip_address)
)
        behaviour.request_interval = (
    calculate_request_interval(ip_address)
)
        
        evaluation_reason = []

        if behaviour.failed_attempt_count > 3:
            evaluation_reason.append(
                "Multiple failed login attempts"
            )
        if behaviour.unique_usernames_tested > 5:
            evaluation_reason.append(
                "Multiple usernames tested"
            )
        
        if behaviour.request_rate > 10:
            evaluation_reason.append(
                "High request rate detected"
            )
        
        if behaviour.request_interval < 3:
            evaluation_reason.append(
                "Rapid successive requests detected"
            )

        if not evaluation_reason:
            evaluation_reason.append(
                "No suspicious activity detected"
            )
        
        reason = ", ".join(
            evaluation_reason
        )
        

    

       
        trust_score = behaviour.trust_score
        if not success:
            print("Failed login attempt, reducing trust score")
            trust_score -= 5
        
        if behaviour.unique_usernames_tested > 5:
            print("Multiple usernames tested, reducing trust score")
            trust_score -= 10
            print("New trust score after multiple usernames:", trust_score)
        
        if behaviour.request_rate > 10:
            print("High request rate detected, reducing trust score")
            trust_score -= 10
            print("New trust score after high request rate:", trust_score)
        
        if behaviour.request_interval < 3:
            print("Rapid requests detected, reducing trust score")
            trust_score -= 10
            print("New trust score after rapid requests:", trust_score)

        if trust_score < 0:
            trust_score = 0
        
        if trust_score > 100:
            trust_score = 100

        behaviour.trust_score = trust_score
        
        behaviour.last_updated = datetime.now()

        risk_level = get_risk_level(
            behaviour.trust_score
            )
        print("RISK LEVEL:", risk_level)

        print("NEW TRUST SCORE:", behaviour.trust_score)

        db.session.commit()
        print("IP BEHAVIOUR SAVED")

        return (
            risk_level,
            behaviour.trust_score,
            reason
        )

    except Exception as e:
        print("ERROR IN UPDATE IP BEHAVIOUR:", str(e))
        db.session.rollback()

def count_unique_usernames(ip_address):

    one_hour_ago = datetime.now() - timedelta(
        hours=1
    )

    usernames = db.session.query(
        LoginAttempt.username_entered
    ).filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.timestamp >= one_hour_ago
    ).distinct().all()

    return len(usernames)

def calculate_request_rate(ip_address):

    one_minute_ago = datetime.now() - timedelta(
        minutes=1
    )

    attempts = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.timestamp >= one_minute_ago
    ).all()

    return len(attempts)

def calculate_request_interval(ip_address):

    attempts = LoginAttempt.query.filter_by(
        ip_address=ip_address
    ).order_by(
        LoginAttempt.timestamp.desc()
    ).limit(2).all()

    if len(attempts) < 2:
        return 0

    latest = attempts[0].timestamp
    previous = attempts[1].timestamp

    interval = (
        latest - previous
    ).total_seconds()

    return int(interval)

def get_risk_level(trust_score):

    if trust_score >= 80:
        return "Low Risk"

    elif trust_score >= 50:
        return "Medium Risk"

    else:
        return "High Risk"
    
def create_decoy_session(
        ip_address,
        username, 
        attempt_id,
        fingerprint_id
        ):

    decoy_session = DecoySession(
        attempt_id=attempt_id,
        fake_username=username,
        ip_address=ip_address,
        entry_time=datetime.now(),
        
        last_activity_time=datetime.now(),
        exit_time=None,
        status="Active",
        fingerprint_id=fingerprint_id,
        pages_visited=1,

        actions_performed=0
    )

    db.session.add(decoy_session)
    db.session.commit()

    session["decoy_session_id"] = (
        decoy_session.session_id
    )

    print(
        "DECOY SESSION CREATED:",
        decoy_session.session_id
    )

from flask import session, redirect, url_for

def update_decoy_session():

    decoy_session_id = session.get("decoy_session_id")

    if not decoy_session_id:
        return None

    decoy_session = db.session.get(
        DecoySession,
        decoy_session_id
    )

    if not decoy_session:
        return None

    # Admin has terminated or blocked this session
    if decoy_session.status != "Active":

        session.clear()

        return redirect(url_for("login"))

    # Still active
    decoy_session.pages_visited += 1
    decoy_session.last_activity_time = datetime.now()

    db.session.commit()

    return None
from datetime import datetime, timedelta

def cleanup_expired_sessions():

    timeout = timedelta(minutes=5)

    now = datetime.now()

    active_sessions = DecoySession.query.filter_by(
        status="Active"
    ).all()

    for decoy_session in active_sessions:

        if decoy_session.last_activity_time:

            if now - decoy_session.last_activity_time > timeout:

                decoy_session.status = "Terminated"
                decoy_session.exit_time = now

                print(
                    f"Session {decoy_session.session_id} automatically terminated."
                )

    db.session.commit()

def session_is_active():

    decoy_session_id = session.get(
        "decoy_session_id"
    )

    if not decoy_session_id:
        return False

    decoy_session = db.session.get(
        DecoySession,
        decoy_session_id
    )

    if not decoy_session:
        return False

    if decoy_session.status != "Active":
        return False

    return True

def record_decoy_action():

    decoy_session_id = session.get(
        "decoy_session_id"
    )

    if not decoy_session_id:
        return

    decoy_session = db.session.get(
        DecoySession,
        decoy_session_id
    )

    if decoy_session:

        decoy_session.actions_performed += 1

        db.session.commit()


def save_risk_evaluation(
    attempt_id,
    risk_score,
    risk_level,
    reason
):

    evaluation = RiskEvaluation(
        attempt_id=attempt_id,
        risk_score=risk_score,
        risk_level=risk_level,
        evaluation_reason=reason,
        evaluated_at=datetime.now()
    )

    db.session.add(evaluation)
    db.session.commit()

    print(
        "RISK EVALUATION SAVED"
    )

def create_security_notification(user_id):

    existing = Notification.query.filter_by(

        user_id=user_id,
        is_read=False

    ).first()

    if existing:
        return

    notification = Notification(

        user_id=user_id,

        title="Security Alert",

        message=(
            "Our security systems detected suspicious login activity from an unfamiliar device "
            "targeting your Readers Odyssey account. "
            "Your account remains secure "
            "\n\n"
            "We recommend changing your password immediately "
            "and enabling Two-Factor Authentication."
        )

    )

    db.session.add(notification)
    db.session.commit()


@app.route("/")
def home():
    return redirect(url_for("login"))



@app.route("/register", methods=["GET", "POST"])
def register():

    form = RegistrationForm()

    if form.validate_on_submit():

        hashed_password = generate_password_hash(form.password.data)

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html", form=form)

@app.route("/hello")
def hello():
    return "HELLO TEST"


@app.route("/login", methods=["GET", "POST"])
def login():

    form = LoginForm()

    ip_address = request.remote_addr



    blocked = BlockedIP.query.filter_by(
    ip_address=ip_address
    ).first()

    if blocked:
        abort(403)
      

    user_agent = request.headers.get("User-Agent")
   
    platform = request.form.get("platform")


    language = request.form.get("language")

    timezone = request.form.get("timezone")

    screen_resolution = request.form.get("screen_resolution")

    fingerprint_id = request.form.get("fingerprint_id")

    print("FINGERPRINT:", fingerprint_id, flush=True)

    print("FORM SUBMITTED:", request.method, flush=True)
    sys.stdout.flush()
    print("FORM ERRORS:", form.errors, flush=True)
    sys.stdout.flush()

    if form.validate_on_submit():

        user = User.query.filter_by(
            username=form.username.data
        ).first()

        if user and check_password_hash(
            user.password_hash,
            form.password.data
        ):
            
            

            login_attempt = LoginAttempt(
                user_id=user.user_id,
                username_entered=form.username.data,
                ip_address=ip_address,
                attempt_status="success",
                user_agent=user_agent,
                fingerprint_id=fingerprint_id
            )

            print("SUCCESS LOGIN ATTEMPT", flush=True)
            sys.stdout.flush()

            db.session.add(login_attempt)
            db.session.commit()
            
            attempt_id = login_attempt.attempt_id

            print("ABOUT TO CALL UPDATE IP BEHAVIOUR", flush=True)
            sys.stdout.flush()

            risk_level, trust_score, reason = update_ip_behaviour(
                ip_address,
                form.username.data,
                True
            )

            save_risk_evaluation(
                attempt_id,
                trust_score,
                risk_level,
                reason
            )

            if risk_level == "High Risk":

                create_security_notification(user.user_id)

                user.security_alert_read = False

                db.session.commit()

                session.pop("decoy_session_id", None)

                session["decoy_username"] = form.username.data

                session["attempt_id"] = attempt_id

                create_decoy_session(
                    ip_address,
                    form.username.data,
                    attempt_id,
                    fingerprint_id
                )

                return redirect(url_for("decoy_dashboard"))
            
            session["username"] = user.username
            session["user_id"] = user.user_id

            return redirect(url_for("dashboard"))

            

        login_attempt = LoginAttempt(
            user_id=None,
            username_entered=form.username.data,
            ip_address=ip_address,
            attempt_status="failed",
            user_agent=user_agent,
            fingerprint_id=fingerprint_id
        )

        print("FAILED LOGIN ATTEMPT", flush=True)
        sys.stdout.flush()

        db.session.add(login_attempt)
        db.session.commit()
        
        attempt_id = login_attempt.attempt_id

        print("ABOUT TO CALL UPDATE IP BEHAVIOUR", flush=True)
        sys.stdout.flush()

        risk_level, trust_score, reason = update_ip_behaviour(
            ip_address,
            form.username.data,
            False
        )
        save_risk_evaluation(
            attempt_id,
            trust_score,
            risk_level,
            reason
        )


        flash(
             "Invalid username or password.",
             "danger"
            )
    print("FORM DID NOT VALIDATE", flush=True)
    sys.stdout.flush()

    return render_template(
        "login.html",
        form=form
    )

@app.route("/mark-alert-read")
def mark_alert_read():

    user_id = session.get("user_id")

    if not user_id:
        return redirect(url_for("login"))

    user = User.query.get(user_id)

    if user:

        user.security_alert_read = True

        db.session.commit()

    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():

    notifications = Notification.query.filter_by(

    user_id=session["user_id"]

).order_by(

    Notification.created_at.desc()

).all()
    
    
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        notifications=notifications
    )
@app.route("/article")
def article():
    return render_template("article.html")



@app.route("/decoy-dashboard")
def decoy_dashboard():

    print("SESSION DATA:", dict(session))

    ip_address = request.remote_addr

    username = session.get(
        "decoy_username",
        "Unknown"
    )

    attempt_id = session.get(
        "attempt_id"
    )

    if "decoy_session_id" not in session:

        print("CREATING NEW DECOY SESSION")

        create_decoy_session(
            ip_address,
            username,
            attempt_id
        )

    else:

        print(
            "UPDATING SESSION:",
            session["decoy_session_id"]
        )
        response= update_decoy_session()
        if response:
            return response


    return render_template(
        "decoy_dashboard.html",
        username=username,
        active_page="dashboard"
    )
@app.route("/decoy-profile")
def decoy_profile():

    response= update_decoy_session()
    if response:
        return response

    

    record_interaction(
        "view",
        "profile"
    )

    username = session.get(
        "decoy_username",
        "Unknown"
    )

    return render_template(
        "decoy_profile.html",
        username=username,
        active_page="profile"
    )
@app.route("/decoy-articles")
def decoy_articles():

    response= update_decoy_session()
    if response:
        return response

    

    record_interaction(
        "view",
        "articles"
    )

    username = session.get(
        "decoy_username",
        "Unknown"
    )

    resources = (
        Resource.query
        .filter_by(access_level="Premium")
        .all()
    )

    return render_template(
        "decoy_articles.html",
        username=username,
        resources=resources,
        active_page="articles"
    )
@app.route("/decoy-collections")
def decoy_collections():

    response= update_decoy_session()
    if response:
        return response

   

    record_interaction(
        "view", 
        "collections"
    )

    username = session.get(
        "decoy_username",
        "Unknown"
    )

    return render_template(
        "decoy_collections.html",
        username=username
    )

@app.route("/download-report")
def download_report():

    update_decoy_session()
    record_decoy_action()

    record_interaction(
        "download",
        "executive_report"
    )

    return """
    Premium Report Download Started...
    """

def record_interaction(
    action_type,
    page_name
):

    decoy_session_id = session.get(
        "decoy_session_id"
    )

    if not decoy_session_id:
        return

    interaction = DecoyInteraction(
        session_id=decoy_session_id,
        action_type=action_type,
        page_name=page_name
    )

    db.session.add(interaction)

    # Update the session statistics
    decoy_session = db.session.get(
        DecoySession,
        decoy_session_id
    )

    if decoy_session:

        decoy_session.actions_performed += 1
    db.session.commit()



@app.route("/decoy-subscription")
def decoy_subscription():

    response= update_decoy_session()
    if response:
        return response

    record_interaction(
        "view",
        "subscription"
    )

    username = session.get(
        "decoy_username",
        "Unknown"
    )

    return render_template(
        "decoy_subscription.html",
        username=username,
        active_page="subscription"
    )

@app.route("/decoy-history")
def decoy_history():
    response= update_decoy_session()
    if response:
        return response

    

    record_interaction(
        "view",
        "history"
    )
    username = session.get(
        "decoy_username",
        "Unknown"
    )


    return render_template(
        "decoy_history.html",
        username=username,
        active_page="history"

    )

@app.route("/decoy-saved")
def decoy_saved():
    response= update_decoy_session()
    if response:
        return response

    update_decoy_session()

    record_interaction(
        "view",
        "saved_articles"
    )
    username = session.get(
        "decoy_username",
        "Unknown"
    )

    return render_template(
        "decoy_saved.html",
        username=username,
        active_page="saved"
    )

@app.route("/decoy-downloads")
def decoy_downloads():

    response= update_decoy_session()
    if response:
        return response

    record_interaction(
        "view",
        "downloads"
    )
    username = session.get(
    "decoy_username",
    "Unknown"
)

    return render_template(
    "decoy_downloads.html",
    username=username,
    active_page="downloads"
)

    
@app.route("/download-market-report")
def download_market_report():

    update_decoy_session()

    record_decoy_action()

    record_interaction(
        "download",
        "market_report"
    )

    return "Downloading..."

@app.route("/download-tech-report")
def download_tech_report():

    update_decoy_session()

    record_decoy_action()

    record_interaction(
        "download",
        "tech_report"
    )

    return "Downloading..."

@app.route("/decoy-settings")
def decoy_settings():
    response= update_decoy_session()
    if response:
        return response

    

    record_interaction(
        "view",
        "settings"
    )

    username = session.get(
        "decoy_username",
        "Unknown"
    )

    return render_template(
        "decoy_settings.html",
        username=username,
        active_page="settings"
    )

@app.route("/decoy-article/<int:resource_id>")
def decoy_article(resource_id):
    response= update_decoy_session()
    if response:
        return response

    

    record_interaction(
        "view",
        f"article_{resource_id}"
    )

    resource = Resource.query.get_or_404(resource_id)

    username = session.get(
        "decoy_username",
        "Unknown"
    )

    return render_template(
        "decoy_article.html",
        username=username,
        resource=resource,
        active_page="articles"
    )

@app.route("/download-invoice")
def download_invoice():

    response = update_decoy_session()
    if response:
        return response

    record_decoy_action()

    record_interaction(
        "download_invoice",
        "subscription"
    )

    return send_from_directory(
        "static/downloads",
        "Premium_Invoice.pdf",
        as_attachment=True
    )

@app.route("/bookmark/<int:resource_id>")
def bookmark_resource(resource_id):

    update_decoy_session()

    record_interaction(
        "bookmark",
        f"resource_{resource_id}"
    )

    return redirect(
        url_for(
            "decoy_article",
            resource_id=resource_id
        )
    )

@app.route("/download-resource/<int:resource_id>")
def download_resource(resource_id):

    update_decoy_session()

    record_interaction(
        "download",
        f"resource_{resource_id}"
    )

    resource = Resource.query.get_or_404(resource_id)

    return send_from_directory(
        "static/downloads",
        resource.download_file,
        as_attachment=True
    )

@app.route("/reveal-recovery-codes")
def reveal_recovery_codes():

    response = update_decoy_session()
    if response:
        return response

    record_decoy_action()

    record_interaction(
        "Recovery Codes Revealed!!",
        "settings"
    )

    return "",204

@app.route("/reveal-api-key")
def reveal_api_key():

    response = update_decoy_session()
    if response:
        return response

    record_decoy_action()

    record_interaction(
        "API Key Revealed!!",
        "settings"
    )

    return "",204

@app.route("/reveal-backup-key")
def reveal_backup_key():

    response = update_decoy_session()
    if response:
        return response

    record_decoy_action()

    record_interaction(
        "Backup Key Revealed!!",
        "settings"
    )

    return "",204

@app.route("/copy-recovery-codes")
def copy_recovery_codes():

    response = update_decoy_session()
    if response:
        return response

    record_decoy_action()

    record_interaction(
        "Recovery Codes Copied!!",
        "settings"
    )

    return "", 204


@app.route("/copy-api-key")
def copy_api_key():

    response = update_decoy_session()
    if response:
        return response

    record_decoy_action()

    record_interaction(
        "API Key Copied!!",
        "settings"
    )

    return "", 204

@app.route("/copy-backup-key")
def copy_backup_key():

    response = update_decoy_session()
    if response:
        return response

    record_decoy_action()

    record_interaction(
        "Backup Key Copied!!",
        "settings"
    )

    return "", 204

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    if session.get("admin_logged_in"):

        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":

        username = request.form.get("username")

        password = request.form.get("password")

        if (

            username == ADMIN_USERNAME

            and

            check_password_hash(ADMIN_PASSWORD_HASH, password)

        ):

            session["admin_logged_in"] = True

            return redirect(url_for("admin_dashboard"))

        flash(
            "Invalid administrator credentials.",
            "danger"
        )

    return render_template("admin/admin_login.html")



def admin_required(f):

    @wraps(f)

    def decorated(*args, **kwargs):

        if not session.get("admin_logged_in"):

            return redirect(url_for("admin_login"))

        return f(*args, **kwargs)

    return decorated

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():


    cleanup_expired_sessions()
    current_time = datetime.now()

    one_hour_ago = datetime.now() - timedelta(hours=1)

    active_sessions = DecoySession.query.filter_by(
    status="Active"
).count()

    login_attempts = LoginAttempt.query.count()

    downloads = DecoyInteraction.query.filter_by(
        action_type="download"
    ).count()

    bookmarks = DecoyInteraction.query.filter_by(
        action_type="bookmark"
    ).count()

    page_views = DecoyInteraction.query.filter_by(
        action_type="view"
    ).count()

    alerts = RiskEvaluation.query.filter(
        RiskEvaluation.risk_level == "High Risk"
    ).count()


    live_sessions = (
    DecoySession.query
    .filter_by(status="Active")
    .order_by(
        DecoySession.entry_time.desc()
    )
    .limit(5)
    .all()
)

    recent_interactions = (
        DecoyInteraction.query
        .order_by(
            DecoyInteraction.interaction_time.desc()
        )
        .limit(5)
        .all()
    )
    recent_activity = []

    page_names = {
    "dashboard": "Dashboard",
    "articles": "Premium Articles",
    "history": "Reading History",
    "downloads": "Downloads",
    "bookmarks": "Bookmarks",
    "profile": "Profile",
    "magazines": "Magazines",
    "journals": "Journals"
    }

    action_names = {
    "view": "Viewed",
    "download": "Downloaded",
    "bookmark": "Bookmarked",
    "login": "Logged In"
    }

    for interaction in recent_interactions:

        display_name = page_names.get(
        interaction.page_name,
        interaction.page_name
        )

    # If it's a resource, replace resource_4 with the real title
        if interaction.page_name.startswith("resource_"):

            try:
               resource_id = int(
                   interaction.page_name.split("_")[1]
               )

               resource = db.session.get(
                    Resource,
                    resource_id
               )

               if resource:
                    display_name = resource.title

            except Exception:
                pass

        session = db.session.get(
            DecoySession,
            interaction.session_id
        )

        recent_activity.append({

            "time": interaction.interaction_time,

            "action": action_names.get(
            interaction.action_type,
            interaction.action_type.title()
            ),

            "resource": display_name,

            "username": session.fake_username if session else "Unknown"

        })

    targeted_resources = (
    db.session.query(
        DecoyInteraction.page_name,
        func.count(DecoyInteraction.interaction_id).label("hits")
    )
    .filter(
        DecoyInteraction.page_name.like("resource_%")
    )
    .group_by(
        DecoyInteraction.page_name
    )
    .order_by(
        func.count(DecoyInteraction.interaction_id).desc()
    )
    .limit(5)
    .all()
)
    resource_stats = []

    for item in targeted_resources:

        resource_id = int(item.page_name.split("_")[1])

        resource = db.session.get(
            Resource,
            resource_id
        )

        if resource:

            resource_stats.append({

                "title": resource.title,

                "hits": item.hits

            })
            


   
    active_sessions_last_hour = DecoySession.query.filter(
        DecoySession.entry_time >= one_hour_ago
    ).count()

    login_attempts_last_hour = LoginAttempt.query.filter(
        LoginAttempt.timestamp >= one_hour_ago
    ).count()

    downloads_last_hour = DecoyInteraction.query.filter(
        DecoyInteraction.action_type == "download",
        DecoyInteraction.interaction_time >= one_hour_ago
    ).count()

    bookmarks_last_hour = DecoyInteraction.query.filter(
        DecoyInteraction.action_type == "bookmark",
        DecoyInteraction.interaction_time >= one_hour_ago
    ).count()

    page_views_last_hour = DecoyInteraction.query.filter(
        DecoyInteraction.action_type == "view",
        DecoyInteraction.interaction_time >= one_hour_ago
    ).count()

    alerts_last_hour = RiskEvaluation.query.filter(
        RiskEvaluation.risk_level == "High Risk",
        RiskEvaluation.evaluated_at >= one_hour_ago
    ).count()
    return render_template(
        "admin/admin_dashboard.html",

        current_time=current_time,
        active_sessions=active_sessions,
        login_attempts=login_attempts,
        downloads=downloads,
        bookmarks=bookmarks,
        page_views=page_views,
        alerts=alerts,
        active_sessions_last_hour=active_sessions_last_hour,
login_attempts_last_hour=login_attempts_last_hour,
downloads_last_hour=downloads_last_hour,
bookmarks_last_hour=bookmarks_last_hour,
page_views_last_hour=page_views_last_hour,
alerts_last_hour=alerts_last_hour,
        live_sessions=live_sessions,
        recent_activity=recent_activity,
        resource_stats=resource_stats
    )



@app.route("/admin/active-sessions")
def activesessions():

    page = request.args.get("page", 1, type=int)

    pagination = (
    DecoySession.query
    .order_by(DecoySession.entry_time.desc())
    .paginate(
        page=page,
        per_page=10,
        error_out=False
    )
)

    sessions = pagination.items

    session_list = []

    for session in sessions:

        # Status
        if session.exit_time:
            status = "ended"
        else:
            status = "active"

        # Duration
        end_time = session.exit_time or datetime.now()

        duration = int(
            (end_time - session.entry_time)
            .total_seconds() / 60
        )

        # Number of actions
        actions = DecoyInteraction.query.filter_by(
            session_id=session.session_id
        ).count()

        session_list.append({

            "session_id": session.session_id,

            "fake_username": session.fake_username,

            "ip_address": session.ip_address,

            "entry_time": session.entry_time,

            "exit_time": session.exit_time,

            "duration": duration,

            "pages_visited": session.pages_visited,

            "actions": actions,

            "status": status

        })

    return render_template(
        "admin/activesessions.html",
        sessions=session_list,
        active_page="dashboard",
        pagination=pagination
    )


@app.route("/admin/sessions/<int:session_id>")
def admin_sessions(session_id):

    session = DecoySession.query.get_or_404(session_id)

    # Number of interactions
    interaction_count = (
        DecoyInteraction.query
        .filter_by(session_id=session.session_id)
        .count()
    )

    # Session duration
    end_time = session.exit_time or datetime.now()

    duration = int(
        (end_time - session.entry_time).total_seconds() / 60
    )

    # Login attempt (optional)
    login_attempt = (
        LoginAttempt.query
        .filter_by(attempt_id=session.attempt_id)
        .first()
    )

    # Browser / OS
    browser = "Unknown"
    operating_system = "Unknown"

    
    
    if login_attempt and login_attempt.user_agent:

        ua = parse(login_attempt.user_agent)

        browser = ua.browser.family
        operating_system = ua.os.family
    

    # Timeline
    timeline = (
        DecoyInteraction.query
        .filter_by(session_id=session.session_id)
        .order_by(DecoyInteraction.interaction_time.asc())
        .all()
    )

    page_names = {
        "dashboard": "Dashboard",
        "articles": "Premium Articles",
        "history": "Reading History",
        "downloads": "Downloads",
        "bookmarks": "Bookmarks",
        "profile": "Profile",
        "magazines": "Magazines",
        "journals": "Journals"
    }

    action_names = {
        "login": "Logged In",
        "view": "Viewed",
        "download": "Downloaded",
        "bookmark": "Bookmarked"
    }

    timeline_events = []

    for interaction in timeline:

        display_name = page_names.get(
            interaction.page_name,
            interaction.page_name
        )

        # Convert resource_4 into the actual resource title
        if interaction.page_name.startswith("resource_"):

            try:

                resource_id = int(
                    interaction.page_name.split("_")[1]
                )

                resource = db.session.get(
                    Resource,
                    resource_id
                )

                if resource:
                    display_name = resource.title

            except Exception:
                pass

        timeline_events.append({

            "time": interaction.interaction_time,

            "action": action_names.get(
                interaction.action_type,
                interaction.action_type.title()
            ),

            "resource": display_name,

            "action_type": interaction.action_type

        })

    # Counts for Session Statistics
    downloads = (
        DecoyInteraction.query
        .filter_by(
            session_id=session.session_id,
            action_type="download"
        )
        .count()
    )

    bookmarks = (
        DecoyInteraction.query
        .filter_by(
            session_id=session.session_id,
            action_type="bookmark"
        )
        .count()
    )

    page_views = (
        DecoyInteraction.query
        .filter_by(
            session_id=session.session_id,
            action_type="view"
        )
        .count()
    )

    risk = (
    RiskEvaluation.query
    .filter_by(attempt_id=session.attempt_id)
    .order_by(RiskEvaluation.evaluated_at.desc())
    .first()
)

    if risk:

     risk_level = risk.risk_level
     risk_score = risk.risk_score

    else:

     risk_level = "Low Risk"
     risk_score = 0

    return render_template(

        "admin/sessions.html",

        session=session,

        duration=duration,

        interaction_count=interaction_count,

        browser=browser,

        operating_system=operating_system,

        timeline_events=timeline_events,

        downloads=downloads,

        bookmarks=bookmarks,

        page_views=page_views,

        risk_level=risk_level,

        risk_score=risk_score,

        active_page="sessions"

    )

@app.route("/admin/resources")
def admin_resources():

    resources = Resource.query.all()

    total_resources = len(resources)

    total_views = 0
    total_downloads = 0
    total_bookmarks = 0

    resource_stats = []

    for resource in resources:

        page_name = f"resource_{resource.resource_id}"

        views = (
            DecoyInteraction.query
            .filter_by(
                page_name=page_name,
                action_type="view"
            )
            .count()
        )

        downloads = (
            DecoyInteraction.query
            .filter_by(
                page_name=page_name,
                action_type="download"
            )
            .count()
        )

        bookmarks = (
            DecoyInteraction.query
            .filter_by(
                page_name=page_name,
                action_type="bookmark"
            )
            .count()
        )

        last_access = (
            DecoyInteraction.query
            .filter_by(page_name=page_name)
            .order_by(
                DecoyInteraction.interaction_time.desc()
            )
            .first()
        )

        total_views += views
        total_downloads += downloads
        total_bookmarks += bookmarks

        resource_stats.append({

            "title": resource.title,

            "type": resource.resource_type,

            "views": views,

            "downloads": downloads,

            "bookmarks": bookmarks,

            "last_access": (
                last_access.interaction_time
                if last_access
                else None
            )

        })

    # Sort resources by most viewed
    resource_stats.sort(
        key=lambda x: x["views"],
        reverse=True
    )

    # Top 5 resources
    top_resources = resource_stats[:5]

    # Resource type distribution
    articles = (
        Resource.query
        .filter_by(resource_type="Article")
        .count()
    )

    reports = (
        Resource.query
        .filter_by(resource_type="Report")
        .count()
    )

    magazines = (
        Resource.query
        .filter_by(resource_type="Magazine")
        .count()
    )

    total_types = articles + reports + magazines

    article_percent = (
        (articles / total_types) * 100
        if total_types else 0
    )

    report_percent = (
        (reports / total_types) * 100
        if total_types else 0
    )

    magazine_percent = (
        (magazines / total_types) * 100
        if total_types else 0
    )

    return render_template(

        "admin/admin_resources.html",

        total_resources=total_resources,

        total_views=total_views,

        total_downloads=total_downloads,

        total_bookmarks=total_bookmarks,

        resource_stats=resource_stats,

        top_resources=top_resources,

        articles=articles,

        reports=reports,

        magazines=magazines,

        total_types=total_types,

        article_percent=article_percent,

        report_percent=report_percent,

        magazine_percent=magazine_percent,

        active_page="resources"

    )
@app.route("/admin/logs")
def admin_logs():

    interactions = (
        DecoyInteraction.query
        .order_by(DecoyInteraction.interaction_time.desc())
        .all()
    )

    page_names = {
        "dashboard": "Dashboard",
        "articles": "Premium Articles",
        "history": "Reading History",
        "downloads": "Downloads",
        "bookmarks": "Bookmarks",
        "profile": "Profile",
        "magazines": "Magazines",
        "journals": "Journals"
    }

    action_names = {
        "view": "View",
        "download": "Download",
        "bookmark": "Bookmark",
        "login": "Login",
        "login_failed": "Login Failed"
    }

    logs = []

    for interaction in interactions:

        session = db.session.get(
            DecoySession,
            interaction.session_id
        )

        resource_name = page_names.get(
            interaction.page_name,
            interaction.page_name
        )

        # Convert resource_4 into the actual article title
        if interaction.page_name.startswith("resource_"):

            try:

                resource_id = int(
                    interaction.page_name.split("_")[1]
                )

                resource = db.session.get(
                    Resource,
                    resource_id
                )

                if resource:
                    resource_name = resource.title

            except Exception:
                pass

        logs.append({

            "timestamp": interaction.interaction_time.strftime(
                "%d %b %Y %I:%M %p"
            ),

            "action": action_names.get(
                interaction.action_type,
                interaction.action_type.title()
            ),

            "action_type": interaction.action_type,

            "resource": resource_name,

            "session_id": (
                session.session_id
                if session
                else "-"
            ),
            "session_code": session.session_id,

            "ip_address": (
                session.ip_address
                if session
                else "-"
            )

        })

    pagination = {

        "start": 1 if logs else 0,

        "end": len(logs),

        "total": len(logs),

        "current": 1,

        "last": 1,

        "pages": [1]

    }

    return render_template(

        "admin/admin_logs.html",

        logs=logs,

        resources=Resource.query.order_by(Resource.title).all(),

sessions=DecoySession.query.order_by(
    DecoySession.session_id.desc()
).all(),

        pagination=pagination,

        active_page="logs"

    )

@app.route("/admin/analytics")
def admin_analytics():

    # =========================
    # Top Statistics
    # =========================

    total_interactions = DecoyInteraction.query.count()

    total_sessions = DecoySession.query.count()

    unique_ips = (
        db.session.query(
            DecoySession.ip_address
        )
        .distinct()
        .count()
    )

    page_views = DecoyInteraction.query.filter_by(
        action_type="view"
    ).count()

    downloads = DecoyInteraction.query.filter_by(
        action_type="download"
    ).count()

    bookmarks = DecoyInteraction.query.filter_by(
        action_type="bookmark"
    ).count()

    logins = LoginAttempt.query.count()


    # =========================
    # Average Session Duration
    # =========================

    sessions = DecoySession.query.all()

    durations = []

    for s in sessions:

        if s.entry_time and s.exit_time:

            duration = (
                s.exit_time - s.entry_time
            ).total_seconds()

            if 0 < duration < 3600:  # Only consider sessions less than 1 hour

                durations.append(duration)

    if durations:

        avg_seconds = sum(durations) / len(durations)

    else:

        avg_seconds = 0

    avg_minutes = int(avg_seconds // 60)

    avg_remaining = int(avg_seconds % 60)

    avg_session_duration = f"{avg_minutes}m {avg_remaining}s"


    # =========================
    # Bounce Rate
    # =========================

    bounced_sessions = sum(

        1

        for s in sessions

        if s.pages_visited <= 1

    )

    if total_sessions:

        bounce_rate = round(
            (bounced_sessions / total_sessions) * 100,
            1
        )

    else:

        bounce_rate = 0


    # =========================
    # Interaction Percentages
    # =========================

    interaction_total = (

        page_views +

        downloads +

        bookmarks +

        logins

    )

    if interaction_total:

        page_views_percent = round(
            page_views * 100 / interaction_total,
            1
        )

        downloads_percent = round(
            downloads * 100 / interaction_total,
            1
        )

        bookmarks_percent = round(
            bookmarks * 100 / interaction_total,
            1
        )

        logins_percent = round(
            logins * 100 / interaction_total,
            1
        )

    else:

        page_views_percent = 0
        downloads_percent = 0
        bookmarks_percent = 0
        logins_percent = 0


    # =========================
    # Top Attacker IPs
    # =========================

    top_ips = (

        db.session.query(

            DecoySession.ip_address,

            func.count(
                DecoySession.session_id
            ).label("sessions")

        )

        .group_by(
            DecoySession.ip_address
        )

        .order_by(
            func.count(
                DecoySession.session_id
            ).desc()
        )

        .limit(5)

        .all()

    )

    top_attackers = []

    for ip in top_ips:

        interaction_count = (

            db.session.query(

                func.count(
                    DecoyInteraction.interaction_id
                )

            )

            .join(

                DecoySession,

                DecoyInteraction.session_id
                ==
                DecoySession.session_id

            )

            .filter(

                DecoySession.ip_address
                ==
                ip.ip_address

            )

            .scalar()

        )

        top_attackers.append({

            "ip_address": ip.ip_address,

            "sessions": ip.sessions,

            "interactions": interaction_count

        })
    today = datetime.now()

    week_start = today - timedelta(days=6)

    daily_interactions = []

    for i in range(7):

        day = week_start + timedelta(days=i)

        next_day = day + timedelta(days=1)

        count = DecoyInteraction.query.filter(

            DecoyInteraction.interaction_time >= day,

            DecoyInteraction.interaction_time < next_day

        ).count()

        daily_interactions.append({

            "label": day.strftime("%b %d"),

            "count": count

    })
    max_interactions = max(
    [d["count"] for d in daily_interactions],
    default=1
)


    # =========================
    # Render Page
    # =========================

    return render_template(

        "admin/admin_analytics.html",

        total_interactions=total_interactions,

        avg_session_duration=avg_session_duration,

        unique_ips=unique_ips,

        bounce_rate=bounce_rate,

        page_views=page_views,

        downloads=downloads,

        bookmarks=bookmarks,

        logins=logins,

        page_views_percent=page_views_percent,

        downloads_percent=downloads_percent,

        bookmarks_percent=bookmarks_percent,

        logins_percent=logins_percent,

        top_attackers=top_attackers,

        today=today,
        week_start=week_start,
        daily_interactions=daily_interactions,

max_interactions=max_interactions,



        active_page="analytics"

    )

@app.route("/admin/settings")
@admin_required
def admin_settings():

    blocked_ips = BlockedIP.query.order_by(
        BlockedIP.blocked_at.desc()
    ).all()

    return render_template(
        "admin/admin_settings.html",
        active_page="settings",
        blocked_ips=blocked_ips
    )


def end_decoy_session(session_id):

    decoy_session = db.session.get(
        DecoySession,
        session_id
    )

    if not decoy_session:
        return

    if decoy_session.exit_time is None:

        decoy_session.exit_time = datetime.now()

    decoy_session.status = "Terminated"

    db.session.commit()

@app.route("/admin/session/<int:session_id>/terminate", methods=["POST"])
def terminate_session(session_id):

    decoy_session = DecoySession.query.get_or_404(session_id)

    decoy_session.status = "Terminated"

    if decoy_session.exit_time is None:
        decoy_session.exit_time = datetime.now()

    db.session.commit()

    flash("Session terminated successfully.", "success")

    return redirect(
        url_for(
            "admin_sessions",
            session_id=session_id
        )
    )
@app.route("/admin/block_ip/<int:session_id>", methods=["POST"])
def block_ip(session_id):

    decoy_session = db.session.get(
        DecoySession,
        session_id
    )

    if not decoy_session:

        flash(
            "Session not found.",
            "danger"
        )

        return redirect(
            url_for("activesessions")
        )

    existing = BlockedIP.query.filter_by(
        ip_address=decoy_session.ip_address
    ).first()

    if not existing:

        blocked = BlockedIP(

            ip_address=decoy_session.ip_address,

            reason="Blocked by administrator",

            blocked_by="Admin"

        )

        db.session.add(blocked)

    decoy_session.status = "Terminated"
    decoy_session.exit_time = datetime.now()

    db.session.commit()

    flash(
        f"{decoy_session.ip_address} blocked successfully.",
        "success"
    )

    return redirect(
        url_for(
            "admin_sessions",
            session_id=session_id
        )
    )

@app.route("/admin/unblock-ip", methods=["POST"])
@admin_required
def unblock_ip():

    data = request.get_json()

    ip = data.get("ip")

    blocked = BlockedIP.query.filter_by(
        ip_address=ip
    ).first()

    if blocked:

        db.session.delete(blocked)

        db.session.commit()

        return jsonify(success=True)

    return jsonify(success=False)

@app.route("/admin/logout")
@admin_required
def admin_logout():

    session.pop("admin_logged_in", None)

    flash(
        "Logged out successfully.",
        "success"
    )

    return redirect(url_for("admin_login"))







import sys
print(app.url_map, flush=True)
sys.stdout.flush()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)