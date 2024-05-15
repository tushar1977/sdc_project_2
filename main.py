import os
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import LargeBinary
from werkzeug.utils import secure_filename
from flask import send_file, make_response
import io
import bcrypt
from flask_login import UserMixin, current_user, LoginManager

from flask_login import login_user, logout_user

app = Flask(__name__)

upload_folder = "images"
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.init_app(app)
app.config["SECRET_KEY"] = "test"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db_main.sqlite"
app.config["UPLOAD_FOLDER"] = upload_folder
app.config["UPLOAD_EXTENSIONS"] = [".jpeg", ".png", ".pdf"]
db = SQLAlchemy(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pdf = db.Column(db.LargeBinary, nullable=False)
    file_name = db.Column(db.String(1000), nullable=False)


class User_login(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


@app.route("/index/<int:user_id>", methods=["GET"])
def view_pdf(user_id):
    user = User.query.get(user_id)
    if user:
        binary_pdf = user.pdf
        response = make_response(
            send_file(
                io.BytesIO(binary_pdf),
                mimetype="application/pdf",
                as_attachment=False,
            )
        )
        response.headers["Content-Disposition"] = f'inline; filename="{user.file_name}"'
        return response
    else:
        return "User not found", 404


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        files = request.files.get("file")
        if files:
            file_name = secure_filename(files.filename)
            if file_name != "":
                file_ext = os.path.splitext(file_name)[1]
                if file_ext in app.config["UPLOAD_EXTENSIONS"]:
                    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_name)
                    files.save(file_path)
                    with open(file_path, "rb") as f:
                        file_data = f.read()
                    user = User(pdf=file_data, file_name=file_name)
                    db.session.add(user)
                    db.session.commit()
                    print("Upload successful")
                    return redirect(url_for("view_pdf", user_id=user.id))
                else:
                    return "Invalid file extension", 400
            else:
                return "No file selected", 400
    return render_template("upload.html")


@app.route("/signup")
def signup():
    return render_template("signup.html")


@app.route("/signup", methods=["POST"])
def signup_post():
    # code to validate and add user to database goes here
    email = request.form.get("email")
    name = request.form.get("name")
    password = request.form.get("password")
    if not email or not password or not name:
        flash("Email and password are required")
    user = User_login.query.filter_by(email=email).first()
    if user:
        flash("Email already exist")
        return redirect(url_for("auth.signup"))

    salt = bcrypt.gensalt(rounds=5)

    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)

    new_user = User_login(
        email=email,
        name=name,
        password=hashed,
    )
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for("login"))


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_check():
    email = request.form.get("email")
    password = request.form.get("password")

    remember = True if request.form.get("remember") else False

    user = User_login.query.filter_by(email=email).first()

    if not user or not bcrypt.checkpw(password.encode("utf-8"), user.password):
        flash("Please check your login details and try again.")
        return redirect(url_for("login"))
    login_user(user, remember=remember)
    return redirect(url_for("upload"))


@app.route("/logout")
def logout():
    logout_user()

    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, port=8001)
