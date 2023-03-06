from flask import Flask, render_template, render_template_string, request, url_for, redirect, session, make_response, abort
from urllib.parse import unquote
import logging
import os
from manager import sess, seed, User

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()


@app.errorhandler(404)
def page_not_found(e):
    url = unquote(request.url)
    return render_template_string(f'Page not found: %s' % url), 404


@app.route('/profile')
def profile():
    if "logged_in" not in session:
        return redirect(url_for('login'))

    if session["logged_in"]:
        return render_template('profile.html', username=session["username"])
    else:
        return redirect(url_for('login'))


@app.route("/hidden")
def hidden():
    if "logged_in" not in session:
        make_response(abort(404))
    if session["logged_in"]:
        return render_template_string('Well done {{username}}!', username=session["username"])
    else:
        make_response(abort(404))


@app.route('/', methods=['GET', 'POST'])
def login():
    if "logged_in" in session:
        if session["logged_in"] is True:
            msg = "Logged in"
    else:
        msg = "Not logged in"
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        user = request.form["username"]
        passwd = request.form["password"]
        result = sess.query(User).filter(User.username == user, User.password == passwd)
        user_exists = result.first()
        if user_exists:
            logging.debug(f"User '{user}' logged in successfully")
            session["logged_in"] = True
            session["username"] = user
            return redirect(url_for('profile'))
        else:
            msg = "Invalid Credentials"

    return render_template("index.html", msg=msg)


if __name__ == "__main__":
    if not os.path.isfile("/tmp/ctf.db"):
        logging.info("Seeding the database...")
        seed()
    app.run(host="0.0.0.0", port=3000)
