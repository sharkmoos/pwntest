from flask import Flask, request, render_template, make_response, render_template_string
from urllib.parse import unquote
import logging

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)


@app.errorhandler(404)
def page_not_found(e):
    url = unquote(request.url)
    return render_template_string(f'Page not found: %s' % url), 404


@app.route('/')
def index():
    return render_template('index.html', error="")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
