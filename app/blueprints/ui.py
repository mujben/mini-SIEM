from flask import Blueprint, render_template
from flask_login import login_required

ui_bp = Blueprint('ui', __name__)

@ui_bp.route('/')
def index() -> str:
    return render_template('index.html')

@ui_bp.route('/config')
@login_required
def config() -> str:
    return render_template('config.html')
