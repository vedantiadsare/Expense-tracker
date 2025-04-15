from app import app
from routes.auth import auth_bp
from routes.finance import finance_bp

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(finance_bp, url_prefix='/finance') 