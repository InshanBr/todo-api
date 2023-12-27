from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def configure(app):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:CSgdtH2fRUggJ5FkOiBFYZEvxvIQGsed@dpg-cm64fdud3nmc73ccls50-a/todo_database_45hs'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), unique=False, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'
