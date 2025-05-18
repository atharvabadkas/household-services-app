from flask import Flask, render_template
from applications.models import db, Service, User, UserRole, Customer
from applications.routes import auth
from werkzeug.security import generate_password_hash
import os
from applications.utils import UPLOAD_FOLDER
from datetime import datetime

app = Flask(__name__, static_folder='static', template_folder='templates')
app.register_blueprint(auth)

def create_app():
    # Configure database and secret key
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    # Initialize database
    db.init_app(app)
    
    # Register routes
    @app.route('/')
    def landing_page():
        return render_template('landing.html')
    
    return app

def create_test_services():
    with app.app_context():
        # Check if services already exist
        if Service.query.count() == 0:
            test_services = [
                Service(
                    name='House Cleaning',
                    description='Complete house cleaning service',
                    base_price=100.00,
                    estimated_time=120,
                    is_active=True
                ),
                Service(
                    name='Plumbing',
                    description='General plumbing services',
                    base_price=80.00,
                    estimated_time=60,
                    is_active=True
                ),
                Service(
                    name='Electrical Work',
                    description='Electrical repair and installation',
                    base_price=90.00,
                    estimated_time=90,
                    is_active=True
                )
            ]
            
            for service in test_services:
                db.session.add(service)
            
            try:
                db.session.commit()
                print("Test services created successfully!")
            except Exception as e:
                db.session.rollback()
                print(f"Error creating test services: {str(e)}")

def create_admin_user():
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin_user = User(
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                role=UserRole.ADMIN,
                is_active=True
            )
            
            try:
                db.session.add(admin_user)
                db.session.commit()
                print("Admin user created successfully!")
                print("Email: admin@example.com")
                print("Password: admin123")
            except Exception as e:
                db.session.rollback()
                print(f"Error creating admin user: {str(e)}")

def update_customer_created_at():
    with app.app_context():
        try:
            customers = Customer.query.all()
            for customer in customers:
                if not customer.created_at:
                    customer.created_at = customer.user.created_at or datetime.utcnow()
            db.session.commit()
            print("Successfully updated customer creation dates!")
        except Exception as e:
            db.session.rollback()
            print(f"Error updating customer creation dates: {str(e)}")

if __name__ == '__main__':
    app = create_app()
    
    with app.app_context():
        db.create_all()
        create_admin_user()
        create_test_services()
        update_customer_created_at()
    
    app.run(debug=True)