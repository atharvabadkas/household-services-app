from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from enum import Enum

db = SQLAlchemy()

# Enums for static choices
class UserRole(str, Enum):
    ADMIN = 'admin'
    PROFESSIONAL = 'professional'
    CUSTOMER = 'customer'

class RequestStatus(str, Enum):
    REQUESTED = 'requested'
    ADMIN_APPROVED = 'admin_approved'
    ASSIGNED = 'assigned'
    ACCEPTED = 'accepted'
    REJECTED = 'rejected'
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    CANCELLED = 'cancelled'
    RATED = 'rated'

# Base User Model
class User(db.Model):
    __tablename__ = 'users'
    
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    customer = db.relationship('Customer', backref='user', uselist=False)
    professional = db.relationship('Professional', backref='user', uselist=False)

class Customer(db.Model):
    __tablename__ = 'customers'
    
    customer_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text)
    pincode = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    service_requests = db.relationship('ServiceRequest', backref='customer')
    reviews = db.relationship('Review', backref='customer')

class Service(db.Model):
    __tablename__ = 'services'
    
    service_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    base_price = db.Column(db.Numeric(10, 2), nullable=False)
    estimated_time = db.Column(db.Integer, nullable=False)  # in minutes
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Service {self.name}>'

    # Relationships
    professionals = db.relationship('Professional', backref='service')
    service_requests = db.relationship('ServiceRequest', backref='service')

class Professional(db.Model):
    __tablename__ = 'professionals'
    
    professional_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.service_id'))
    experience_years = db.Column(db.Integer)
    description = db.Column(db.Text)
    is_verified = db.Column(db.Boolean, default=False)
    average_rating = db.Column(db.Numeric(3, 2), default=0)
    document_url = db.Column(db.Text)

    # Relationships
    service_requests = db.relationship('ServiceRequest', backref='professional')
    availability = db.relationship('ProfessionalAvailability', backref='professional')
    reviews = db.relationship('Review', backref='professional')

class ServiceRequest(db.Model):
    __tablename__ = 'service_requests'
    
    request_id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.service_id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.customer_id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professionals.professional_id'))
    status = db.Column(db.Enum(RequestStatus), nullable=False, default=RequestStatus.REQUESTED)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    scheduled_date = db.Column(db.DateTime, nullable=False)
    completion_date = db.Column(db.DateTime)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    customer_address = db.Column(db.Text, nullable=False)
    customer_pincode = db.Column(db.String(10), nullable=False)
    special_instructions = db.Column(db.Text)

    # Relationships
    review = db.relationship('Review', backref='service_request', uselist=False)

class Review(db.Model):
    __tablename__ = 'reviews'
    
    review_id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('service_requests.request_id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.customer_id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professionals.professional_id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.CheckConstraint('rating >= 1 AND rating <= 5', name='check_rating_range'),
    )

class ProfessionalAvailability(db.Model):
    __tablename__ = 'professional_availability'
    
    availability_id = db.Column(db.Integer, primary_key=True)
    professional_id = db.Column(db.Integer, db.ForeignKey('professionals.professional_id'), nullable=False)
    day_of_week = db.Column(db.Integer, nullable=False)  # 0 = Monday, 6 = Sunday
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)

    __table_args__ = (
        db.CheckConstraint('day_of_week >= 0 AND day_of_week <= 6', name='check_day_range'),
    )

class AdminAction(db.Model):
    __tablename__ = 'admin_actions'
    
    action_id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    target_table = db.Column(db.String(50), nullable=False)
    target_id = db.Column(db.Integer)
    action_description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship
    admin = db.relationship('User', backref='admin_actions')

class Booking(db.Model):
    __tablename__ = 'bookings'
    
    booking_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.service_id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    status = db.Column(db.String(20), default='pending')

    # Add this relationship
    service = db.relationship('Service', backref='bookings')
    user = db.relationship('User', backref='bookings')
