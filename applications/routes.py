from flask import Blueprint, render_template, request, flash, redirect, url_for, session, current_app, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from applications.models import db, User, UserRole, Customer, Professional, ServiceRequest, Service, RequestStatus, Booking, Review
from datetime import datetime, timedelta
from applications.utils import save_document
from werkzeug.utils import secure_filename
from flask_login import current_user, login_required
from sqlalchemy import or_ as db_or
from sqlalchemy import func

auth = Blueprint('auth', __name__)

# Login required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please login first.')
            return redirect(url_for('auth.admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Existing login route
@auth.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email, role=UserRole.ADMIN).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['admin_id'] = user.user_id
            return redirect(url_for('auth.admin_dashboard'))
        else:
            flash('Invalid email or password')
            
    return render_template('admin_login.html')

# New routes
@auth.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Get search parameters
    search_query = request.args.get('search', '').strip()
    search_type = request.args.get('search_type', 'requests')

    # Initialize variables
    service_requests = []
    professionals = []
    customers = []
    services = []

    # Apply search filters based on search_type
    if search_query:
        if search_type == 'requests':
            service_requests = ServiceRequest.query.join(Service).join(Customer).filter(
                db_or(
                    Service.name.ilike(f'%{search_query}%'),
                    Customer.full_name.ilike(f'%{search_query}%'),
                    ServiceRequest.status.ilike(f'%{search_query}%')
                )
            ).order_by(ServiceRequest.request_date.desc()).all()
        
        elif search_type == 'professionals':
            professionals = Professional.query.join(Service).filter(
                db_or(
                    Professional.full_name.ilike(f'%{search_query}%'),
                    Professional.phone.ilike(f'%{search_query}%'),
                    Service.name.ilike(f'%{search_query}%')
                )
            ).all()
        
        elif search_type == 'customers':
            customers = Customer.query.join(User).filter(
                db_or(
                    Customer.full_name.ilike(f'%{search_query}%'),
                    User.email.ilike(f'%{search_query}%'),
                    Customer.phone.ilike(f'%{search_query}%')
                )
            ).all()
        
        elif search_type == 'services':
            services = Service.query.filter(
                db_or(
                    Service.name.ilike(f'%{search_query}%'),
                    Service.description.ilike(f'%{search_query}%')
                )
            ).all()
    else:
        # If no search query, show default data
        service_requests = ServiceRequest.query.order_by(ServiceRequest.request_date.desc()).limit(10).all()
        professionals = Professional.query.all()  # Needed for assignment modal
        customers = Customer.query.all()
        services = Service.query.all()

    # Get stats for dashboard
    total_users = User.query.count()
    active_requests = ServiceRequest.query.filter_by(status=RequestStatus.REQUESTED).count()
    total_professionals = Professional.query.count()

    return render_template('admin_dashboard.html',
                         service_requests=service_requests,
                         professionals=professionals,
                         customers=customers,
                         services=services,
                         total_users=total_users,
                         active_requests=active_requests,
                         total_professionals=total_professionals)

@auth.route('/admin/logout')
@admin_required
def admin_logout():
    session.pop('admin_id', None)
    flash('You have been logged out.')
    return redirect(url_for('auth.admin_login'))

@auth.route('/admin/manage-users')
@admin_required
def manage_users():
    customers = Customer.query.all()
    professionals = Professional.query.all()
    return render_template('admin/manage_users.html', 
                         customers=customers, 
                         professionals=professionals)

@auth.route('/admin/verify-professional/<int:professional_id>', methods=['POST'])
@admin_required
def verify_professional(professional_id):
    professional = Professional.query.get_or_404(professional_id)
    professional.is_verified = True
    db.session.commit()
    flash('Professional has been verified successfully.', 'success')
    return redirect(url_for('auth.manage_users'))

@auth.route('/admin/toggle-user-status/<string:user_type>/<int:user_id>', methods=['POST'])
@admin_required
def toggle_user_status(user_type, user_id):
    try:
        if user_type == 'customer':
            customer = Customer.query.get_or_404(user_id)
            user = customer.user
        elif user_type == 'professional':
            professional = Professional.query.get_or_404(user_id)
            user = professional.user
        else:
            flash('Invalid user type', 'danger')
            return redirect(url_for('auth.manage_users'))

        # Toggle the is_active status
        user.is_active = not user.is_active
        db.session.commit()

        status = 'activated' if user.is_active else 'blocked'
        flash(f'User has been {status} successfully', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user status: {str(e)}', 'danger')

    return redirect(url_for('auth.manage_users'))

@auth.route('/admin/manage-services')
@admin_required
def manage_services():
    services = Service.query.all()
    return render_template('admin/manage_services.html', services=services)

@auth.route('/admin/service/create', methods=['GET', 'POST'])
@admin_required
def create_service():
    if request.method == 'POST':
        service = Service(
            name=request.form.get('name'),
            base_price=float(request.form.get('base_price')),
            description=request.form.get('description'),
            estimated_time=int(request.form.get('estimated_time')),
        )
        db.session.add(service)
        db.session.commit()
        flash('Service created successfully!', 'success')
        return redirect(url_for('auth.manage_services'))
    
    return render_template('admin/service_form.html', service=None)

@auth.route('/admin/service/edit/<int:service_id>', methods=['GET', 'POST'])
@admin_required
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)
    
    if request.method == 'POST':
        service.name = request.form.get('name')
        service.base_price = float(request.form.get('base_price'))
        service.description = request.form.get('description')
        service.estimated_time = int(request.form.get('estimated_time'))
        db.session.commit()
        flash('Service updated successfully!', 'success')
        return redirect(url_for('auth.manage_services'))
    
    return render_template('admin/service_form.html', service=service)

@auth.route('/admin/service/delete/<int:service_id>', methods=['POST'])
@admin_required
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()
    flash('Service deleted successfully!', 'success')
    return redirect(url_for('auth.manage_services'))

# Customer login route
@auth.route('/customer/login', methods=['GET', 'POST'])
def customer_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Find user by email and role
        user = User.query.filter_by(email=email, role=UserRole.CUSTOMER).first()
        
        if user and check_password_hash(user.password_hash, password):
            # Get customer details
            customer = Customer.query.filter_by(user_id=user.user_id).first()
            if customer:
                session['customer_id'] = customer.customer_id
                session['user_id'] = user.user_id
                session['full_name'] = customer.full_name
                flash(f'Welcome back, {customer.full_name}!')
                return redirect(url_for('auth.customer_home'))
            else:
                flash('Customer profile not found')
        else:
            flash('Invalid email or password')
    
    return render_template('customer_login.html')

@auth.route('/customer/dashboard')
def customer_dashboard():
    if 'customer_id' not in session:
        flash('Please login first.')
        return redirect(url_for('auth.customer_login'))
    
    # Get customer data
    customer = Customer.query.get(session['customer_id'])
    if not customer:
        session.clear()
        flash('Customer not found')
        return redirect(url_for('auth.customer_login'))
    
    return render_template('customer_dashboard.html', customer=customer)

@auth.route('/customer/register', methods=['GET', 'POST'])
def customer_register():
    if request.method == 'POST':
        try:
            # Get form data
            email = request.form.get('email')
            phone = request.form.get('phone')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            full_name = f"{request.form.get('first_name')} {request.form.get('last_name')}"
            
            print(f"Received registration data - Email: {email}, Name: {full_name}")  # Debug print
            
            # Validation
            if User.query.filter_by(email=email).first():
                flash('Email already registered')
                return redirect(url_for('auth.customer_register'))
            
            if password != confirm_password:
                flash('Passwords do not match')
                return redirect(url_for('auth.customer_register'))
            
            # Create new user
            new_user = User(
                email=email,
                password_hash=generate_password_hash(password),
                role=UserRole.CUSTOMER
            )
            db.session.add(new_user)
            db.session.flush()  # Get the user_id
            
            print(f"Created user with ID: {new_user.user_id}")  # Debug print
            
            # Create customer profile
            new_customer = Customer(
                user_id=new_user.user_id,
                full_name=full_name,
                phone=phone
            )
            db.session.add(new_customer)
            
            # Commit both records
            db.session.commit()
            
            print(f"Successfully created customer profile with ID: {new_customer.customer_id}")  # Debug print
            flash('Registration successful! Please login.')
            return redirect(url_for('auth.customer_login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error during registration: {str(e)}")  # Debug print
            flash(f'An error occurred during registration: {str(e)}')
            return redirect(url_for('auth.customer_register'))
    
    return render_template('customer_register.html')

@auth.route('/customer/home')
def customer_home():
    if 'customer_id' not in session:
        return redirect(url_for('auth.customer_login'))
    
    services = Service.query.filter_by(is_active=True).all()
    
    # Get pre-selected professional and service from query parameters
    professional_id = request.args.get('professional_id')
    service_id = request.args.get('service_id')
    
    selected_professional = None
    selected_service = None
    
    if professional_id and service_id:
        selected_professional = Professional.query.get(professional_id)
        selected_service = Service.query.get(service_id)
    
    return render_template('customer_home.html',
                         services=services,
                         selected_professional=selected_professional,
                         selected_service=selected_service)

@auth.route('/customer/logout')
def customer_logout():
    session.pop('customer_id', None)
    session.pop('user_id', None)
    session.pop('full_name', None)
    flash('You have been logged out.')
    return redirect(url_for('auth.customer_login'))

@auth.route('/customer/services')
def services():
    # Fetch all active services
    all_services = Service.query.filter_by(is_active=True).order_by(Service.name).all()
    return render_template('services.html', services=all_services)

@auth.route('/customer/bookings')
def bookings():
    if 'customer_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.customer_login'))
    
    try:
        customer = Customer.query.get(session['customer_id'])
        if not customer:
            flash('Customer profile not found.', 'danger')
            return redirect(url_for('auth.customer_login'))
        
        # Get all bookings for the customer
        customer_bookings = Booking.query.filter_by(user_id=customer.user_id)\
            .order_by(Booking.date.desc(), Booking.time.desc()).all()
        
        return render_template('bookings.html', bookings=customer_bookings)
        
    except Exception as e:
        flash(f'Error retrieving bookings: {str(e)}', 'danger')
        return redirect(url_for('auth.customer_home'))

@auth.route('/customer/request-service', methods=['POST'])
def request_service():
    if 'customer_id' not in session:
        flash('Please login first.')
        return redirect(url_for('auth.customer_login'))
    
    try:
        # Get form data
        service_type = request.form.get('service_type')
        preferred_date = request.form.get('preferred_date')
        preferred_time = request.form.get('preferred_time')
        location = request.form.get('location')
        description = request.form.get('description')

        # Combine date and time into datetime object
        scheduled_date = datetime.strptime(f"{preferred_date} {preferred_time}", '%Y-%m-%d %H:%M')
        
        # Get the service to get its base price
        service = Service.query.get_or_404(service_type)
        
        # Create new service request
        new_request = ServiceRequest(
            service_id=service_type,
            customer_id=session['customer_id'],
            status=RequestStatus.REQUESTED,
            scheduled_date=scheduled_date,
            price=service.base_price,
            customer_address=location,
            customer_pincode='',  # You might want to add pincode to your form
            special_instructions=description
        )
        
        db.session.add(new_request)
        db.session.commit()
        
        flash('Your service request has been submitted successfully! We will process it shortly.', 'success')
        return redirect(url_for('auth.customer_home'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {str(e)}', 'danger')
        return redirect(url_for('auth.customer_home'))

# Add new admin routes for handling service requests
@auth.route('/admin/service-requests')
@admin_required
def admin_service_requests():
    requests = ServiceRequest.query.order_by(ServiceRequest.request_date.desc()).all()
    return render_template('admin/service_requests.html', requests=requests)

@auth.route('/admin/service-request/<int:request_id>/update-status', methods=['POST'])
@admin_required
def update_request_status(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    new_status = request.form.get('status')
    
    try:
        if new_status == 'approved':
            service_request.status = RequestStatus.ADMIN_APPROVED
            flash('Service request approved. Please assign a professional.', 'success')
            
            # Redirect to professional assignment page
            return redirect(url_for('auth.assign_professional_to_request', request_id=request_id))
            
        elif new_status == 'rejected':
            service_request.status = RequestStatus.REJECTED
            flash('Service request rejected', 'success')
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating request status: {str(e)}', 'danger')
    
    return redirect(url_for('auth.admin_dashboard'))

@auth.route('/admin/service-request/<int:request_id>/assign-professional', methods=['GET', 'POST'])
@admin_required
def assign_professional_to_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    
    if request.method == 'POST':
        professional_id = request.form.get('professional_id')
        try:
            service_request.professional_id = professional_id
            service_request.status = RequestStatus.ASSIGNED
            db.session.commit()
            flash('Professional assigned successfully', 'success')
            return redirect(url_for('auth.admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error assigning professional: {str(e)}', 'danger')
    
    # Get available professionals for this service
    available_professionals = Professional.query.filter_by(
        service_id=service_request.service_id,
        is_verified=True
    ).join(User).filter(User.is_active == True).all()
    
    return render_template('admin/assign_professional.html',
                         request=service_request,
                         professionals=available_professionals)

# Professional login route
@auth.route('/professional/login', methods=['GET', 'POST'])
def professional_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email, role=UserRole.PROFESSIONAL).first()
        
        if user and check_password_hash(user.password_hash, password):
            # Check if professional is verified
            professional = Professional.query.filter_by(user_id=user.user_id).first()
            if not professional:
                flash('Professional profile not found')
                return redirect(url_for('auth.professional_login'))
            
            if not professional.is_verified:
                flash('Your account is pending verification. Please wait for admin approval.')
                return redirect(url_for('auth.professional_login'))
            
            if not user.is_active:
                flash('Your account has been deactivated. Please contact admin.')
                return redirect(url_for('auth.professional_login'))
            
            session['professional_id'] = professional.professional_id
            session['user_id'] = user.user_id
            session['full_name'] = professional.full_name
            flash(f'Welcome back, {professional.full_name}!')
            return redirect(url_for('auth.professional_dashboard'))
        else:
            flash('Invalid email or password')
    
    return render_template('professional_login.html')

@auth.route('/professional/register', methods=['GET', 'POST'])
def professional_register():
    if request.method == 'POST':
        try:
            # Get form data
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            full_name = request.form.get('full_name')
            phone = request.form.get('phone')
            service_id = request.form.get('service_id')
            experience_years = request.form.get('experience_years')
            description = request.form.get('description')
            
            # Validation
            if User.query.filter_by(email=email).first():
                flash('Email already registered')
                return redirect(url_for('auth.professional_register'))
            
            if password != confirm_password:
                flash('Passwords do not match')
                return redirect(url_for('auth.professional_register'))
            
            # Handle document upload
            document = request.files.get('document_url')
            if not document:
                flash('Please upload required documents')
                return redirect(url_for('auth.professional_register'))
            
            document_path = save_document(document)
            if not document_path:
                flash('Invalid file type. Allowed files are PDF, PNG, JPG, JPEG, DOC, DOCX')
                return redirect(url_for('auth.professional_register'))
            
            # Create new user
            new_user = User(
                email=email,
                password_hash=generate_password_hash(password),
                role=UserRole.PROFESSIONAL
            )
            db.session.add(new_user)
            db.session.flush()
            
            # Create professional profile
            new_professional = Professional(
                user_id=new_user.user_id,
                full_name=full_name,
                phone=phone,
                service_id=service_id,
                experience_years=int(experience_years),
                description=description,
                document_url=document_path,
                is_verified=False
            )
            db.session.add(new_professional)
            db.session.commit()
            
            flash('Registration successful! Please wait for admin verification before logging in.')
            return redirect(url_for('auth.professional_login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {str(e)}')
            return redirect(url_for('auth.professional_register'))
    
    # Get all services for the registration form
    services = Service.query.filter_by(is_active=True).all()
    return render_template('professional_register.html', services=services)

@auth.route('/professional/dashboard')
def professional_dashboard():
    if 'professional_id' not in session:
        flash('Please login first.')
        return redirect(url_for('auth.professional_login'))
    
    professional = Professional.query.get(session['professional_id'])
    if not professional:
        session.clear()
        flash('Professional not found')
        return redirect(url_for('auth.professional_login'))
    
    # Get assigned service requests
    service_requests = ServiceRequest.query.filter_by(
        professional_id=professional.professional_id
    ).order_by(ServiceRequest.scheduled_date.desc()).all()
    
    return render_template('professional_dashboard.html', 
                         professional=professional,
                         service_requests=service_requests)

@auth.route('/professional/logout')
def professional_logout():
    session.pop('professional_id', None)
    session.pop('user_id', None)
    session.pop('full_name', None)
    flash('You have been logged out.')
    return redirect(url_for('auth.professional_login'))

@auth.route('/uploads/documents/<filename>')
@admin_required
def view_document(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

@auth.route('/service/<int:service_id>/professionals')
def service_professionals(service_id):
    if 'customer_id' not in session:
        return redirect(url_for('auth.customer_login'))
    
    service = Service.query.get_or_404(service_id)
    professionals = Professional.query.filter_by(
        service_id=service_id,
        is_verified=True
    ).join(User).filter(User.is_active == True).all()
    
    return render_template('service_professionals.html',
                         service=service,
                         professionals=professionals)

@auth.route('/admin/professional/<int:professional_id>/toggle-status', methods=['POST'])
@admin_required
def toggle_professional_status(professional_id):
    try:
        professional = Professional.query.get_or_404(professional_id)
        user = User.query.get(professional.user_id)
        
        # Toggle the active status
        user.is_active = not user.is_active
        
        # If blocking the professional, also update their assigned service requests
        if not user.is_active:
            pending_requests = ServiceRequest.query.filter_by(
                professional_id=professional.professional_id
            ).filter(ServiceRequest.status.in_([
                RequestStatus.ASSIGNED, 
                RequestStatus.ACCEPTED, 
                RequestStatus.IN_PROGRESS
            ])).all()
            
            for request in pending_requests:
                request.status = RequestStatus.REQUESTED
                request.professional_id = None
        
        db.session.commit()
        
        status = 'blocked' if not user.is_active else 'unblocked'
        flash(f'Professional has been {status} successfully.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating professional status: {str(e)}', 'danger')
    
    return redirect(url_for('auth.admin_dashboard'))

@auth.route('/search')
def search_services():
    if 'customer_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.customer_login'))
    
    query = request.args.get('query', '').strip()
    print(f"Search query: {query}")  # Debug log
    
    if query:
        try:
            # Search in services table
            services = Service.query.filter(
                db_or(
                    Service.name.ilike(f'%{query}%'),
                    Service.description.ilike(f'%{query}%')
                ),
                Service.is_active == True
            ).all()
            print(f"Found {len(services)} services")  # Debug log
            
            # Search in professionals table to find services by location
            professional_services = Service.query.join(Professional).filter(
                db_or(
                    Professional.description.ilike(f'%{query}%'),
                    Professional.full_name.ilike(f'%{query}%')
                ),
                Service.is_active == True
            ).all()
            print(f"Found {len(professional_services)} professional services")  # Debug log
            
            # Combine results and remove duplicates
            all_services = list(set(services + professional_services))
            print(f"Total unique services: {len(all_services)}")  # Debug log
            
        except Exception as e:
            print(f"Search error: {str(e)}")  # Debug log
            flash('An error occurred while searching.', 'danger')
            all_services = []
    else:
        all_services = []
    
    return render_template('search_results.html', 
                         services=all_services, 
                         query=query)

@auth.route('/professional/services')
def professional_services():
    if 'professional_id' not in session:
        return redirect(url_for('auth.professional_login'))
    
    professional = Professional.query.get(session['professional_id'])
    service_requests = ServiceRequest.query.filter_by(professional_id=professional.professional_id)\
        .order_by(ServiceRequest.scheduled_date.desc()).all()
    
    return render_template('professional_services.html', 
                         service_requests=service_requests,
                         professional=professional)

@auth.route('/customer/profile')
def customer_profile():
    if 'customer_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.customer_login'))
    
    try:
        customer = Customer.query.get_or_404(session['customer_id'])
        
        # Get booking statistics
        total_bookings = Booking.query.filter_by(user_id=customer.user_id).count()
        active_bookings = Booking.query.filter_by(
            user_id=customer.user_id,
            status='pending'
        ).count()
        completed_bookings = Booking.query.filter_by(
            user_id=customer.user_id,
            status='completed'
        ).count()
        
        # Get recent bookings
        recent_bookings = Booking.query.filter_by(user_id=customer.user_id)\
            .order_by(Booking.date.desc())\
            .limit(5)\
            .all()
        
        return render_template('customer_profile.html',
                             customer=customer,
                             total_bookings=total_bookings,
                             active_bookings=active_bookings,
                             completed_bookings=completed_bookings,
                             recent_bookings=recent_bookings)
                             
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'danger')
        return redirect(url_for('auth.customer_home'))

@auth.route('/customer/profile/edit', methods=['GET', 'POST'])
def edit_customer_profile():
    if 'customer_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.customer_login'))
    
    customer = Customer.query.get_or_404(session['customer_id'])
    
    if request.method == 'POST':
        try:
            # Update customer information
            customer.full_name = request.form['full_name']
            customer.phone = request.form['phone']
            customer.user.email = request.form['email']
            
            # Update password if provided
            if request.form['password']:
                customer.user.password = generate_password_hash(request.form['password'])
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('auth.customer_profile'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
    
    return render_template('edit_customer_profile.html', customer=customer)

@auth.route('/professional/profile')
def professional_profile():
    if 'professional_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.professional_login'))
    
    try:
        professional = Professional.query.get_or_404(session['professional_id'])
        
        # Get service statistics
        total_services = ServiceRequest.query.filter_by(professional_id=professional.professional_id).count()
        active_services = ServiceRequest.query.filter_by(
            professional_id=professional.professional_id,
            status=RequestStatus.ASSIGNED
        ).count()
        completed_services = ServiceRequest.query.filter_by(
            professional_id=professional.professional_id,
            status=RequestStatus.COMPLETED
        ).count()
        
        # Get recent services
        recent_services = ServiceRequest.query.filter_by(
            professional_id=professional.professional_id
        ).order_by(ServiceRequest.scheduled_date.desc()).limit(5).all()
        
        return render_template('professional_profile.html',
                             professional=professional,
                             total_services=total_services,
                             active_services=active_services,
                             completed_services=completed_services,
                             recent_services=recent_services)
                             
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'danger')
        return redirect(url_for('auth.professional_dashboard'))

@auth.route('/professional/profile/edit', methods=['GET', 'POST'])
def edit_professional_profile():
    if 'professional_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.professional_login'))
    
    professional = Professional.query.get_or_404(session['professional_id'])
    
    if request.method == 'POST':
        try:
            # Update professional information
            professional.full_name = request.form['full_name']
            professional.phone = request.form['phone']
            professional.user.email = request.form['email']
            professional.experience_years = int(request.form['experience_years'])
            professional.description = request.form['description']
            
            # Update password if provided
            if request.form['password']:
                professional.user.password = generate_password_hash(request.form['password'])
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('auth.professional_profile'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
    
    return render_template('edit_professional_profile.html', professional=professional)

@auth.route('/book-professional/<int:professional_id>', methods=['GET', 'POST'])
def book_professional(professional_id):
    if 'customer_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.customer_login'))
    
    professional = Professional.query.get_or_404(professional_id)
    today_date = datetime.now().strftime('%Y-%m-%d')
    max_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
    
    return render_template('book_professional.html',
                         professional=professional,
                         today_date=today_date,
                         max_date=max_date)

@auth.route('/create-booking/<int:professional_id>', methods=['POST'])
def create_booking(professional_id):
    if 'customer_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.customer_login'))
    
    try:
        professional = Professional.query.get_or_404(professional_id)
        customer = Customer.query.get(session['customer_id'])
        
        # Create service request
        booking_date = datetime.strptime(f"{request.form['date']} {request.form['time']}", '%Y-%m-%d %H:%M')
        
        service_request = ServiceRequest(
            service_id=professional.service_id,
            customer_id=customer.customer_id,
            professional_id=professional.professional_id,
            status=RequestStatus.REQUESTED,
            scheduled_date=booking_date,
            price=professional.service.base_price,
            customer_address=request.form['address'],
            customer_pincode='',  # You might want to add this to the form
            special_instructions=request.form.get('notes', '')
        )
        
        db.session.add(service_request)
        
        # Create booking record
        booking = Booking(
            user_id=customer.user_id,
            service_id=professional.service_id,
            date=booking_date.date(),
            time=booking_date.time(),
            status='pending'
        )
        
        db.session.add(booking)
        db.session.commit()
        
        flash('Booking created successfully! The professional will confirm your request shortly.', 'success')
        return redirect(url_for('auth.bookings'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating booking: {str(e)}', 'danger')
        return redirect(url_for('auth.book_professional', professional_id=professional_id))

@auth.route('/customer/cancel-booking/<int:booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    if 'customer_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.customer_login'))
    
    try:
        booking = Booking.query.get_or_404(booking_id)
        customer = Customer.query.get(session['customer_id'])
        
        # Verify this booking belongs to the current customer
        if booking.user_id != customer.user_id:
            flash('Unauthorized access', 'danger')
            return redirect(url_for('auth.bookings'))
        
        # Only allow cancellation of pending bookings
        if booking.status != 'pending':
            flash('Only pending bookings can be cancelled', 'warning')
            return redirect(url_for('auth.bookings'))
        
        # Update the booking status
        booking.status = 'cancelled'
        
        # Also update any associated service request
        service_request = ServiceRequest.query.filter_by(
            customer_id=customer.customer_id,
            service_id=booking.service_id,
            scheduled_date=datetime.combine(booking.date, booking.time)
        ).first()
        
        if service_request:
            service_request.status = RequestStatus.CANCELLED
        
        db.session.commit()
        flash('Booking has been cancelled successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error cancelling booking: {str(e)}', 'danger')
    
    return redirect(url_for('auth.bookings'))

@auth.route('/professional/service-request/<int:request_id>/update', methods=['POST'])
def update_professional_request(request_id):
    if 'professional_id' not in session:
        return redirect(url_for('auth.professional_login'))
    
    action = request.form.get('action')
    service_request = ServiceRequest.query.get_or_404(request_id)
    
    try:
        if action == 'accept':
            service_request.status = RequestStatus.IN_PROGRESS
            # Update the associated booking status
            booking = Booking.query.filter_by(
                user_id=service_request.customer.user_id,
                service_id=service_request.service_id
            ).first()
            if booking:
                booking.status = 'in_progress'
            
            flash('Service request accepted and marked as in progress', 'success')
            
        elif action == 'complete':
            if service_request.status == RequestStatus.IN_PROGRESS:
                service_request.status = RequestStatus.COMPLETED
                # Update the associated booking status
                booking = Booking.query.filter_by(
                    user_id=service_request.customer.user_id,
                    service_id=service_request.service_id
                ).first()
                if booking:
                    booking.status = 'completed'
                
                flash('Service has been marked as completed', 'success')
            else:
                flash('Only in-progress services can be marked as completed', 'warning')
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating request: {str(e)}', 'danger')
    
    return redirect(url_for('auth.professional_services'))

@auth.route('/service-request/<int:request_id>/complete', methods=['POST'])
def complete_service_request(request_id):
    if 'customer_id' not in session and 'professional_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.login'))
    
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        
        # Verify the user has permission
        if ('customer_id' in session and service_request.customer_id != session['customer_id']) or \
           ('professional_id' in session and service_request.professional_id != session['professional_id']):
            flash('Unauthorized access', 'danger')
            return redirect(url_for('auth.customer_home'))
        
        if service_request.status != RequestStatus.IN_PROGRESS:
            flash('Only in-progress services can be marked as completed.', 'warning')
        else:
            service_request.status = RequestStatus.COMPLETED
            service_request.completion_date = datetime.utcnow()
            db.session.commit()
            flash('Service has been marked as completed!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error completing service: {str(e)}', 'danger')
    
    return redirect(request.referrer or url_for('auth.customer_home'))

@auth.route('/service-request/<int:request_id>/rate', methods=['POST'])
def rate_service(request_id):
    if 'customer_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.customer_login'))
    
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        
        # Verify this is the customer's request
        if service_request.customer_id != session['customer_id']:
            flash('Unauthorized access', 'danger')
            return redirect(url_for('auth.customer_home'))
        
        if service_request.status != RequestStatus.COMPLETED:
            flash('Only completed services can be rated.', 'warning')
        else:
            rating = int(request.form.get('rating', 0))
            comment = request.form.get('comment', '')
            
            if not 1 <= rating <= 5:
                flash('Rating must be between 1 and 5 stars.', 'warning')
            else:
                # Create review
                review = Review(
                    request_id=request_id,
                    customer_id=session['customer_id'],
                    professional_id=service_request.professional_id,
                    rating=rating,
                    comment=comment
                )
                
                # Update service request status
                service_request.status = RequestStatus.RATED
                
                # Update professional's average rating
                professional = service_request.professional
                reviews = Review.query.filter_by(professional_id=professional.professional_id).all()
                total_rating = sum(r.rating for r in reviews) + rating
                professional.average_rating = total_rating / (len(reviews) + 1)
                
                db.session.add(review)
                db.session.commit()
                flash('Thank you for your rating!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error submitting rating: {str(e)}', 'danger')
    
    return redirect(request.referrer or url_for('auth.customer_home'))

@auth.route('/customer/service-request/<int:request_id>/update', methods=['POST'])
def update_customer_request(request_id):
    if 'customer_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('auth.customer_login'))
    
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        
        # Verify this request belongs to the current customer
        if service_request.customer_id != session['customer_id']:
            flash('Unauthorized access', 'danger')
            return redirect(url_for('auth.customer_home'))
        
        action = request.form.get('action')
        
        if action == 'complete':
            if service_request.status == RequestStatus.IN_PROGRESS:
                service_request.status = RequestStatus.COMPLETED
                service_request.completion_date = datetime.utcnow()
                db.session.commit()
                flash('Service has been marked as completed!', 'success')
            else:
                flash('Only in-progress services can be marked as completed.', 'warning')
                
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating service request: {str(e)}', 'danger')
    
    return redirect(url_for('auth.bookings'))

@auth.route('/service-request/<int:request_id>/close', methods=['POST'])
def close_service(request_id):
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        service_request.status = RequestStatus.COMPLETED
        
        # Update associated booking
        booking = Booking.query.filter_by(
            user_id=service_request.customer.user_id,
            service_id=service_request.service_id
        ).first()
        if booking:
            booking.status = 'completed'
        
        db.session.commit()
        flash('Service has been closed successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error closing service: {str(e)}', 'danger')
    
    return redirect(request.referrer or url_for('auth.bookings'))
