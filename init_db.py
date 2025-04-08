import os
from app import app, db, User, migrate_database
from werkzeug.security import generate_password_hash
from datetime import datetime

# Get absolute path to database file
db_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fuetime.db')

# Delete existing database file
if os.path.exists(db_file):
    os.remove(db_file)
    print(f"Removed existing database: {db_file}")

def init_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Run the migration to add username column
        migrate_database()
        
        try:
            # Create admin user with all required fields
            admin = User()
            admin.email = 'admin@example.com'
            admin.phone = '1234567890'
            admin.full_name = 'Admin User'
            admin.username = 'admin'  # Set a fixed username for admin
            admin.password_hash = generate_password_hash('admin123')
            admin.is_admin = True
            admin.work = 'Administrator'
            admin.experience = '5+ years'
            admin.education = 'Bachelor\'s Degree'
            admin.live_location = 'Main Office'
            admin.current_location = 'Main Office'
            admin.payment_type = 'Hourly'
            admin.payment_charge = 0.0
            admin.skills = 'Administration, Management'
            admin.categories = 'Admin'
            admin.availability = 'available'
            admin.created_at = datetime.utcnow()
            admin.last_active = datetime.utcnow()
            admin.is_online = True
            admin.profile_views = 0
            admin.wallet_balance = 0.0
            admin.average_rating = 0.0
            admin.total_reviews = 0
            
            db.session.add(admin)
            db.session.commit()
            print('Database initialization completed!')
            print(f'Created admin user:')
            print(f'Email: admin@example.com')
            print(f'Password: admin123')
        except Exception as e:
            print(f"Error creating admin user: {str(e)}")
        
        print("Database initialized and migrated successfully")

if __name__ == '__main__':
    init_database()
