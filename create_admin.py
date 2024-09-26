# from app import app, db, user_datastore, hash_password
#
# with app.app_context():
#     admin_role = user_datastore.find_or_create_role(name='admin', description='Administrator')
#
#     if not user_datastore.find_user(email="admin@example.com"):
#         user = user_datastore.create_user(username="admin", email="admin@example.com",
#                                           password=hash_password("adminpass"))
#         user_datastore.add_role_to_user(user, admin_role)
#         db.session.commit()
#         print("Admin user created.")
#     else:
#         print("Admin user already exists.")
#
from app import db, User, app

# Find and delete the admin user from the database
with app.app_context():
    admin_user = User.query.filter_by(email='admin@example.com').first()
    if admin_user:
        db.session.delete(admin_user)
        db.session.commit()
        print("Admin user deleted successfully.")
    else:
        print("Admin user not found.")
