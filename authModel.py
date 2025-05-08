from pymongo import MongoClient
import bcrypt
import os
from dotenv import load_dotenv
from datetime import datetime
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

# Connect to MongoDB
client = MongoClient("mongodb+srv://simpevans:Hlx7tyHG7fy8Hq0B@cluster0.7bg8cvk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["PROJECT_DB"]
users_collection = db["users"]
logged_collection = db["logged_in"]

# Function to create a user
def create(name, surname, email, password, role):
    try:
        # Hash the user's password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Check if email already exists
        if users_collection.find_one({"email": {"$regex": f"^{email}$", "$options": "i"}}):
            logger.debug("Email already exists")
            return False

        # Insert user document into MongoDB
        user = {
            "name": name,
            "surname": surname,
            "email": email.lower(),
            "password": hashed_password.decode('utf-8'),
            "role": role,
            "timestamp": datetime.now()
        }
        users_collection.insert_one(user)
        return True

    except Exception as error:
        logger.error(f"ERROR: {error}")
        return False

# User login function
def login(email, password):
    try:
        # Find user by email (case-insensitive)
        user = users_collection.find_one({"email": {"$regex": f"^{email}$", "$options": "i"}})

        if user:
            logger.debug(f"User document: {user}")
            stored_hashed_password = user['password'].encode('utf-8')

            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
                logger.debug("Login successful")

                logged_in_user = {
                    "name": user.get("name"),
                    "surname": user.get("surname"),
                    "email": user.get("email"),
                    "timestamp": datetime.now()
                }

                logged_collection.insert_one(logged_in_user)

                return user
            else:
                logger.debug("Invalid password")
                return None
        else:
            logger.debug("User not found")
            return None

    except Exception as error:
        logger.error(f"ERROR: {error}")
        return None
    
# User logout function
def logout(email):
    try:

        # Find user by email (case-insensitive)
        user = logged_collection.find_one({"email": {"$regex": f"^{email}$", "$options": "i"}})

        if user:
            logged_collection.delete_one(user)
            return True
        else:
            return False

    except Exception as error:
        logger.error(f"ERROR: {error}")
        return None 
