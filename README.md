# Daily Diet API

This project is a RESTful API built with Flask, MySQL, and Flask-Login for user authentication. It allows users to register, log in, and manage their meals by adding, editing, viewing, and deleting entries. Each meal entry includes details like name, description, date/time, and whether it fits within the user's diet plan.

## Features

- **User Authentication**: Registration, login, and logout functionality using `bcrypt` for password hashing and `Flask-Login` for session management.
- **User Management**: 
  - Create standard users and admin users.
  - Update and delete user accounts.
- **Meal Management**: 
  - CRUD operations (Create, Read, Update, Delete) for meals.
  - Each user can manage their own meals with fields for name, description, date/time, and in-diet status.
  
## Requirements

- Python 3.11
- MySQL
- Flask
- Flask-SQLAlchemy
- Flask-Login
- bcrypt
