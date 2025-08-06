from app import app, initialize_database

if __name__ == "__main__":
    # Initialize database before running the app
    with app.app_context():
        initialize_database()
    
    app.run(host="0.0.0.0", port=5000, debug=True)
