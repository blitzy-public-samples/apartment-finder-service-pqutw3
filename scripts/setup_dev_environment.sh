#!/bin/bash

# Check for required software
check_software() {
    echo "Checking for required software..."
    
    if ! command -v docker &> /dev/null; then
        echo "Docker is not installed. Please install Docker and try again."
        exit 1
    fi
    
    if ! command -v python3 &> /dev/null; then
        echo "Python 3 is not installed. Please install Python 3 and try again."
        exit 1
    fi
    
    if ! command -v node &> /dev/null; then
        echo "Node.js is not installed. Please install Node.js and try again."
        exit 1
    fi
    
    echo "All required software is installed."
}

# Install project dependencies
install_dependencies() {
    echo "Installing project dependencies..."
    
    # Install Python dependencies
    pip3 install -r requirements.txt
    
    # Install Node.js dependencies
    npm install
}

# Set up virtual environments
setup_virtual_env() {
    echo "Setting up virtual environment..."
    
    python3 -m venv venv
    source venv/bin/activate
    
    echo "Virtual environment activated."
}

# Configure environment variables
configure_env_vars() {
    echo "Configuring environment variables..."
    
    # HUMAN ASSISTANCE NEEDED
    # The following block needs to be customized based on the specific project requirements
    cat << EOF > .env
DEBUG=True
SECRET_KEY=your_secret_key_here
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
REDIS_URL=redis://localhost:6379/0
EOF
    
    echo "Environment variables configured. Please update the values in .env file."
}

# Initialize local database
init_database() {
    echo "Initializing local database..."
    
    # HUMAN ASSISTANCE NEEDED
    # The following commands assume a PostgreSQL database. Adjust if using a different database.
    createdb dbname
    psql -c "CREATE USER user WITH PASSWORD 'password';"
    psql -c "GRANT ALL PRIVILEGES ON DATABASE dbname TO user;"
    
    echo "Local database initialized."
}

# Run initial data migrations
run_migrations() {
    echo "Running initial data migrations..."
    
    # HUMAN ASSISTANCE NEEDED
    # The following command assumes using Django. Adjust if using a different framework.
    python3 manage.py migrate
    
    echo "Initial data migrations completed."
}

# Main execution
main() {
    check_software
    install_dependencies
    setup_virtual_env
    configure_env_vars
    init_database
    run_migrations
    
    echo "Development environment setup completed successfully!"
}

main