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
    
    # SEC-01: credential values are generated at run time and never stored in this file
    # SEC-12: key length satisfies the 32-character floor on Settings.SECRET_KEY
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
    DB_APP_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
    DB_OWNER_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')

    if [ "${#SECRET_KEY}" -lt 32 ] || [ -z "$DB_APP_PASSWORD" ] || [ -z "$DB_OWNER_PASSWORD" ]; then
        echo "Credential generation failed. Please ensure Python 3 is available and try again."
        exit 1
    fi

    cat << EOF > .env
DEBUG=True
SECRET_KEY=${SECRET_KEY}
DATABASE_URL=postgresql://app_user:${DB_APP_PASSWORD}@localhost:5432/dbname
REDIS_URL=redis://localhost:6379/0
EOF

    # SEC-01: restricts the generated secret file to the owning user
    chmod 600 .env
    
    echo "Environment variables configured. Generated credentials written to .env file."
}

# Initialize local database
init_database() {
    echo "Initializing local database..."
    
    createdb dbname
    # SEC-11: owner role performs schema work; application role is limited to table data operations
    psql -v ON_ERROR_STOP=1 -v owner_pw="$DB_OWNER_PASSWORD" -v app_pw="$DB_APP_PASSWORD" -d dbname <<'SQL'
CREATE ROLE app_owner WITH LOGIN PASSWORD :'owner_pw';
CREATE ROLE app_user WITH LOGIN PASSWORD :'app_pw';
ALTER DATABASE dbname OWNER TO app_owner;
GRANT CREATE, USAGE ON SCHEMA public TO app_owner;
GRANT CONNECT ON DATABASE dbname TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_user;
SQL
    
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