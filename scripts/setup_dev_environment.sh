#!/bin/bash

# Absolute path to the directory holding this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Absolute path to the repository root
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

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
    pip3 install -r "${REPO_ROOT}/backend/requirements.txt" -r "${REPO_ROOT}/backend/requirements-dev.txt"
    
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
    
    local env_template="${REPO_ROOT}/.env.example"
    local env_file="${REPO_ROOT}/.env"
    local env_tmp
    local secret_key
    local line
    
    # Leave an environment file that is already present untouched
    if [ -e "${env_file}" ]; then
        echo "An environment file already exists at ${env_file}."
        echo "Refusing to overwrite it. Move it aside and re-run this script to regenerate it."
        exit 1
    fi
    
    if [ ! -f "${env_template}" ]; then
        echo "The environment template ${env_template} is missing."
        exit 1
    fi
    
    # Create the local environment file from the committed template
    if ! cp "${env_template}" "${env_file}"; then
        echo "Failed to create ${env_file} from ${env_template}."
        exit 1
    fi
    
    # Generate the token signing key
    if command -v openssl &> /dev/null; then
        secret_key="$(openssl rand -hex 32)"
    else
        secret_key="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    fi
    
    if [ -z "${secret_key}" ]; then
        echo "Failed to generate a value for SECRET_KEY."
        exit 1
    fi
    
    env_tmp="$(mktemp "${env_file}.XXXXXX")"
    if [ ! -f "${env_tmp}" ]; then
        echo "Failed to create a temporary file alongside ${env_file}."
        exit 1
    fi
    
    # Write the generated key into the SECRET_KEY entry, leaving every other entry as copied
    while IFS= read -r line || [ -n "${line}" ]; do
        case "${line}" in
            SECRET_KEY=*) printf '%s\n' "SECRET_KEY=${secret_key}" ;;
            *) printf '%s\n' "${line}" ;;
        esac
    done < "${env_file}" > "${env_tmp}"
    
    # Confirm the SECRET_KEY entry now carries at least 32 characters
    if ! grep -q '^SECRET_KEY=.\{32,\}$' "${env_tmp}"; then
        rm -f "${env_tmp}"
        echo "Failed to write a generated SECRET_KEY into ${env_file}."
        exit 1
    fi
    
    mv "${env_tmp}" "${env_file}"
    chmod 600 "${env_file}"
    
    echo "Created ${env_file} from ${env_template} with a generated SECRET_KEY."
    echo "Environment variables configured. Please update the values in .env file."
}

# Initialize local database
init_database() {
    echo "Initializing local database..."
    
    local db_password
    local db_password_confirm
    local db_password_sql
    
    # Read the password for the database role
    read -r -s -p "Enter a password for the local database role: " db_password
    echo
    read -r -s -p "Re-enter the password: " db_password_confirm
    echo
    
    if [ -z "${db_password}" ]; then
        echo "No password was entered. The database role was not created."
        exit 1
    fi
    
    if [ "${db_password}" != "${db_password_confirm}" ]; then
        echo "The passwords entered do not match. The database role was not created."
        exit 1
    fi
    
    # Double each single quote in the value for the SQL string literal
    db_password_sql="${db_password//\'/\'\'}"
    
    createdb dbname
    # Pass the statement over standard input
    psql <<< "CREATE USER user WITH PASSWORD '${db_password_sql}';"
    psql -c "GRANT ALL PRIVILEGES ON DATABASE dbname TO user;"
    
    echo "Local database initialized."
    echo "Set the database role and password in the DATABASE_URL entry of ${REPO_ROOT}/.env."
}

# Run initial data migrations
run_migrations() {
    echo "Running initial data migrations..."
    
    # Apply the Alembic migrations from the backend package
    (cd "${REPO_ROOT}/backend" && alembic upgrade head)
    
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