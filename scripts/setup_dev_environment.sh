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
    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || return 1

    echo "Installing project dependencies..."

    # SEC-11: installs the tracked backend manifest with the active
    # interpreter; a failed install aborts the run (CWE-252)
    if ! python3 -m pip install -r "$repo_root/backend/requirements.txt"; then
        echo "Failed to install $repo_root/backend/requirements.txt. Resolve the installation error, then rerun." >&2
        return 1
    fi
    
    # Install Node.js dependencies
    npm install
}

# Set up virtual environments
setup_virtual_env() {
    echo "Setting up virtual environment..."

    # SEC-11: an unusable interpreter aborts the run (CWE-252)
    if ! python3 -m venv venv; then
        echo "Failed to create the virtual environment at ./venv. Install the python3 venv module, then rerun." >&2
        return 1
    fi

    if ! source venv/bin/activate; then
        echo "Failed to activate ./venv. Remove the directory, then rerun." >&2
        return 1
    fi
    
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
        echo "Credential generation failed. Ensure Python 3 is available, then rerun." >&2
        return 1
    fi

    # SEC-11: role passwords reach psql as quoted SQL literals; this guard
    # keeps them to the generator's own character set
    if ! [[ "$DB_APP_PASSWORD" =~ ^[A-Za-z0-9_-]+$ ]] || ! [[ "$DB_OWNER_PASSWORD" =~ ^[A-Za-z0-9_-]+$ ]]; then
        echo "Generated role password carries an unexpected character. Please re-run." >&2
        return 1
    fi

    # SEC-01: the secrets are written to a new owner-only temporary file in
    # this directory and renamed over .env, so no byte is ever readable by
    # another user (CWE-367, CWE-732) and an existing symlink at .env is
    # replaced instead of written through (CWE-59)
    env_tmp=$(umask 077 && mktemp ./.env.tmp.XXXXXXXX)
    if [ -z "$env_tmp" ] || [ ! -f "$env_tmp" ]; then
        echo "Unable to create the environment file. Setup aborted." >&2
        return 1
    fi
    trap 'rm -f "$env_tmp"' EXIT

    cat << EOF > "$env_tmp"
DEBUG=True
SECRET_KEY=${SECRET_KEY}
DATABASE_URL=postgresql://app_user:${DB_APP_PASSWORD}@localhost:5432/dbname
REDIS_URL=redis://localhost:6379/0
EOF
    env_write_status=$?

    if [ "$env_write_status" -ne 0 ] || [ ! -s "$env_tmp" ]; then
        echo "Failed to write the environment file. Check write access to $(pwd), then rerun." >&2
        return 1
    fi

    # SEC-01: restricts the generated secret file to the owning user; an
    # unrestricted secret file aborts the run (CWE-252)
    if ! chmod 600 "$env_tmp"; then
        echo "Failed to restrict .env to the owning user. Secure or remove .env before continuing." >&2
        return 1
    fi

    if ! mv -f "$env_tmp" .env; then
        echo "Failed to install .env. Environment configuration aborted." >&2
        return 1
    fi
    trap - EXIT
    
    echo "Environment variables configured. Generated credentials written to .env file."
}

# Verify the owner bootstrap can import what it needs
check_schema_prerequisites() {
    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || return 1

    PYTHONPATH="$repo_root" python3 - <<'PY'
import importlib

importlib.import_module("sqlalchemy")
importlib.import_module("psycopg2")
importlib.import_module("backend.app.db.models")
PY
}

# Create the database schema with the owner role
create_schema_as_owner() {
    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || return 1

    # SEC-11: schema objects are owned by app_owner; app_user holds no CREATE
    # on schema public and issues no DDL
    # SEC-11: the owner credential travels in the environment, never in the
    # process argument list
    OWNER_DATABASE_URL="postgresql://app_owner:${DB_OWNER_PASSWORD}@localhost:5432/dbname" \
    PYTHONPATH="$repo_root" python3 - <<'PY'
import os

from sqlalchemy import create_engine

from backend.app.db.models import Base

engine = create_engine(os.environ["OWNER_DATABASE_URL"])
try:
    Base.metadata.create_all(bind=engine)
finally:
    engine.dispose()
PY
}

# Initialize local database
init_database() {
    echo "Initializing local database..."

    # SEC-11: verifies the owner bootstrap's imports before the first
    # database object exists (CWE-252)
    if ! check_schema_prerequisites; then
        echo "Cannot import SQLAlchemy, psycopg2 and backend.app.db.models with this interpreter. Install backend/requirements.txt, then rerun." >&2
        return 1
    fi
    
    if ! createdb dbname; then
        echo "Failed to create database dbname. Check the local PostgreSQL server, then rerun." >&2
        return 1
    fi

    # SEC-11: owner role performs schema work; application role is limited to table data operations
    # SEC-11: the two role passwords reach psql on standard input through the
    # printf builtin, so neither value appears in any process argument list
    # (CWE-214); a failed grant batch aborts the run (CWE-252)
    {
        printf "\\\\set owner_pw '%s'\\n" "$DB_OWNER_PASSWORD"
        printf "\\\\set app_pw '%s'\\n" "$DB_APP_PASSWORD"
        cat <<'SQL'
CREATE ROLE app_owner WITH LOGIN PASSWORD :'owner_pw';
CREATE ROLE app_user WITH LOGIN PASSWORD :'app_pw';
ALTER DATABASE dbname OWNER TO app_owner;
GRANT CREATE, USAGE ON SCHEMA public TO app_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE dbname TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_user;
SQL
    } | psql -v ON_ERROR_STOP=1 -d dbname
    if [ "${PIPESTATUS[1]}" -ne 0 ]; then
        echo "Failed to provision the least-privilege database roles. Drop dbname and its app roles, then rerun." >&2
        return 1
    fi

    if ! create_schema_as_owner; then
        echo "Failed to create the database schema as app_owner. Drop dbname and its app roles, then rerun." >&2
        return 1
    fi
    
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
    # SEC-11: prepares and populates the interpreter before the credential
    # and database steps
    setup_virtual_env || exit 1
    install_dependencies || exit 1
    # SEC-01/SEC-11: a failed credential or role provisioning step stops the run
    configure_env_vars || exit 1
    init_database || exit 1
    run_migrations
    
    echo "Development environment setup completed successfully!"
}

main