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

    # SEC-11: installs the tracked manifest with the active interpreter;
    # a failed install aborts the run (CWE-252)
    if ! python3 -m pip install -r "$repo_root/backend/requirements.txt"; then
        echo "Failed to install $repo_root/backend/requirements.txt. Resolve the installation error, then rerun." >&2
        return 1
    fi
    
    # Install Node.js dependencies
    if ! (cd "$repo_root/frontend" && npm install); then
        echo "Failed to install the frontend dependencies in $repo_root/frontend. Resolve the installation error, then rerun." >&2
        return 1
    fi
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

# SEC-01: publishes the generated file with link(2), which fails when the
# destination exists as a file, a directory or a symlink. No check precedes
# the call (CWE-367, CWE-59). DL-370
publish_env_file() {
    local source_file="$1"
    local destination="$2"

    if [ -z "$source_file" ] || [ -z "$destination" ]; then
        echo "publish_env_file needs a source file and a destination." >&2
        return 1
    fi

    PUBLISH_SOURCE="$source_file" PUBLISH_DESTINATION="$destination" python3 - <<'PY'
import os
import sys

try:
    os.link(os.environ["PUBLISH_SOURCE"], os.environ["PUBLISH_DESTINATION"])
except OSError as error:
    sys.stderr.write("Refusing to publish {0}: {1}\n".format(
        os.environ["PUBLISH_DESTINATION"], error
    ))
    sys.exit(1)
PY
    local link_status=$?

    if [ "$link_status" -ne 0 ]; then
        return 1
    fi

    # SEC-01: the temporary name is dropped, leaving the destination as the
    # only name for the inode the run created (CWE-732)
    if ! rm -f "$source_file"; then
        echo "Failed to remove $source_file after publishing $destination." >&2
        return 1
    fi

    # SEC-01: the published path is the regular, non-empty file just linked
    if [ ! -f "$destination" ] || [ -L "$destination" ] || [ ! -s "$destination" ]; then
        echo "Refusing to report success: $destination is not the file setup wrote." >&2
        return 1
    fi
}

# Configure environment variables
configure_env_vars() {
    echo "Configuring environment variables..."

    # SEC-01: an existing secret file stops the run before any credential
    # is generated. publish_env_file carries the race-free refusal
    # (CWE-59, CWE-367). DL-370
    if [ -e .env ] || [ -L .env ]; then
        echo "An .env file is already present. Move it aside, then rerun." >&2
        return 1
    fi
    
    # SEC-01: credential values are generated at run time, never stored here
    # SEC-12: key length clears the floor on Settings.SECRET_KEY
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
    DB_APP_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
    DB_OWNER_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')

    if [ "${#SECRET_KEY}" -lt 32 ] || [ -z "$DB_APP_PASSWORD" ] || [ -z "$DB_OWNER_PASSWORD" ]; then
        echo "Credential generation failed. Ensure python3 is available and re-run." >&2
        return 1
    fi

    # SEC-11: holds both role passwords to the generator's character set,
    # since each reaches psql as a quoted SQL literal (CWE-89)
    if ! [[ "$DB_APP_PASSWORD" =~ ^[A-Za-z0-9_-]+$ ]] || ! [[ "$DB_OWNER_PASSWORD" =~ ^[A-Za-z0-9_-]+$ ]]; then
        echo "A generated role password carries an unexpected character. Please re-run." >&2
        return 1
    fi

    # SEC-01/SEC-12: the owner-only temporary file is published with
    # link(2); any existing destination is left unchanged and aborts the run
    # (CWE-59, CWE-367, CWE-732). DL-352
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

    # SEC-01: restricts the secret file to its owner, and aborts the run
    # on failure (CWE-732, CWE-252). DL-370
    if ! chmod 600 "$env_tmp"; then
        echo "Failed to restrict .env to the owning user. Secure or remove .env before continuing." >&2
        return 1
    fi

    # SEC-01: an atomic no-clobber publish of the owner-only temporary
    # file (CWE-367, CWE-59). DL-370
    if ! publish_env_file "$env_tmp" .env; then
        echo "Failed to install .env. Remove or rename anything standing at .env, then rerun." >&2
        return 1
    fi
    trap - EXIT
    
    echo "Environment variables configured. Please update the values in .env file."
    echo "This file carries four keys; .env.example documents the complete variable set."
    echo "The app_owner password was generated for this run only and is not retained. Issue ALTER ROLE app_owner WITH PASSWORD, or rerun setup, before further schema work."
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

    # SEC-11: schema objects are owned by app_owner, and app_user issues
    # no DDL (CWE-250)
    # SEC-11: the owner credential travels in the environment, never in the
    # process argument list (CWE-214)
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

    # SEC-11: checks the owner bootstrap's imports before the first
    # database object exists (CWE-252)
    if ! check_schema_prerequisites; then
        echo "Cannot import SQLAlchemy, psycopg2 and backend.app.db.models with this interpreter. Install backend/requirements.txt, then rerun." >&2
        return 1
    fi

    if ! createdb dbname; then
        echo "Failed to create database dbname. Check the local PostgreSQL server, then rerun." >&2
        return 1
    fi

    # SEC-11: owner role performs schema work; application role is limited
    # to table data operations. The two revokes remove what PostgreSQL 13
    # grants PUBLIC by default: CREATE on schema public, and CONNECT plus
    # TEMPORARY on the database (CWE-250, CWE-269)
    # SEC-11: the final block reads the effective ACLs rather than trusting
    # the statements above, and aborts the batch when PUBLIC retains a
    # database privilege or the application role holds more than the
    # granted set (CWE-269)
    # SEC-11: both role passwords reach psql on standard input and neither
    # appears in a process argument list (CWE-214); a failed grant batch
    # aborts the run (CWE-252)
    {
        printf "\\\\set owner_pw '%s'\\n" "$DB_OWNER_PASSWORD"
        printf "\\\\set app_pw '%s'\\n" "$DB_APP_PASSWORD"
        cat <<'SQL'
CREATE ROLE app_owner WITH LOGIN PASSWORD :'owner_pw';
CREATE ROLE app_user WITH LOGIN PASSWORD :'app_pw';
ALTER DATABASE dbname OWNER TO app_owner;
ALTER SCHEMA public OWNER TO app_owner;
GRANT CREATE, USAGE ON SCHEMA public TO app_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CONNECT, TEMPORARY ON DATABASE dbname FROM PUBLIC;
GRANT CONNECT ON DATABASE dbname TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_user;
DO $$
DECLARE
    held text;
BEGIN
    SELECT string_agg(a.privilege_type, ', ' ORDER BY a.privilege_type) INTO held
      FROM pg_database d, aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
     WHERE d.datname = current_database() AND a.grantee = 0;
    IF held IS NOT NULL THEN
        RAISE EXCEPTION 'PUBLIC still holds % on database %', held, current_database();
    END IF;
    SELECT string_agg(a.privilege_type, ', ' ORDER BY a.privilege_type) INTO held
      FROM pg_namespace n, aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
     WHERE n.nspname = 'public' AND a.grantee = 0 AND a.privilege_type <> 'USAGE';
    IF held IS NOT NULL THEN
        RAISE EXCEPTION 'PUBLIC still holds % on schema public', held;
    END IF;
    IF NOT has_database_privilege('app_user', current_database(), 'CONNECT') THEN
        RAISE EXCEPTION 'app_user cannot connect to %', current_database();
    END IF;
    IF has_database_privilege('app_user', current_database(), 'TEMPORARY') THEN
        RAISE EXCEPTION 'app_user retains TEMPORARY on %', current_database();
    END IF;
    IF has_schema_privilege('app_user', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'app_user retains CREATE on schema public';
    END IF;
    IF NOT has_schema_privilege('app_user', 'public', 'USAGE') THEN
        RAISE EXCEPTION 'app_user cannot use schema public';
    END IF;
END
$$;
SQL
    } | psql -v ON_ERROR_STOP=1 -d dbname
    if [ "${PIPESTATUS[1]}" -ne 0 ]; then
        echo "Failed to provision the least-privilege database roles. Drop dbname and its app roles, then rerun." >&2
        return 1
    fi

    if ! create_schema_as_owner; then
        echo "Failed to create the database schema as app_owner. Install backend/requirements.txt, drop dbname and its app roles, then rerun." >&2
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
    # SEC-11: prepares the interpreter the owner bootstrap needs before the
    # credential and database steps
    setup_virtual_env || exit 1
    install_dependencies || exit 1
    # SEC-01/SEC-11: a failed credential or role provisioning step stops the run
    configure_env_vars || exit 1
    init_database || exit 1
    run_migrations
    
    echo "Development environment setup completed successfully!"
}

main
