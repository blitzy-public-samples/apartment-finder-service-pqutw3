#!/bin/bash
#
# Prepares a local development environment for the
# apartment-finder-service: a virtual environment, the project
# dependencies, an environment file, a database role and database, and
# the schema.
#
# Every step is checked and the script stops at the first failure, so the
# closing success message is printed only once all of them have
# succeeded. Decision rationale is recorded in
# docs/security/DECISION_LOG.md.

# Abort on any failing command, on any unset variable and on any failure
# within a pipeline, and let the ERR trap below reach every function.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Interpreter version the project is pinned to
readonly REQUIRED_PYTHON_VERSION="3.9"

# Virtual environment this script creates and installs into
readonly VENV_DIR="${REPO_ROOT}/venv"

# Local database objects this script creates. The same values are written
# into the DATABASE_URL entry of the environment file.
readonly DB_HOST="localhost"
readonly DB_PORT="5432"
readonly DB_NAME="apartment_finder"
readonly DB_ROLE="apartment_finder"

# Variety rules the settings validator applies to SECRET_KEY. A key must
# carry at least this many distinct characters, must not repeat one
# character more times in a row than this, and must not carry a longer run
# of consecutive code points than this.
readonly MIN_SIGNING_KEY_DISTINCT_CHARACTERS=12
readonly MAX_SIGNING_KEY_REPEAT_RUN=3
readonly MAX_SIGNING_KEY_SEQUENCE_RUN=4

# Keys generate_signing_key produces before it gives up
readonly SIGNING_KEY_ATTEMPTS=10

# Interpreter found by check_software
PYTHON_BIN=""

# Interpreter of the virtual environment, set by setup_virtual_env
VENV_PYTHON=""

# Activation script of the virtual environment, set by setup_virtual_env
VENV_ACTIVATE=""

# Key produced by generate_signing_key
GENERATED_SIGNING_KEY=""

# Variety rule the key last measured by check_signing_key_variety fails,
# or the empty string when that key clears every rule
SIGNING_KEY_REJECTION=""

# Files removed when the script exits
TEMP_FILES=()

# Remove the temporary files recorded above
cleanup() {
    local file
    for file in ${TEMP_FILES[@]+"${TEMP_FILES[@]}"}; do
        rm -f "${file}"
    done
}

# Report the line a failed command was on. The shell that started this
# script reports; a subshell that inherited the ERR trap does not, so one
# failure produces one line.
report_failure() {
    if [ "${BASHPID:-$$}" != "$$" ]; then
        return 0
    fi
    echo "Setup failed at line ${1}. The environment is incomplete." >&2
}

trap 'report_failure "${LINENO}"' ERR
trap cleanup EXIT

# Print the name of an interpreter whose version is the pinned one
resolve_python() {
    local candidates=()
    local candidate
    local version

    if [ -n "${PYTHON:-}" ]; then
        candidates+=("${PYTHON}")
    fi
    candidates+=("python${REQUIRED_PYTHON_VERSION}" "python3")

    for candidate in "${candidates[@]}"; do
        if ! command -v "${candidate}" > /dev/null 2>&1; then
            continue
        fi
        version="$("${candidate}" -c \
            'import sys; print("%d.%d" % sys.version_info[:2])' \
            2> /dev/null || true)"
        if [ "${version}" = "${REQUIRED_PYTHON_VERSION}" ]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done

    return 1
}

# Stop unless setup_virtual_env has recorded an interpreter
require_venv_python() {
    if [ -z "${VENV_PYTHON}" ]; then
        echo "The virtual environment has not been created yet." >&2
        exit 1
    fi
}

# Check for required software
check_software() {
    echo "Checking for required software..."

    local tool

    if ! PYTHON_BIN="$(resolve_python)"; then
        echo "Python ${REQUIRED_PYTHON_VERSION} was not found." >&2
        echo "Install it, or set PYTHON to the interpreter to use, then" \
            "try again." >&2
        exit 1
    fi
    echo "Using Python ${REQUIRED_PYTHON_VERSION}: $(command -v "${PYTHON_BIN}")"

    if ! "${PYTHON_BIN}" -c 'import venv' > /dev/null 2>&1; then
        echo "The venv module is unavailable for ${PYTHON_BIN}." >&2
        echo "Install it and try again." >&2
        exit 1
    fi

    for tool in npm psql createdb; do
        if ! command -v "${tool}" > /dev/null 2>&1; then
            echo "${tool} is not installed. Please install it and try" \
                "again." >&2
            exit 1
        fi
    done

    echo "All required software is installed."
}

# Set up the virtual environment
setup_virtual_env() {
    echo "Setting up virtual environment..."

    local version

    if [ ! -x "${VENV_DIR}/bin/python" ] \
        && [ ! -x "${VENV_DIR}/Scripts/python.exe" ]; then
        "${PYTHON_BIN}" -m venv "${VENV_DIR}"
    fi

    if [ -x "${VENV_DIR}/bin/python" ]; then
        VENV_PYTHON="${VENV_DIR}/bin/python"
        VENV_ACTIVATE="${VENV_DIR}/bin/activate"
    elif [ -x "${VENV_DIR}/Scripts/python.exe" ]; then
        VENV_PYTHON="${VENV_DIR}/Scripts/python.exe"
        VENV_ACTIVATE="${VENV_DIR}/Scripts/activate"
    else
        echo "The virtual environment at ${VENV_DIR} carries no" \
            "interpreter." >&2
        exit 1
    fi

    version="$("${VENV_PYTHON}" -c \
        'import sys; print("%d.%d" % sys.version_info[:2])')"
    if [ "${version}" != "${REQUIRED_PYTHON_VERSION}" ]; then
        echo "The virtual environment at ${VENV_DIR} is Python" \
            "${version}, not ${REQUIRED_PYTHON_VERSION}." >&2
        echo "Remove it and re-run this script." >&2
        exit 1
    fi

    echo "Virtual environment ready at ${VENV_DIR}."
}

# Install project dependencies
install_dependencies() {
    echo "Installing project dependencies..."

    require_venv_python

    # Install the pinned Python dependencies into the virtual environment
    "${VENV_PYTHON}" -m pip install --upgrade pip
    "${VENV_PYTHON}" -m pip install \
        -r "${REPO_ROOT}/backend/requirements.txt" \
        -r "${REPO_ROOT}/backend/requirements-dev.txt"

    # Install the Node.js dependencies from the committed lock file
    npm ci --prefix "${REPO_ROOT}/frontend"

    echo "Project dependencies installed."
}

# Record which of the variety rules a signing key fails, if any
check_signing_key_variety() {
    local value="$1"
    local length="${#value}"
    local index
    local character
    local seen=""
    local distinct=0
    local code=0
    local previous_code=0
    local delta=0
    local step=0
    local repeat_run=0
    local sequence_run=0
    local longest_repeat=0
    local longest_sequence=0

    SIGNING_KEY_REJECTION=""

    for ((index = 0; index < length; index++)); do
        character="${value:index:1}"

        # Count the character unless an earlier position carried it
        case "${seen}" in
            *"${character}"*) ;;
            *)
                seen="${seen}${character}"
                distinct=$((distinct + 1))
                ;;
        esac

        printf -v code '%d' "'${character}"

        if [ "${index}" -eq 0 ]; then
            repeat_run=1
            sequence_run=1
        else
            if [ "${code}" -eq "${previous_code}" ]; then
                repeat_run=$((repeat_run + 1))
            else
                repeat_run=1
            fi

            # Extend the run while the code points step by one in the
            # direction the run already carries
            delta=$((code - previous_code))
            if { [ "${delta}" -eq 1 ] || [ "${delta}" -eq -1 ]; } \
                && { [ "${step}" -eq 0 ] \
                    || [ "${delta}" -eq "${step}" ]; }; then
                step="${delta}"
                sequence_run=$((sequence_run + 1))
            elif [ "${delta}" -eq 1 ] || [ "${delta}" -eq -1 ]; then
                step="${delta}"
                sequence_run=2
            else
                step=0
                sequence_run=1
            fi
        fi

        if [ "${repeat_run}" -gt "${longest_repeat}" ]; then
            longest_repeat="${repeat_run}"
        fi
        if [ "${sequence_run}" -gt "${longest_sequence}" ]; then
            longest_sequence="${sequence_run}"
        fi

        previous_code="${code}"
    done

    if [ "${distinct}" -lt "${MIN_SIGNING_KEY_DISTINCT_CHARACTERS}" ]; then
        printf -v SIGNING_KEY_REJECTION \
            'carries fewer than %s distinct characters' \
            "${MIN_SIGNING_KEY_DISTINCT_CHARACTERS}"
    elif [ "${longest_repeat}" -gt "${MAX_SIGNING_KEY_REPEAT_RUN}" ]; then
        printf -v SIGNING_KEY_REJECTION \
            'repeats one character more than %s times in a row' \
            "${MAX_SIGNING_KEY_REPEAT_RUN}"
    elif [ "${longest_sequence}" -gt "${MAX_SIGNING_KEY_SEQUENCE_RUN}" ]
    then
        printf -v SIGNING_KEY_REJECTION \
            'carries a run of more than %s consecutive characters' \
            "${MAX_SIGNING_KEY_SEQUENCE_RUN}"
    fi
}

# Generate a signing key that clears every variety rule
generate_signing_key() {
    local attempt
    local candidate

    GENERATED_SIGNING_KEY=""
    SIGNING_KEY_REJECTION=""

    for ((attempt = 1; attempt <= SIGNING_KEY_ATTEMPTS; attempt++)); do
        if command -v openssl > /dev/null 2>&1; then
            candidate="$(openssl rand -hex 32)"
        else
            require_venv_python
            candidate="$("${VENV_PYTHON}" -c \
                'import secrets; print(secrets.token_hex(32))')"
        fi

        if [ -z "${candidate}" ]; then
            echo "Failed to generate a value for SECRET_KEY." >&2
            exit 1
        fi

        check_signing_key_variety "${candidate}"
        if [ -z "${SIGNING_KEY_REJECTION}" ]; then
            GENERATED_SIGNING_KEY="${candidate}"
            return 0
        fi
    done

    echo "Generated ${SIGNING_KEY_ATTEMPTS} values for SECRET_KEY and" \
        "none of them cleared the variety rules the settings validator" \
        "applies." >&2
    echo "The last one ${SIGNING_KEY_REJECTION}. Re-run this script to" \
        "try again." >&2
    exit 1
}

configure_env_vars() {
    echo "Configuring environment variables..."

    local env_template="${REPO_ROOT}/.env.example"
    local env_file="${REPO_ROOT}/.env"
    local env_tmp
    local secret_key
    local line

    if [ ! -f "${env_template}" ]; then
        echo "The environment template ${env_template} is missing." >&2
        exit 1
    fi

    # Keep an environment file that is already present
    if [ -e "${env_file}" ]; then
        if ! grep -q '^SECRET_KEY=.\{32,\}$' "${env_file}"; then
            echo "The existing ${env_file} carries no SECRET_KEY of at" \
                "least 32 characters." >&2
            echo "Set one, or move the file aside and re-run this" \
                "script." >&2
            exit 1
        fi
        if ! grep -q '^DATABASE_URL=' "${env_file}"; then
            echo "The existing ${env_file} carries no DATABASE_URL" \
                "entry." >&2
            echo "Add one, or move the file aside and re-run this" \
                "script." >&2
            exit 1
        fi
        echo "Keeping the existing ${env_file}."
        return 0
    fi

    # Generate the token signing key
    generate_signing_key
    secret_key="${GENERATED_SIGNING_KEY}"

    env_tmp="$(mktemp "${env_file}.XXXXXX")"
    TEMP_FILES+=("${env_tmp}")

    # Write the template through, replacing the SECRET_KEY entry
    while IFS= read -r line || [ -n "${line}" ]; do
        case "${line}" in
            SECRET_KEY=*) printf '%s\n' "SECRET_KEY=${secret_key}" ;;
            *) printf '%s\n' "${line}" ;;
        esac
    done < "${env_template}" > "${env_tmp}"

    # Confirm the SECRET_KEY entry carries at least 32 characters
    if ! grep -q '^SECRET_KEY=.\{32,\}$' "${env_tmp}"; then
        echo "Failed to write a generated SECRET_KEY into" \
            "${env_file}." >&2
        exit 1
    fi

    # The environment file appears complete or not at all
    mv "${env_tmp}" "${env_file}"
    chmod 600 "${env_file}"

    echo "Created ${env_file} from ${env_template} with a generated" \
        "SECRET_KEY."
    echo "Environment variables configured. Please update the values in" \
        ".env file."
}

init_database() {
    echo "Initializing local database..."

    local env_file="${REPO_ROOT}/.env"
    local current_url
    local db_password
    local db_password_confirm
    local db_password_sql
    local db_password_url
    local database_url
    local env_tmp
    local line
    local role_present
    local database_present

    require_venv_python

    if [ ! -f "${env_file}" ]; then
        echo "The environment file ${env_file} is missing." >&2
        exit 1
    fi

    current_url="$(sed -n 's/^DATABASE_URL=//p' "${env_file}" \
        | head -n 1)"

    case "${current_url}" in
        "" | *REPLACE_DB_USER* | *REPLACE_DB_PASSWORD*)
            ;;
        *)
            echo "${env_file} already names a configured DATABASE_URL."
            echo "Leaving it and the database it addresses untouched."
            return 0
            ;;
    esac

    # Read the password for the database role
    read -r -s -p "Enter a password for the ${DB_ROLE} database role: " \
        db_password
    echo
    read -r -s -p "Re-enter the password: " db_password_confirm
    echo

    if [ -z "${db_password}" ]; then
        echo "No password was entered. The database role was not" \
            "created." >&2
        exit 1
    fi

    if [ "${db_password}" != "${db_password_confirm}" ]; then
        echo "The passwords entered do not match. The database role was" \
            "not created." >&2
        exit 1
    fi

    # Double each single quote in the value for the SQL string literal
    db_password_sql="${db_password//\'/\'\'}"

    # Percent-encode the value for the DATABASE_URL entry
    db_password_url="$(SETUP_DB_PASSWORD="${db_password}" \
        "${VENV_PYTHON}" -c 'import os, sys, urllib.parse
sys.stdout.write(urllib.parse.quote(os.environ["SETUP_DB_PASSWORD"],
                                    safe=""))')"

    if [ -z "${db_password_url}" ]; then
        echo "Failed to encode the database password for" \
            "DATABASE_URL." >&2
        exit 1
    fi

    # Create the role when it is absent and set its password either way.
    # The statement carrying the password is passed over standard input,
    # so the value does not appear in an argument list.
    role_present="$(psql --no-psqlrc --quiet --tuples-only --no-align \
        --dbname=postgres --command \
        "SELECT 1 FROM pg_roles WHERE rolname = '${DB_ROLE}'")"
    if [ "${role_present}" = "1" ]; then
        printf 'ALTER ROLE "%s" WITH LOGIN PASSWORD %s;\n' \
            "${DB_ROLE}" "'${db_password_sql}'" \
            | psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
                --dbname=postgres
    else
        printf 'CREATE ROLE "%s" WITH LOGIN PASSWORD %s;\n' \
            "${DB_ROLE}" "'${db_password_sql}'" \
            | psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
                --dbname=postgres
    fi

    # Create the database when it is absent
    database_present="$(psql --no-psqlrc --quiet --tuples-only \
        --no-align --dbname=postgres --command \
        "SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}'")"
    if [ "${database_present}" != "1" ]; then
        createdb --owner="${DB_ROLE}" "${DB_NAME}"
    fi

    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --dbname=postgres \
        --command \
        "GRANT ALL PRIVILEGES ON DATABASE \"${DB_NAME}\" TO \"${DB_ROLE}\""

    # Write the URL the objects above are reached by
    database_url="postgresql://${DB_ROLE}:${db_password_url}"
    database_url="${database_url}@${DB_HOST}:${DB_PORT}/${DB_NAME}"

    env_tmp="$(mktemp "${env_file}.XXXXXX")"
    TEMP_FILES+=("${env_tmp}")

    while IFS= read -r line || [ -n "${line}" ]; do
        case "${line}" in
            DATABASE_URL=*) printf '%s\n' "DATABASE_URL=${database_url}" ;;
            *) printf '%s\n' "${line}" ;;
        esac
    done < "${env_file}" > "${env_tmp}"

    if ! grep -q "^DATABASE_URL=postgresql://${DB_ROLE}:" "${env_tmp}"; then
        echo "Failed to write the DATABASE_URL entry into" \
            "${env_file}." >&2
        exit 1
    fi

    mv "${env_tmp}" "${env_file}"
    chmod 600 "${env_file}"

    echo "Local database ${DB_NAME} and role ${DB_ROLE} are ready."
    echo "Wrote the matching DATABASE_URL entry into ${env_file}."
}

run_migrations() {
    echo "Running initial data migrations..."

    require_venv_python

    # Apply the Alembic migrations from the repository root
    (cd "${REPO_ROOT}" \
        && "${VENV_PYTHON}" -m alembic -c backend/alembic.ini upgrade head)

    echo "Initial data migrations completed."
}

main() {
    check_software
    setup_virtual_env
    install_dependencies
    configure_env_vars
    init_database
    run_migrations

    echo "Development environment setup completed successfully!"
    echo "Activate the virtual environment with: source ${VENV_ACTIVATE}"
}

main "$@"
