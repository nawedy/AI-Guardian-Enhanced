import os
import subprocess
import sys

# Define colors for output
GREEN = '\\033[0;32m'
YELLOW = '\\033[1;33m'
RED = '\\033[0;31m'
NC = '\\033[0m' # No Color

def log(message):
    """Prints a formatted log message."""
    print(f"{GREEN}[MIGRATOR] {message}{NC}")

def warn(message):
    """Prints a formatted warning message."""
    print(f"{YELLOW}[MIGRATOR] WARNING: {message}{NC}")

def error(message):
    """Prints a formatted error message and exits."""
    print(f"{RED}[MIGRATOR] ERROR: {message}{NC}")
    sys.exit(1)

def run_command(command, cwd):
    """Runs a command in a given directory and handles errors."""
    log(f"Running command: {' '.join(command)} in {cwd}")
    process = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True
    )
    if process.returncode != 0:
        error(f"Command failed.\\nSTDOUT:\\n{process.stdout}\\nSTDERR:\\n{process.stderr}")
    log("Command successful.")
    return process

def main():
    """
    Main function to initialize and apply database migrations for all services.
    """
    log("Starting database migration process for all services...")
    backend_path = os.path.join(os.path.dirname(__file__), 'backend')
    services = [
        'api-gateway/api-gateway-service',
        'code-scanner/code-scanner-service',
        'remediation-engine/remediation-engine-service',
        'intelligent-analysis/intelligent-analysis-service',
        'adaptive-learning/adaptive-learning-service',
    ]

    for service_rel_path in services:
        service_abs_path = os.path.join(backend_path, service_rel_path)
        log(f"Processing service: {service_rel_path}")

        # Check if the service uses Flask-Migrate by checking requirements
        req_path = os.path.join(service_abs_path, 'requirements.txt')
        if not os.path.exists(req_path):
            warn(f"No requirements.txt found for {service_rel_path}. Skipping.")
            continue
        
        with open(req_path, 'r') as f:
            if 'flask-migrate' not in f.read().lower():
                warn(f"Flask-Migrate not found in requirements for {service_rel_path}. Skipping.")
                continue

        # Check for migrations directory
        migrations_path = os.path.join(service_abs_path, 'migrations')
        if not os.path.exists(migrations_path):
            log("No migrations directory found. Initializing...")
            run_command(['flask', 'db', 'init'], cwd=service_abs_path)

        # Generate the initial migration if no versions exist
        versions_path = os.path.join(migrations_path, 'versions')
        if not os.path.exists(versions_path) or not os.listdir(versions_path):
            log("No migration versions found. Generating initial migration...")
            run_command(['flask', 'db', 'migrate', '-m', 'Initial migration'], cwd=service_abs_path)

        # Apply the migrations
        log("Applying database migrations...")
        run_command(['flask', 'db', 'upgrade'], cwd=service_abs_path)

        log(f"Successfully processed service: {service_rel_path}")

    log("All database migrations completed successfully!")

if __name__ == "__main__":
    main() 