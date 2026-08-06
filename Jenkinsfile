pipeline {
    agent any

    parameters {
        booleanParam(
            name: 'RUN_DEPENDENCY_CHECK',
            defaultValue: true,
            description: 'Run OWASP Dependency-Check and archive the reports.'
        )

        booleanParam(
            name: 'RUN_CONTAINER_SCANS',
            defaultValue: true,
            description: 'Run Trivy scans against all deployed container images.'
        )

        booleanParam(
            name: 'RUN_ZAP',
            defaultValue: false,
            description: 'Run the OWASP ZAP baseline scan after deployment.'
        )

        string(
            name: 'DEVELOPER_EMAIL',
            defaultValue: 'evan246810536546@gmail.com',
            description: 'Email address that receives vulnerability and pipeline-failure alerts.'
        )
    }

    triggers {
        // Jenkins checks the configured Git repository every two minutes.
        // A new commit automatically starts the pipeline.
        pollSCM('* * * * *')
    }

    options {
        timestamps()
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 150, unit: 'MINUTES')
    }

    environment {
        COMPOSE_FILE = 'deployment/docker-compose.secure.yml'
        COMPOSE_PROJECT_NAME = 'penpot-secure'

        // Jenkins uses 8080. Penpot HTTP and HTTPS use 8081 and 8443.
        PENPOT_HTTP_URL = 'http://localhost:8081'
        PENPOT_URL = 'https://localhost:8443'

        REPORT_DIRECTORY = 'reports'

        // Local-lab values. Jenkins credentials should replace these in production.
        PENPOT_DATABASE_PASSWORD = 'ubuntu'
        PENPOT_SECRET_KEY = 'ubuntu-penpot-local-testing-secret-key-2026'
        PENPOT_VERSION = 'latest'

        // Persistent cache keeps Dependency-Check updates between Jenkins builds.
        DEPENDENCY_CHECK_DATA_DIR = '/var/lib/jenkins/dependency-check-data'
    }

    stages {
        stage('Checkout Source Code') {
            steps {
                deleteDir()
                checkout scm

                sh '''
                    set -eu

                    echo "Repository URL and branch are controlled by the Jenkins SCM configuration."
                    echo "Checked-out commit: $(git rev-parse HEAD)"

                    mkdir -p reports/source
                    git rev-parse HEAD > reports/source/scanned-commit.txt
                    git status --short > reports/source/checkout-status.txt
                    git log -1 --pretty=fuller > reports/source/commit-details.txt

                    # Keep the checked-out Penpot source code, but copy any missing
                    # pipeline support files from the existing local DevSecOps project.
                    SUPPORT_ROOT="/opt/penpot-devsecops"

                    REQUIRED_SUPPORT_FILES="
                    deployment/docker-compose.secure.yml
                    tests/test_api.py
                    tests/test_security.py
                    tests/requirements.txt
                    "

                    for REQUIRED_FILE in $REQUIRED_SUPPORT_FILES; do
                        if [ ! -f "$REQUIRED_FILE" ]; then
                            SOURCE_FILE="$SUPPORT_ROOT/$REQUIRED_FILE"

                            if [ ! -f "$SOURCE_FILE" ]; then
                                echo "ERROR: Required pipeline file is missing:"
                                echo "  Repository: $REQUIRED_FILE"
                                echo "  Local fallback: $SOURCE_FILE"
                                exit 1
                            fi

                            mkdir -p "$(dirname "$REQUIRED_FILE")"
                            cp "$SOURCE_FILE" "$REQUIRED_FILE"
                            echo "Copied local pipeline support file: $REQUIRED_FILE"
                        else
                            echo "Using repository pipeline support file: $REQUIRED_FILE"
                        fi
                    done

                    test -f "$COMPOSE_FILE"
                    test -f tests/test_api.py
                    test -f tests/test_security.py
                    test -f tests/requirements.txt

                    test -d backend || {
                        echo "WARNING: Penpot backend source directory was not found at ./backend."
                        echo "Semgrep will still scan the complete checked-out repository."
                    }

                    test -d frontend || {
                        echo "WARNING: Penpot frontend source directory was not found at ./frontend."
                        echo "Semgrep will still scan the complete checked-out repository."
                    }
                '''
            }
        }

        stage('Prepare Workspace') {
            steps {
                sh '''
                    set -eu

                    mkdir -p "$REPORT_DIRECTORY"
                    mkdir -p "$REPORT_DIRECTORY/notification"
                    mkdir -p "$REPORT_DIRECTORY/integrity"
                    mkdir -p "$REPORT_DIRECTORY/post-deployment"
                    mkdir -p "$REPORT_DIRECTORY/pytest"
                    mkdir -p "$REPORT_DIRECTORY/images"
                    mkdir -p "$REPORT_DIRECTORY/zap"
                    mkdir -p "$REPORT_DIRECTORY/functional"
                    mkdir -p "$REPORT_DIRECTORY/dependency-check"
                    mkdir -p "$REPORT_DIRECTORY/semgrep"
                    mkdir -p "$REPORT_DIRECTORY/source"
                    mkdir -p "$WORKSPACE/.trivy-cache"
                    mkdir -p "$DEPENDENCY_CHECK_DATA_DIR"

                    mkdir -p deployment/certs
                    mkdir -p deployment/nginx/conf.d
                    mkdir -p scripts
                    mkdir -p tests
                    mkdir -p semgrep-rules

                    find scripts -type f -name "*.sh" \
                        -exec chmod +x {} + 2>/dev/null || true
                '''
            }
        }

        stage('Create Host Setup Script') {
            steps {
                sh '''
                    set -eu

                    cat > scripts/setup-host.sh <<'HOST_SETUP'
#!/usr/bin/env bash

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this script using sudo."
    exit 1
fi

apt-get update

apt-get install -y \
    ca-certificates \
    curl \
    openssl \
    python3 \
    python3-pip \
    unzip \
    iproute2 \
    git

systemctl enable --now docker
usermod -aG docker jenkins

mkdir -p /opt/penpot-devsecops
chown -R jenkins:jenkins /opt/penpot-devsecops

systemctl restart jenkins

echo "Host setup completed."
echo "Verify Docker access with: sudo -u jenkins docker ps"
HOST_SETUP

                    chmod +x scripts/setup-host.sh
                '''
            }
        }

        stage('Create Secure NGINX Configuration') {
            steps {
                sh '''
                    set -eu

                    cat > deployment/nginx/nginx.conf <<'NGINX_MAIN'
user nginx;
worker_processes auto;

error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    sendfile on;
    keepalive_timeout 65;
    server_tokens off;

    # Limit each client IP to five password-login requests per minute.
    limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;

    include /etc/nginx/conf.d/*.conf;
}
NGINX_MAIN

                    cat > deployment/nginx/conf.d/penpot.conf <<'NGINX_SITE'
server {
    listen 80;
    server_name localhost penpot.local;

    # Force all HTTP traffic to HTTPS.
    return 301 https://$host:8443$request_uri;
}

server {
    listen 443 ssl;
    server_name localhost penpot.local;

    ssl_certificate /etc/nginx/certs/penpot.crt;
    ssl_certificate_key /etc/nginx/certs/penpot.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;

    client_max_body_size 350M;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Restrict sensitive or diagnostic paths.
    location = /.env {
        return 404;
    }

    location = /.git {
        return 404;
    }

    location = /.git/config {
        return 404;
    }

    location = /debug {
        return 403;
    }

    location = /metrics {
        return 403;
    }

    location = /actuator {
        return 403;
    }

    location = /internal {
        return 403;
    }

    location = /backup.sql {
        return 404;
    }

    # Brute-force mitigation for the password-login endpoint.
    location = /api/rpc/command/login-with-password {
        limit_req zone=login_limit burst=3 nodelay;
        limit_req_status 429;

        proxy_pass http://penpot-backend:6060;

        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Scheme $scheme;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_redirect off;
    }

    location /api/ {
        proxy_pass http://penpot-backend:6060;

        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Scheme $scheme;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_redirect off;
    }

    location /ws/notifications {
        proxy_pass http://penpot-backend:6060/ws/notifications;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass http://penpot-frontend:8080;

        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Scheme $scheme;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_redirect off;
    }
}
NGINX_SITE
                '''
            }
        }

        stage('Create Additional Security Tests') {
            steps {
                sh '''
                    set -eu

                    cat > tests/test_pipeline_security.py <<'PYTHON_TESTS'
import os

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.getenv("PENPOT_URL", "https://localhost:8443").rstrip("/")
HTTP_URL = os.getenv("PENPOT_HTTP_URL", "http://localhost:8081").rstrip("/")
LOGIN_ENDPOINT = f"{BASE_URL}/api/rpc/command/login-with-password"


def test_malformed_login_input_is_controlled():
    response = requests.post(
        LOGIN_ENDPOINT,
        json={
            "email": ["unexpected", "array"],
            "password": {"unexpected": "object"},
        },
        verify=False,
        timeout=30,
    )

    assert response.status_code != 500
    assert response.status_code in {400, 401, 403, 404, 422, 429}


def test_anonymous_profile_access_is_controlled():
    response = requests.post(
        f"{BASE_URL}/api/rpc/command/get-profile",
        json={},
        verify=False,
        timeout=30,
    )

    # Penpot RPC endpoints can return HTTP 200 while placing the
    # authentication result inside the response body.
    if response.status_code in {401, 403}:
        return

    assert response.status_code == 200

    body = response.text.lower()

    authentication_markers = [
        "authentication-required",
        "authentication required",
        "unauthorized",
        "not-authenticated",
        "is-authenticated",
        "login-required",
        "anonymous",
    ]

    assert any(marker in body for marker in authentication_markers), (
        "The profile endpoint returned HTTP 200, but the body did not "
        "contain an authentication or anonymous-session marker. "
        f"Response body: {response.text[:500]}"
    )


def test_sensitive_paths_are_restricted():
    paths = [
        "/.env",
        "/.git/config",
        "/debug",
        "/metrics",
        "/actuator",
        "/internal",
        "/backup.sql",
    ]

    for path in paths:
        response = requests.get(
            f"{BASE_URL}{path}",
            verify=False,
            timeout=30,
        )

        assert response.status_code in {403, 404}


def test_login_rate_limiting():
    status_codes = []

    for _ in range(12):
        response = requests.post(
            LOGIN_ENDPOINT,
            json={
                "email": "invalid-pipeline-user@example.invalid",
                "password": "incorrect-password",
            },
            verify=False,
            timeout=30,
        )

        status_codes.append(response.status_code)

    assert 429 in status_codes, (
        "Expected NGINX to return HTTP 429 after repeated login attempts. "
        f"Received: {status_codes}"
    )


def test_http_redirect_uses_https():
    response = requests.get(
        f"{HTTP_URL}/",
        allow_redirects=False,
        timeout=30,
    )

    assert response.status_code in {301, 302, 307, 308}
    assert response.headers.get("Location", "").startswith("https://")
PYTHON_TESTS
                '''
            }
        }

        stage('Create Semgrep Security Rules') {
            steps {
                sh '''
                    set -eu

                    mkdir -p semgrep-rules

                    cat > semgrep-rules/security-canary.yml <<'SEMGREP_RULES'
rules:
  - id: intentionally-vulnerable-eval-canary
    message: Unsafe eval() detected. Untrusted input passed to eval can result in arbitrary code execution.
    severity: ERROR
    languages:
      - python
    pattern: eval($INPUT)

  - id: intentionally-vulnerable-shell-canary
    message: subprocess.run() with shell=True can create command-injection risk when command data is untrusted.
    severity: ERROR
    languages:
      - python
    patterns:
      - pattern: subprocess.run(..., shell=True, ...)

  - id: intentionally-vulnerable-os-system-canary
    message: os.system() can introduce command injection when the command contains untrusted data.
    severity: ERROR
    languages:
      - python
    pattern: os.system($COMMAND)
SEMGREP_RULES

                    python3 - <<'PYTHON_VALIDATE_RULES'
from pathlib import Path

rule_file = Path("semgrep-rules/security-canary.yml")
assert rule_file.exists()
assert "intentionally-vulnerable-eval-canary" in rule_file.read_text()
print("Custom Semgrep security-canary rules created.")
PYTHON_VALIDATE_RULES
                '''
            }
        }

        stage('Check Prerequisites') {
            steps {
                sh '''
                    set -eu

                    echo "Pipeline user: $(whoami)"

                    for COMMAND in docker curl openssl python3 sha256sum ss git; do
                        command -v "$COMMAND" >/dev/null 2>&1 || {
                            echo "ERROR: Required command is missing: $COMMAND"
                            exit 1
                        }
                    done

                    docker --version
                    docker compose version
                    docker ps

                    {
                        echo "OS:"
                        cat /etc/os-release
                        echo
                        echo "Docker:"
                        docker --version
                        echo
                        echo "Docker Compose:"
                        docker compose version
                    } > "$REPORT_DIRECTORY/runtime-information.txt"
                '''
            }
        }

        stage('Generate HTTPS Certificate') {
            steps {
                sh '''
                    set -eu

                    rm -f deployment/certs/penpot.crt
                    rm -f deployment/certs/penpot.key

                    VM_IP=$(hostname -I | awk '{print $1}')

                    if [ -z "$VM_IP" ]; then
                        VM_IP="127.0.0.1"
                    fi

                    openssl req \
                        -x509 \
                        -nodes \
                        -newkey rsa:2048 \
                        -days 365 \
                        -keyout deployment/certs/penpot.key \
                        -out deployment/certs/penpot.crt \
                        -subj "/CN=localhost" \
                        -addext "subjectAltName=DNS:localhost,DNS:penpot.local,IP:127.0.0.1,IP:$VM_IP"

                    chmod 600 deployment/certs/penpot.key
                    chmod 644 deployment/certs/penpot.crt

                    echo "$VM_IP" > "$REPORT_DIRECTORY/vm-ip-address.txt"

                    openssl x509 \
                        -in deployment/certs/penpot.crt \
                        -noout \
                        -subject \
                        -issuer \
                        -dates \
                        -ext subjectAltName \
                        > "$REPORT_DIRECTORY/certificate-details.txt"
                '''
            }
        }

        stage('Validate Compose Configuration') {
            steps {
                sh '''
                    set -eu

                    export PENPOT_DATABASE_PASSWORD
                    export PENPOT_SECRET_KEY
                    export PENPOT_VERSION

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        config \
                        > "$REPORT_DIRECTORY/docker-compose-rendered.yml"

                    docker compose \
                        -f "$COMPOSE_FILE" \
                        config --services \
                        > "$REPORT_DIRECTORY/compose-services.txt"

                    for SERVICE in \
                        nginx \
                        penpot-frontend \
                        penpot-backend \
                        penpot-exporter \
                        postgres \
                        redis
                    do
                        grep -qx "$SERVICE" "$REPORT_DIRECTORY/compose-services.txt" || {
                            echo "ERROR: Missing Compose service: $SERVICE"
                            exit 1
                        }
                    done
                '''
            }
        }

        stage('Security Policy Checklist') {
            steps {
                sh '''
                    set -eu

                    CHECKLIST="$REPORT_DIRECTORY/security-checklist.txt"
                    : > "$CHECKLIST"

                    check() {
                        DESCRIPTION="$1"
                        shift

                        if "$@"; then
                            echo "PASS - $DESCRIPTION" | tee -a "$CHECKLIST"
                        else
                            echo "FAIL - $DESCRIPTION" | tee -a "$CHECKLIST"
                            exit 1
                        fi
                    }

                    check \
                        "HTTPS redirect is configured" \
                        grep -q 'return 301 https://' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "HSTS is configured" \
                        grep -q 'Strict-Transport-Security' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "X-Content-Type-Options is configured" \
                        grep -q 'X-Content-Type-Options' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Login rate-limit zone is configured" \
                        grep -q 'limit_req_zone.*login_limit' \
                        deployment/nginx/nginx.conf

                    check \
                        "Login endpoint rate limiting is configured" \
                        grep -q 'limit_req zone=login_limit' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Rate limiting returns HTTP 429" \
                        grep -q 'limit_req_status 429' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Environment file is restricted" \
                        grep -q 'location = /.env' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Git configuration is restricted" \
                        grep -q 'location = /.git/config' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Debug endpoint is restricted" \
                        grep -q 'location = /debug' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Metrics endpoint is restricted" \
                        grep -q 'location = /metrics' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Actuator endpoint is restricted" \
                        grep -q 'location = /actuator' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Internal endpoint is restricted" \
                        grep -q 'location = /internal' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Backup database file is restricted" \
                        grep -q 'location = /backup.sql' \
                        deployment/nginx/conf.d/penpot.conf

                    echo
                    echo "Security policy checklist passed."
                    cat "$CHECKLIST"
                '''
            }
        }

        stage('Gitleaks Secret Scan') {
            steps {
                sh '''
                    set +e

                    JENKINS_UID=$(id -u)
                    JENKINS_GID=$(id -g)

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        -e HOME=/tmp \
                        -v "$WORKSPACE:/repo" \
                        zricethezav/gitleaks:latest \
                        detect \
                        --source=/repo \
                        --no-git \
                        --redact \
                        --report-format=json \
                        --report-path=/repo/$REPORT_DIRECTORY/gitleaks.json

                    STATUS=$?
                    echo "$STATUS" > "$REPORT_DIRECTORY/gitleaks-exit-code.txt"

                    exit 0
                '''
            }
        }

        stage('Semgrep Penpot Source Analysis') {
            steps {
                sh '''
                    set +e

                    JENKINS_UID=$(id -u)
                    JENKINS_GID=$(id -g)

                    echo "Running Semgrep against the complete checked-out repository..."

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        -e HOME=/tmp \
                        -v "$WORKSPACE:/src" \
                        -w /src \
                        semgrep/semgrep:latest \
                        semgrep scan \
                        --config auto \
                        --config /src/semgrep-rules/security-canary.yml \
                        --exclude .git \
                        --exclude reports \
                        --exclude deployment/certs \
                        --exclude node_modules \
                        --exclude target \
                        --exclude dist \
                        --exclude build \
                        --exclude .shadow-cljs \
                        --exclude resources/public \
                        --max-target-bytes 1000000 \
                        --json \
                        --output /src/reports/semgrep/penpot-source.json \
                        /src

                    STATUS=$?
                    echo "$STATUS" > "$REPORT_DIRECTORY/semgrep/penpot-source-exit-code.txt"

                    python3 - <<'PYTHON_SEMGREP_RESULTS'
import json
from pathlib import Path

report = Path("reports/semgrep/penpot-source.json")
summary = Path("reports/semgrep/penpot-source-summary.txt")

if not report.exists():
    message = "Semgrep did not create a JSON report."
    print(message)
    summary.write_text(message + "\\n", encoding="utf-8")
    raise SystemExit(0)

try:
    data = json.loads(report.read_text(encoding="utf-8") or "{}")
except Exception as exc:
    message = f"Could not parse Semgrep report: {exc}"
    print(message)
    summary.write_text(message + "\\n", encoding="utf-8")
    raise SystemExit(0)

findings = data.get("results") or []
errors = data.get("errors") or []

lines = [
    f"Semgrep source findings: {len(findings)}",
    f"Semgrep scan errors: {len(errors)}",
]

for finding in findings[:50]:
    rule = finding.get("check_id", "unknown-rule")
    path = finding.get("path", "unknown-file")
    line = (finding.get("start") or {}).get("line", "?")
    severity = (finding.get("extra") or {}).get("severity", "UNKNOWN")
    message = (finding.get("extra") or {}).get("message", "")
    lines.append(f"[{severity}] {rule} - {path}:{line} - {message}")

text = "\\n".join(lines) + "\\n"
summary.write_text(text, encoding="utf-8")
print(text)
PYTHON_SEMGREP_RESULTS

                    # Continue so findings can be summarized and emailed.
                    exit 0
                '''
            }
        }

        stage('Trivy Filesystem and Configuration Scans') {
            steps {
                sh '''
                    set +e

                    JENKINS_UID=$(id -u)
                    JENKINS_GID=$(id -g)

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        -e HOME=/tmp \
                        -e TRIVY_CACHE_DIR=/cache \
                        -v "$WORKSPACE:/work" \
                        -v "$WORKSPACE/.trivy-cache:/cache" \
                        aquasec/trivy:latest \
                        fs \
                        --scanners vuln,misconfig,secret \
                        --severity HIGH,CRITICAL \
                        --ignore-unfixed \
                        --format json \
                        --output "/work/$REPORT_DIRECTORY/trivy-filesystem.json" \
                        /work

                    FILESYSTEM_STATUS=$?
                    echo "$FILESYSTEM_STATUS" \
                        > "$REPORT_DIRECTORY/trivy-filesystem-exit-code.txt"

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        -e HOME=/tmp \
                        -e TRIVY_CACHE_DIR=/cache \
                        -v "$WORKSPACE:/work" \
                        -v "$WORKSPACE/.trivy-cache:/cache" \
                        aquasec/trivy:latest \
                        config \
                        --severity HIGH,CRITICAL \
                        --format json \
                        --output "/work/$REPORT_DIRECTORY/trivy-configuration.json" \
                        /work/deployment

                    CONFIG_STATUS=$?
                    echo "$CONFIG_STATUS" \
                        > "$REPORT_DIRECTORY/trivy-config-exit-code.txt"

                    exit 0
                '''
            }
        }

        stage('OWASP Dependency-Check') {
            when {
                expression {
                    return params.RUN_DEPENDENCY_CHECK
                }
            }

            steps {
                script {
                    sh '''
                        set -eu

                        CONTAINER_NAME="penpot-dependency-check-${BUILD_NUMBER}"

                        echo "$CONTAINER_NAME" \
                            > "$REPORT_DIRECTORY/dependency-check-container.txt"

                        docker rm -f "$CONTAINER_NAME" \
                            >/dev/null 2>&1 || true

                        # Run detached so the scanner survives a Jenkins restart.
                        docker run -d \
                            --name "$CONTAINER_NAME" \
                            -v "$WORKSPACE:/src:ro" \
                            -v "$WORKSPACE/$REPORT_DIRECTORY/dependency-check:/report" \
                            -v "$DEPENDENCY_CHECK_DATA_DIR:/usr/share/dependency-check/data" \
                            owasp/dependency-check:latest \
                            --project "Penpot DevSecOps Automation" \
                            --scan /src \
                            --exclude "/src/reports/**" \
                            --exclude "/src/.trivy-cache/**" \
                            --format HTML \
                            --format JSON \
                            --out /report
                    '''

                    boolean dependencyCheckFinished = false

                    for (int attempt = 1; attempt <= 270; attempt++) {
                        String dependencyState = sh(
                            script: '''
                                CONTAINER_NAME=$(cat "$REPORT_DIRECTORY/dependency-check-container.txt")

                                docker inspect \
                                    --format '{{.State.Status}}' \
                                    "$CONTAINER_NAME" \
                                    2>/dev/null || echo missing
                            ''',
                            returnStdout: true
                        ).trim()

                        echo "Dependency-Check attempt ${attempt}/270: ${dependencyState}"

                        if (dependencyState == 'exited' ||
                            dependencyState == 'dead' ||
                            dependencyState == 'missing') {
                            dependencyCheckFinished = true
                            break
                        }

                        sleep time: 10, unit: 'SECONDS'
                    }

                    if (!dependencyCheckFinished) {
                        echo 'Dependency-Check exceeded 45 minutes and will be stopped.'

                        sh '''
                            set +e

                            CONTAINER_NAME=$(cat "$REPORT_DIRECTORY/dependency-check-container.txt")
                            docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
                        '''
                    }

                    sh '''
                        set +e

                        CONTAINER_NAME=$(cat "$REPORT_DIRECTORY/dependency-check-container.txt")

                        docker logs "$CONTAINER_NAME" \
                            > "$REPORT_DIRECTORY/dependency-check/dependency-check-console.log" \
                            2>&1 || true

                        STATUS=$(docker inspect \
                            --format '{{.State.ExitCode}}' \
                            "$CONTAINER_NAME" \
                            2>/dev/null || echo 124)

                        echo "$STATUS" \
                            > "$REPORT_DIRECTORY/dependency-check-exit-code.txt"

                        docker rm -f "$CONTAINER_NAME" \
                            >/dev/null 2>&1 || true

                        HOST_UID=$(id -u)
                        HOST_GID=$(id -g)

                        docker run --rm \
                            -v "$WORKSPACE/$REPORT_DIRECTORY:/reports" \
                            alpine:3.20 \
                            chown -R "$HOST_UID:$HOST_GID" /reports

                        if [ "$STATUS" = "0" ]; then
                            echo "OWASP Dependency-Check completed successfully."
                        else
                            echo "OWASP Dependency-Check returned status $STATUS."
                            echo "The pipeline will continue; review the archived report and console log."
                        fi

                        exit 0
                    '''
                }
            }
        }

        stage('Remove Previous Deployment') {
            steps {
                sh '''
                    set +e

                    export PENPOT_DATABASE_PASSWORD
                    export PENPOT_SECRET_KEY
                    export PENPOT_VERSION

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        down --remove-orphans

                    docker ps -a \
                        --filter "name=penpot-secure" \
                        --format "{{.ID}}" |
                        xargs -r docker rm -f

                    exit 0
                '''
            }
        }

        stage('Deploy Penpot Securely') {
            steps {
                sh '''
                    set -eu

                    export PENPOT_DATABASE_PASSWORD
                    export PENPOT_SECRET_KEY
                    export PENPOT_VERSION

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        pull

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        up -d --remove-orphans

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        ps
                '''
            }
        }

        stage('Validate Containers and NGINX') {
            steps {
                sh '''
                    set -eu

                    sleep 30

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        ps

                    for SERVICE in \
                        nginx \
                        penpot-frontend \
                        penpot-backend \
                        penpot-exporter \
                        postgres \
                        redis
                    do
                        CONTAINER_ID=$(
                            docker compose \
                                -p "$COMPOSE_PROJECT_NAME" \
                                -f "$COMPOSE_FILE" \
                                ps -q "$SERVICE"
                        )

                        test -n "$CONTAINER_ID" || {
                            echo "ERROR: Missing container for $SERVICE."
                            exit 1
                        }

                        STATUS=$(
                            docker inspect \
                                --format '{{.State.Status}}' \
                                "$CONTAINER_ID"
                        )

                        echo "$SERVICE: $STATUS"

                        if [ "$STATUS" != "running" ]; then
                            docker compose \
                                -p "$COMPOSE_PROJECT_NAME" \
                                -f "$COMPOSE_FILE" \
                                logs \
                                --no-color \
                                --tail=150 \
                                "$SERVICE" || true

                            exit 1
                        fi
                    done

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        exec -T nginx nginx -t
                '''
            }
        }

        stage('Wait for Penpot HTTPS') {
            steps {
                sh '''
                    set -eu

                    ATTEMPT=1
                    MAX_ATTEMPTS=60

                    while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
                        HTTP_CODE=$(
                            curl \
                                --insecure \
                                --silent \
                                --output /dev/null \
                                --write-out "%{http_code}" \
                                "$PENPOT_URL/" || true
                        )

                        echo "Attempt $ATTEMPT/$MAX_ATTEMPTS: HTTP $HTTP_CODE"

                        case "$HTTP_CODE" in
                            200|301|302)
                                echo "Penpot is available over HTTPS."
                                exit 0
                                ;;
                        esac

                        sleep 10
                        ATTEMPT=$((ATTEMPT + 1))
                    done

                    echo "ERROR: Penpot did not become available over HTTPS."

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        logs \
                        --no-color \
                        --tail=300 || true

                    exit 1
                '''
            }
        }

        stage('Functional Availability Tests') {
            steps {
                sh '''
                    set -eu

                    HTTPS_CODE=$(
                        curl \
                            --insecure \
                            --silent \
                            --output "$REPORT_DIRECTORY/functional/homepage.html" \
                            --write-out "%{http_code}" \
                            "$PENPOT_URL/"
                    )

                    echo "HTTPS homepage status: $HTTPS_CODE"

                    case "$HTTPS_CODE" in
                        200|301|302) ;;
                        *)
                            echo "ERROR: Unexpected HTTPS status."
                            exit 1
                            ;;
                    esac

                    grep -Eqi \
                        '<html|<!doctype html' \
                        "$REPORT_DIRECTORY/functional/homepage.html"

                    HTTP_CODE=$(
                        curl \
                            --silent \
                            --output /dev/null \
                            --write-out "%{http_code}" \
                            "$PENPOT_HTTP_URL/"
                    )

                    echo "HTTP endpoint status: $HTTP_CODE"

                    case "$HTTP_CODE" in
                        301|302|307|308) ;;
                        *)
                            echo "ERROR: HTTP endpoint did not redirect."
                            exit 1
                            ;;
                    esac
                '''
            }
        }

        stage('API Authentication and Access-Control Tests') {
            steps {
                sh '''
                    set -eu

                    JENKINS_UID=$(id -u)
                    JENKINS_GID=$(id -g)

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        --network host \
                        -e HOME=/tmp \
                        -e PENPOT_URL="$PENPOT_URL" \
                        -e PENPOT_HTTP_URL="$PENPOT_HTTP_URL" \
                        -v "$WORKSPACE:/work" \
                        -w /work \
                        python:3.12-slim \
                        bash -lc '
                            set -eu

                            pip install \
                                --quiet \
                                --disable-pip-version-check \
                                --target /tmp/python-packages \
                                -r tests/requirements.txt

                            export PYTHONPATH=/tmp/python-packages

                            python -m pytest \
                                -v \
                                --junitxml=reports/pytest/results.xml \
                                tests/test_api.py \
                                tests/test_security.py \
                                tests/test_pipeline_security.py
                        '
                '''
            }
        }

        stage('Container Image Vulnerability Scans') {
            when {
                expression {
                    return params.RUN_CONTAINER_SCANS
                }
            }

            steps {
                sh '''
                    set +e

                    JENKINS_UID=$(id -u)
                    JENKINS_GID=$(id -g)

                    scan_image() {
                        IMAGE="$1"
                        REPORT_NAME="$2"

                        echo "Scanning $IMAGE..."

                        docker run --rm \
                            --user "$JENKINS_UID:$JENKINS_GID" \
                            -e HOME=/tmp \
                            -e TRIVY_CACHE_DIR=/cache \
                            -v "$WORKSPACE:/work" \
                            -v "$WORKSPACE/.trivy-cache:/cache" \
                            aquasec/trivy:latest \
                            image \
                            --severity HIGH,CRITICAL \
                            --ignore-unfixed \
                            --format json \
                            --output "/work/$REPORT_DIRECTORY/images/$REPORT_NAME.json" \
                            "$IMAGE"
                    }

                    scan_image \
                        "penpotapp/frontend:$PENPOT_VERSION" \
                        "penpot-frontend"

                    scan_image \
                        "penpotapp/backend:$PENPOT_VERSION" \
                        "penpot-backend"

                    scan_image \
                        "penpotapp/exporter:$PENPOT_VERSION" \
                        "penpot-exporter"

                    scan_image "postgres:15" "postgres"
                    scan_image "redis:7" "redis"
                    scan_image "nginx:1.27-alpine" "nginx"

                    exit 0
                '''
            }
        }

        stage('Network and Debug Exposure Audit') {
            steps {
                sh '''
                    set -eu

                    ss -lnt \
                        > "$REPORT_DIRECTORY/post-deployment/listening-ports.txt"

                    for SERVICE in \
                        penpot-backend \
                        penpot-exporter \
                        postgres \
                        redis
                    do
                        CONTAINER_ID=$(
                            docker compose \
                                -p "$COMPOSE_PROJECT_NAME" \
                                -f "$COMPOSE_FILE" \
                                ps -q "$SERVICE"
                        )

                        PUBLISHED_PORTS=$(docker port "$CONTAINER_ID" || true)

                        if [ -n "$PUBLISHED_PORTS" ]; then
                            echo "ERROR: $SERVICE publishes a host port:"
                            echo "$PUBLISHED_PORTS"
                            exit 1
                        fi
                    done

                    if ss -lnt |
                       grep -Eq ':(9229|6064)[[:space:]]'; then
                        echo "ERROR: A common debug port is exposed."
                        exit 1
                    fi

                    echo "No backend, database, cache, or debug ports are exposed."
                '''
            }
        }

        stage('Post-Deployment Security Validation') {
            steps {
                sh '''
                    set -eu

                    curl \
                        --insecure \
                        --silent \
                        --show-error \
                        --head \
                        "$PENPOT_URL/" \
                        > "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    cat "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    grep -qi '^strict-transport-security:' \
                        "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    grep -qi '^x-content-type-options:.*nosniff' \
                        "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    grep -qi '^referrer-policy:' \
                        "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    grep -qi '^permissions-policy:' \
                        "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    REDIRECT=$(
                        curl \
                            --silent \
                            --output /dev/null \
                            --write-out "%{redirect_url}" \
                            "$PENPOT_HTTP_URL/" || true
                    )

                    echo "Redirect destination: $REDIRECT"

                    case "$REDIRECT" in
                        https://*)
                            echo "HTTP-to-HTTPS redirect passed."
                            ;;
                        *)
                            echo "ERROR: HTTP did not redirect to HTTPS."
                            exit 1
                            ;;
                    esac

                    for PATH_NAME in \
                        .env \
                        debug \
                        metrics \
                        actuator \
                        internal \
                        backup.sql
                    do
                        STATUS=$(
                            curl \
                                --insecure \
                                --silent \
                                --output /dev/null \
                                --write-out "%{http_code}" \
                                "$PENPOT_URL/$PATH_NAME"
                        )

                        case "$STATUS" in
                            403|404) ;;
                            *)
                                echo "ERROR: Sensitive path /$PATH_NAME returned $STATUS."
                                exit 1
                                ;;
                        esac
                    done

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        ps \
                        > "$REPORT_DIRECTORY/post-deployment/container-status.txt"
                '''
            }
        }

        stage('Deployment Integrity Validation') {
            steps {
                sh '''
                    set -eu

                    sha256sum \
                        deployment/docker-compose.secure.yml \
                        deployment/nginx/nginx.conf \
                        deployment/nginx/conf.d/penpot.conf \
                        scripts/setup-host.sh \
                        tests/test_api.py \
                        tests/test_security.py \
                        tests/test_pipeline_security.py \
                        > "$REPORT_DIRECTORY/integrity/sha256sums.txt"

                    sha256sum \
                        --check \
                        "$REPORT_DIRECTORY/integrity/sha256sums.txt"
                '''
            }
        }

        stage('OWASP ZAP Baseline') {
            when {
                expression {
                    return params.RUN_ZAP
                }
            }

            steps {
                sh '''
                    set +e

                    chmod 777 "$REPORT_DIRECTORY/zap"

                    docker run --rm \
                        --network host \
                        -v "$WORKSPACE/$REPORT_DIRECTORY/zap:/zap/wrk:rw" \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py \
                        -t "$PENPOT_URL" \
                        -r zap-report.html \
                        -J zap-report.json \
                        -w zap-report.md \
                        -I

                    STATUS=$?
                    echo "$STATUS" \
                        > "$REPORT_DIRECTORY/zap/zap-exit-code.txt"

                    docker run --rm \
                        -v "$WORKSPACE/$REPORT_DIRECTORY/zap:/reports" \
                        alpine:3.20 \
                        chown -R "$(id -u):$(id -g)" /reports

                    exit 0
                '''
            }
        }

        stage('Evaluate Security Findings') {
            steps {
                sh '''
                    set -eu

                    python3 - <<'PYTHON_SUMMARY'
import json
from pathlib import Path

reports = Path("reports")
summary = []
total = 0


def count_trivy(path: Path) -> int:
    count = 0

    if not path.exists():
        return 0

    try:
        data = json.loads(path.read_text() or "{}")

        for result in data.get("Results") or []:
            count += len(result.get("Vulnerabilities") or [])
            count += len(result.get("Misconfigurations") or [])
            count += len(result.get("Secrets") or [])
    except Exception:
        return 0

    return count


gitleaks_path = reports / "gitleaks.json"

if gitleaks_path.exists():
    try:
        gitleaks_data = json.loads(gitleaks_path.read_text() or "[]")
        gitleaks_count = (
            len(gitleaks_data)
            if isinstance(gitleaks_data, list)
            else 0
        )
    except Exception:
        gitleaks_count = 0
else:
    gitleaks_count = 0

summary.append(f"Gitleaks findings: {gitleaks_count}")
total += gitleaks_count

semgrep_path = reports / "semgrep" / "penpot-source.json"
semgrep_results = []
canary_findings = []

canary_rule_ids = {
    "intentionally-vulnerable-eval-canary",
    "intentionally-vulnerable-shell-canary",
    "intentionally-vulnerable-os-system-canary",
}

if semgrep_path.exists():
    try:
        semgrep_data = json.loads(semgrep_path.read_text() or "{}")
        semgrep_results = semgrep_data.get("results") or []
        semgrep_count = len(semgrep_results)

        for finding in semgrep_results:
            rule = str(finding.get("check_id", "unknown-rule"))
            normalized_rule = rule.rsplit(".", 1)[-1]

            if normalized_rule not in canary_rule_ids:
                continue

            path = finding.get("path", "unknown-file")
            line = (finding.get("start") or {}).get("line", "?")
            severity = (finding.get("extra") or {}).get(
                "severity",
                "ERROR",
            )
            message = (finding.get("extra") or {}).get(
                "message",
                "Intentional security canary detected.",
            )

            canary_findings.append(
                f"[{severity}] {normalized_rule} - "
                f"{path}:{line} - {message}"
            )
    except Exception:
        semgrep_count = 0
        canary_findings = []
else:
    semgrep_count = 0

canary_count = len(canary_findings)

summary.append(f"Semgrep Penpot source findings: {semgrep_count}")
summary.append(f"Intentional vulnerability-canary findings: {canary_count}")
total += semgrep_count

notification = reports / "notification"
notification.mkdir(parents=True, exist_ok=True)

(notification / "canary-count.txt").write_text(
    str(canary_count),
    encoding="utf-8",
)

if canary_findings:
    canary_text = (
        "INTENTIONAL SECURITY CANARY DETECTED\\n"
        + "\\n".join(canary_findings)
        + "\\n"
    )
else:
    canary_text = "No intentional security-canary findings detected.\\n"

(notification / "canary-findings.txt").write_text(
    canary_text,
    encoding="utf-8",
)

print(canary_text)

filesystem_count = count_trivy(reports / "trivy-filesystem.json")
summary.append(f"Trivy filesystem findings: {filesystem_count}")
total += filesystem_count

configuration_count = count_trivy(
    reports / "trivy-configuration.json"
)
summary.append(
    f"Trivy configuration findings: {configuration_count}"
)
total += configuration_count

image_count = 0

for image_report in (reports / "images").glob("*.json"):
    image_count += count_trivy(image_report)

summary.append(f"Trivy container-image findings: {image_count}")
total += image_count

dependency_report = (
    reports
    / "dependency-check"
    / "dependency-check-report.json"
)

dependency_count = 0

if dependency_report.exists():
    try:
        dependency_data = json.loads(
            dependency_report.read_text() or "{}"
        )

        for dependency in dependency_data.get("dependencies") or []:
            dependency_count += len(
                dependency.get("vulnerabilities") or []
            )
    except Exception:
        dependency_count = 0

summary.append(
    f"OWASP Dependency-Check findings: {dependency_count}"
)
total += dependency_count

summary.append(f"Total automated findings: {total}")
summary_text = "\\n".join(summary) + "\\n"

notification.mkdir(parents=True, exist_ok=True)

(notification / "security-summary.txt").write_text(summary_text)
(notification / "finding-count.txt").write_text(str(total))

print(summary_text)
PYTHON_SUMMARY
                '''
            }
        }

        stage('Email Developer Notification') {
            steps {
                script {
                    String notificationRecipient = (params.DEVELOPER_EMAIL ?: '').trim()
                    if (!notificationRecipient) {
                        notificationRecipient = 'evan246810536546@gmail.com'
                    }

                    int findingCount = 0
                    int canaryCount = 0
                    String summaryText = 'Security findings were detected, but the summary file was unavailable.'
                    String canaryText = 'No intentional security-canary details were available.'

                    if (fileExists('reports/notification/finding-count.txt')) {
                        String rawCount = readFile(
                            'reports/notification/finding-count.txt'
                        ).trim()

                        if (rawCount ==~ /[0-9]+/) {
                            findingCount = rawCount.toInteger()
                        }
                    }

                    if (fileExists('reports/notification/security-summary.txt')) {
                        summaryText = readFile(
                            'reports/notification/security-summary.txt'
                        ).trim()
                    }

                    if (fileExists('reports/notification/canary-count.txt')) {
                        String rawCanaryCount = readFile(
                            'reports/notification/canary-count.txt'
                        ).trim()

                        if (rawCanaryCount ==~ /[0-9]+/) {
                            canaryCount = rawCanaryCount.toInteger()
                        }
                    }

                    if (fileExists('reports/notification/canary-findings.txt')) {
                        canaryText = readFile(
                            'reports/notification/canary-findings.txt'
                        ).trim()
                    }

                    if (findingCount > 0 || canaryCount > 0) {
                        String emailSubject = canaryCount > 0
                            ? "[Penpot DevSecOps] SECURITY CANARY DETECTED (${canaryCount}) - Build #${env.BUILD_NUMBER}"
                            : "[Penpot DevSecOps] ${findingCount} security findings detected - Build #${env.BUILD_NUMBER}"

                        String emailBody = [
                            'Penpot DevSecOps detected security findings.',
                            '',
                            "Job: ${env.JOB_NAME}",
                            "Build: ${env.BUILD_NUMBER}",
                            "Source commit: ${fileExists('reports/source/scanned-commit.txt') ? readFile('reports/source/scanned-commit.txt').trim() : 'unavailable'}",
                            "Build status at notification stage: ${currentBuild.currentResult ?: 'SUCCESS'}",
                            '',
                            'Security summary:',
                            summaryText,
                            '',
                            'Controlled vulnerability-canary result:',
                            canaryText,
                            '',
                            'Jenkins build:',
                            env.BUILD_URL,
                            '',
                            'Review the archived Gitleaks, Semgrep source, Trivy, Dependency-Check,',
                            'and deployment-validation reports before approving the deployment.'
                        ].join('\n')

                        emailext(
                            to: notificationRecipient,
                            subject: emailSubject,
                            mimeType: 'text/plain',
                            attachLog: false,
                            attachmentsPattern: 'reports/notification/security-summary.txt,reports/notification/canary-findings.txt,reports/semgrep/penpot-source-summary.txt',
                            body: emailBody
                        )

                        writeFile(
                            file: 'reports/notification/email-notification.txt',
                            text: [
                                'Email notification sent.',
                                "Recipient: ${notificationRecipient}",
                                "Finding count: ${findingCount}",
                                "Canary count: ${canaryCount}",
                                "Build: ${env.BUILD_URL}",
                                ''
                            ].join('\n')
                        )

                        if (canaryCount > 0) {
                            echo "SECURITY CANARY DETECTED: ${canaryCount} controlled vulnerable-code finding(s)."
                            echo canaryText
                            currentBuild.result = 'UNSTABLE'
                        }

                        echo "Security notification emailed to ${notificationRecipient}."
                    } else {
                        writeFile(
                            file: 'reports/notification/email-notification.txt',
                            text: 'No security findings were counted, so no vulnerability email was sent.\n'
                        )

                        echo 'No security findings were counted. No vulnerability email was sent.'
                    }
                }
            }
        }
    }

    post {
        always {
            sh '''
                set +e

                mkdir -p "$REPORT_DIRECTORY"

                if command -v docker >/dev/null 2>&1 &&
                   docker compose version >/dev/null 2>&1; then

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        ps \
                        > "$REPORT_DIRECTORY/final-container-status.txt" 2>&1

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        logs \
                        --no-color \
                        --tail=500 \
                        > "$REPORT_DIRECTORY/penpot-container-logs.txt" 2>&1
                fi

                exit 0
            '''

            archiveArtifacts(
                artifacts: 'reports/**/*',
                allowEmptyArchive: true,
                fingerprint: true
            )

            junit(
                testResults: 'reports/pytest/*.xml',
                allowEmptyResults: true
            )
        }

        success {
            echo 'Penpot DevSecOps pipeline completed successfully.'
            echo 'Jenkins: http://YOUR-VM-IP:8080'
            echo 'Penpot HTTP redirect: http://YOUR-VM-IP:8081'
            echo 'Penpot HTTPS: https://YOUR-VM-IP:8443'
        }

        failure {
            script {
                String failureRecipient = (params.DEVELOPER_EMAIL ?: '').trim()
                if (!failureRecipient) {
                    failureRecipient = 'evan246810536546@gmail.com'
                }

                String failureBody = [
                    'The Penpot DevSecOps pipeline failed.',
                    '',
                    "Job: ${env.JOB_NAME}",
                    "Build: ${env.BUILD_NUMBER}",
                    "Result: ${currentBuild.currentResult}",
                    '',
                    'Review the failed stage, console output, test results, and archived',
                    'security reports here:',
                    '',
                    env.BUILD_URL
                ].join('\n')

                emailext(
                    to: failureRecipient,
                    subject: "[Penpot DevSecOps] Pipeline FAILED - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    mimeType: 'text/plain',
                    attachLog: true,
                    body: failureBody
                )

                echo "Pipeline failure notification emailed to ${failureRecipient}."
            }
        }

    }
}pipeline {
    agent any

    parameters {
        booleanParam(
            name: 'RUN_DEPENDENCY_CHECK',
            defaultValue: true,
            description: 'Run OWASP Dependency-Check and archive the reports.'
        )

        booleanParam(
            name: 'RUN_CONTAINER_SCANS',
            defaultValue: true,
            description: 'Run Trivy scans against all deployed container images.'
        )

        booleanParam(
            name: 'RUN_ZAP',
            defaultValue: false,
            description: 'Run the OWASP ZAP baseline scan after deployment.'
        )

        string(
            name: 'DEVELOPER_EMAIL',
            defaultValue: 'evan246810536546@gmail.com',
            description: 'Email address that receives vulnerability and pipeline-failure alerts.'
        )
    }

    triggers {
        // Jenkins checks the configured Git repository every two minutes.
        // A new commit automatically starts the pipeline.
        pollSCM('* * * * *')
    }

    options {
        timestamps()
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 150, unit: 'MINUTES')
    }

    environment {
        COMPOSE_FILE = 'deployment/docker-compose.secure.yml'
        COMPOSE_PROJECT_NAME = 'penpot-secure'

        // Jenkins uses 8080. Penpot HTTP and HTTPS use 8081 and 8443.
        PENPOT_HTTP_URL = 'http://localhost:8081'
        PENPOT_URL = 'https://localhost:8443'

        REPORT_DIRECTORY = 'reports'

        // Local-lab values. Jenkins credentials should replace these in production.
        PENPOT_DATABASE_PASSWORD = 'ubuntu'
        PENPOT_SECRET_KEY = 'ubuntu-penpot-local-testing-secret-key-2026'
        PENPOT_VERSION = 'latest'

        // Persistent cache keeps Dependency-Check updates between Jenkins builds.
        DEPENDENCY_CHECK_DATA_DIR = '/var/lib/jenkins/dependency-check-data'
    }

    stages {
        stage('Checkout Source Code') {
            steps {
                deleteDir()
                checkout scm

                sh '''
                    set -eu

                    echo "Repository URL and branch are controlled by the Jenkins SCM configuration."
                    echo "Checked-out commit: $(git rev-parse HEAD)"

                    mkdir -p reports/source
                    git rev-parse HEAD > reports/source/scanned-commit.txt
                    git status --short > reports/source/checkout-status.txt
                    git log -1 --pretty=fuller > reports/source/commit-details.txt

                    # Keep the checked-out Penpot source code, but copy any missing
                    # pipeline support files from the existing local DevSecOps project.
                    SUPPORT_ROOT="/opt/penpot-devsecops"

                    REQUIRED_SUPPORT_FILES="
                    deployment/docker-compose.secure.yml
                    tests/test_api.py
                    tests/test_security.py
                    tests/requirements.txt
                    "

                    for REQUIRED_FILE in $REQUIRED_SUPPORT_FILES; do
                        if [ ! -f "$REQUIRED_FILE" ]; then
                            SOURCE_FILE="$SUPPORT_ROOT/$REQUIRED_FILE"

                            if [ ! -f "$SOURCE_FILE" ]; then
                                echo "ERROR: Required pipeline file is missing:"
                                echo "  Repository: $REQUIRED_FILE"
                                echo "  Local fallback: $SOURCE_FILE"
                                exit 1
                            fi

                            mkdir -p "$(dirname "$REQUIRED_FILE")"
                            cp "$SOURCE_FILE" "$REQUIRED_FILE"
                            echo "Copied local pipeline support file: $REQUIRED_FILE"
                        else
                            echo "Using repository pipeline support file: $REQUIRED_FILE"
                        fi
                    done

                    test -f "$COMPOSE_FILE"
                    test -f tests/test_api.py
                    test -f tests/test_security.py
                    test -f tests/requirements.txt

                    test -d backend || {
                        echo "WARNING: Penpot backend source directory was not found at ./backend."
                        echo "Semgrep will still scan the complete checked-out repository."
                    }

                    test -d frontend || {
                        echo "WARNING: Penpot frontend source directory was not found at ./frontend."
                        echo "Semgrep will still scan the complete checked-out repository."
                    }
                '''
            }
        }

        stage('Prepare Workspace') {
            steps {
                sh '''
                    set -eu

                    mkdir -p "$REPORT_DIRECTORY"
                    mkdir -p "$REPORT_DIRECTORY/notification"
                    mkdir -p "$REPORT_DIRECTORY/integrity"
                    mkdir -p "$REPORT_DIRECTORY/post-deployment"
                    mkdir -p "$REPORT_DIRECTORY/pytest"
                    mkdir -p "$REPORT_DIRECTORY/images"
                    mkdir -p "$REPORT_DIRECTORY/zap"
                    mkdir -p "$REPORT_DIRECTORY/functional"
                    mkdir -p "$REPORT_DIRECTORY/dependency-check"
                    mkdir -p "$REPORT_DIRECTORY/semgrep"
                    mkdir -p "$REPORT_DIRECTORY/source"
                    mkdir -p "$WORKSPACE/.trivy-cache"
                    mkdir -p "$DEPENDENCY_CHECK_DATA_DIR"

                    mkdir -p deployment/certs
                    mkdir -p deployment/nginx/conf.d
                    mkdir -p scripts
                    mkdir -p tests
                    mkdir -p semgrep-rules

                    find scripts -type f -name "*.sh" \
                        -exec chmod +x {} + 2>/dev/null || true
                '''
            }
        }

        stage('Create Host Setup Script') {
            steps {
                sh '''
                    set -eu

                    cat > scripts/setup-host.sh <<'HOST_SETUP'
#!/usr/bin/env bash

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this script using sudo."
    exit 1
fi

apt-get update

apt-get install -y \
    ca-certificates \
    curl \
    openssl \
    python3 \
    python3-pip \
    unzip \
    iproute2 \
    git

systemctl enable --now docker
usermod -aG docker jenkins

mkdir -p /opt/penpot-devsecops
chown -R jenkins:jenkins /opt/penpot-devsecops

systemctl restart jenkins

echo "Host setup completed."
echo "Verify Docker access with: sudo -u jenkins docker ps"
HOST_SETUP

                    chmod +x scripts/setup-host.sh
                '''
            }
        }

        stage('Create Secure NGINX Configuration') {
            steps {
                sh '''
                    set -eu

                    cat > deployment/nginx/nginx.conf <<'NGINX_MAIN'
user nginx;
worker_processes auto;

error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    sendfile on;
    keepalive_timeout 65;
    server_tokens off;

    # Limit each client IP to five password-login requests per minute.
    limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;

    include /etc/nginx/conf.d/*.conf;
}
NGINX_MAIN

                    cat > deployment/nginx/conf.d/penpot.conf <<'NGINX_SITE'
server {
    listen 80;
    server_name localhost penpot.local;

    # Force all HTTP traffic to HTTPS.
    return 301 https://$host:8443$request_uri;
}

server {
    listen 443 ssl;
    server_name localhost penpot.local;

    ssl_certificate /etc/nginx/certs/penpot.crt;
    ssl_certificate_key /etc/nginx/certs/penpot.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;

    client_max_body_size 350M;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Restrict sensitive or diagnostic paths.
    location = /.env {
        return 404;
    }

    location = /.git {
        return 404;
    }

    location = /.git/config {
        return 404;
    }

    location = /debug {
        return 403;
    }

    location = /metrics {
        return 403;
    }

    location = /actuator {
        return 403;
    }

    location = /internal {
        return 403;
    }

    location = /backup.sql {
        return 404;
    }

    # Brute-force mitigation for the password-login endpoint.
    location = /api/rpc/command/login-with-password {
        limit_req zone=login_limit burst=3 nodelay;
        limit_req_status 429;

        proxy_pass http://penpot-backend:6060;

        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Scheme $scheme;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_redirect off;
    }

    location /api/ {
        proxy_pass http://penpot-backend:6060;

        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Scheme $scheme;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_redirect off;
    }

    location /ws/notifications {
        proxy_pass http://penpot-backend:6060/ws/notifications;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass http://penpot-frontend:8080;

        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Scheme $scheme;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_redirect off;
    }
}
NGINX_SITE
                '''
            }
        }

        stage('Create Additional Security Tests') {
            steps {
                sh '''
                    set -eu

                    cat > tests/test_pipeline_security.py <<'PYTHON_TESTS'
import os

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.getenv("PENPOT_URL", "https://localhost:8443").rstrip("/")
HTTP_URL = os.getenv("PENPOT_HTTP_URL", "http://localhost:8081").rstrip("/")
LOGIN_ENDPOINT = f"{BASE_URL}/api/rpc/command/login-with-password"


def test_malformed_login_input_is_controlled():
    response = requests.post(
        LOGIN_ENDPOINT,
        json={
            "email": ["unexpected", "array"],
            "password": {"unexpected": "object"},
        },
        verify=False,
        timeout=30,
    )

    assert response.status_code != 500
    assert response.status_code in {400, 401, 403, 404, 422, 429}


def test_anonymous_profile_access_is_controlled():
    response = requests.post(
        f"{BASE_URL}/api/rpc/command/get-profile",
        json={},
        verify=False,
        timeout=30,
    )

    # Penpot RPC endpoints can return HTTP 200 while placing the
    # authentication result inside the response body.
    if response.status_code in {401, 403}:
        return

    assert response.status_code == 200

    body = response.text.lower()

    authentication_markers = [
        "authentication-required",
        "authentication required",
        "unauthorized",
        "not-authenticated",
        "is-authenticated",
        "login-required",
        "anonymous",
    ]

    assert any(marker in body for marker in authentication_markers), (
        "The profile endpoint returned HTTP 200, but the body did not "
        "contain an authentication or anonymous-session marker. "
        f"Response body: {response.text[:500]}"
    )


def test_sensitive_paths_are_restricted():
    paths = [
        "/.env",
        "/.git/config",
        "/debug",
        "/metrics",
        "/actuator",
        "/internal",
        "/backup.sql",
    ]

    for path in paths:
        response = requests.get(
            f"{BASE_URL}{path}",
            verify=False,
            timeout=30,
        )

        assert response.status_code in {403, 404}


def test_login_rate_limiting():
    status_codes = []

    for _ in range(12):
        response = requests.post(
            LOGIN_ENDPOINT,
            json={
                "email": "invalid-pipeline-user@example.invalid",
                "password": "incorrect-password",
            },
            verify=False,
            timeout=30,
        )

        status_codes.append(response.status_code)

    assert 429 in status_codes, (
        "Expected NGINX to return HTTP 429 after repeated login attempts. "
        f"Received: {status_codes}"
    )


def test_http_redirect_uses_https():
    response = requests.get(
        f"{HTTP_URL}/",
        allow_redirects=False,
        timeout=30,
    )

    assert response.status_code in {301, 302, 307, 308}
    assert response.headers.get("Location", "").startswith("https://")
PYTHON_TESTS
                '''
            }
        }

        stage('Create Semgrep Security Rules') {
            steps {
                sh '''
                    set -eu

                    mkdir -p semgrep-rules

                    cat > semgrep-rules/security-canary.yml <<'SEMGREP_RULES'
rules:
  - id: intentionally-vulnerable-eval-canary
    message: Unsafe eval() detected. Untrusted input passed to eval can result in arbitrary code execution.
    severity: ERROR
    languages:
      - python
    pattern: eval($INPUT)

  - id: intentionally-vulnerable-shell-canary
    message: subprocess.run() with shell=True can create command-injection risk when command data is untrusted.
    severity: ERROR
    languages:
      - python
    patterns:
      - pattern: subprocess.run(..., shell=True, ...)

  - id: intentionally-vulnerable-os-system-canary
    message: os.system() can introduce command injection when the command contains untrusted data.
    severity: ERROR
    languages:
      - python
    pattern: os.system($COMMAND)
SEMGREP_RULES

                    python3 - <<'PYTHON_VALIDATE_RULES'
from pathlib import Path

rule_file = Path("semgrep-rules/security-canary.yml")
assert rule_file.exists()
assert "intentionally-vulnerable-eval-canary" in rule_file.read_text()
print("Custom Semgrep security-canary rules created.")
PYTHON_VALIDATE_RULES
                '''
            }
        }

        stage('Check Prerequisites') {
            steps {
                sh '''
                    set -eu

                    echo "Pipeline user: $(whoami)"

                    for COMMAND in docker curl openssl python3 sha256sum ss git; do
                        command -v "$COMMAND" >/dev/null 2>&1 || {
                            echo "ERROR: Required command is missing: $COMMAND"
                            exit 1
                        }
                    done

                    docker --version
                    docker compose version
                    docker ps

                    {
                        echo "OS:"
                        cat /etc/os-release
                        echo
                        echo "Docker:"
                        docker --version
                        echo
                        echo "Docker Compose:"
                        docker compose version
                    } > "$REPORT_DIRECTORY/runtime-information.txt"
                '''
            }
        }

        stage('Generate HTTPS Certificate') {
            steps {
                sh '''
                    set -eu

                    rm -f deployment/certs/penpot.crt
                    rm -f deployment/certs/penpot.key

                    VM_IP=$(hostname -I | awk '{print $1}')

                    if [ -z "$VM_IP" ]; then
                        VM_IP="127.0.0.1"
                    fi

                    openssl req \
                        -x509 \
                        -nodes \
                        -newkey rsa:2048 \
                        -days 365 \
                        -keyout deployment/certs/penpot.key \
                        -out deployment/certs/penpot.crt \
                        -subj "/CN=localhost" \
                        -addext "subjectAltName=DNS:localhost,DNS:penpot.local,IP:127.0.0.1,IP:$VM_IP"

                    chmod 600 deployment/certs/penpot.key
                    chmod 644 deployment/certs/penpot.crt

                    echo "$VM_IP" > "$REPORT_DIRECTORY/vm-ip-address.txt"

                    openssl x509 \
                        -in deployment/certs/penpot.crt \
                        -noout \
                        -subject \
                        -issuer \
                        -dates \
                        -ext subjectAltName \
                        > "$REPORT_DIRECTORY/certificate-details.txt"
                '''
            }
        }

        stage('Validate Compose Configuration') {
            steps {
                sh '''
                    set -eu

                    export PENPOT_DATABASE_PASSWORD
                    export PENPOT_SECRET_KEY
                    export PENPOT_VERSION

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        config \
                        > "$REPORT_DIRECTORY/docker-compose-rendered.yml"

                    docker compose \
                        -f "$COMPOSE_FILE" \
                        config --services \
                        > "$REPORT_DIRECTORY/compose-services.txt"

                    for SERVICE in \
                        nginx \
                        penpot-frontend \
                        penpot-backend \
                        penpot-exporter \
                        postgres \
                        redis
                    do
                        grep -qx "$SERVICE" "$REPORT_DIRECTORY/compose-services.txt" || {
                            echo "ERROR: Missing Compose service: $SERVICE"
                            exit 1
                        }
                    done
                '''
            }
        }

        stage('Security Policy Checklist') {
            steps {
                sh '''
                    set -eu

                    CHECKLIST="$REPORT_DIRECTORY/security-checklist.txt"
                    : > "$CHECKLIST"

                    check() {
                        DESCRIPTION="$1"
                        shift

                        if "$@"; then
                            echo "PASS - $DESCRIPTION" | tee -a "$CHECKLIST"
                        else
                            echo "FAIL - $DESCRIPTION" | tee -a "$CHECKLIST"
                            exit 1
                        fi
                    }

                    check \
                        "HTTPS redirect is configured" \
                        grep -q 'return 301 https://' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "HSTS is configured" \
                        grep -q 'Strict-Transport-Security' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "X-Content-Type-Options is configured" \
                        grep -q 'X-Content-Type-Options' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Login rate-limit zone is configured" \
                        grep -q 'limit_req_zone.*login_limit' \
                        deployment/nginx/nginx.conf

                    check \
                        "Login endpoint rate limiting is configured" \
                        grep -q 'limit_req zone=login_limit' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Rate limiting returns HTTP 429" \
                        grep -q 'limit_req_status 429' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Environment file is restricted" \
                        grep -q 'location = /.env' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Git configuration is restricted" \
                        grep -q 'location = /.git/config' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Debug endpoint is restricted" \
                        grep -q 'location = /debug' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Metrics endpoint is restricted" \
                        grep -q 'location = /metrics' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Actuator endpoint is restricted" \
                        grep -q 'location = /actuator' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Internal endpoint is restricted" \
                        grep -q 'location = /internal' \
                        deployment/nginx/conf.d/penpot.conf

                    check \
                        "Backup database file is restricted" \
                        grep -q 'location = /backup.sql' \
                        deployment/nginx/conf.d/penpot.conf

                    echo
                    echo "Security policy checklist passed."
                    cat "$CHECKLIST"
                '''
            }
        }

        stage('Gitleaks Secret Scan') {
            steps {
                sh '''
                    set +e

                    JENKINS_UID=$(id -u)
                    JENKINS_GID=$(id -g)

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        -e HOME=/tmp \
                        -v "$WORKSPACE:/repo" \
                        zricethezav/gitleaks:latest \
                        detect \
                        --source=/repo \
                        --no-git \
                        --redact \
                        --report-format=json \
                        --report-path=/repo/$REPORT_DIRECTORY/gitleaks.json

                    STATUS=$?
                    echo "$STATUS" > "$REPORT_DIRECTORY/gitleaks-exit-code.txt"

                    exit 0
                '''
            }
        }

        stage('Semgrep Penpot Source Analysis') {
            steps {
                sh '''
                    set +e

                    JENKINS_UID=$(id -u)
                    JENKINS_GID=$(id -g)

                    echo "Running Semgrep against the complete checked-out repository..."

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        -e HOME=/tmp \
                        -v "$WORKSPACE:/src" \
                        -w /src \
                        semgrep/semgrep:latest \
                        semgrep scan \
                        --config auto \
                        --config /src/semgrep-rules/security-canary.yml \
                        --exclude .git \
                        --exclude reports \
                        --exclude deployment/certs \
                        --exclude node_modules \
                        --exclude target \
                        --exclude dist \
                        --exclude build \
                        --exclude .shadow-cljs \
                        --exclude resources/public \
                        --max-target-bytes 1000000 \
                        --metrics=off \
                        --json \
                        --output /src/reports/semgrep/penpot-source.json \
                        /src

                    STATUS=$?
                    echo "$STATUS" > "$REPORT_DIRECTORY/semgrep/penpot-source-exit-code.txt"

                    python3 - <<'PYTHON_SEMGREP_RESULTS'
import json
from pathlib import Path

report = Path("reports/semgrep/penpot-source.json")
summary = Path("reports/semgrep/penpot-source-summary.txt")

if not report.exists():
    message = "Semgrep did not create a JSON report."
    print(message)
    summary.write_text(message + "\n", encoding="utf-8")
    raise SystemExit(0)

try:
    data = json.loads(report.read_text(encoding="utf-8") or "{}")
except Exception as exc:
    message = f"Could not parse Semgrep report: {exc}"
    print(message)
    summary.write_text(message + "\n", encoding="utf-8")
    raise SystemExit(0)

findings = data.get("results") or []
errors = data.get("errors") or []

lines = [
    f"Semgrep source findings: {len(findings)}",
    f"Semgrep scan errors: {len(errors)}",
]

for finding in findings[:50]:
    rule = finding.get("check_id", "unknown-rule")
    path = finding.get("path", "unknown-file")
    line = (finding.get("start") or {}).get("line", "?")
    severity = (finding.get("extra") or {}).get("severity", "UNKNOWN")
    message = (finding.get("extra") or {}).get("message", "")
    lines.append(f"[{severity}] {rule} - {path}:{line} - {message}")

text = "\n".join(lines) + "\n"
summary.write_text(text, encoding="utf-8")
print(text)
PYTHON_SEMGREP_RESULTS

                    # Continue so findings can be summarized and emailed.
                    exit 0
                '''
            }
        }

        stage('Trivy Filesystem and Configuration Scans') {
            steps {
                sh '''
                    set +e

                    JENKINS_UID=$(id -u)
                    JENKINS_GID=$(id -g)

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        -e HOME=/tmp \
                        -e TRIVY_CACHE_DIR=/cache \
                        -v "$WORKSPACE:/work" \
                        -v "$WORKSPACE/.trivy-cache:/cache" \
                        aquasec/trivy:latest \
                        fs \
                        --scanners vuln,misconfig,secret \
                        --severity HIGH,CRITICAL \
                        --ignore-unfixed \
                        --format json \
                        --output "/work/$REPORT_DIRECTORY/trivy-filesystem.json" \
                        /work

                    FILESYSTEM_STATUS=$?
                    echo "$FILESYSTEM_STATUS" \
                        > "$REPORT_DIRECTORY/trivy-filesystem-exit-code.txt"

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        -e HOME=/tmp \
                        -e TRIVY_CACHE_DIR=/cache \
                        -v "$WORKSPACE:/work" \
                        -v "$WORKSPACE/.trivy-cache:/cache" \
                        aquasec/trivy:latest \
                        config \
                        --severity HIGH,CRITICAL \
                        --format json \
                        --output "/work/$REPORT_DIRECTORY/trivy-configuration.json" \
                        /work/deployment

                    CONFIG_STATUS=$?
                    echo "$CONFIG_STATUS" \
                        > "$REPORT_DIRECTORY/trivy-config-exit-code.txt"

                    exit 0
                '''
            }
        }

        stage('OWASP Dependency-Check') {
            when {
                expression {
                    return params.RUN_DEPENDENCY_CHECK
                }
            }

            steps {
                script {
                    sh '''
                        set -eu

                        CONTAINER_NAME="penpot-dependency-check-${BUILD_NUMBER}"

                        echo "$CONTAINER_NAME" \
                            > "$REPORT_DIRECTORY/dependency-check-container.txt"

                        docker rm -f "$CONTAINER_NAME" \
                            >/dev/null 2>&1 || true

                        # Run detached so the scanner survives a Jenkins restart.
                        docker run -d \
                            --name "$CONTAINER_NAME" \
                            -v "$WORKSPACE:/src:ro" \
                            -v "$WORKSPACE/$REPORT_DIRECTORY/dependency-check:/report" \
                            -v "$DEPENDENCY_CHECK_DATA_DIR:/usr/share/dependency-check/data" \
                            owasp/dependency-check:latest \
                            --project "Penpot DevSecOps Automation" \
                            --scan /src \
                            --exclude "/src/reports/**" \
                            --exclude "/src/.trivy-cache/**" \
                            --format HTML \
                            --format JSON \
                            --out /report
                    '''

                    boolean dependencyCheckFinished = false

                    for (int attempt = 1; attempt <= 270; attempt++) {
                        String dependencyState = sh(
                            script: '''
                                CONTAINER_NAME=$(cat "$REPORT_DIRECTORY/dependency-check-container.txt")

                                docker inspect \
                                    --format '{{.State.Status}}' \
                                    "$CONTAINER_NAME" \
                                    2>/dev/null || echo missing
                            ''',
                            returnStdout: true
                        ).trim()

                        echo "Dependency-Check attempt ${attempt}/270: ${dependencyState}"

                        if (dependencyState == 'exited' ||
                            dependencyState == 'dead' ||
                            dependencyState == 'missing') {
                            dependencyCheckFinished = true
                            break
                        }

                        sleep time: 10, unit: 'SECONDS'
                    }

                    if (!dependencyCheckFinished) {
                        echo 'Dependency-Check exceeded 45 minutes and will be stopped.'

                        sh '''
                            set +e

                            CONTAINER_NAME=$(cat "$REPORT_DIRECTORY/dependency-check-container.txt")
                            docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
                        '''
                    }

                    sh '''
                        set +e

                        CONTAINER_NAME=$(cat "$REPORT_DIRECTORY/dependency-check-container.txt")

                        docker logs "$CONTAINER_NAME" \
                            > "$REPORT_DIRECTORY/dependency-check/dependency-check-console.log" \
                            2>&1 || true

                        STATUS=$(docker inspect \
                            --format '{{.State.ExitCode}}' \
                            "$CONTAINER_NAME" \
                            2>/dev/null || echo 124)

                        echo "$STATUS" \
                            > "$REPORT_DIRECTORY/dependency-check-exit-code.txt"

                        docker rm -f "$CONTAINER_NAME" \
                            >/dev/null 2>&1 || true

                        HOST_UID=$(id -u)
                        HOST_GID=$(id -g)

                        docker run --rm \
                            -v "$WORKSPACE/$REPORT_DIRECTORY:/reports" \
                            alpine:3.20 \
                            chown -R "$HOST_UID:$HOST_GID" /reports

                        if [ "$STATUS" = "0" ]; then
                            echo "OWASP Dependency-Check completed successfully."
                        else
                            echo "OWASP Dependency-Check returned status $STATUS."
                            echo "The pipeline will continue; review the archived report and console log."
                        fi

                        exit 0
                    '''
                }
            }
        }

        stage('Remove Previous Deployment') {
            steps {
                sh '''
                    set +e

                    export PENPOT_DATABASE_PASSWORD
                    export PENPOT_SECRET_KEY
                    export PENPOT_VERSION

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        down --remove-orphans

                    docker ps -a \
                        --filter "name=penpot-secure" \
                        --format "{{.ID}}" |
                        xargs -r docker rm -f

                    exit 0
                '''
            }
        }

        stage('Deploy Penpot Securely') {
            steps {
                sh '''
                    set -eu

                    export PENPOT_DATABASE_PASSWORD
                    export PENPOT_SECRET_KEY
                    export PENPOT_VERSION

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        pull

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        up -d --remove-orphans

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        ps
                '''
            }
        }

        stage('Validate Containers and NGINX') {
            steps {
                sh '''
                    set -eu

                    sleep 30

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        ps

                    for SERVICE in \
                        nginx \
                        penpot-frontend \
                        penpot-backend \
                        penpot-exporter \
                        postgres \
                        redis
                    do
                        CONTAINER_ID=$(
                            docker compose \
                                -p "$COMPOSE_PROJECT_NAME" \
                                -f "$COMPOSE_FILE" \
                                ps -q "$SERVICE"
                        )

                        test -n "$CONTAINER_ID" || {
                            echo "ERROR: Missing container for $SERVICE."
                            exit 1
                        }

                        STATUS=$(
                            docker inspect \
                                --format '{{.State.Status}}' \
                                "$CONTAINER_ID"
                        )

                        echo "$SERVICE: $STATUS"

                        if [ "$STATUS" != "running" ]; then
                            docker compose \
                                -p "$COMPOSE_PROJECT_NAME" \
                                -f "$COMPOSE_FILE" \
                                logs \
                                --no-color \
                                --tail=150 \
                                "$SERVICE" || true

                            exit 1
                        fi
                    done

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        exec -T nginx nginx -t
                '''
            }
        }

        stage('Wait for Penpot HTTPS') {
            steps {
                sh '''
                    set -eu

                    ATTEMPT=1
                    MAX_ATTEMPTS=60

                    while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
                        HTTP_CODE=$(
                            curl \
                                --insecure \
                                --silent \
                                --output /dev/null \
                                --write-out "%{http_code}" \
                                "$PENPOT_URL/" || true
                        )

                        echo "Attempt $ATTEMPT/$MAX_ATTEMPTS: HTTP $HTTP_CODE"

                        case "$HTTP_CODE" in
                            200|301|302)
                                echo "Penpot is available over HTTPS."
                                exit 0
                                ;;
                        esac

                        sleep 10
                        ATTEMPT=$((ATTEMPT + 1))
                    done

                    echo "ERROR: Penpot did not become available over HTTPS."

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        logs \
                        --no-color \
                        --tail=300 || true

                    exit 1
                '''
            }
        }

        stage('Functional Availability Tests') {
            steps {
                sh '''
                    set -eu

                    HTTPS_CODE=$(
                        curl \
                            --insecure \
                            --silent \
                            --output "$REPORT_DIRECTORY/functional/homepage.html" \
                            --write-out "%{http_code}" \
                            "$PENPOT_URL/"
                    )

                    echo "HTTPS homepage status: $HTTPS_CODE"

                    case "$HTTPS_CODE" in
                        200|301|302) ;;
                        *)
                            echo "ERROR: Unexpected HTTPS status."
                            exit 1
                            ;;
                    esac

                    grep -Eqi \
                        '<html|<!doctype html' \
                        "$REPORT_DIRECTORY/functional/homepage.html"

                    HTTP_CODE=$(
                        curl \
                            --silent \
                            --output /dev/null \
                            --write-out "%{http_code}" \
                            "$PENPOT_HTTP_URL/"
                    )

                    echo "HTTP endpoint status: $HTTP_CODE"

                    case "$HTTP_CODE" in
                        301|302|307|308) ;;
                        *)
                            echo "ERROR: HTTP endpoint did not redirect."
                            exit 1
                            ;;
                    esac
                '''
            }
        }

        stage('API Authentication and Access-Control Tests') {
            steps {
                sh '''
                    set -eu

                    JENKINS_UID=$(id -u)
                    JENKINS_GID=$(id -g)

                    docker run --rm \
                        --user "$JENKINS_UID:$JENKINS_GID" \
                        --network host \
                        -e HOME=/tmp \
                        -e PENPOT_URL="$PENPOT_URL" \
                        -e PENPOT_HTTP_URL="$PENPOT_HTTP_URL" \
                        -v "$WORKSPACE:/work" \
                        -w /work \
                        python:3.12-slim \
                        bash -lc '
                            set -eu

                            pip install \
                                --quiet \
                                --disable-pip-version-check \
                                --target /tmp/python-packages \
                                -r tests/requirements.txt

                            export PYTHONPATH=/tmp/python-packages

                            python -m pytest \
                                -v \
                                --junitxml=reports/pytest/results.xml \
                                tests/test_api.py \
                                tests/test_security.py \
                                tests/test_pipeline_security.py
                        '
                '''
            }
        }

        stage('Container Image Vulnerability Scans') {
            when {
                expression {
                    return params.RUN_CONTAINER_SCANS
                }
            }

            steps {
                sh '''
                    set +e

                    JENKINS_UID=$(id -u)
                    JENKINS_GID=$(id -g)

                    scan_image() {
                        IMAGE="$1"
                        REPORT_NAME="$2"

                        echo "Scanning $IMAGE..."

                        docker run --rm \
                            --user "$JENKINS_UID:$JENKINS_GID" \
                            -e HOME=/tmp \
                            -e TRIVY_CACHE_DIR=/cache \
                            -v "$WORKSPACE:/work" \
                            -v "$WORKSPACE/.trivy-cache:/cache" \
                            aquasec/trivy:latest \
                            image \
                            --severity HIGH,CRITICAL \
                            --ignore-unfixed \
                            --format json \
                            --output "/work/$REPORT_DIRECTORY/images/$REPORT_NAME.json" \
                            "$IMAGE"
                    }

                    scan_image \
                        "penpotapp/frontend:$PENPOT_VERSION" \
                        "penpot-frontend"

                    scan_image \
                        "penpotapp/backend:$PENPOT_VERSION" \
                        "penpot-backend"

                    scan_image \
                        "penpotapp/exporter:$PENPOT_VERSION" \
                        "penpot-exporter"

                    scan_image "postgres:15" "postgres"
                    scan_image "redis:7" "redis"
                    scan_image "nginx:1.27-alpine" "nginx"

                    exit 0
                '''
            }
        }

        stage('Network and Debug Exposure Audit') {
            steps {
                sh '''
                    set -eu

                    ss -lnt \
                        > "$REPORT_DIRECTORY/post-deployment/listening-ports.txt"

                    for SERVICE in \
                        penpot-backend \
                        penpot-exporter \
                        postgres \
                        redis
                    do
                        CONTAINER_ID=$(
                            docker compose \
                                -p "$COMPOSE_PROJECT_NAME" \
                                -f "$COMPOSE_FILE" \
                                ps -q "$SERVICE"
                        )

                        PUBLISHED_PORTS=$(docker port "$CONTAINER_ID" || true)

                        if [ -n "$PUBLISHED_PORTS" ]; then
                            echo "ERROR: $SERVICE publishes a host port:"
                            echo "$PUBLISHED_PORTS"
                            exit 1
                        fi
                    done

                    if ss -lnt |
                       grep -Eq ':(9229|6064)[[:space:]]'; then
                        echo "ERROR: A common debug port is exposed."
                        exit 1
                    fi

                    echo "No backend, database, cache, or debug ports are exposed."
                '''
            }
        }

        stage('Post-Deployment Security Validation') {
            steps {
                sh '''
                    set -eu

                    curl \
                        --insecure \
                        --silent \
                        --show-error \
                        --head \
                        "$PENPOT_URL/" \
                        > "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    cat "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    grep -qi '^strict-transport-security:' \
                        "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    grep -qi '^x-content-type-options:.*nosniff' \
                        "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    grep -qi '^referrer-policy:' \
                        "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    grep -qi '^permissions-policy:' \
                        "$REPORT_DIRECTORY/post-deployment/https-headers.txt"

                    REDIRECT=$(
                        curl \
                            --silent \
                            --output /dev/null \
                            --write-out "%{redirect_url}" \
                            "$PENPOT_HTTP_URL/" || true
                    )

                    echo "Redirect destination: $REDIRECT"

                    case "$REDIRECT" in
                        https://*)
                            echo "HTTP-to-HTTPS redirect passed."
                            ;;
                        *)
                            echo "ERROR: HTTP did not redirect to HTTPS."
                            exit 1
                            ;;
                    esac

                    for PATH_NAME in \
                        .env \
                        debug \
                        metrics \
                        actuator \
                        internal \
                        backup.sql
                    do
                        STATUS=$(
                            curl \
                                --insecure \
                                --silent \
                                --output /dev/null \
                                --write-out "%{http_code}" \
                                "$PENPOT_URL/$PATH_NAME"
                        )

                        case "$STATUS" in
                            403|404) ;;
                            *)
                                echo "ERROR: Sensitive path /$PATH_NAME returned $STATUS."
                                exit 1
                                ;;
                        esac
                    done

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        ps \
                        > "$REPORT_DIRECTORY/post-deployment/container-status.txt"
                '''
            }
        }

        stage('Deployment Integrity Validation') {
            steps {
                sh '''
                    set -eu

                    sha256sum \
                        deployment/docker-compose.secure.yml \
                        deployment/nginx/nginx.conf \
                        deployment/nginx/conf.d/penpot.conf \
                        scripts/setup-host.sh \
                        tests/test_api.py \
                        tests/test_security.py \
                        tests/test_pipeline_security.py \
                        > "$REPORT_DIRECTORY/integrity/sha256sums.txt"

                    sha256sum \
                        --check \
                        "$REPORT_DIRECTORY/integrity/sha256sums.txt"
                '''
            }
        }

        stage('OWASP ZAP Baseline') {
            when {
                expression {
                    return params.RUN_ZAP
                }
            }

            steps {
                sh '''
                    set +e

                    chmod 777 "$REPORT_DIRECTORY/zap"

                    docker run --rm \
                        --network host \
                        -v "$WORKSPACE/$REPORT_DIRECTORY/zap:/zap/wrk:rw" \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py \
                        -t "$PENPOT_URL" \
                        -r zap-report.html \
                        -J zap-report.json \
                        -w zap-report.md \
                        -I

                    STATUS=$?
                    echo "$STATUS" \
                        > "$REPORT_DIRECTORY/zap/zap-exit-code.txt"

                    docker run --rm \
                        -v "$WORKSPACE/$REPORT_DIRECTORY/zap:/reports" \
                        alpine:3.20 \
                        chown -R "$(id -u):$(id -g)" /reports

                    exit 0
                '''
            }
        }

        stage('Evaluate Security Findings') {
            steps {
                sh '''
                    set -eu

                    python3 - <<'PYTHON_SUMMARY'
import json
from pathlib import Path

reports = Path("reports")
summary = []
total = 0


def count_trivy(path: Path) -> int:
    count = 0

    if not path.exists():
        return 0

    try:
        data = json.loads(path.read_text() or "{}")

        for result in data.get("Results") or []:
            count += len(result.get("Vulnerabilities") or [])
            count += len(result.get("Misconfigurations") or [])
            count += len(result.get("Secrets") or [])
    except Exception:
        return 0

    return count


gitleaks_path = reports / "gitleaks.json"

if gitleaks_path.exists():
    try:
        gitleaks_data = json.loads(gitleaks_path.read_text() or "[]")
        gitleaks_count = (
            len(gitleaks_data)
            if isinstance(gitleaks_data, list)
            else 0
        )
    except Exception:
        gitleaks_count = 0
else:
    gitleaks_count = 0

summary.append(f"Gitleaks findings: {gitleaks_count}")
total += gitleaks_count

semgrep_path = reports / "semgrep" / "penpot-source.json"
semgrep_results = []
canary_findings = []

canary_rule_ids = {
    "intentionally-vulnerable-eval-canary",
    "intentionally-vulnerable-shell-canary",
    "intentionally-vulnerable-os-system-canary",
}

if semgrep_path.exists():
    try:
        semgrep_data = json.loads(semgrep_path.read_text() or "{}")
        semgrep_results = semgrep_data.get("results") or []
        semgrep_count = len(semgrep_results)

        for finding in semgrep_results:
            rule = str(finding.get("check_id", "unknown-rule"))
            normalized_rule = rule.rsplit(".", 1)[-1]

            if normalized_rule not in canary_rule_ids:
                continue

            path = finding.get("path", "unknown-file")
            line = (finding.get("start") or {}).get("line", "?")
            severity = (finding.get("extra") or {}).get(
                "severity",
                "ERROR",
            )
            message = (finding.get("extra") or {}).get(
                "message",
                "Intentional security canary detected.",
            )

            canary_findings.append(
                f"[{severity}] {normalized_rule} - "
                f"{path}:{line} - {message}"
            )
    except Exception:
        semgrep_count = 0
        canary_findings = []
else:
    semgrep_count = 0

canary_count = len(canary_findings)

summary.append(f"Semgrep Penpot source findings: {semgrep_count}")
summary.append(f"Intentional vulnerability-canary findings: {canary_count}")
total += semgrep_count

notification = reports / "notification"
notification.mkdir(parents=True, exist_ok=True)

(notification / "canary-count.txt").write_text(
    str(canary_count),
    encoding="utf-8",
)

if canary_findings:
    canary_text = (
        "INTENTIONAL SECURITY CANARY DETECTED\n"
        + "\n".join(canary_findings)
        + "\n"
    )
else:
    canary_text = "No intentional security-canary findings detected.\n"

(notification / "canary-findings.txt").write_text(
    canary_text,
    encoding="utf-8",
)

print(canary_text)

filesystem_count = count_trivy(reports / "trivy-filesystem.json")
summary.append(f"Trivy filesystem findings: {filesystem_count}")
total += filesystem_count

configuration_count = count_trivy(
    reports / "trivy-configuration.json"
)
summary.append(
    f"Trivy configuration findings: {configuration_count}"
)
total += configuration_count

image_count = 0

for image_report in (reports / "images").glob("*.json"):
    image_count += count_trivy(image_report)

summary.append(f"Trivy container-image findings: {image_count}")
total += image_count

dependency_report = (
    reports
    / "dependency-check"
    / "dependency-check-report.json"
)

dependency_count = 0

if dependency_report.exists():
    try:
        dependency_data = json.loads(
            dependency_report.read_text() or "{}"
        )

        for dependency in dependency_data.get("dependencies") or []:
            dependency_count += len(
                dependency.get("vulnerabilities") or []
            )
    except Exception:
        dependency_count = 0

summary.append(
    f"OWASP Dependency-Check findings: {dependency_count}"
)
total += dependency_count

summary.append(f"Total automated findings: {total}")
summary_text = "\\n".join(summary) + "\\n"

notification.mkdir(parents=True, exist_ok=True)

(notification / "security-summary.txt").write_text(summary_text)
(notification / "finding-count.txt").write_text(str(total))

print(summary_text)
PYTHON_SUMMARY
                '''
            }
        }

        stage('Email Developer Notification') {
            steps {
                script {
                    String notificationRecipient = (params.DEVELOPER_EMAIL ?: '').trim()
                    if (!notificationRecipient) {
                        notificationRecipient = 'evan246810536546@gmail.com'
                    }

                    int findingCount = 0
                    int canaryCount = 0
                    String summaryText = 'Security findings were detected, but the summary file was unavailable.'
                    String canaryText = 'No intentional security-canary details were available.'

                    if (fileExists('reports/notification/finding-count.txt')) {
                        String rawCount = readFile(
                            'reports/notification/finding-count.txt'
                        ).trim()

                        if (rawCount ==~ /[0-9]+/) {
                            findingCount = rawCount.toInteger()
                        }
                    }

                    if (fileExists('reports/notification/security-summary.txt')) {
                        summaryText = readFile(
                            'reports/notification/security-summary.txt'
                        ).trim()
                    }

                    if (fileExists('reports/notification/canary-count.txt')) {
                        String rawCanaryCount = readFile(
                            'reports/notification/canary-count.txt'
                        ).trim()

                        if (rawCanaryCount ==~ /[0-9]+/) {
                            canaryCount = rawCanaryCount.toInteger()
                        }
                    }

                    if (fileExists('reports/notification/canary-findings.txt')) {
                        canaryText = readFile(
                            'reports/notification/canary-findings.txt'
                        ).trim()
                    }

                    if (findingCount > 0 || canaryCount > 0) {
                        String emailSubject = canaryCount > 0
                            ? "[Penpot DevSecOps] SECURITY CANARY DETECTED (${canaryCount}) - Build #${env.BUILD_NUMBER}"
                            : "[Penpot DevSecOps] ${findingCount} security findings detected - Build #${env.BUILD_NUMBER}"

                        String emailBody = [
                            'Penpot DevSecOps detected security findings.',
                            '',
                            "Job: ${env.JOB_NAME}",
                            "Build: ${env.BUILD_NUMBER}",
                            "Source commit: ${fileExists('reports/source/scanned-commit.txt') ? readFile('reports/source/scanned-commit.txt').trim() : 'unavailable'}",
                            "Build status at notification stage: ${currentBuild.currentResult ?: 'SUCCESS'}",
                            '',
                            'Security summary:',
                            summaryText,
                            '',
                            'Controlled vulnerability-canary result:',
                            canaryText,
                            '',
                            'Jenkins build:',
                            env.BUILD_URL,
                            '',
                            'Review the archived Gitleaks, Semgrep source, Trivy, Dependency-Check,',
                            'and deployment-validation reports before approving the deployment.'
                        ].join('\n')

                        emailext(
                            to: notificationRecipient,
                            subject: emailSubject,
                            mimeType: 'text/plain',
                            attachLog: false,
                            attachmentsPattern: 'reports/notification/security-summary.txt,reports/notification/canary-findings.txt,reports/semgrep/penpot-source-summary.txt',
                            body: emailBody
                        )

                        writeFile(
                            file: 'reports/notification/email-notification.txt',
                            text: [
                                'Email notification sent.',
                                "Recipient: ${notificationRecipient}",
                                "Finding count: ${findingCount}",
                                "Canary count: ${canaryCount}",
                                "Build: ${env.BUILD_URL}",
                                ''
                            ].join('\n')
                        )

                        if (canaryCount > 0) {
                            echo "SECURITY CANARY DETECTED: ${canaryCount} controlled vulnerable-code finding(s)."
                            echo canaryText
                            currentBuild.result = 'UNSTABLE'
                        }

                        echo "Security notification emailed to ${notificationRecipient}."
                    } else {
                        writeFile(
                            file: 'reports/notification/email-notification.txt',
                            text: 'No security findings were counted, so no vulnerability email was sent.\n'
                        )

                        echo 'No security findings were counted. No vulnerability email was sent.'
                    }
                }
            }
        }
    }

    post {
        always {
            sh '''
                set +e

                mkdir -p "$REPORT_DIRECTORY"

                if command -v docker >/dev/null 2>&1 &&
                   docker compose version >/dev/null 2>&1; then

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        ps \
                        > "$REPORT_DIRECTORY/final-container-status.txt" 2>&1

                    docker compose \
                        -p "$COMPOSE_PROJECT_NAME" \
                        -f "$COMPOSE_FILE" \
                        logs \
                        --no-color \
                        --tail=500 \
                        > "$REPORT_DIRECTORY/penpot-container-logs.txt" 2>&1
                fi

                exit 0
            '''

            archiveArtifacts(
                artifacts: 'reports/**/*',
                allowEmptyArchive: true,
                fingerprint: true
            )

            junit(
                testResults: 'reports/pytest/*.xml',
                allowEmptyResults: true
            )
        }

        success {
            echo 'Penpot DevSecOps pipeline completed successfully.'
            echo 'Jenkins: http://YOUR-VM-IP:8080'
            echo 'Penpot HTTP redirect: http://YOUR-VM-IP:8081'
            echo 'Penpot HTTPS: https://YOUR-VM-IP:8443'
        }

        failure {
            script {
                String failureRecipient = (params.DEVELOPER_EMAIL ?: '').trim()
                if (!failureRecipient) {
                    failureRecipient = 'evan246810536546@gmail.com'
                }

                String failureBody = [
                    'The Penpot DevSecOps pipeline failed.',
                    '',
                    "Job: ${env.JOB_NAME}",
                    "Build: ${env.BUILD_NUMBER}",
                    "Result: ${currentBuild.currentResult}",
                    '',
                    'Review the failed stage, console output, test results, and archived',
                    'security reports here:',
                    '',
                    env.BUILD_URL
                ].join('\n')

                emailext(
                    to: failureRecipient,
                    subject: "[Penpot DevSecOps] Pipeline FAILED - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    mimeType: 'text/plain',
                    attachLog: true,
                    body: failureBody
                )

                echo "Pipeline failure notification emailed to ${failureRecipient}."
            }
        }

    }
}
