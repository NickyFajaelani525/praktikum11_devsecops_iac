pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        timestamps()
    }

    environment {
        CHECKOV_IMAGE = 'bridgecrew/checkov@sha256:89a4c477508225cdc3ed8a23d15c7e0d9d3029bc8ae192b7f113a6ff5f210c94'

        GITHUB_OWNER = 'NickyFajaelani525'
        GITHUB_REPO  = 'praktikum11_devsecops_iac'

        GITHUB_CREDENTIALS = 'github-token'

        SECURITY_GATE = 'PENDING'
        SCAN_ERROR = 'false'
    }

    stages {

        stage('Clean WS') {
            steps {
                echo 'Cleaning Jenkins workspace...'
                deleteDir()
            }
        }

        stage('Checkout SCM') {
            steps {
                checkout scm

                script {
                    echo "Repository: ${GITHUB_OWNER}/${GITHUB_REPO}"
                    echo "Commit: ${env.GIT_COMMIT}"
                    echo "Branch: ${env.GIT_BRANCH}"
                    echo "Workspace: ${env.WORKSPACE}"
                }

                sh '''
                    echo "=== Repository Structure ==="
                    ls -lah

                    echo "=== Required Directories ==="
                    test -d terraform
                    test -d kubernetes
                    test -d dockerfile

                    echo "All required directories exist."
                '''
            }
        }

        stage('Checkov Scan - Terraform') {
            steps {
                script {
                    int result = sh(
                        script: """
                            docker run --rm \
                              --user "\$(id -u):\$(id -g)" \
			      -e HOME=/tmp \
                              --volumes-from jenkins \
                              -w "\$WORKSPACE" \
                              "$CHECKOV_IMAGE" \
                              -d terraform \
                              --framework terraform \
                              -o cli \
                              -o json \
                              -o sarif \
                              --output-file-path console,reports/terraform/checkov-terraform.json,reports/terraform/checkov-terraform.sarif \
                              --soft-fail
                        """,
                        returnStatus: true
                    )

                    if (result != 0) {
                        env.SCAN_ERROR = 'true'
                        echo "Terraform scan execution error. Exit code: ${result}"
                    } else {
                        echo 'Terraform scan completed.'
                    }
                }
            }
        }

        stage('Checkov Scan - Kubernetes') {
            steps {
                script {
                    int result = sh(
                        script: """
                            docker run --rm \
                              --user "\$(id -u):\$(id -g)" \
			      -e HOME=/tmp \
                              --volumes-from jenkins \
                              -w "\$WORKSPACE" \
                              "$CHECKOV_IMAGE" \
                              -d kubernetes \
                              --framework kubernetes \
                              -o cli \
                              -o json \
                              -o sarif \
                              --output-file-path console,reports/kubernetes/checkov-kubernetes.json,reports/kubernetes/checkov-kubernetes.sarif \
                              --soft-fail
                        """,
                        returnStatus: true
                    )

                    if (result != 0) {
                        env.SCAN_ERROR = 'true'
                        echo "Kubernetes scan execution error. Exit code: ${result}"
                    } else {
                        echo 'Kubernetes scan completed.'
                    }
                }
            }
        }

        stage('Checkov Scan - Dockerfile') {
            steps {
                script {
                    int result = sh(
                        script: """
                            docker run --rm \
                              --user "\$(id -u):\$(id -g)" \
                              -e HOME=/tmp \
                              --volumes-from jenkins \
                              -w "\$WORKSPACE" \
                              "$CHECKOV_IMAGE" \
                              -d dockerfile \
                              --framework dockerfile \
                              -o cli \
                              -o json \
                              -o sarif \
                              --output-file-path console,reports/dockerfile/checkov-dockerfile.json,reports/dockerfile/checkov-dockerfile.sarif \
                              --soft-fail
                        """,
                        returnStatus: true
                    )

                    if (result != 0) {
                        env.SCAN_ERROR = 'true'
                        echo "Dockerfile scan execution error. Exit code: ${result}"
                    } else {
                        echo 'Dockerfile scan completed.'
                    }
                }
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    int gateResult = sh(
                        script: """
                            docker run --rm \
                              --user "\$(id -u):\$(id -g)" \
			      -e HOME=/tmp \
                              --volumes-from jenkins \
                              -w "\$WORKSPACE" \
                              --entrypoint python3 \
                              "$CHECKOV_IMAGE" \
                              -c '
import json
import sys
from pathlib import Path

files = [
    "reports/terraform/checkov-terraform.json",
    "reports/kubernetes/checkov-kubernetes.json",
    "reports/dockerfile/checkov-dockerfile.json"
]

blocked = []
unknown = []
total = 0

for filename in files:
    path = Path(filename)

    if not path.is_file():
        print(f"ERROR: Report missing: {filename}")
        sys.exit(2)

    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        print(f"ERROR: Invalid JSON in {filename}: {exc}")
        sys.exit(2)

    datasets = data if isinstance(data, list) else [data]

    for dataset in datasets:
        if not isinstance(dataset, dict):
            print(f"ERROR: Unexpected JSON structure: {filename}")
            sys.exit(2)

        results = dataset.get("results", {})
        if not isinstance(results, dict):
            print(f"ERROR: Missing results object: {filename}")
            sys.exit(2)

        failed = results.get("failed_checks", [])
        if not isinstance(failed, list):
            print(f"ERROR: Invalid failed_checks: {filename}")
            sys.exit(2)

        for finding in failed:
            total += 1
            severity = str(finding.get("severity") or "").upper()
            check_id = finding.get("check_id", "UNKNOWN")
            resource = finding.get("resource", "UNKNOWN")

            print(f"{severity or 'UNCLASSIFIED'} | {check_id} | {resource}")

            if severity in ("HIGH", "CRITICAL"):
                blocked.append((severity, check_id, resource))
            elif severity not in ("LOW", "MEDIUM"):
                unknown.append((check_id, resource))

print()
print(f"Total failed checks: {total}")
print(f"HIGH/CRITICAL findings: {len(blocked)}")
print(f"Unclassified findings: {len(unknown)}")

if blocked or unknown:
    sys.exit(1)

sys.exit(0)
'
                        """,
                        returnStatus: true
                    )

                    if (env.SCAN_ERROR == 'true' || gateResult != 0) {
                        env.SECURITY_GATE = 'FAIL'
                        echo 'SECURITY GATE: FAIL'

                        catchError(
                            buildResult: 'FAILURE',
                            stageResult: 'FAILURE',
                            message: 'Checkov Security Gate failed.'
                        ) {
                            error('Pipeline blocked by Checkov Security Gate.')
                        }

                    } else {
                        env.SECURITY_GATE = 'PASS'
                        echo 'SECURITY GATE: PASS'
                    }
                }
            }
        }

        stage('Publish Reports') {
            steps {
                echo 'Publishing Checkov reports...'

                archiveArtifacts(
                    artifacts: 'reports/**/*.json,reports/**/*.sarif',
                    allowEmptyArchive: false,
                    fingerprint: true
                )

                sh '''
                    echo "=== Generated Reports ==="
                    find reports -type f -print
                '''
            }
        }

        stage('GitHub Status') {
            steps {
                script {
                    def statusState =
                        env.SECURITY_GATE == 'PASS' ? 'success' : 'failure'

                    def statusDescription =
                        env.SECURITY_GATE == 'PASS'
                        ? 'Checkov security gate passed'
                        : 'Checkov security gate failed'

                    withCredentials([
                        string(
                            credentialsId: GITHUB_CREDENTIALS,
                            variable: 'GITHUB_TOKEN'
                        )
                    ]) {
                        sh """
                            set +x

                            docker run --rm \
                              --volumes-from jenkins \
                              -e GITHUB_TOKEN="\$GITHUB_TOKEN" \
                              --entrypoint /bin/sh \
                              curlimages/curl:8.12.1 \
                              -c '
                                curl --fail-with-body --silent --show-error \
                                  -X POST \
                                  -H "Accept: application/vnd.github+json" \
                                  -H "Authorization: Bearer \$GITHUB_TOKEN" \
                                  -H "X-GitHub-Api-Version: 2022-11-28" \
                                  https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/statuses/${GIT_COMMIT} \
                                  -d "{\\"state\\":\\"${statusState}\\",\\"context\\":\\"jenkins/checkov-security-gate\\",\\"description\\":\\"${statusDescription}\\",\\"target_url\\":\\"${BUILD_URL}\\"}"
                              '
                        """
                    }

                    echo "GitHub commit status published: ${statusState}"
                }
            }
        }
    }

    post {
        always {
            echo 'Pipeline execution completed.'
            echo "Final Security Gate: ${env.SECURITY_GATE}"
        }
    }
}
