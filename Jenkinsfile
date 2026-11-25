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
                              scripts/checkov_security_gate.py
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
