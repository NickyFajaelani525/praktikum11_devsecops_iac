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
        GITHUB_REPO = 'praktikum11_devsecops_iac'
        GITHUB_CREDENTIALS = 'github-token'
    }

    stages {
        stage('Clean WS') {
            steps {
                echo 'Cleaning Jenkins workspace...'
                deleteDir()
            }
        }

        stage('Initialize Pipeline State') {
            steps {
                script {
                    // Mutable pipeline state is initialized here, not in declarative environment.
                    env.SECURITY_GATE = 'PENDING'
                    env.SCAN_ERROR = 'false'
                    env.SCAN_COMMIT = ''

                    echo 'Pipeline state initialized.'
                    echo "Initial Security Gate: ${env.SECURITY_GATE}"
                }
            }
        }

        stage('Checkout SCM') {
            steps {
                checkout scm

                script {
                    env.SCAN_COMMIT = sh(
                        script: 'git rev-parse HEAD',
                        returnStdout: true
                    ).trim()

                    echo "Repository: ${env.GITHUB_OWNER}/${env.GITHUB_REPO}"
                    echo "Commit: ${env.SCAN_COMMIT}"
                    echo "Branch: ${env.GIT_BRANCH}"
                    echo "Workspace: ${env.WORKSPACE}"
                }

                sh '''
                    set -eu
                    echo "=== Repository Structure ==="
                    ls -lah
                    echo "=== Required Directories ==="
                    test -d terraform
                    test -d kubernetes
                    test -d dockerfile
                    test -f scripts/checkov_security_gate.py
                    mkdir -p reports/terraform reports/kubernetes reports/dockerfile
                    echo "Repository structure is valid."
                '''
            }
        }

        stage('Checkov Scan - Terraform') {
            steps {
                script {
                    int result = sh(
                        script: '''
                            docker run --rm \
                              --user "$(id -u):$(id -g)" \
                              -e HOME=/tmp \
                              --volumes-from jenkins \
                              -w "$WORKSPACE" \
                              "$CHECKOV_IMAGE" \
                              -d terraform \
                              --framework terraform \
                              -o cli \
                              -o json \
                              -o sarif \
                              --output-file-path console,reports/terraform/checkov-terraform.json,reports/terraform/checkov-terraform.sarif \
                              --soft-fail
                        ''',
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
                        script: '''
                            docker run --rm \
                              --user "$(id -u):$(id -g)" \
                              -e HOME=/tmp \
                              --volumes-from jenkins \
                              -w "$WORKSPACE" \
                              "$CHECKOV_IMAGE" \
                              -d kubernetes \
                              --framework kubernetes \
                              -o cli \
                              -o json \
                              -o sarif \
                              --output-file-path console,reports/kubernetes/checkov-kubernetes.json,reports/kubernetes/checkov-kubernetes.sarif \
                              --soft-fail
                        ''',
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
                        script: '''
                            docker run --rm \
                              --user "$(id -u):$(id -g)" \
                              -e HOME=/tmp \
                              --volumes-from jenkins \
                              -w "$WORKSPACE" \
                              "$CHECKOV_IMAGE" \
                              -d dockerfile \
                              --framework dockerfile \
                              -o cli \
                              -o json \
                              -o sarif \
                              --output-file-path console,reports/dockerfile/checkov-dockerfile.json,reports/dockerfile/checkov-dockerfile.sarif \
                              --soft-fail
                        ''',
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
                        script: '''
                            docker run --rm \
                              --user "$(id -u):$(id -g)" \
                              -e HOME=/tmp \
                              --volumes-from jenkins \
                              -w "$WORKSPACE" \
                              --entrypoint python3 \
                              "$CHECKOV_IMAGE" \
                              scripts/checkov_security_gate.py
                        ''',
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
                    set -eu
                    echo "=== Generated Reports ==="
                    find reports -type f -print
                '''
            }
        }
    }

    post {
        always {
            script {
                // Evaluate final Jenkins result only after all stages have completed.
                def finalBuildResult = currentBuild.currentResult ?: 'FAILURE'
                def finalGateResult = env.SECURITY_GATE ?: 'PENDING'
                def finalCommit = env.SCAN_COMMIT?.trim()

                if (!finalCommit) {
                    finalCommit = sh(
                        script: 'git rev-parse HEAD',
                        returnStdout: true
                    ).trim()
                    env.SCAN_COMMIT = finalCommit
                }

                // GitHub is successful only if the Security Gate AND the full pipeline pass.
                def githubState = (
                    finalGateResult == 'PASS' &&
                    finalBuildResult == 'SUCCESS'
                ) ? 'success' : 'failure'

                def githubDescription = (githubState == 'success')
                    ? 'Checkov security gate and pipeline passed'
                    : "Pipeline ${finalBuildResult}; Security Gate ${finalGateResult}"

                echo '=== Final Pipeline Status ==='
                echo "Jenkins Result: ${finalBuildResult}"
                echo "Security Gate: ${finalGateResult}"
                echo "GitHub Status: ${githubState}"
                echo "Commit: ${finalCommit}"

                if (finalCommit) {
                    withCredentials([
                        string(
                            credentialsId: GITHUB_CREDENTIALS,
                            variable: 'GITHUB_TOKEN'
                        )
                    ]) {
                        withEnv([
                            "STATUS_STATE=${githubState}",
                            "STATUS_DESCRIPTION=${githubDescription}",
                            "STATUS_TARGET_URL=${env.BUILD_URL}",
                            "STATUS_API_URL=https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/statuses/${finalCommit}"
                        ]) {
                            sh '''
                                set -eu

                                docker run --rm \
                                  --volumes-from jenkins \
                                  -e GITHUB_TOKEN \
                                  -e STATUS_STATE \
                                  -e STATUS_DESCRIPTION \
                                  -e STATUS_TARGET_URL \
                                  -e STATUS_API_URL \
                                  curlimages/curl:8.12.1 \
                                  --fail-with-body --silent --show-error \
                                  -X POST \
                                  -H "Accept: application/vnd.github+json" \
                                  -H "Authorization: Bearer $GITHUB_TOKEN" \
                                  -H "X-GitHub-Api-Version: 2022-11-28" \
                                  "$STATUS_API_URL" \
                                  -d "{\"state\":\"$STATUS_STATE\",\"context\":\"jenkins/checkov-security-gate\",\"description\":\"$STATUS_DESCRIPTION\",\"target_url\":\"$STATUS_TARGET_URL\"}"
                            '''
                        }
                    }

                    echo "GitHub commit status published: ${githubState}"
                } else {
                    echo 'WARNING: No checked-out commit SHA is available; GitHub status was not published.'
                }
            }

            echo 'Pipeline execution completed.'
        }
    }
}
