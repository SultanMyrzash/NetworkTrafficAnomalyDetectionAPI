// Use Declarative Pipeline syntax
pipeline {
    agent any

    environment {
        DOCKERHUB_USERNAME = 'sultanmyrzash'
        DOCKERHUB_REPONAME = 'ntad-api'
        DOCKERHUB_CREDENTIALS_ID = 'dockerhub-credentials'
        IMAGE_NAME = "${DOCKERHUB_USERNAME}/${DOCKERHUB_REPONAME}"
        IMAGE_TAG = "${env.BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                echo "Checking out code..."
                checkout scm
            }
        }

        stage('Build Docker Image') {
            steps {
                echo "Building Docker image..."
                script {
                    // Use bat for Windows build commands
                    bat "docker build -t \"${IMAGE_NAME}:${IMAGE_TAG}\" --pull \".\\ntad\""
                    bat "docker tag \"${IMAGE_NAME}:${IMAGE_TAG}\" \"${IMAGE_NAME}:latest\""
                }
            }
        }

        stage('Run Tests') {
            steps {
                echo "Running Pytest via explicit docker run..."
                script {
                    def windowsWorkspace = pwd().replace('\\', '/')
                    def containerWorkspace = "/jenkins-ws" // Use a distinct path inside container
                    def containerTestPath = "${containerWorkspace}/ntad/api/tests.py"
                    def containerWorkDir = "${containerWorkspace}/ntad" // WORKDIR is /app in Dockerfile, but workspace mounts elsewhere? Let's set WORKDIR explicitly here

                    // FIX: Remove ':ro' from the volume mount for the test stage
                    bat """
                        docker run --rm ^
                            -u root ^
                            -v "${windowsWorkspace}:${containerWorkspace}" ^
                            -w "${containerWorkDir}" ^
                            --entrypoint pytest ^
                            "${IMAGE_NAME}:${IMAGE_TAG}" ^
                            -v "api/tests.py"
                    """
                    // Explanation of changes:
                    // -v "${windowsWorkspace}:${containerWorkspace}" : Removed ':ro'. Mount is now read-write.
                    // -w "${containerWorkDir}" : Set WORKDIR to /jenkins-ws/ntad
                    // Arguments to pytest: Just specify the path relative to the WORKDIR
                }
            }
        }
        

        stage('Check Branch Name') {
            steps {
                script {
                    // Print the environment variable Jenkins provides
                    echo "Jenkins believes the current branch is: ${env.BRANCH_NAME}"
                }
            }
        }

        stage('Push to Docker Hub') {
            // Compare against the variable Jenkins provides
            when { expression { return env.BRANCH_NAME == 'main' } } // More explicit check
            steps {
                echo "Pushing Docker image..."
                script {
                    docker.withRegistry('https://registry.hub.docker.com', DOCKERHUB_CREDENTIALS_ID) {
                        docker.image("${IMAGE_NAME}:${IMAGE_TAG}").push()
                        docker.image("${IMAGE_NAME}:latest").push()
                    }
                }
            }
            post {
                success { echo "Image successfully pushed." }
                failure { error "Failed to push image." }
            }
        }

        stage('Deploy') {
            when { branch 'main' }
            steps {
                echo "Deploying application... (Placeholder)"
                sh 'echo Deployment step needs implementation.'
                // error('Deployment step not implemented')
            }
        }
    } // End of stages

    // --- Post Actions remain the same ---
    post {
        always {
            echo 'Pipeline finished.'
            node('built-in') { // Or your specific node label
                echo 'Cleaning workspace...'
                cleanWs()
            }
        }
        success { echo 'Pipeline completed successfully!' }
        failure { echo 'Pipeline failed.' }
    } // End of post
} // End of pipeline