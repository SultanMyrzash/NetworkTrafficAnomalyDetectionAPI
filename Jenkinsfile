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
                echo "Running Pytest integration tests inside the container..."
                script {
                    // Try passing arguments as a list to inside()
                    // Explicitly setting the working directory to /app
                    // Using -u root for permissions
                    def args = '-u root --workdir /app' // Using --workdir long form
                    docker.image("${IMAGE_NAME}:${IMAGE_TAG}").inside(args) {
                        sh 'echo "Running tests as user: $(id -u):$(id -g) in dir: $(pwd)"' // Should show /app
                        sh 'ls -la' // List contents of /app
                        sh 'ls -la ntad/' // List contents of /app/ntad
                        sh 'ls -la ntad/api/' // List contents of /app/ntad/api
                        // Run pytest using the path relative to the WORKDIR /app
                        // Ensure pytest and dependencies are in the container's PATH
                        sh 'pytest -v ntad/api/tests.py'
                    }
                }
            }
        }

        // --- Stages Push and Deploy remain the same as before ---
        stage('Push to Docker Hub') {
            when { branch 'main' }
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