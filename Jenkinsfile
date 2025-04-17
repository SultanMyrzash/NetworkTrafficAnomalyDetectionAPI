// Use Declarative Pipeline syntax
pipeline {
    // Agent selection: Use the 'dockerfile' agent.
    agent {
        dockerfile {
            // Specify the directory containing the Dockerfile relative to the workspace root
            dir 'ntad' // Assumes Dockerfile is inside the 'ntad' subdirectory
            // FIX: Explicitly set the working directory *inside* the container
            // Use the WORKDIR defined in your Dockerfile (e.g., /app)
            // This prevents Jenkins passing the Windows host path incorrectly.
            args '-w /app'
        }
    }

    // --- Environment Variables ---
    environment {
        // <<< EDIT HERE >>>: Your Docker Hub Username
        DOCKERHUB_USERNAME = 'sultanmyrzash'
        // <<< EDIT HERE >>>: Name of your Docker Hub Repository
        DOCKERHUB_REPONAME = 'ntad-api'
        // ID of the Docker Hub credential you created in Jenkins
        DOCKERHUB_CREDENTIALS_ID = 'dockerhub-credentials' // Ensure this ID matches your Jenkins credential
        // Construct the Full Image Name on Docker Hub
        IMAGE_NAME = "${DOCKERHUB_USERNAME}/${DOCKERHUB_REPONAME}"
        // Define a variable for the image tag using Jenkins' build number
        IMAGE_TAG = "${env.BUILD_NUMBER}"
    }

    // --- Pipeline Stages ---
    stages {
        // Stage 1: Get the code
        stage('Checkout') {
            steps {
                echo "Checking out code from SCM (e.g., GitHub)..."
                checkout scm
            }
        }

        // Stage 2: Build and Tag the Docker image explicitly
        // While the agent builds an image for running steps, we build explicitly
        // here to ensure we have the correctly tagged image object for pushing later.
        stage('Build Docker Image') {
            steps {
                echo "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG} and tagging latest"
                script {
                    // Build the image using the Dockerfile in the 'ntad' subdirectory as context
                    // '--pull' ensures the base image (python:3.12-slim) is updated if necessary
                    def dockerImage = docker.build("${IMAGE_NAME}:${IMAGE_TAG}", "--pull ./ntad")

                    // Also tag the same built image as 'latest'
                    echo "Tagging image ${IMAGE_NAME}:${IMAGE_TAG} as ${IMAGE_NAME}:latest"
                    dockerImage.tag("${IMAGE_NAME}", "latest")
                }
            }
        }

        // Stage 3: Run tests
        stage('Run Tests') {
            steps {
                echo "Running Pytest integration tests inside the container..."
                // This sh step runs inside the container built by the agent { dockerfile } directive.
                // Jenkins automatically mounts the workspace and uses the specified working dir ('/app').
                sh 'pytest -v api/tests.py' // Execute pytest command
            }
        }

        // Stage 4: Push the image (Conditionally)
        stage('Push to Docker Hub') {
            // Only run for the 'main' branch (adjust if needed)
            when { branch 'main' }
            steps {
                echo "Pushing Docker image ${IMAGE_NAME} with tags :${IMAGE_TAG} and :latest to Docker Hub..."
                script {
                    // Login using Jenkins credentials
                    docker.withRegistry('https://registry.hub.docker.com', DOCKERHUB_CREDENTIALS_ID) {
                        // Push the build-number tagged image
                        docker.image("${IMAGE_NAME}:${IMAGE_TAG}").push()
                        // Push the 'latest' tagged image
                        docker.image("${IMAGE_NAME}:latest").push()
                    }
                }
            }
            post {
                success { echo "Image successfully pushed to Docker Hub." }
                // Use 'error' step to clearly mark the build as failed if push fails
                failure { error "Failed to push image to Docker Hub." }
            }
        }

        // Stage 5: Deploy (Placeholder)
        stage('Deploy') {
            // Only run for the 'main' branch after successful push
            when { branch 'main' }
            steps {
                echo "Deploying application... (Placeholder - Requires Implementation)"
                // Deployment logic depends heavily on your target server/cloud environment.
                // Remember to handle volumes for persistent data and a strategy for
                // running both packet_capturing.py and the Django app (e.g., supervisor, docker-compose).
                sh 'echo Deployment step needs implementation based on target infrastructure.'
                // error('Deployment step not implemented') // Uncomment to fail here until implemented
            }
        }
    } // End of stages

    // --- Post Actions ---
    post {
        always {
            echo 'Pipeline finished.'
            // Ensure cleanup runs on a node with workspace access
            // Use a valid agent label from your Jenkins setup ('built-in' is common for the controller)
            // <<< EDIT HERE >>>: Replace 'built-in' if needed with your actual agent label
            node('built-in') {
                echo 'Cleaning workspace...'
                cleanWs()
            }
        }
        success {
            echo 'Pipeline completed successfully!'
            // mail to: 'your-email@example.com', subject: "Pipeline Success: ${currentBuild.fullDisplayName}"
        }
        failure {
            echo 'Pipeline failed.'
            // mail to: 'your-email@example.com', subject: "Pipeline FAILURE: ${currentBuild.fullDisplayName}"
        }
    } // End of post
} // End of pipeline