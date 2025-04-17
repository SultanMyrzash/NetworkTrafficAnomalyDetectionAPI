// Use Declarative Pipeline syntax
pipeline {
    // Run main pipeline orchestration on any available agent node
    agent any

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

        // Stage 2: Build the Docker image explicitly
        stage('Build Docker Image') {
            steps {
                echo "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG} and tagging latest"
                script {
                    // Build the image using the Dockerfile in the 'ntad' subdirectory as context
                    // '--pull' ensures the base image (python:3.12-slim) is updated if necessary
                    // Use bat step for Windows compatibility
                    bat "docker build -t \"${IMAGE_NAME}:${IMAGE_TAG}\" --pull \".\\ntad\"" // Use .\ntad context path for Windows bat

                    // Tag the built image as 'latest'
                    echo "Tagging image ${IMAGE_NAME}:${IMAGE_TAG} as ${IMAGE_NAME}:latest"
                    bat "docker tag \"${IMAGE_NAME}:${IMAGE_TAG}\" \"${IMAGE_NAME}:latest\""
                }
            }
        }

        // Stage 3: Run tests inside the container using docker.image.inside
        stage('Run Tests') {
            steps {
                echo "Running Pytest integration tests inside the container..."
                script {
                    // Use the docker global variable and the image() method
                    // .inside executes the closure block within a running container of the specified image.
                    // Jenkins automatically handles mounting the workspace.
                    // Use '-u root' if needed to avoid permission errors inside container, especially when workspace is mounted from Windows host.
                    docker.image("${IMAGE_NAME}:${IMAGE_TAG}").inside('-u root') {
                        // Commands here run inside the container's default WORKDIR (/app)
                        // Use sh step type, even on Windows host, because command runs INSIDE Linux container
                        sh 'echo "Running tests as user: $(id -u):$(id -g)"'
                        sh 'ls -la' // List files in working dir inside container for debugging
                        sh 'pytest -v api/tests.py' // Execute pytest command
                    }
                }
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
            // <<< EDIT HERE >>>: Replace 'built-in' if needed with your actual agent label
            node('built-in') { // Or your specific node label
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