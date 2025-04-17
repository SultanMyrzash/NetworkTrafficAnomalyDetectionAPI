// Use Declarative Pipeline syntax
pipeline {
    // Agent selection: Use the 'dockerfile' agent.
    // Specify the directory containing the Dockerfile
    agent {
        dockerfile {
            dir 'ntad' // Correctly points to the subdirectory
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

        // Stage 2: Build the Docker image
        stage('Build Docker Image') {
            steps {
                echo "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"
                script {
                    // The 'agent { dockerfile ... }' handles the build implicitly,
                    // but we can get the image object if needed later, e.g., for scanning.
                    // For simplicity now, we let the agent handle the build needed for subsequent stages.
                    // If you specifically need to tag 'latest' during the build *before* tests,
                    // you might need a slightly different agent setup or build step.
                    // Let's assume the agent builds what's needed for tests first.
                    // We will explicitly build and tag again before push if needed.

                    // We rebuild here explicitly for tagging latest, though agent already built.
                    // This ensures we use the correct context path ('ntad').
                    def dockerImage = docker.build("${IMAGE_NAME}:${IMAGE_TAG}", "--pull ./ntad") // Build from 'ntad' subdir
                    echo "Tagging image ${IMAGE_NAME}:${IMAGE_TAG} as ${IMAGE_NAME}:latest"
                    dockerImage.tag("${IMAGE_NAME}", "latest")
                }
            }
        }

        // Stage 3: Run tests
        stage('Run Tests') {
            steps {
                echo "Running Pytest integration tests inside the container..."
                // This sh step runs inside the container built by the agent { dockerfile } directive
                // The workspace files are automatically mounted.
                sh 'pytest -v api/tests.py' // Execute pytest command
            }
        }

        // Stage 4: Push the image (Conditionally)
        stage('Push to Docker Hub') {
            // Only run for the 'main' branch
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
                failure { error "Failed to push image to Docker Hub." }
            }
        }

        // Stage 5: Deploy (Placeholder)
        stage('Deploy') {
            when { branch 'main' }
            steps {
                echo "Deploying application... (Placeholder - Requires Implementation)"
                // Deployment logic depends heavily on your target server/cloud environment
                // Requires handling volumes, potentially running multiple processes (supervisor/docker-compose)
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