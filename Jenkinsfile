// Jenkinsfile (Updated - No Deployment Stage)

pipeline {
    agent any // Tells Jenkins to run this on any available machine/agent

    // --- Environment Variables ---
    // Define some values used later in the pipeline
    environment {
        // <<< EDIT HERE >>>: Your Docker Hub Username (the one you login with)
        DOCKERHUB_USERNAME = 'sultanmyrzash'
        // <<< EDIT HERE >>>: Name of your Docker Hub Repository (e.g., ntad-api)
        DOCKERHUB_REPONAME = 'ntad-api'
        // ID of the Docker Hub credential you created in Jenkins (Step 2)
        DOCKERHUB_CREDENTIALS_ID = 'dockerhub-credentials'
        // Full Image Name on Docker Hub
        IMAGE_NAME = "${DOCKERHUB_USERNAME}/${DOCKERHUB_REPONAME}"

        // --- Deployment Settings Removed ---
        // DEPLOY_SERVER = 'user@your_deployment_server_ip_or_hostname' // REMOVED
        // DEPLOY_SSH_KEY_ID = 'deploy-server-ssh-key' // REMOVED
        // APP_CONTAINER_NAME = 'ntad-api-container' // REMOVED (needed for manual deploy though)
        // DEPLOY_VOLUME_MOUNT = '/path/on/server/data:/app/data' // REMOVED (needed for manual deploy though)
        // DEPLOY_PORT_MAPPING = '80:8000' // REMOVED (needed for manual deploy though)
    }

    // --- Pipeline Stages ---
    // Defines the sequence of steps
    stages {

        // 1. Get Code from GitHub
        stage('Checkout') {
            steps {
                echo 'Getting latest code from GitHub...'
                // Using your repository URL
                git url: 'https://github.com/SultanMyrzash/NetworkTrafficAnomalyDetectionAPI.git', branch: 'main'
                // Add credentialsId here if your repository becomes private later:
                // credentialsId: 'your-github-credential-id'
            }
        }

        // 2. Run Tests (using Docker)
        stage('Test') {
            steps {
                script {
                    echo 'Running tests inside a temporary container...'
                    // Build an image using the Dockerfile in the checked-out code
                    // We tag it temporarily so we can refer to it
                    // Assuming Dockerfile is inside the 'ntad' subdirectory of your checkout
                    def testImage = docker.build("${IMAGE_NAME}:test-${env.BUILD_NUMBER}", "-f ntad/Dockerfile .")

                    try {
                        // Run pytest inside the container we just built
                        testImage.inside {
                            // Command to execute inside container. Adjust path if needed.
                            sh 'pytest -v ntad/api/tests.py'
                        }
                        echo 'Tests passed!'
                    } catch (err) {
                        // If tests fail, stop the pipeline
                        error("Tests failed, stopping pipeline. Error: ${err}")
                    }
                }
            }
        }

        // 3. Build Production Image
        stage('Build Image') {
            steps {
                script {
                    echo "Building production image: ${IMAGE_NAME}..."
                    // Build using the Dockerfile, relative to workspace root
                    // Assuming Dockerfile is inside the 'ntad' subdirectory of your checkout
                    def customImage = docker.build("${IMAGE_NAME}", "-f ntad/Dockerfile .")

                    // Tag the image with 'latest' and the unique Jenkins build number
                    customImage.tag("${IMAGE_NAME}:latest")
                    customImage.tag("${IMAGE_NAME}:${env.BUILD_NUMBER}")
                    echo "Image tagged as ${IMAGE_NAME}:latest and ${IMAGE_NAME}:${env.BUILD_NUMBER}"
                }
            }
        }

        // 4. Push Image to Docker Hub
        stage('Push Image') {
            steps {
                script {
                    // Login to Docker Hub using the credential ID stored in Jenkins
                    docker.withRegistry('https://registry.hub.docker.com', DOCKERHUB_CREDENTIALS_ID) {
                        // Push both tags
                        echo "Pushing ${IMAGE_NAME}:latest..."
                        docker.image(IMAGE_NAME).push('latest')
                        echo "Pushing ${IMAGE_NAME}:${env.BUILD_NUMBER}..."
                        docker.image(IMAGE_NAME).push("${env.BUILD_NUMBER}")
                    }
                }
            }
        }

        // 5. Deploy Stage REMOVED
        // stage('Deploy') { ... } // Entire stage deleted

    } // End of stages

    // --- Post Actions ---
    // These run after all stages complete, regardless of success/failure
    post {
        always {
            echo 'Pipeline finished.'
            // cleanWs() // Optional: Cleans up the Jenkins workspace
        }
        success {
            // This now means the image was successfully pushed to Docker Hub
            echo 'Pipeline completed successfully! Image pushed to Docker Hub.'
            // Add notifications here (e.g., email, Slack) if desired
        }
        failure {
            echo 'Pipeline failed!'
            // Add notifications here
        }
    }
} // End of pipeline