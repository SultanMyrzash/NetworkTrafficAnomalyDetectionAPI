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

        // Stage 2: Run Tests (using Docker)
        stage('Test') {
            steps {
                script {
                    echo 'Building Docker image for testing...'
                    // Build the image using the 'ntad' directory as context
                    def testImageName = "${IMAGE_NAME}:test-${env.BUILD_NUMBER}"
                    docker.build(testImageName, "-f ntad/Dockerfile ntad/")

                    echo 'Running tests inside container...'
                    try {
                        // Explicitly run the container and execute pytest
                        // Mount the current workspace to a path INSIDE the container (e.g., /test_workspace)
                        // The WORKDIR in the Dockerfile is /app, so pytest needs the relative path from there.
                        // Make sure the container is removed afterwards (--rm)
                        docker.image(testImageName).run("--rm -v ${pwd()}:/test_workspace -w /test_workspace", "pytest -v ntad/api/tests.py")

                        // Alternative if pytest needs to run from /app WORKDIR:
                        // docker.image(testImageName).run("--rm -v ${pwd()}:/test_workspace", "sh -c 'cd /app && pytest -v ntad/api/tests.py'")

                        echo 'Tests passed!'
                    } catch (err) {
                        // If tests fail, stop the pipeline
                        error("Tests failed, stopping pipeline. Error: ${err}")
                    } finally {
                        // Optional: Clean up the test image if desired, especially if tests pass
                        // To clean up even on failure, move this outside the try/catch
                         try {
                             sh "docker rmi ${testImageName}"
                         } catch (err) {
                             echo "Warning: Failed to remove test image ${testImageName}. Maybe it wasn't built?"
                         }
                    }
                }
            }
        }

        // Stage 3: Build Production Image
        stage('Build Image') {
            steps {
                script {
                    echo "Building production image: ${IMAGE_NAME}..."
                    // Build using 'ntad' as context and specify Dockerfile path
                    // This command implicitly tags the built image as sultanmyrzash/ntad-api:latest
                    def customImage = docker.build("${IMAGE_NAME}", "-f ntad/Dockerfile ntad/")

                    // Add the build number as an additional tag to the same image ID
                    echo "Adding tag: ${env.BUILD_NUMBER}"
                    customImage.tag("${env.BUILD_NUMBER}") // Just provide the new tag

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