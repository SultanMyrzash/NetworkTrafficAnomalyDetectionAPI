// Use Declarative Pipeline syntax
pipeline {
    // Agent selection: Use the 'dockerfile' agent.
    // This tells Jenkins to:
    // 1. Build an image using the Dockerfile found in the root of your checkout.
    // 2. Run the steps of each stage *inside* containers derived from that built image.
    // This ensures your build and test environment is consistent and matches your Dockerfile.
    agent {
        dockerfile {
            dir 'ntad' // Specify the directory containing the Dockerfile
            // filename 'Dockerfile' // Only needed if named differently
        }
    }

    // --- Environment Variables ---
    // Define values used later in the pipeline
    environment {
        // <<< EDIT HERE >>>: Your Docker Hub Username (the one you login with)
        DOCKERHUB_USERNAME = 'sultanmyrzash'
        // <<< EDIT HERE >>>: Name of your Docker Hub Repository (e.g., ntad-api)
        DOCKERHUB_REPONAME = 'ntad-api'
        // ID of the Docker Hub credential you created in Jenkins (e.g., 'dockerhub-credentials')
        DOCKERHUB_CREDENTIALS_ID = 'dockerhub-credentials' // Ensure this ID matches your Jenkins credential
        // Construct the Full Image Name on Docker Hub
        IMAGE_NAME = "${DOCKERHUB_USERNAME}/${DOCKERHUB_REPONAME}"
        // Define a variable for the image tag using Jenkins' build number
        IMAGE_TAG = "${env.BUILD_NUMBER}"
    }

    // --- Pipeline Stages ---
    // Defines the sequence of steps executed by the pipeline
    stages {
        // Stage 1: Get the code
        stage('Checkout') { // Renamed from 'Clone' for consistency
            steps {
                echo "Checking out code from SCM (e.g., GitHub)..."
                // This step automatically checks out the code from the source control
                // configured in the Jenkins job (e.g., Git repository URL).
                checkout scm
            }
        }

        // Stage 2: Build the Docker image
        stage('Build Docker Image') { // Renamed from 'Build'
            steps {
                echo "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"
                // Use the 'script' step for more complex Groovy logic if needed,
                // like using the 'docker' global variable provided by the Docker Pipeline plugin.
                script {
                    // Build the image using the Dockerfile in the current directory (".")
                    // Store the image object returned by docker.build()
                    // --pull ensures the base image (e.g., python:3.12-slim) is updated if needed
                    def dockerImage = docker.build("${IMAGE_NAME}:${IMAGE_TAG}", "--pull .")

                    // Also tag the same built image as 'latest' for convenience
                    echo "Tagging image ${IMAGE_NAME}:${IMAGE_TAG} as ${IMAGE_NAME}:latest"
                    dockerImage.tag("${IMAGE_NAME}", "latest")
                }
            }
        }

        // Stage 3: Run tests
        stage('Run Tests') { // Renamed from 'Test'
            steps {
                echo "Running Pytest integration tests inside the container..."
                // Because we use 'agent { dockerfile true }', this 'sh' step runs
                // inside a container based on the image built in the previous stage.
                // This ensures tests run in the exact environment defined by the Dockerfile.
                // Use '-s' with pytest to show print statements (like those in the merged test) if needed for debugging.
                sh 'pytest -v api/tests.py' // Execute pytest command
            }
        }

        // Stage 4: Push the image (Conditionally)
        stage('Push to Docker Hub') { // Renamed from 'Push'
            // Use a 'when' directive to only run this stage for specific conditions,
            // typically only when building the 'main' or 'master' branch.
            // <<< EDIT HERE >>>: Change 'main' if your primary branch has a different name.
            when { branch 'main' }
            steps {
                echo "Pushing Docker image ${IMAGE_NAME} with tags :${IMAGE_TAG} and :latest to Docker Hub..."
                script {
                    // Use the 'withRegistry' helper for secure login to Docker Hub
                    // It uses the Jenkins credential specified by DOCKERHUB_CREDENTIALS_ID
                    docker.withRegistry('https://registry.hub.docker.com', DOCKERHUB_CREDENTIALS_ID) {
                        // Push the image tagged with the specific build number
                        docker.image("${IMAGE_NAME}:${IMAGE_TAG}").push()

                        // Push the image tagged as 'latest'
                        docker.image("${IMAGE_NAME}:latest").push()
                    }
                }
            }
            // Optional: Add post actions specifically for this stage
            post {
                success {
                    echo "Image successfully pushed to Docker Hub."
                }
                failure {
                    // Use 'error' to clearly mark the stage/build as failed if push fails
                    error "Failed to push image to Docker Hub."
                }
            }
        }

        // Stage 5: Deploy (Placeholder)
        stage('Deploy') {
            // Only attempt deployment for the 'main' branch after a successful push
             when { branch 'main' }
            steps {
                echo "Deploying application... (Placeholder - Requires Implementation)"
                // Deployment logic is highly dependent on your target environment (server, cloud, Kubernetes, etc.)
                // This usually involves:
                // 1. Connecting to the target server (e.g., via SSH using SSH Agent plugin).
                // 2. Pulling the latest Docker image (`docker pull ${IMAGE_NAME}:latest`).
                // 3. Stopping and removing the old container.
                // 4. Starting the new container using `docker run` or `docker-compose up -d`.
                //    - **Crucially, you need to handle volumes here** to persist data like
                //      `captured_network_data.csv` and `detection_results/` outside the container.
                //    - **Also, you need a strategy to run BOTH `packet_capturing.py` AND the Django app (Gunicorn).**
                //      Common solutions include using a process manager like 'supervisor' inside the container,
                //      or deploying them as two separate containers managed by Docker Compose or Kubernetes.

                // Example using SSH (requires SSH Agent plugin configured):
                /*
                sshagent(credentials: ['your-ssh-credential-id']) {
                    sh '''
                        ssh user@your-deployment-server << EOF
                            echo "Pulling latest image..."
                            docker pull ${IMAGE_NAME}:latest

                            echo "Stopping and removing old container..."
                            docker stop ntad-container || echo "Container not running."
                            docker rm ntad-container || echo "Container not found."

                            echo "Starting new container..."
                            docker run -d --name ntad-container \\
                                -p 80:8000 \\
                                -v /path/on/server/to/data:/app/data \\ # Example volume mount
                                ${IMAGE_NAME}:latest

                            echo "Deployment script finished."
                        EOF
                    '''
                }
                */

                // Since implementation varies greatly, we'll just echo and maybe fail until implemented.
                sh 'echo Deployment step needs implementation based on target infrastructure.'
                // Uncomment the line below to make the pipeline fail here until deployment is implemented
                // error('Deployment step not implemented')
            }
        }
    } // End of stages

    // --- Post Actions ---
    // Define actions that run at the end of the entire pipeline run
        post {
        always {
            echo 'Pipeline finished.'
            // Explicitly allocate a node for workspace cleanup
            node {
                echo 'Cleaning workspace...'
                cleanWs()
            }
        }
        success {
            // No node needed for just echo or simple notifications
            echo 'Pipeline completed successfully!'
            // mail(...)
        }
        failure {
            // No node needed for just echo or simple notifications
            echo 'Pipeline failed.'
            // mail(...)
        }
    } // End of post
} // End of pipeline