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
                    // Attempt to translate Windows workspace path for Docker volume mount
                    // NOTE: This path translation can be fragile. Docker Desktop often maps C:\ to /c/
                    // Adjust if your drive letter or Docker path mapping is different.
                    def windowsWorkspace = pwd().replace('\\', '/') // Get Jenkins workspace path, ensure forward slashes
                    def volumeMountPath = windowsWorkspace.replaceFirst("(?i)C:", "/c") // Replace C: with /c (case-insensitive)

                    // Define path inside container where workspace will be mounted
                    def containerWorkspace = "/jenkins-ws"

                    // Define test file path relative to the mount point inside container
                    def containerTestPath = "${containerWorkspace}/ntad/api/tests.py"

                    // Define working directory inside container (where commands will run)
                    def containerWorkDir = "${containerWorkspace}" // Run from the root of the mounted workspace

                     // Use bat step to execute docker run
                    bat """
                        docker run --rm ^
                            -u root ^
                            -v "${windowsWorkspace}:${containerWorkspace}:ro" ^
                            -w "${containerWorkDir}" ^
                            --entrypoint pytest ^
                            "${IMAGE_NAME}:${IMAGE_TAG}" ^
                            -v "${containerTestPath}"
                    """
                    // Explanation of docker run flags:
                    // --rm : Automatically remove the container when it exits.
                    // -u root : Run commands as root user inside container (often needed for mounted volume permissions).
                    // -v "${windowsWorkspace}:${containerWorkspace}:ro" : Mount Jenkins workspace read-only into container.
                    //    Using the Windows path directly often works with Docker Desktop path mapping. Read-only is safer for tests.
                    // -w "${containerWorkDir}" : Set the working directory inside the container.
                    // --entrypoint pytest : Override the default CMD/ENTRYPOINT to run 'pytest'.
                    // "${IMAGE_NAME}:${IMAGE_TAG}" : The image to run.
                    // -v "${containerTestPath}" : Arguments passed to the pytest entrypoint (verbose flag and the path to tests *inside the container*).
                    // Using caret (^) for line continuation in Windows batch script.
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