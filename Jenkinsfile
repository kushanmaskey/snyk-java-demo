pipeline {
    agent any

    environment {
        SNYK_TOKEN = credentials('snyk-api-token')
        SNYK_HOME  = '/opt/homebrew/bin'
        PATH       = "/opt/homebrew/bin:/opt/homebrew/opt/openjdk@11/bin:${env.PATH}"
    }

    tools {
        maven 'maven 3.9.15'
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/kushanmaskey/snyk-java-demo.git'
            }
        }

        stage('Build') {
            steps {
                sh 'mvn clean package -DskipTests'
            }
        }

        stage('Snyk SCA - Dependency Scan') {
            steps {
                sh '''
                    snyk auth $SNYK_TOKEN
                    snyk test --all-projects --severity-threshold=high
                '''
            }
        }

        stage('Snyk SAST - Code Scan') {
            steps {
                sh '''
                    snyk code test --severity-threshold=high
                '''
            }
        }
    }

    post {
        always {
            echo 'Pipeline complete. Review Snyk findings above.'
        }
    }
}
