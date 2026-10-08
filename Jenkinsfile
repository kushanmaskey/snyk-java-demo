pipeline {
    agent any

    triggers {
        pollSCM('H/2 * * * *')
    }

    options {
        disableConcurrentBuilds()
        quietPeriod(30)
    }

    environment {
        SNYK_TOKEN            = credentials('snyk-api-token')
        SNYK_HOME             = '/opt/homebrew/bin'
        SONAR_API_TOKEN       = credentials('sonar-jenkins')
        PATH                  = "/opt/homebrew/bin:/opt/homebrew/opt/openjdk@11/bin:${env.PATH}"
        MIN_COVERAGE_PERCENT  = '20'
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

        stage('Test & Coverage') {
            steps {
                sh 'mvn test'
            }
            post {
                always {
                    junit '**/target/surefire-reports/*.xml'
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                sh '''
                    mvn sonar:sonar \
                        -Dsonar.host.url=http://localhost:9000 \
                        -Dsonar.token=$SONAR_API_TOKEN \
                        -Dsonar.projectKey=snyk-java-demo \
                        -Dsonar.projectName="Snyk Java Demo" \
                        -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
                '''
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    def coverage = sh(
                        script: '''
                            python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('target/site/jacoco/jacoco.xml')
root = tree.getroot()
for c in root.findall('counter'):
    if c.get('type') == 'LINE':
        missed  = int(c.get('missed'))
        covered = int(c.get('covered'))
        total   = missed + covered
        print(0 if total == 0 else round(covered / total * 100, 2))
"
                        ''',
                        returnStdout: true
                    ).trim().toDouble()

                    echo "Line coverage: ${coverage}%  (minimum required: ${MIN_COVERAGE_PERCENT}%)"

                    if (coverage < MIN_COVERAGE_PERCENT.toDouble()) {
                        error "Quality Gate failed: coverage ${coverage}% is below the required ${MIN_COVERAGE_PERCENT}%."
                    }
                }
            }
        }

        stage('Snyk SCA - Dependency Scan') {
            steps {
                sh '''
                    snyk auth $SNYK_TOKEN
                    snyk test --file=pom.xml --json > snyk-sca-report.json || true
                    snyk test --file=pom.xml --severity-threshold=high
                '''
            }
        }

        stage('Snyk SAST - Code Scan') {
            steps {
                sh '''
                    snyk code test --json > snyk-sast-report.json || true
                    snyk code test --severity-threshold=high
                '''
            }
        }

        stage('Security Dashboard') {
            steps {
                sh 'python3 generate-snyk-dashboard.py'
            }
        }
    }

    post {
        always {
            echo 'Pipeline complete. Review Snyk and SonarQube findings above.'
        }
    }
}
