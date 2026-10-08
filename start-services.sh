#!/bin/bash

echo "Starting Jenkins on port 9090..."
launchctl load /opt/homebrew/Cellar/jenkins-lts/2.555.1/homebrew.mxcl.jenkins-lts.plist 2>/dev/null
echo "  Jenkins -> http://localhost:9090"

echo "Starting SonarQube on port 9000..."
"/Users/kushanmaskey/Personal/Security Tools/Scanning Tools/sonarqube-26.5.0.122743/bin/macosx-universal-64/sonar.sh" start
echo "  SonarQube -> http://localhost:9000"

echo ""
echo "Services started. Give them ~30 seconds to be ready."
