pipeline {
    agent { 
        node {
            label 'built-in'
            }
      }
    triggers {
        pollSCM '*/2 * * * *'
    }
    stages {
        stage('Build') {
            steps {
                echo "Running getResults.py..."
                sh '''
                echo "ixia" | sudo -S python3 getResults.py
                '''
            }
        }
        stage('Test') {
            steps {
                echo "Testing.."
                sh '''
                echo "doing test stuff.."
                '''
            }
        }
        stage('Deliver') {
            steps {
                echo 'Deliver....'
                sh '''
                echo "doing delivery stuff.."
                '''
            }
        }
    }
}
