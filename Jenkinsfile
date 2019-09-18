pipeline {
  agent none
  options {
    disableConcurrentBuilds()
    timeout(time: 30, unit: "MINUTES")
  }
  tools {
    nodejs '10.15.3'
  }
  environment {
    HOSTED_NPMRC = 'HOSTED_NPMRC'
  }
  stages {
    stage('Install') {
      agent {
        label 'ubuntu'
      }
      steps {
        sh 'npm install'
      }
      post {
        success {
          stash includes: 'node_modules/**', excludes: 'node_modules/.cache/**', name: 'node_modules'
        }
      }
    }
    stage('Lint / Build / Test') {
      agent {
        docker {
          image 'amio/node-chrome'
        }
      }
      steps {
        unstash 'node_modules'
        // TSLint
        sh 'npm run lint'
        // Compile TS and Rollup
        sh 'npm run build'
        // Node Tests
        sh 'npm test -- --collect-coverage'
        // Browser Tests
        sh 'npm run browser -- --single-run --browsers=ChromeHeadlessNoSandbox'
      }
      post {
        always {
          junit 'junit.xml'
        }
        success {
          publishHTML target: [
            allowMissing: false,
            alwaysLinkToLastBuild: false,
            keepAll: true,
            allowMissing: false,
            reportDir: 'coverage/lcov-report',
            reportFiles: 'index.html',
            reportName: 'Test Coverage'
          ]
        }
      }
    }
    stage('Publish') {
      when { anyOf { branch 'master'; } }
      agent {
        label 'ubuntu'
      }
      steps {
        unstash 'node_modules'
        configFileProvider ([configFile (fileId: HOSTED_NPMRC, targetLocation: '.npmrc')]) {
          script {
            sh "npm publish --verbose"
          }
        }
      }
    }
  }
}