pipeline {
  agent any

  stages {
    stage('Scan current') {
      steps {
        sh 'mkdir -p artifacts'
        sh 'cargo run -p skill-veil -- scan-package . --preset ci --format json --output artifacts/current.json'
        sh 'cargo run -p skill-veil -- scan-package . --format sarif --output artifacts/current.sarif'
      }
    }

    stage('Gate diff') {
      steps {
        sh 'cargo run -p skill-veil -- diff artifacts/previous.json artifacts/current.json --baseline .skill-veil/baseline.json --waivers .skill-veil/waivers.yaml --ci-summary --fail-on-new-active'
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'artifacts/*', fingerprint: true
    }
  }
}
