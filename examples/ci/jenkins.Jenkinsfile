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
        sh './scripts/ci/skill-veil-pr-gate.sh artifacts/previous.json artifacts/current.json .skill-veil/baseline.json .skill-veil/waivers.yaml'
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'artifacts/*', fingerprint: true
    }
  }
}
