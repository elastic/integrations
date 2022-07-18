@Library('apm@current') _

pipeline {
  agent none
  environment {
    NOTIFY_TO = credentials('notify-to')
    PIPELINE_LOG_LEVEL = 'INFO'
    SLACK_CHANNEL = "#beats-build"
    INTEGRATION_JOB = 'Ingest-manager/integrations/main'
  }
  options {
    timeout(time: 6, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '20', daysToKeepStr: '30'))
    timestamps()
    ansiColor('xterm')
    disableResume()
    durabilityHint('PERFORMANCE_OPTIMIZED')
    rateLimitBuilds(throttle: [count: 60, durationName: 'hour', userBoost: true])
    quietPeriod(10)
  }
  triggers {
    cron('H H(2-5) * * *')
  }
  stages {
    stage('Daily integration builds') {
      parallel {
        stage('with stack v7.17') {
          steps {
            build(
              job: env.INTEGRATION_JOB,
              parameters: [stringParam(name: 'stackVersion', value: '7.17-SNAPSHOT')],
              quietPeriod: 0,
              wait: true,
              propagate: true,
            )
          }
        }
        stage('with stack v8.3') {
          steps {
            build(
              job: env.INTEGRATION_JOB,
              parameters: [stringParam(name: 'stackVersion', value: '8.3.0-SNAPSHOT')],
              quietPeriod: 0,
              wait: true,
              propagate: true,
            )
          }
        }
      }
    }
  }
  post {
    cleanup {
      notifyBuildResult(prComment: false, slackHeader: "Integration job failed ${env.JENKINS_URL}search/?q=${env.INTEGRATION_JOB.replaceAll('/','+')}")
    }
  }
}
