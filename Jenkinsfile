@Library('jenkins-divvy-shared-libraries@master') _
makefilePipeline(
    dockerRepoName: 'ics/trivy',
    publishDevImage: true,
    snykParams: '--severity-threshold=high --fail-on=all',
    failOnSnyk: true,
    podTemplateName: 'devbox_v2',
    containerName: 'jnlp',
    publishStagingImage: false,
    trivyScan: true,
    slackNotifyChannel: '#cloudsec-jenkins-alerts'
)
