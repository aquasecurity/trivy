@Library('jenkins-divvy-shared-libraries@master') _
goPipelineV2(
    dockerRepoName: 'ics/trivy',
    runUnitTests: true,
    isReleasePublic: true,
    snykParams: '--severity-threshold=critical',
    failOnSnyk: true,
    trivyScan: true
)
