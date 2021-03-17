# Comparison with other scanners

| Scanner        | OS<br>Packages  | Application<br>Dependencies | Easy to use  | Accuracy    | Suitable<br>for CI  |
| -------------- | :-------------: | :-------------------------: | :----------: | :---------: | :-----------------: |
| Trivy          |       ✅        |       ✅<br>(7 languages)   |    ⭐ ⭐ ⭐    |  ⭐ ⭐ ⭐    |      ⭐ ⭐ ⭐         |
| Clair          |       ✅        |              ×              |      ⭐       |   ⭐ ⭐      |      ⭐ ⭐           |
| Anchore Engine |       ✅        |       ✅<br>(4 languages)   |     ⭐ ⭐      |   ⭐ ⭐      |     ⭐ ⭐ ⭐         |
| Quay           |       ✅        |              ×              |    ⭐ ⭐ ⭐    |   ⭐ ⭐      |        ×            |
| Docker Hub     |       ✅        |              ×              |    ⭐ ⭐ ⭐    |    ⭐        |        ×            |
| GCR            |       ✅        |              ×              |    ⭐ ⭐ ⭐    |   ⭐ ⭐      |        ×            |

- [Open Source CVE Scanner Round-Up: Clair vs Anchore vs Trivy][round-up]
- [Docker Image Security: Static Analysis Tool Comparison – Anchore Engine vs Clair vs Trivy][tool-comparison]
- [Research Spike: evaluate Trivy for scanning running containers](https://gitlab.com/gitlab-org/gitlab/-/issues/270888)

[round-up]: https://boxboat.com/2020/04/24/image-scanning-tech-compared/
[tool-comparison]: https://www.a10o.net/devsecops/docker-image-security-static-analysis-tool-comparison-anchore-engine-vs-clair-vs-trivy/
