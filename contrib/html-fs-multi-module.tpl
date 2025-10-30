<!DOCTYPE html>
<html>

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    {{- if . }}
    <style>
        * {
            font-family: Arial, Helvetica, sans-serif;
        }

        h1,
        h2,
        h3 {
            text-align: center;
        }

        .group-header th {
            font-size: 150%;
        }

        .sub-header th {
            font-size: 120%;
        }

        table,
        th,
        td {
            border: 1px solid black;
            border-collapse: collapse;
            white-space: nowrap;
            padding: .3em;
        }

        table {
            margin: 1em auto;
        }

        .severity {
            text-align: center;
            font-weight: bold;
            color: #fafafa;
        }

        .severity-LOW .severity {
            background-color: #5fbb31;
        }

        .severity-MEDIUM .severity {
            background-color: #e9c600;
        }

        .severity-HIGH .severity {
            background-color: #ff8800;
        }

        .severity-CRITICAL .severity {
            background-color: #e40000;
        }

        .severity-UNKNOWN .severity {
            background-color: #747474;
        }

        .severity-LOW {
            background-color: #5fbb3160;
        }

        .severity-MEDIUM {
            background-color: #e9c60060;
        }

        .severity-HIGH {
            background-color: #ff880060;
        }

        .severity-CRITICAL {
            background-color: #e4000060;
        }

        .severity-UNKNOWN {
            background-color: #74747460;
        }

        table tr td:first-of-type {
            font-weight: bold;
        }

        .links a,
        .links[data-more-links=on] a {
            display: block;
        }

        .links[data-more-links=off] a:nth-of-type(1n+5) {
            display: none;
        }

        a.toggle-more-links {
            cursor: pointer;
        }

        .target-section {
            margin-bottom: 3em;
        }
    </style>

    <title>Trivy Report - {{ now }}</title>

    <script>
        window.onload = function () {
            document.querySelectorAll('td.links').forEach(function (linkCell) {
                var links = [].slice.call(linkCell.querySelectorAll('a'));
                links.sort(function (a, b) { return a.href.localeCompare(b.href); });
                links.forEach(function (link, idx) {
                    if (links.length > 3 && idx === 3) {
                        var toggleLink = document.createElement('a');
                        toggleLink.innerText = "Toggle more links";
                        toggleLink.href = "#toggleMore";
                        toggleLink.className = "toggle-more-links";
                        linkCell.appendChild(toggleLink);
                    }
                    linkCell.appendChild(link);
                });
            });
            document.querySelectorAll('a.toggle-more-links').forEach(function (toggleLink) {
                toggleLink.onclick = function () {
                    var expanded = toggleLink.parentElement.getAttribute("data-more-links");
                    toggleLink.parentElement.setAttribute("data-more-links", expanded === "on" ? "off" : "on");
                    return false;
                };
            });
        };
    </script>
</head>

<body>
    <h1>Trivy Report - {{ now }}</h1>

    {{- range . }}
    <div class="target-section">
        <h2>{{ escapeXML .Target }}</h2>
        <h3>Type: {{ .Type }} | Class: {{ .Class }}</h3>

        {{- if (or (gt (len .Vulnerabilities) 0) (gt (len .Misconfigurations) 0)) }}
        <table>
            {{- if (gt (len .Vulnerabilities) 0) }}
            <tr class="group-header">
                <th colspan="6">Vulnerabilities</th>
            </tr>
            <tr class="sub-header">
                <th>Package</th>
                <th>Vulnerability ID</th>
                <th>Severity</th>
                <th>Installed Version</th>
                <th>Fixed Version</th>
                <th>Links</th>
            </tr>
            {{- range .Vulnerabilities }}
            <tr class="severity-{{ escapeXML .Vulnerability.Severity }}">
                <td class="pkg-name">{{ escapeXML .PkgName }}</td>
                <td>{{ escapeXML .VulnerabilityID }}</td>
                <td class="severity">{{ escapeXML .Vulnerability.Severity }}</td>
                <td class="pkg-version">{{ escapeXML .InstalledVersion }}</td>
                <td>{{ escapeXML .FixedVersion }}</td>
                <td class="links" data-more-links="off">
                    {{- range .Vulnerability.References }}
                    <a href={{ escapeXML . | printf "%q" }}>{{ escapeXML . }}</a>
                    {{- end }}
                </td>
            </tr>
            {{- end }}
            {{- else }}
            <tr>
                <th colspan="6">No Vulnerabilities found</th>
            </tr>
            {{- end }}

            {{- if (gt (len .Misconfigurations) 0) }}
            <tr class="group-header">
                <th colspan="6">Misconfigurations</th>
            </tr>
            <tr class="sub-header">
                <th>Type</th>
                <th>Misconf ID</th>
                <th>Check</th>
                <th>Severity</th>
                <th colspan="2">Message</th>
            </tr>
            {{- range .Misconfigurations }}
            <tr class="severity-{{ escapeXML .Severity }}">
                <td>{{ escapeXML .Type }}</td>
                <td>{{ escapeXML .ID }}</td>
                <td>{{ escapeXML .Title }}</td>
                <td class="severity">{{ escapeXML .Severity }}</td>
                <td colspan="2" style="white-space:normal;">
                    {{ escapeXML .Message }}<br>
                    <a href={{ escapeXML .PrimaryURL | printf "%q" }}>{{ escapeXML .PrimaryURL }}</a>
                </td>
            </tr>
            {{- end }}
            {{- else }}
            <tr>
                <th colspan="6">No Misconfigurations found</th>
            </tr>
            {{- end }}
        </table>
        {{- else }}
        <p style="text-align:center;">No findings for this target.</p>
        {{- end }}
    </div>
    {{- end }}
    {{- else }}
    </head>

    <body>
        <h1>Trivy Returned Empty Report</h1>
        {{- end }}
    </body>

</html>