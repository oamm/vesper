using System.Net;
using System.Text;
using System.Text.Json;

namespace Vesper.Cli;

internal static class ReportHtmlWriter
{
    private static readonly string[] SeverityValues = ["critical", "high", "medium", "low", "info", "unknown"];
    private static readonly string[] CategoryValues = ["dependency", "secret", "sast", "iac", "container"];

    public static void Write(string reportDirectory, string outputPath, JsonElement summary, IReadOnlyDictionary<string, int>? comparisonCounts)
    {
        using var scan = Load(reportDirectory, "scan.json");
        using var findings = Load(reportDirectory, "findings.json");
        using var remediations = Load(reportDirectory, "remediations.json");
        using var project = LoadOptional(reportDirectory, "project.json");
        var scanRoot = scan.RootElement;
        var gate = summary.TryGetProperty("gate", out var gateValue) ? gateValue : EmptyObject;
        var findingSummary = summary.TryGetProperty("findings", out var nestedFindings) ? nestedFindings : summary;
        var blockingIds = ReadStringSet(gate, "blockingFindingIds");
        var html = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        html.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Vesper Security Report</title>");
        AppendStyle(html);
        html.Append("</head><body><a class=\"skip-link\" href=\"#findings\">Skip to findings</a><main>");
        AppendProjectSummary(html, reportDirectory, scanRoot, summary, project, findingSummary);
        AppendAssessments(html, summary, scanRoot, gate, findings.RootElement, blockingIds);
        AppendPolicy(html, summary);
        AppendComparison(html, comparisonCounts);
        AppendRemediations(html, remediations.RootElement, blockingIds);
        AppendCoverage(html, reportDirectory, outputPath, summary, scanRoot, project);
        AppendFindings(html, findings.RootElement, remediations.RootElement, blockingIds);
        AppendReproducibility(html, reportDirectory, outputPath, scanRoot, summary);
        html.Append("</main>");
        AppendScript(html);
        html.Append("</body></html>");
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        File.WriteAllText(outputPath, html.ToString(), new UTF8Encoding(false));
    }

    private static void AppendProjectSummary(StringBuilder html, string reportDirectory, JsonElement scan, JsonElement summary, JsonDocument? project, JsonElement findingSummary)
    {
        var projectRoot = project?.RootElement;
        var name = projectRoot is not null ? Text(projectRoot.Value, "projectName") : "";
        if (string.IsNullOrWhiteSpace(name)) name = DerivedProjectName(reportDirectory);
        if (string.IsNullOrWhiteSpace(name)) name = "Project name unavailable";
        html.Append("<header class=\"hero\"><p class=\"eyebrow\">Vesper Security Report</p><h1>").Append(E(name)).Append("</h1><p class=\"muted\">Deterministic report from open-source scanner evidence. A passing gate does not prove that no vulnerabilities exist.</p></header>");
        html.Append("<section aria-labelledby=\"summary-heading\"><h2 id=\"summary-heading\">Scan summary</h2><div class=\"cards\">");
        Card(html, "Findings", Text(findingSummary, "total", "0"));
        Card(html, "Remediation groups", Text(summary, "remediations.total", "0"));
        Card(html, "Scan ID", Text(scan, "scanId", "Not recorded"));
        Card(html, "Started", Text(scan, "startedAt", "Not recorded"));
        Card(html, "Duration", Duration(scan));
        html.Append("</div>");
        if (projectRoot is not null) html.Append("<dl class=\"facts\"><dt>Technologies</dt><dd>").Append(E(JoinArray(projectRoot.Value, "technologies"))).Append("</dd><dt>Inventory</dt><dd>").Append(E(Text(projectRoot.Value, "fileCount", "Not recorded"))).Append(" files; ").Append(E(Text(projectRoot.Value, "sourceFileCount", "Not recorded"))).Append(" source files; ").Append(E(Text(projectRoot.Value, "artifactCount", "Not recorded"))).Append(" detected artifacts.</dd></dl>");
        html.Append("</section>");
    }

    private static void AppendAssessments(StringBuilder html, JsonElement summary, JsonElement scan, JsonElement gate, JsonElement findings, HashSet<string> blockingIds)
    {
        var execution = Text(scan, "executionStatus", Text(summary, "status", "not evaluated"));
        var gateStatus = Text(gate, "status", "not evaluated");
        var coverage = summary.TryGetProperty("coverage", out var coverageValue) ? Text(coverageValue, "assessment", "unknown") : "unknown";
        html.Append("<section aria-labelledby=\"decision-heading\"><h2 id=\"decision-heading\">Security decision</h2><div class=\"assessment-grid\">");
        Assessment(html, "Execution", execution, ExecutionExplanation(execution));
        Assessment(html, "Security gate", gateStatus, GateExplanation(gate, findings));
        Assessment(html, "Coverage", coverage, CoverageExplanation(coverage));
        html.Append("</div>");
        if (gate.TryGetProperty("executionLimitation", out var limitation)) html.Append("<p class=\"notice\"><strong>Execution limitation:</strong> ").Append(E(Value(limitation))).Append("</p>");
        if (blockingIds.Count > 0)
        {
            html.Append("<p><strong>Gate-blocking findings:</strong> ");
            foreach (var id in blockingIds.OrderBy(value => value)) html.Append("<a class=\"chip danger\" href=\"#").Append(E(id)).Append("\">").Append(E(id)).Append("</a> ");
            html.Append("</p>");
        }
        html.Append("</section>");
    }

    private static void AppendPolicy(StringBuilder html, JsonElement summary)
    {
        html.Append("<section aria-labelledby=\"policy-heading\"><h2 id=\"policy-heading\">Effective gate policy</h2><div class=\"table-wrap\"><table><tbody>");
        if (!summary.TryGetProperty("effectivePolicy", out var policy)) Row(html, "Policy metadata", "Not recorded");
        else
        {
            Row(html, "Blocking severities", JoinArray(policy, "blockingSeverities"));
            Row(html, "Secret findings block", Text(policy, "failOnSecrets", "Not recorded"));
            Row(html, "Maximum high findings", Text(policy, "maxHigh", "Not recorded"));
            Row(html, "Required scanners", Text(policy, "requiredScanners", "Not recorded"));
            Row(html, "Required categories", Text(policy, "requiredCategories", "Not recorded"));
            Row(html, "Coverage requirements", Text(policy, "coverageRequirements", "Not recorded"));
            Row(html, "Exceptions / suppressions", Text(policy, "exceptions", "Not recorded"));
            Row(html, "Configuration source", Text(policy, "configurationSource", "Not recorded"));
            Row(html, "Configuration hash", Text(policy, "configurationHash", "Not recorded"), true);
        }
        html.Append("</tbody></table></div><p class=\"muted\">Blocking findings are policy violations. Other findings remain follow-up work even when they do not affect the gate.</p></section>");
    }

    private static void AppendComparison(StringBuilder html, IReadOnlyDictionary<string, int>? counts)
    {
        if (counts is null) return;
        html.Append("<section aria-labelledby=\"comparison-heading\"><h2 id=\"comparison-heading\">Baseline comparison</h2><div class=\"cards\">");
        foreach (var state in new[] { "new", "existing", "changed", "resolved", "unverified" }) Card(html, state, counts.TryGetValue(state, out var value) ? value.ToString() : "Not recorded");
        html.Append("</div></section>");
    }

    private static void AppendRemediations(StringBuilder html, JsonElement remediations, HashSet<string> blockingIds)
    {
        html.Append("<section aria-labelledby=\"remediations-heading\"><h2 id=\"remediations-heading\">Prioritized remediations</h2>");
        if (remediations.ValueKind != JsonValueKind.Array || remediations.GetArrayLength() == 0) { html.Append("<p class=\"muted\">No remediation groups were recorded.</p></section>"); return; }
        foreach (var remediation in remediations.EnumerateArray())
        {
            var priority = Text(remediation, "priority", "unknown");
            html.Append("<article id=\"").Append(E(Text(remediation, "id", "remediation"))).Append("\" class=\"remediation\"><div class=\"remediation-heading\"><span class=\"priority ").Append(E(priority)).Append("\">").Append(E(priority)).Append("</span><h3>").Append(E(Text(remediation, "title", "Review finding"))).Append("</h3></div><p>").Append(E(Text(remediation, "summary", "Review the affected evidence and apply a supported correction."))).Append("</p>");
            html.Append("<dl class=\"facts compact\"><dt>Priority reason</dt><dd>").Append(E(JoinArray(remediation, "priorityReasons"))).Append("</dd><dt>Findings addressed</dt><dd>").Append(E(Text(remediation, "findingCount", "Not recorded"))).Append("</dd><dt>Affected files</dt><dd>").Append(E(JoinArray(remediation, "affectedFiles"))).Append("</dd>");
            var package = remediation.TryGetProperty("package", out var packageValue) ? packageValue : EmptyObject;
            if (package.ValueKind == JsonValueKind.Object)
            {
                html.Append("<dt>Package</dt><dd>").Append(E(Text(package, "ecosystem", "unknown ecosystem"))).Append(" / ").Append(E(Text(package, "name", "Not recorded"))).Append("</dd><dt>Current version</dt><dd>").Append(E(Text(package, "currentVersion", "Not recorded"))).Append("</dd><dt>Scanner-reported candidates</dt><dd>").Append(E(JoinArray(package, "candidateFixedVersions"))).Append("</dd><dt>Selected compatible candidate</dt><dd>").Append(E(Text(package, "recommendedVersion", "Not recorded"))).Append("</dd>");
            }
            html.Append("</dl><p><strong>Linked findings:</strong> ");
            foreach (var findingId in ArrayValues(remediation, "affectedFindings")) html.Append("<a class=\"chip ").Append(blockingIds.Contains(findingId) ? "danger" : "").Append("\" href=\"#").Append(E(findingId)).Append("\">").Append(E(findingId)).Append("</a> ");
            html.Append("</p><p class=\"muted\"><strong>Validation:</strong> ").Append(E(ValidationSuggestion(remediation))).Append("</p></article>");
        }
        html.Append("</section>");
    }

    private static void AppendCoverage(StringBuilder html, string reportDirectory, string outputPath, JsonElement summary, JsonElement scan, JsonDocument? project)
    {
        html.Append("<section aria-labelledby=\"coverage-heading\"><h2 id=\"coverage-heading\">Scanner coverage and limitations</h2>");
        if (summary.TryGetProperty("coverage", out var coverage) && coverage.TryGetProperty("warnings", out var warnings) && warnings.ValueKind == JsonValueKind.Array && warnings.GetArrayLength() > 0)
        {
            html.Append("<div class=\"notice\"><strong>Coverage warnings</strong><ul>");
            foreach (var warning in warnings.EnumerateArray()) html.Append("<li>").Append(E(warning.ValueKind == JsonValueKind.String ? warning.GetString() ?? "" : Text(warning, "message", warning.GetRawText()))).Append("</li>");
            html.Append("</ul></div>");
        }
        var summaryScanners = summary.TryGetProperty("coverage", out var summaryCoverage) && summaryCoverage.TryGetProperty("scanners", out var values) ? values : EmptyObject;
        if (!scan.TryGetProperty("scanners", out var scanners) || scanners.ValueKind != JsonValueKind.Array) { html.Append("<p class=\"muted\">Scanner execution metadata is not recorded.</p></section>"); return; }
        foreach (var scanner in scanners.EnumerateArray())
        {
            var name = Text(scanner, "name", "scanner");
            var coverageValue = scanner.TryGetProperty("coverage", out var rawCoverage) ? rawCoverage : EmptyObject;
            var compact = summaryScanners.ValueKind == JsonValueKind.Object && summaryScanners.TryGetProperty(name, out var compactValue) ? compactValue : EmptyObject;
            html.Append("<article class=\"scanner\"><div class=\"scanner-heading\"><h3>").Append(E(name)).Append("</h3><span class=\"status ").Append(E(Text(compact, "assessment", "unknown"))).Append("\">").Append(E(Text(compact, "assessment", "unknown"))).Append(" coverage</span></div><p><strong>Status:</strong> ").Append(E(Text(scanner, "status", "Not recorded"))).Append("; <strong>Version:</strong> ").Append(E(Text(scanner, "version", "Not recorded"))).Append("; <strong>Duration:</strong> ").Append(E(Duration(scanner))).Append("; <strong>Findings:</strong> ").Append(E(Text(scanner, "findingCount", "0"))).Append(".</p><p><strong>Reason:</strong> ").Append(E(ScannerReason(name, compact, coverageValue))).Append("</p>");
            AppendScannerScope(html, name, coverageValue);
            if (scanner.TryGetProperty("rawOutput", out var rawOutput) && rawOutput.ValueKind == JsonValueKind.String) html.Append("<p><strong>Raw output:</strong> ").Append(ArtifactLink(reportDirectory, outputPath, rawOutput.GetString()!)).Append("</p>");
            AppendDiagnostics(html, name, coverageValue);
            html.Append("</article>");
        }
        if (project is not null && project.RootElement.TryGetProperty("exclusions", out var exclusions) && exclusions.ValueKind == JsonValueKind.Array && exclusions.GetArrayLength() > 0)
        {
            html.Append("<details class=\"scanner\"><summary>Excluded paths ( ").Append(exclusions.GetArrayLength()).Append(" )</summary><ul>");
            foreach (var exclusion in exclusions.EnumerateArray()) html.Append("<li class=\"code\">").Append(E(Value(exclusion))).Append("</li>");
            html.Append("</ul></details>");
        }
        html.Append("</section>");
    }

    private static void AppendFindings(StringBuilder html, JsonElement findings, JsonElement remediations, HashSet<string> blockingIds)
    {
        html.Append("<section id=\"findings\" aria-labelledby=\"findings-heading\"><h2 id=\"findings-heading\">Findings</h2><div class=\"toolbar\"><label>Search <input id=\"finding-search\" type=\"search\" placeholder=\"title, package, path, ID\"></label><label>Severity <select id=\"finding-severity\"><option value=\"\">All</option>");
        foreach (var value in SeverityValues) html.Append("<option value=\"").Append(E(value)).Append("\">").Append(E(value)).Append("</option>");
        html.Append("</select></label><label>Category <select id=\"finding-category\"><option value=\"\">All</option>");
        foreach (var value in CategoryValues) html.Append("<option value=\"").Append(E(value)).Append("\">").Append(E(value)).Append("</option>");
        html.Append("</select></label><label>Scanner <select id=\"finding-scanner\"><option value=\"\">All</option></select></label><label><input id=\"finding-blocking\" type=\"checkbox\"> Blocking only</label><span id=\"finding-count\" class=\"muted\" aria-live=\"polite\"></span></div><div class=\"table-wrap\"><table id=\"findings-table\"><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Location</th><th>Scanners</th><th>Gate</th><th>Remediation</th></tr></thead><tbody>");
        var remediationMap = new Dictionary<string, (string Id, string Title)>(StringComparer.Ordinal);
        if (remediations.ValueKind == JsonValueKind.Array) foreach (var remediation in remediations.EnumerateArray()) foreach (var findingId in ArrayValues(remediation, "affectedFindings")) remediationMap[findingId] = (Text(remediation, "id", "remediation"), Text(remediation, "title", "Remediation"));
        if (findings.ValueKind == JsonValueKind.Array) foreach (var finding in findings.EnumerateArray()) AppendFinding(html, finding, remediationMap, blockingIds);
        html.Append("</tbody></table></div></section>");
    }

    private static void AppendFinding(StringBuilder html, JsonElement finding, IReadOnlyDictionary<string, (string Id, string Title)> remediationMap, HashSet<string> blockingIds)
    {
        var id = Text(finding, "id", "finding");
        var severity = Text(finding, "severity", "unknown");
        var category = Text(finding, "category", "unknown");
        var scanners = JoinArray(finding, "detectors");
        if (string.IsNullOrWhiteSpace(scanners) && finding.TryGetProperty("scanner", out var scanner)) scanners = Text(scanner, "name", "unknown");
        var blocking = blockingIds.Contains(id);
        var search = string.Join(" ", [Text(finding, "title"), Text(finding, "description"), Text(finding, "fingerprint"), Text(finding, "package.name"), Text(finding, "location.file"), scanners]);
        html.Append("<tr id=\"").Append(E(id)).Append("\" data-severity=\"").Append(E(severity)).Append("\" data-category=\"").Append(E(category)).Append("\" data-scanners=\"").Append(E(scanners.ToLowerInvariant())).Append("\" data-blocking=\"").Append(blocking ? "true" : "false").Append("\" data-search=\"").Append(E(search.ToLowerInvariant())).Append("\"><td><span class=\"severity ").Append(E(severity)).Append("\">").Append(E(severity)).Append("</span></td><td>").Append(E(category)).Append("</td><td><a href=\"#details-").Append(E(id)).Append("\">").Append(E(Text(finding, "title", "Untitled finding"))).Append("</a><details id=\"details-").Append(E(id)).Append("\"><summary>Evidence and context</summary>");
        AppendFindingDetails(html, finding);
        var remediationLink = remediationMap.TryGetValue(id, out var remediation) ? $"<a href=\"#{E(remediation.Id)}\">{E(remediation.Title)}</a>" : "<span class=\"muted\">Not recorded</span>";
        html.Append("</details></td><td class=\"code\">").Append(E(Text(finding, "location.file", "Not recorded"))).Append(LineSuffix(finding)).Append("</td><td>").Append(E(scanners)).Append("</td><td>").Append(blocking ? "<span class=\"chip danger\">BLOCKS GATE</span>" : "<span class=\"muted\">Follow-up</span>").Append("</td><td>").Append(remediationLink).Append("</td></tr>");
    }

    private static void AppendFindingDetails(StringBuilder html, JsonElement finding)
    {
        html.Append("<dl class=\"facts compact\"><dt>Stable ID</dt><dd class=\"code\">").Append(E(Text(finding, "id", "Not recorded"))).Append("</dd><dt>Fingerprint</dt><dd class=\"code\">").Append(E(Text(finding, "fingerprint", "Not recorded"))).Append("</dd><dt>Package / detected version</dt><dd>");
        if (finding.TryGetProperty("package", out var package) && package.ValueKind == JsonValueKind.Object) html.Append(E(Text(package, "ecosystem", "unknown ecosystem"))).Append(" / ").Append(E(Text(package, "name", "Not recorded"))).Append(" / ").Append(E(Text(package, "version", "Not recorded"))); else html.Append("Not recorded");
        html.Append("</dd><dt>CVEs / CWEs</dt><dd>").Append(E(JoinArray(finding, "security.cve"))).Append(" / ").Append(E(JoinArray(finding, "security.cwe"))).Append("</dd><dt>CVSS</dt><dd>").Append(E(Text(finding, "security.cvss", "Not recorded"))).Append("</dd><dt>Applicability</dt><dd>").Append(E(Text(finding, "applicability", "unknown"))).Append("</dd><dt>Reachability</dt><dd>").Append(E(Text(finding, "reachability", "unknown"))).Append("</dd><dt>Detection confidence</dt><dd>").Append(E(Text(finding, "detectionConfidence", "unknown"))).Append("; this describes detector confidence, not exploitability or reachability.</dd><dt>Vulnerable functionality use</dt><dd>Not confirmed by the available evidence.</dd>");
        if (finding.TryGetProperty("evidence", out var evidence))
        {
            var message = Text(evidence, "message");
            html.Append("<dt>Evidence</dt><dd>").Append(IsHttpUrl(message) ? SafeLink(message) : E(message)).Append("</dd>");
            foreach (var key in new[] { "snippet", "sourceExcerpt", "lines" }) if (evidence.TryGetProperty(key, out var value)) html.Append("<dt>").Append(E(key)).Append("</dt><dd class=\"code\">").Append(E(Value(value))).Append("</dd>");
        }
        html.Append("</dl><h4>Scanner evidence</h4><ul>");
        if (finding.TryGetProperty("scannerEvidence", out var evidenceList) && evidenceList.ValueKind == JsonValueKind.Array) foreach (var evidenceItem in evidenceList.EnumerateArray()) html.Append("<li><strong>").Append(E(Text(evidenceItem, "scanner", "unknown"))).Append("</strong> ").Append(E(Text(evidenceItem, "nativeId", ""))).Append("<br>").Append(E(Text(evidenceItem, "nativeTitle", "Advisory title not recorded"))).Append("<br><span class=\"muted\">").Append(E(Text(evidenceItem, "nativeDescription", "Description not recorded"))).Append("</span></li>"); else html.Append("<li>Not recorded</li>");
        html.Append("</ul>");
    }

    private static void AppendReproducibility(StringBuilder html, string reportDirectory, string outputPath, JsonElement scan, JsonElement summary)
    {
        html.Append("<section aria-labelledby=\"repro-heading\"><h2 id=\"repro-heading\">Reproducibility and artifacts</h2><div class=\"table-wrap\"><table><tbody>");
        Row(html, "Vesper version", Text(scan, "generator.version", "Not recorded"));
        Row(html, "Report schema", Text(summary, "schemaVersion", "Not recorded"));
        Row(html, "Finished", Text(scan, "finishedAt", "Not recorded"));
        Row(html, "Repository commit", Text(scan, "repository.commit", "Not recorded"), true);
        Row(html, "Repository branch", Text(scan, "repository.branch", "Not recorded"));
        Row(html, "Dirty working tree", Text(scan, "repository.dirty", "Not recorded"));
        Row(html, "Effective configuration hash", Text(summary, "effectivePolicy.configurationHash", "Not recorded"), true);
        Row(html, "Runner image digest", Text(scan, "runnerImageDigest", "Not recorded"), true);
        Row(html, "Ruleset / database metadata", Text(scan, "reproducibilityMetadata", "Not recorded"));
        html.Append("</tbody></table></div><p><strong>Artifacts:</strong> ");
        foreach (var artifact in new[] { "project.json", "scan.json", "summary.json", "findings.json", "remediations.json", "components.json", "comparison.json" }) if (File.Exists(Path.Combine(reportDirectory, artifact))) html.Append(ArtifactLink(reportDirectory, outputPath, artifact)).Append(" ");
        html.Append("</p></section>");
    }

    private static void AppendScannerScope(StringBuilder html, string name, JsonElement coverage)
    {
        html.Append("<dl class=\"facts compact\"><dt>Input and scope</dt><dd>");
        if (name.Equals("grype", StringComparison.OrdinalIgnoreCase)) html.Append("Analysis is scoped to the supplied SBOM: ").Append(E(Text(coverage, "input", "Not recorded"))).Append(". A zero-match result does not prove dependencies missing from that SBOM were checked.");
        else if (name.Equals("syft", StringComparison.OrdinalIgnoreCase)) html.Append("SBOM generated: ").Append(E(Text(coverage, "componentsProduced", "Not recorded"))).Append(" components. This is inventory generation, not vulnerability assessment.");
        else html.Append(E(ScopeText(coverage)));
        html.Append("</dd><dt>Metrics</dt><dd class=\"code\">").Append(E(ScalarMetrics(coverage))).Append("</dd></dl>");
    }

    private static void AppendDiagnostics(StringBuilder html, string name, JsonElement coverage)
    {
        if (!name.Equals("semgrep", StringComparison.OrdinalIgnoreCase) || !coverage.TryGetProperty("parseErrorFiles", out var errors) || errors.ValueKind != JsonValueKind.Array) return;
        html.Append("<details class=\"diagnostics\"><summary>Parse diagnostics ( ").Append(errors.GetArrayLength()).Append(" )</summary><table><thead><tr><th>Path</th><th>Type</th><th>Message</th></tr></thead><tbody>");
        foreach (var error in errors.EnumerateArray()) html.Append("<tr><td class=\"code\">").Append(E(Text(error, "path", "Not recorded"))).Append("</td><td>").Append(E(Text(error, "type", "Not recorded"))).Append("</td><td class=\"code\">").Append(E(Text(error, "message", "Not recorded"))).Append("</td></tr>");
        html.Append("</tbody></table></details>");
    }

    private static string GateExplanation(JsonElement gate, JsonElement findings)
    {
        var status = Text(gate, "status", "not evaluated");
        var ids = ReadStringSet(gate, "blockingFindingIds");
        if (status == "failed" && ids.Count > 0)
        {
            var counts = findings.ValueKind == JsonValueKind.Array ? findings.EnumerateArray().Where(item => ids.Contains(Text(item, "id"))).GroupBy(item => Text(item, "severity", "unknown")).OrderBy(item => item.Key).Select(item => $"{item.Count()} {item.Key}-severity") : [];
            var plural = ids.Count == 1 ? "finding violates" : "findings violate";
            return $"Security gate failed: {string.Join(", ", counts)} {plural} the configured policy.";
        }
        if (status == "passed") return "Security gate passed: no finding matched the configured blocking policy. This does not prove that no vulnerabilities exist.";
        if (status == "indeterminate") return "Security gate is indeterminate because required execution or coverage evidence is unavailable.";
        return "Security gate was not evaluated.";
    }

    private static string ExecutionExplanation(string status) => status switch { "completed" => "All applicable enabled scanner processes completed.", "incomplete" => "At least one applicable scanner failed, timed out, or lacked required input; this is separate from known policy blockers.", "cancelled" => "The scan was cancelled before all applicable analysis completed.", "failed" => "The scan runner failed before producing complete execution evidence.", _ => "Execution status is not recorded." };
    private static string CoverageExplanation(string assessment) => assessment switch { "complete" => "The declared applicable scope has complete measured coverage.", "partial" => "Some declared scope was analyzed, but parse errors, exclusions, or unsupported inputs limit coverage.", _ => "Coverage is unknown within the declared scope because available scanner evidence lacks a valid completeness measure." };
    private static string ScannerReason(string name, JsonElement compact, JsonElement coverage) { var reason = Text(compact, "reason"); if (!string.IsNullOrWhiteSpace(reason)) return reason; if (name.Equals("syft", StringComparison.OrdinalIgnoreCase)) return "Inventory generation completed; component presence does not establish vulnerability coverage."; if (name.Equals("grype", StringComparison.OrdinalIgnoreCase)) return "Analysis is bounded by the supplied Syft SBOM and its input assessment."; return Text(compact, "assessment", "unknown") == "unknown" ? "Scanner output did not expose enough metrics to measure coverage." : "Coverage classification is based on the retained scanner metrics."; }
    private static string ScopeText(JsonElement coverage) { var values = new List<string>(); foreach (var key in new[] { "filesDiscovered", "filesAnalyzed", "attemptedFiles", "componentsProduced", "resultSourcesWithFindings" }) if (coverage.TryGetProperty(key, out var value)) values.Add($"{key}: {Value(value)}"); if (coverage.TryGetProperty("candidateArtifacts", out var artifacts) && artifacts.ValueKind == JsonValueKind.Array) values.Add($"eligible artifacts: {artifacts.GetArrayLength()}"); return values.Count == 0 ? "Not recorded" : string.Join("; ", values); }
    private static string ScalarMetrics(JsonElement element) { var values = new List<string>(); if (element.ValueKind == JsonValueKind.Object) foreach (var property in element.EnumerateObject()) if (property.Value.ValueKind is JsonValueKind.Number or JsonValueKind.String or JsonValueKind.True or JsonValueKind.False) values.Add($"{property.Name}={Value(property.Value)}"); return values.Count == 0 ? "Not recorded" : string.Join("; ", values); }
    private static string ValidationSuggestion(JsonElement remediation) => Text(remediation, "type") == "container_hardening" ? "Review affected Dockerfiles and verify orchestrator health probes before applying a blanket change." : remediation.TryGetProperty("package", out var package) && package.ValueKind == JsonValueKind.Object ? "Apply a scanner-reported candidate, restore dependencies, and rerun relevant scanners; candidates are not verified latest or universally compatible." : "Review linked evidence, apply the rule-specific correction, and rerun the relevant scanner.";
    private static string LineSuffix(JsonElement finding) => finding.TryGetProperty("location", out var location) && location.TryGetProperty("line", out var line) && line.ValueKind != JsonValueKind.Null ? $":{E(Value(line))}" : "";
    private static string Duration(JsonElement element) => element.TryGetProperty("durationMs", out var value) && value.ValueKind == JsonValueKind.Number ? $"{value.GetInt64() / 1000d:0.0}s" : "Not recorded";
    private static void Assessment(StringBuilder html, string label, string value, string explanation) => html.Append("<div class=\"assessment card\"><div class=\"label\">").Append(E(label)).Append("</div><div class=\"assessment-value ").Append(E(value)).Append("\">").Append(E(value)).Append("</div><p>").Append(E(explanation)).Append("</p></div>");
    private static void Card(StringBuilder html, string label, string value) => html.Append("<div class=\"card\"><div class=\"label\">").Append(E(label)).Append("</div><div class=\"value\">").Append(E(value)).Append("</div></div>");
    private static void Row(StringBuilder html, string label, string value, bool code = false) => html.Append("<tr><th scope=\"row\">").Append(E(label)).Append("</th><td class=\"").Append(code ? "code" : "").Append("\">").Append(E(value)).Append("</td></tr>");
    private static string Text(JsonElement element, string path, string fallback = "") { var value = Get(element, path); return value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null ? fallback : Value(value); }
    private static JsonElement Get(JsonElement element, string path) { foreach (var part in path.Split('.')) { if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(part, out element)) return default; } return element; }
    private static string Value(JsonElement value) => value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.ValueKind == JsonValueKind.Null ? "Not recorded" : value.ToString();
    private static string JoinArray(JsonElement element, string path) { var value = Get(element, path); return value.ValueKind == JsonValueKind.Array ? string.Join(", ", value.EnumerateArray().Select(Value)) : value.ValueKind == JsonValueKind.Undefined ? "Not recorded" : Value(value); }
    private static IEnumerable<string> ArrayValues(JsonElement element, string path) { var value = Get(element, path); return value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().Select(Value) : []; }
    private static HashSet<string> ReadStringSet(JsonElement element, string property) => new(ArrayValues(element, property), StringComparer.Ordinal);
    private static string DerivedProjectName(string reportDirectory) => Directory.GetParent(reportDirectory)?.Parent?.Parent?.Name ?? "";
    private static string E(string value) => WebUtility.HtmlEncode(value);
    private static readonly JsonElement EmptyObject = default;
    private static JsonDocument Load(string directory, string name) => JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, name)));
    private static JsonDocument? LoadOptional(string directory, string name) => File.Exists(Path.Combine(directory, name)) ? Load(directory, name) : null;
    private static string ArtifactLink(string reportDirectory, string outputPath, string relativeArtifact) { var root = Path.GetFullPath(reportDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar; var artifact = Path.GetFullPath(Path.Combine(reportDirectory, relativeArtifact.Replace('/', Path.DirectorySeparatorChar))); if (!artifact.StartsWith(root, StringComparison.OrdinalIgnoreCase) || !File.Exists(artifact)) return $"<span class=\"muted\">{E(relativeArtifact)} (missing)</span>"; var href = Path.GetRelativePath(Path.GetDirectoryName(outputPath) ?? ".", artifact).Replace(Path.DirectorySeparatorChar, '/'); return $"<a href=\"{E(href)}\">{E(relativeArtifact)}</a>"; }
    private static bool IsHttpUrl(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    private static string SafeLink(string value) => $"<a rel=\"noreferrer\" href=\"{E(value)}\">{E(value)}</a>";
    private static void AppendStyle(StringBuilder html) => html.Append("<style>:root{color-scheme:light}*{box-sizing:border-box}body{font:15px system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.45;color:#17202a;background:#f5f7fa;margin:0}main{max-width:1240px;margin:0 auto;padding:28px 20px 60px}.skip-link{position:absolute;left:-9999px}.skip-link:focus{left:12px;top:12px;background:#fff;padding:8px;z-index:3}h1{margin:0 0 5px;font-size:32px}h2{margin:32px 0 13px;font-size:21px;border-bottom:1px solid #d9e0e7;padding-bottom:7px}h3{margin:0;font-size:17px}h4{margin:16px 0 5px}.eyebrow{font-weight:700;color:#52606d;text-transform:uppercase;letter-spacing:.08em;font-size:12px}.muted{color:#596675}.hero{margin-bottom:20px}.cards,.assessment-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px}.card{background:#fff;border:1px solid #d9e0e7;border-radius:6px;padding:15px}.value{font-size:22px;font-weight:700;overflow-wrap:anywhere}.label{color:#596675;font-size:13px}.assessment-value{font-size:20px;font-weight:700;text-transform:uppercase}.passed,.complete{color:#18794e}.failed,.critical,.high{color:#b42318}.indeterminate,.unknown,.partial,.limited{color:#9a6700}.facts{display:grid;grid-template-columns:minmax(170px,240px) 1fr;gap:5px 14px;margin:16px 0}.facts dt{font-weight:700}.facts dd{margin:0;overflow-wrap:anywhere}.compact{font-size:14px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d9e0e7}th,td{text-align:left;vertical-align:top;padding:9px;border-bottom:1px solid #e5e9ef}th{background:#edf1f5;font-size:13px}tr:last-child td,tr:last-child th{border-bottom:0}.severity,.status{font-weight:700;text-transform:uppercase}.chip{display:inline-block;padding:2px 6px;border-radius:3px;background:#edf1f5;font-size:12px;font-weight:700;margin:2px}.danger{color:#b42318;background:#fde8e7}.notice{background:#fff8e6;border:1px solid #edc967;border-radius:5px;padding:12px;margin:12px 0}.remediation,.scanner{margin:12px 0;padding:15px;background:#fff;border:1px solid #d9e0e7;border-radius:6px}.remediation-heading,.scanner-heading{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.priority{font-weight:700;text-transform:uppercase;background:#eef2f6;padding:3px 7px;border-radius:3px}.toolbar{display:flex;gap:10px;align-items:end;flex-wrap:wrap;background:#edf1f5;border:1px solid #d9e0e7;padding:12px;margin-bottom:10px}.toolbar label{font-weight:600}.toolbar input,.toolbar select{display:block;margin-top:4px;padding:7px;border:1px solid #9aa8b6;border-radius:4px;background:#fff}.toolbar input[type=checkbox]{display:inline;margin:0}.code{font:13px ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-word}details{margin-top:8px}summary{cursor:pointer;font-weight:600}article:target{outline:3px solid #78a9d4}@media print{body{background:#fff}main{max-width:none;padding:0}.toolbar{display:none}.remediation,.scanner,.card,table{break-inside:avoid}a{color:#17202a;text-decoration:none}}@media(max-width:700px){.facts{grid-template-columns:1fr}}</style>");
    private static void AppendScript(StringBuilder html) => html.Append("<script>(function(){const rows=[...document.querySelectorAll('#findings-table tbody tr')],search=document.getElementById('finding-search'),severity=document.getElementById('finding-severity'),category=document.getElementById('finding-category'),scanner=document.getElementById('finding-scanner'),blocking=document.getElementById('finding-blocking'),count=document.getElementById('finding-count');[...new Set(rows.flatMap(r=>(r.dataset.scanners||'').split(', ').filter(Boolean)))].sort().forEach(s=>{const o=document.createElement('option');o.value=s;o.textContent=s;scanner.appendChild(o)});function apply(){const q=(search.value||'').toLowerCase(),s=severity.value,c=category.value,n=scanner.value,b=blocking.checked;let shown=0;rows.forEach(r=>{const ok=(!q||(r.dataset.search||'').includes(q))&&(!s||r.dataset.severity===s)&&(!c||r.dataset.category===c)&&(!n||(r.dataset.scanners||'').split(', ').includes(n))&&(!b||r.dataset.blocking==='true');r.hidden=!ok;if(ok)shown++});count.textContent=shown+' of '+rows.length+' findings shown'}[search,severity,category,scanner,blocking].forEach(e=>e.addEventListener('input',apply));apply()})();</script>");
}
