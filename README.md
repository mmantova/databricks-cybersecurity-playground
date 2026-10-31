# databricks-cybersecurity-playground

Different pieces of code related to doing cybersecurity on Databricks

* [uc-udfs](uc-udfs/) - cybersecurity-related user-defined functions for Unity Catalog.
* [lumina_cortex](lumina_cortex/) - Lumina Cortex 0.4.1, the process-mining hunting library (AGPL-3.0, see [NOTICE.md](NOTICE.md)). `uc-udfs/lumina_activity.sql` is the SQL form of its frozen activity map, and `dlt_modern_stuff/src/lumina_functions.py` re-exports `activity_for` and `assess_threat`.
* [vuln-info-ingest](vuln-info-ingest/) - ingestion of vulnerability data (CVE v5, GitHub advisories, OSV, CISA KEV) with Databricks Asset Bundles.

## Source code/supporting materials for blog posts

* [iocs-ingest](iocs-ingest/) - source code for ingesting data with Filebeat's Threat Intel module.
* [dlt_modern_stuff](dlt_modern_stuff/) - source code that demonstrates the use of latest feature of DLT (append flows, sinks, direct publishing).
* [graph-analytics-blog](graph-analytics-blog/) - source code for blog post "Graph analytics for cybersecurity data in the lakehouse".
* [threat-analyst-agentbricks](threat-analyst-agentbricks/) - an example of cybersecurity agent built on top of Databricks Agent Bricks.
* [web-graph-analysis](web-graph-analysis/) - source code for blog post "Scoring and clustering domain indicators with the Common Crawl web graph".
