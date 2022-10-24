# Databricks Notebook Command Monitoring

Example of using open source static analysis tools to monitor notebook command logs for security

## Background

This uses the Databricks [verbose notebook audit logs](https://docs.databricks.com/administration-guide/account-settings/audit-logs.html#configure-verbose-audit-logs) to process commands and run them through a static analysis tool to detect possible security issues.
For this example, it uses the [Pyre/Pysa](https://pyre-check.org/) static analysis tool as it has data and control flow analysis with built-in rules for security and the ability to
define custom rules. We've included some example configurations for Databricks notebooks under `conf/` to enable signatures for [dbutils](https://docs.databricks.com/dev-tools/databricks-utils.html), and the Spark DataFrame API as well as taint configurations.

## Instructions

Clone this project into a Databricks [repo](https://docs.databricks.com/repos/index.html), attach to a standard or single-user cluster with permissions to read your workspace audit logs. This assumes you've already enabled verbose audit logs and ingested them into a Delta Lake table. Open the `src/process-command-logs.py` file in Databricks and attach to your cluster. You can change the `lookback_days` and `audit_log_table` parameters based on your environment. Then use `Run All` which will process the audit logs, process them through Pyre/Pysa and generate an embedded report.