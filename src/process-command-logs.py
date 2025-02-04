# Databricks notebook source
# MAGIC %pip install pyre-check

# COMMAND ----------

import pyspark.sql.functions as F
from pyspark.sql import Window

# COMMAND ----------

# adjust accordingly, could be job parameters

lookback_days = 90
audit_log_table = "system.access.audit"

# COMMAND ----------

# get all successful notebook commands for the last day
commands = (spark.read.table(audit_log_table)
            .filter(F.col("service_name").isin('notebook')
                    &
                    F.col("action_name").isin('runCommand', 'attachNotebook', 'detachNotebook', 'runStart', 'runFailed', 'runSucceeded'))
            .filter(f"event_date >= current_date() - interval {lookback_days} days")
            .filter(F.col("request_params.path").isNotNull() | ~F.col("request_params.commandText").startswith("%")))

# COMMAND ----------

# sessionize based on attach events
sessionized = (commands
               .withColumn("notebook_path", F.when(F.col("action_name") == "attachNotebook", F.col("request_params.path")).otherwise(None))
               .withColumn("session_started", F.col("action_name").isin("attachNotebook"))
               .withColumn("session_id", F.sum(F.when(F.col("session_started"), 1).otherwise(0)).over(Window.partitionBy("request_params.notebookId").orderBy("event_time")))
               .withColumn("notebook_path", F.first("notebook_path").over(Window.partitionBy("session_id", "request_params.notebookId").orderBy("event_time"))))

# COMMAND ----------

combined = (sessionized
            .select(
                "event_time",
                "notebook_path",
                "user_identity.email",
                "session_id",
                F.col("request_params.notebookId").alias("notebook_id"),
                F.col("request_params.commandId").alias("command_id"),
                F.col("request_params.commandText").alias("command_text"),
                F.col("request_params.commandLanguage").alias("command_language")
            )
            .filter("command_id is not null and command_language = 'python'")
            .groupBy("notebook_id", "notebook_path", "email", "session_id")
            .agg(F.collect_list(F.concat(F.lit("## command_id: "), F.col("command_id"), F.lit("\n"), F.col("command_text"))).alias("command_texts"))
            .withColumn("command_texts", F.array_join("command_texts", "\n")))

# COMMAND ----------

pdf_combined = combined.toPandas()

if len(pdf_combined) == 0:
    print("WARNING: No commands found in audit logs!")

# COMMAND ----------

import os

conf_path = os.path.abspath("../conf")
stubs_path = os.path.abspath("../conf/stubs")

scanner_path = "/tmp/code-scanning"

code_base_path = "code"

pyre_config_path = os.path.join(scanner_path, ".pyre_configuration")

output_path = os.path.join(scanner_path, "pysa-output")

# COMMAND ----------

import ast
import shutil

# we attempt to parse the line to check if it's valid
# Python code
def verify_is_python(code):
    try:
        ast.parse(code)
    except:
        return False
    
    return True

# clean up any existing notebook code

code_output_path = os.path.join(scanner_path, code_base_path)

shutil.rmtree(code_output_path, ignore_errors=True)

os.makedirs(code_output_path, exist_ok=True)

# iterate over the results, write the code out to files based on notebook id and session id
for row in pdf_combined.itertuples():
    # command_id = row.command_id
    command_text = row.command_texts
    notebook_path = row.notebook_path
    notebook_id = row.notebook_id
    session_id = str(row.session_id)

    if notebook_path is None:
        continue

    print(f'Write code for {notebook_path} {session_id}')
    
    if verify_is_python(command_text):
        code_path = "/".join([code_output_path, notebook_path, session_id])

        os.makedirs(code_path, exist_ok=True)

        with open(f"{code_path}/code.py", "w") as f:
            f.write(f"{command_text}\n\n")
    else:
        print(f'Skipping {notebook_path} {session_id} because it is not valid Python code')

# COMMAND ----------

import sys
import json

# generate a Pyre config file to use for scanning
# we set the paths for dependencies and stubs
# note that if you have common 3rd party or custom libraries you should install them so they get indexed by Pyre
pyre_config = {
    "site_package_search_strategy": "pep561",
    "source_directories": [
        code_base_path
    ],
    "taint_models_path": [
        conf_path,
        os.path.join(os.environ['VIRTUAL_ENV'], "lib/pyre_check/taint"),
        os.path.join(os.environ['VIRTUAL_ENV'], "lib/pyre_check/third_party_taint")
    ],
    "search_path": [
        "/databricks/spark/python/",
        stubs_path
    ],
    "workers": 4
}

with open(pyre_config_path, 'w') as f:
    f.write(json.dumps(pyre_config, indent=2))

# COMMAND ----------

import subprocess

# clean up any existing output
shutil.rmtree(output_path, ignore_errors=True)

# run pysa scan
run = subprocess.run(["pyre", "-n", "--output", "json", "analyze", "--no-verify", "--save-results-to", output_path], cwd=scanner_path)

if run.returncode != 0:
    print("pyre scan failed, please review the logs for issues!")

# COMMAND ----------

subprocess.run(["tar", "-czf", "code.tar.gz", code_base_path], cwd=scanner_path)

app_path = "/Workspace/Users/example@databricks.com/databricks_apps/sapp/" # CHANGE

shutil.copy(os.path.join(scanner_path, "code.tar.gz"), os.path.join(app_path, "code.tar.gz"))

# COMMAND ----------

# MAGIC %pip install fb-sapp

# COMMAND ----------

subprocess.run(["sapp", "--database-name", "sapp.db", "analyze", output_path], cwd=scanner_path)

# COMMAND ----------

shutil.copy(os.path.join(scanner_path, "sapp.db"), os.path.join(app_path, "sapp.db"))

# COMMAND ----------
