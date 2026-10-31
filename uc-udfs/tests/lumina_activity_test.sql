-- Databricks notebook source
-- MAGIC %md
-- MAGIC
-- MAGIC ## Tests for `lumina_activity.sql`
-- MAGIC
-- MAGIC Each cell fails with `raise_error` and lists the failed cases. Create the functions from `../lumina_activity.sql` in the same schema first.

-- COMMAND ----------

SELECT if(lumina_vocabulary_version() = 'lumina-vocab-2', 'ok: lumina_vocabulary_version',
          raise_error(concat('lumina_vocabulary_version: ', coalesce(lumina_vocabulary_version(), 'NULL'))));

-- COMMAND ----------

SELECT if(count(*) = 0, 'ok: lumina_activity_name',
          raise_error(concat('lumina_activity_name: ', string(count(*)), ' failed: ', array_join(collect_list(failure), ' | '))))
FROM (
  SELECT concat(string(class_uid), '/', string(activity_id), ' => ', coalesce(actual, 'NULL'), ', expected ', coalesce(expected, 'NULL')) AS failure
  FROM (
    SELECT class_uid, activity_id, expected, lumina_activity_name(class_uid, activity_id) AS actual
    FROM VALUES
      (4001, 1, 'Network: Connection Open'),
      (4001, 2, 'Network: Connection Close'),
      (4003, 1, 'DNS: Query'),
      (4003, 2, 'DNS: Response'),
      (1001, 1, 'Process: Launch'),
      (1001, 2, 'Process: Terminate'),
      (1001, 3, 'Process: Open'),
      (1005, 1, 'Module: Load'),
      (1002, 1, 'File: Read'),
      (1002, 2, 'File: Write'),
      (1002, 3, 'File: Delete'),
      (1002, 4, 'File: Create'),
      (1002, 5, 'File: Access'),
      (1003, 1, 'Registry: Modify'),
      (1003, 2, 'Registry: Create'),
      (1003, 3, 'Registry: Delete'),
      (3002, 1, 'Authentication: Logon'),
      (3002, 2, 'Authentication: Logon Failure'),
      (3002, 3, 'Authentication: Logoff'),
      (5001, 1, 'API: Call'),
      (5002, 1, 'Cloud: Activity'),
      (4001, 99, CAST(NULL AS STRING)),
      (4002, 99, CAST(NULL AS STRING)),
      (0, 0, CAST(NULL AS STRING))
    AS t(class_uid, activity_id, expected)
  )
  WHERE actual IS DISTINCT FROM expected
);
