-- Databricks notebook source
-- MAGIC %md
-- MAGIC
-- MAGIC ## Lumina Cortex activity functions
-- MAGIC
-- MAGIC SQL twin of `lumina_cortex.vocabulary.ocsf_to_activity.activity_for`
-- MAGIC (vocabulary `lumina-vocab-2`). The map is frozen: a pair that is not listed
-- MAGIC returns NULL. The playground's normalized Zeek rows use `activity_id` 99,
-- MAGIC so they stay unnamed here.

-- COMMAND ----------

CREATE OR REPLACE FUNCTION lumina_vocabulary_version()
  RETURNS STRING
  COMMENT 'Frozen Lumina Cortex activity vocabulary tag.'
  RETURN 'lumina-vocab-2';

-- COMMAND ----------

CREATE OR REPLACE FUNCTION lumina_activity_name(class_uid INT, activity_id INT)
  RETURNS STRING
  COMMENT 'Maps an OCSF (class_uid, activity_id) pair to the Lumina Cortex activity name. Unknown pairs return NULL.'
  RETURN CASE
    WHEN class_uid = 4001 AND activity_id = 1 THEN 'Network: Connection Open'
    WHEN class_uid = 4001 AND activity_id = 2 THEN 'Network: Connection Close'
    WHEN class_uid = 4003 AND activity_id = 1 THEN 'DNS: Query'
    WHEN class_uid = 4003 AND activity_id = 2 THEN 'DNS: Response'
    WHEN class_uid = 1001 AND activity_id = 1 THEN 'Process: Launch'
    WHEN class_uid = 1001 AND activity_id = 2 THEN 'Process: Terminate'
    WHEN class_uid = 1001 AND activity_id = 3 THEN 'Process: Open'
    WHEN class_uid = 1005 AND activity_id = 1 THEN 'Module: Load'
    WHEN class_uid = 1002 AND activity_id = 1 THEN 'File: Read'
    WHEN class_uid = 1002 AND activity_id = 2 THEN 'File: Write'
    WHEN class_uid = 1002 AND activity_id = 3 THEN 'File: Delete'
    WHEN class_uid = 1002 AND activity_id = 4 THEN 'File: Create'
    WHEN class_uid = 1002 AND activity_id = 5 THEN 'File: Access'
    WHEN class_uid = 1003 AND activity_id = 1 THEN 'Registry: Modify'
    WHEN class_uid = 1003 AND activity_id = 2 THEN 'Registry: Create'
    WHEN class_uid = 1003 AND activity_id = 3 THEN 'Registry: Delete'
    WHEN class_uid = 3002 AND activity_id = 1 THEN 'Authentication: Logon'
    WHEN class_uid = 3002 AND activity_id = 2 THEN 'Authentication: Logon Failure'
    WHEN class_uid = 3002 AND activity_id = 3 THEN 'Authentication: Logoff'
    WHEN class_uid = 5001 AND activity_id = 1 THEN 'API: Call'
    WHEN class_uid = 5002 AND activity_id = 1 THEN 'Cloud: Activity'
    ELSE NULL
  END;
