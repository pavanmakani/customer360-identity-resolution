/* =====================================================================================
   Mal | Customer 360 — Identity Resolution (Silver layer)
   Engine     : Spark SQL on Apache Iceberg (run as dbt-glue models; shown here as plain SQL)
   Schedule   : Daily, T-1, gated by the core banking EOD-complete sensor in MWAA
   Author     : Makani Pavan

   Design principles (see Architecture Document, Section 1)
   1. Deterministic first. Banks have strong, KYC-verified keys; use them before any fuzzy logic.
   2. Never auto-merge on conflict. Conflicts are loaded, flagged and quarantined, then routed
      to Operations as a daily reconciliation queue. Nothing is dropped.
   3. A Mal-owned surrogate customer_key, minted once and kept stable across runs, with an
      xref table recording WHY every source record is linked (rule, confidence, validity).
   4. Idempotent. Re-running the same run_date produces the same keys and the same golden
      record (deterministic tie-breaks; no random UUIDs).
   5. Salesforce Leads without a CIF are NOT part of the golden record. They live in
      fact_onboarding until the customer is onboarded in core banking.

   Conventions
   - ${run_date}               : business date being processed (T-1), substituted by the DAG
   - pii_token(type, value)    : PySpark UDF, HMAC-SHA256 with a KMS-protected key held in
                                 AWS Secrets Manager. Returns '<TYPE>_v<keyver>_<hex>'.
                                 Spark SQL has no native HMAC, hence the UDF.
   - SCD2 columns              : valid_from_ts, valid_to_ts, current_record_indicator (BOOLEAN)
   ===================================================================================== */


/* -------------------------------------------------------------------------------------
   STEP 1 — Standardise identity anchors
   Matching quality is decided here. The same person must produce the same normalised
   value, or the HMAC tokens will not join.
   ------------------------------------------------------------------------------------- */

CREATE OR REPLACE TEMPORARY VIEW v_idr_anchor_documents AS
WITH docs AS (
    SELECT
        p.cif_id,
        p.party_key,
        d.doc_type_code,                                          -- EMIRATES_ID | PASSPORT
        d.issuing_country_code,
        d.expiry_date,
        d.is_verified,
        CASE
            WHEN d.doc_type_code = 'EMIRATES_ID'
                 THEN regexp_replace(d.doc_number, '[^0-9]', '')  -- strip dashes/spaces
            WHEN d.doc_type_code = 'PASSPORT'
                 THEN upper(regexp_replace(d.doc_number, '\\s', ''))
        END AS doc_number_norm
    FROM silver.dim_party p
    JOIN silver.dim_identification_document d
      ON d.party_key = p.party_key
     AND d.current_record_indicator = TRUE
    WHERE p.current_record_indicator = TRUE
      AND d.doc_type_code IN ('EMIRATES_ID', 'PASSPORT')
)
SELECT
    cif_id,
    party_key,
    doc_type_code,
    -- Emirates ID must be 15 digits starting 784; anything else is a DQ failure, not a match key
    CASE
        WHEN doc_type_code = 'EMIRATES_ID'
             AND doc_number_norm RLIKE '^784[0-9]{12}$'
             THEN pii_token('EID', doc_number_norm)
        WHEN doc_type_code = 'PASSPORT'
             AND doc_number_norm IS NOT NULL
             -- passport numbers are only unique per issuing country
             THEN pii_token('PPT', concat(issuing_country_code, '|', doc_number_norm))
    END AS anchor_token,
    is_verified,
    expiry_date
FROM docs;


/* Mobile numbers to E.164 and lower-cased email, used for Salesforce corroboration and
   (post-launch) probabilistic matching of Leads. */
CREATE OR REPLACE TEMPORARY VIEW v_idr_contact_points AS
SELECT
    cp.contact_point_key,
    cp.customer_key,
    cp.source_system,
    cp.source_id,
    cp.contact_type_code,                                         -- EMAIL | MOBILE | ADDRESS
    CASE
        WHEN cp.contact_type_code = 'EMAIL'
             THEN lower(trim(cp.contact_value))
        WHEN cp.contact_type_code = 'MOBILE' THEN
             CASE
                 WHEN regexp_replace(cp.contact_value, '[^0-9]', '') RLIKE '^05[0-9]{8}$'
                      THEN concat('+971', substr(regexp_replace(cp.contact_value, '[^0-9]', ''), 2))
                 WHEN regexp_replace(cp.contact_value, '[^0-9]', '') RLIKE '^00971[0-9]{9}$'
                      THEN concat('+', substr(regexp_replace(cp.contact_value, '[^0-9]', ''), 3))
                 WHEN regexp_replace(cp.contact_value, '[^0-9]', '') RLIKE '^971[0-9]{9}$'
                      THEN concat('+', regexp_replace(cp.contact_value, '[^0-9]', ''))
                 ELSE NULL                                        -- non-UAE / invalid: no match key
             END
        ELSE cp.contact_value
    END AS contact_value_norm,
    cp.is_primary,
    cp.is_verified,
    cp.is_deleted,
    cp.source_effective_ts
FROM silver.dim_contact_point cp
WHERE cp.current_record_indicator = TRUE;


/* -------------------------------------------------------------------------------------
   STEP 2 — Rule R1 (core banking ↔ core banking)
   Anchor hierarchy: verified Emirates ID first, passport as fallback.
   One person should have one CIF. If one anchor maps to more than one CIF, that is a
   conflict (e.g. a customer re-onboarded and received a second CIF). We do NOT merge.
   ------------------------------------------------------------------------------------- */

CREATE OR REPLACE TEMPORARY VIEW v_idr_r1_primary_anchor AS
SELECT cif_id, party_key, doc_type_code, anchor_token
FROM (
    SELECT
        a.*,
        row_number() OVER (
            PARTITION BY a.cif_id
            ORDER BY CASE a.doc_type_code WHEN 'EMIRATES_ID' THEN 1 ELSE 2 END,  -- EID beats passport
                     a.is_verified DESC,
                     a.expiry_date DESC                                       -- newest document
        ) AS rn
    FROM v_idr_anchor_documents a
    WHERE a.anchor_token IS NOT NULL
) ranked
WHERE rn = 1;


CREATE OR REPLACE TEMPORARY VIEW v_idr_r1_conflicts AS
SELECT
    anchor_token,
    collect_set(cif_id)     AS conflicting_cif_ids,
    count(DISTINCT cif_id)  AS cif_count
FROM v_idr_r1_primary_anchor
GROUP BY anchor_token
HAVING count(DISTINCT cif_id) > 1;


/* -------------------------------------------------------------------------------------
   STEP 3 — Mint stable customer_keys and maintain the xref
   customer_key is derived ONCE from the first source record that created the entity
   (core banking CIF). It is deterministic, so a re-run of the same day is idempotent, and
   it is persisted in the xref, so it never changes when attributes change.
   ------------------------------------------------------------------------------------- */

CREATE OR REPLACE TEMPORARY VIEW v_idr_corebanking_links AS
SELECT
    'COREBANKING'                                         AS source_system,
    r.cif_id                                              AS source_id,
    coalesce(
        x.customer_key,                                   -- already known: keep it
        concat('CUS_', substr(sha2(concat('COREBANKING|', r.cif_id), 256), 1, 24))
    )                                                     AS customer_key,
    CASE r.doc_type_code
        WHEN 'EMIRATES_ID' THEN 'R1_EID_EXACT'
        ELSE 'R1_PASSPORT_EXACT'
    END                                                   AS match_rule_code,
    CAST(1.00 AS DECIMAL(5,4))                            AS idr_confidence_score,
    (c.anchor_token IS NOT NULL)                          AS is_quarantined   -- conflict → quarantine
FROM v_idr_r1_primary_anchor r
LEFT JOIN v_idr_r1_conflicts c
       ON c.anchor_token = r.anchor_token
LEFT JOIN silver.xref_customer_identity x
       ON x.source_system = 'COREBANKING'
      AND x.source_id = r.cif_id
      AND x.current_record_indicator = TRUE;


/* -------------------------------------------------------------------------------------
   STEP 4 — Rule R2 (Salesforce ↔ core banking)
   Deterministic only: the CIF is written to Salesforce as an external ID at onboarding.
   - One SF account → one CIF  : link, confidence 1.0
   - One SF account → >1 CIF   : collision → quarantine the SF link (rule 10)
   - >1 SF account  → one CIF  : keep the most recently modified, flag the rest (rule 11)
   - SF record with no CIF     : a Lead; routed to fact_onboarding, not linked here
   ------------------------------------------------------------------------------------- */

CREATE OR REPLACE TEMPORARY VIEW v_idr_salesforce_links AS
WITH sf AS (
    SELECT
        salesforce_account_id,
        trim(cif_external_id)                       AS cif_id,
        last_modified_ts,
        count(DISTINCT trim(cif_external_id))
            OVER (PARTITION BY salesforce_account_id) AS cif_per_sf_account,
        row_number() OVER (
            PARTITION BY trim(cif_external_id)
            ORDER BY last_modified_ts DESC, salesforce_account_id ASC   -- deterministic tie-break
        )                                           AS rn_per_cif
    FROM silver.sf_person_account
    WHERE current_record_indicator = TRUE
      AND is_deleted = FALSE
      AND cif_external_id IS NOT NULL
)
SELECT
    'SALESFORCE'                                    AS source_system,
    sf.salesforce_account_id                        AS source_id,
    cb.customer_key,
    'R2_SF_EXTERNAL_ID'                             AS match_rule_code,
    CAST(1.00 AS DECIMAL(5,4))                      AS idr_confidence_score,
    (sf.cif_per_sf_account > 1 OR sf.rn_per_cif > 1 OR cb.is_quarantined) AS is_quarantined
FROM sf
JOIN v_idr_corebanking_links cb
  ON cb.source_id = sf.cif_id;                      -- unknown CIF on SF → no link; reported in Step 7


/* -------------------------------------------------------------------------------------
   STEP 5 — Rule R3 (Amplitude ↔ customer)
   Agreed standard with the app team: Amplitude user_id = Mal app user ID (pseudonymous,
   never the CIF), set at login. The app-user → CIF mapping comes from the digital channel
   registration table. Anonymous device_ids are stitched in 05_device_stitching (below).
   ------------------------------------------------------------------------------------- */

CREATE OR REPLACE TEMPORARY VIEW v_idr_amplitude_links AS
SELECT
    'AMPLITUDE'                                     AS source_system,
    m.app_user_id                                   AS source_id,
    cb.customer_key,
    'R3_APP_USER_ID'                                AS match_rule_code,
    CAST(1.00 AS DECIMAL(5,4))                      AS idr_confidence_score,
    cb.is_quarantined
FROM silver.map_app_user_cif m
JOIN v_idr_corebanking_links cb
  ON cb.source_id = m.cif_id
WHERE m.current_record_indicator = TRUE;


/* -------------------------------------------------------------------------------------
   STEP 6 — SCD2 merge into the xref
   xref_customer_identity: source_system, source_id → customer_key, match_rule_code,
   idr_confidence_score, is_quarantined, valid_from_ts, valid_to_ts, current_record_indicator
   ------------------------------------------------------------------------------------- */

CREATE OR REPLACE TEMPORARY VIEW v_idr_links_today AS
SELECT * FROM v_idr_corebanking_links
UNION ALL SELECT * FROM v_idr_salesforce_links
UNION ALL SELECT * FROM v_idr_amplitude_links;

-- 6a. Close current rows whose mapping changed (new key, rule, or quarantine status)
MERGE INTO silver.xref_customer_identity t
USING v_idr_links_today s
   ON t.source_system = s.source_system
  AND t.source_id     = s.source_id
  AND t.current_record_indicator = TRUE
WHEN MATCHED AND (   t.customer_key    <> s.customer_key
                  OR t.match_rule_code <> s.match_rule_code
                  OR t.is_quarantined  <> s.is_quarantined) THEN
  UPDATE SET t.valid_to_ts = to_timestamp('${run_date}'),
             t.current_record_indicator = FALSE;

-- 6b. Insert new and changed mappings as the current version
INSERT INTO silver.xref_customer_identity
SELECT
    s.source_system,
    s.source_id,
    s.customer_key,
    s.match_rule_code,
    s.idr_confidence_score,
    s.is_quarantined,
    to_timestamp('${run_date}')          AS valid_from_ts,
    to_timestamp('9999-12-31')           AS valid_to_ts,
    TRUE                                 AS current_record_indicator,
    '${run_date}'                        AS _batch_run_date
FROM v_idr_links_today s
LEFT JOIN silver.xref_customer_identity t
       ON t.source_system = s.source_system
      AND t.source_id     = s.source_id
      AND t.current_record_indicator = TRUE
WHERE t.source_id IS NULL;               -- not current after 6a → insert


/* -------------------------------------------------------------------------------------
   STEP 7 — Exception queue for Operations (daily reconciliation)
   Every conflict is visible and actionable; nothing is silently dropped.
   ------------------------------------------------------------------------------------- */

INSERT INTO silver.idr_exception_queue
SELECT
    sha2(concat_ws('|', exception_type_code, source_system, source_id, '${run_date}'), 256)
                                        AS exception_key,     -- idempotent: same day → same key
    exception_type_code,
    source_system,
    source_id,
    candidate_customer_keys,
    detail,
    to_date('${run_date}')              AS detected_date,
    'OPEN'                              AS status_code,
    CAST(NULL AS STRING)                AS resolved_by,
    CAST(NULL AS TIMESTAMP)             AS resolved_ts
FROM (
    -- Rule 9: two or more CIFs share an Emirates ID / passport
    SELECT 'MULTI_CIF_SAME_ANCHOR' AS exception_type_code, 'COREBANKING' AS source_system,
           array_join(c.conflicting_cif_ids, ',') AS source_id,
           CAST(NULL AS ARRAY<STRING>) AS candidate_customer_keys,
           concat('cif_count=', c.cif_count) AS detail
    FROM v_idr_r1_conflicts c

    UNION ALL
    -- Rules 10/11: Salesforce external-ID collision or duplicate SF accounts for one CIF
    SELECT 'SF_XREF_CONFLICT', 'SALESFORCE', l.source_id,
           array(l.customer_key), 'salesforce link quarantined'
    FROM v_idr_salesforce_links l
    WHERE l.is_quarantined

    UNION ALL
    -- Salesforce carries a CIF that core banking does not know (typo or test data in CRM)
    SELECT 'SF_UNKNOWN_CIF', 'SALESFORCE', sf.salesforce_account_id,
           CAST(NULL AS ARRAY<STRING>), concat('cif_external_id=', sf.cif_external_id)
    FROM silver.sf_person_account sf
    LEFT JOIN v_idr_corebanking_links cb ON cb.source_id = trim(sf.cif_external_id)
    WHERE sf.current_record_indicator = TRUE
      AND sf.cif_external_id IS NOT NULL
      AND cb.source_id IS NULL
) e
-- do not re-raise an exception that is already open
WHERE NOT EXISTS (
    SELECT 1 FROM silver.idr_exception_queue q
    WHERE q.exception_type_code = e.exception_type_code
      AND q.source_system = e.source_system
      AND q.source_id = e.source_id
      AND q.status_code = 'OPEN'
);


/* -------------------------------------------------------------------------------------
   STEP 8 — Survivorship → golden record (dim_customer)
   Config-driven: rules live in the dbt seed ref_survivorship_rule.csv, not in code.
     strategy = PRIORITY          : lowest source_priority wins (identity/KYC: core banking)
     strategy = VERIFIED_RECENCY  : verified > most recent verified (source effective time,
                                    never ingest time) > source priority (contact points)
   Final tie-break on every strategy: lowest source_record_id → deterministic, idempotent.
   Amplitude never competes for identity or contact attributes (rule 15).
   ------------------------------------------------------------------------------------- */

CREATE OR REPLACE TEMPORARY VIEW v_survivorship_candidates AS
-- Core banking identity / KYC attributes, unpivoted to (attribute, value) rows
SELECT x.customer_key, 'COREBANKING' AS source_system, p.cif_id AS source_record_id,
       attr.attribute_name, attr.attribute_value,
       TRUE AS is_verified, p.source_updated_ts AS source_effective_ts
FROM silver.dim_party p
JOIN silver.xref_customer_identity x
  ON x.source_system = 'COREBANKING' AND x.source_id = p.cif_id
 AND x.current_record_indicator = TRUE AND x.is_quarantined = FALSE
LATERAL VIEW stack(5,
    'full_name',        p.full_name,
    'date_of_birth',    CAST(p.date_of_birth AS STRING),
    'nationality_code', p.nationality_code,
    'gender_code',      p.gender_code,
    'language_code',    p.language_code
) attr AS attribute_name, attribute_value
WHERE p.current_record_indicator = TRUE

UNION ALL
-- Salesforce: the same attributes, used only to fill gaps (rule 6) or raise mismatches (rule 4)
SELECT x.customer_key, 'SALESFORCE', sf.salesforce_account_id,
       attr.attribute_name, attr.attribute_value,
       FALSE, sf.last_modified_ts
FROM silver.sf_person_account sf
JOIN silver.xref_customer_identity x
  ON x.source_system = 'SALESFORCE' AND x.source_id = sf.salesforce_account_id
 AND x.current_record_indicator = TRUE AND x.is_quarantined = FALSE
LATERAL VIEW stack(4,
    'full_name',     concat_ws(' ', sf.first_name, sf.last_name),
    'date_of_birth', CAST(sf.birthdate AS STRING),
    'language_code', sf.preferred_language_code,
    'marketing_channel_code', sf.preferred_channel_code
) attr AS attribute_name, attribute_value
WHERE sf.current_record_indicator = TRUE AND sf.is_deleted = FALSE

UNION ALL
-- Contact points from both systems (rule 5: verified > recency > core banking)
SELECT cp.customer_key, cp.source_system, cp.source_id,
       concat('primary_', lower(cp.contact_type_code)) AS attribute_name,   -- primary_email, primary_mobile
       cp.contact_value_norm, cp.is_verified, cp.source_effective_ts
FROM v_idr_contact_points cp
WHERE cp.is_primary = TRUE
  AND cp.is_deleted = FALSE                                                 -- rule 14
  AND cp.contact_type_code IN ('EMAIL', 'MOBILE');


CREATE OR REPLACE TEMPORARY VIEW v_survivorship_ranked AS
SELECT
    c.*,
    r.strategy,
    r.source_priority,
    row_number() OVER (
        PARTITION BY c.customer_key, c.attribute_name
        ORDER BY
            CASE WHEN r.strategy = 'VERIFIED_RECENCY' THEN CAST(c.is_verified AS INT) END DESC NULLS LAST,
            CASE WHEN r.strategy = 'VERIFIED_RECENCY' THEN c.source_effective_ts END        DESC NULLS LAST,
            r.source_priority  ASC,
            c.source_record_id ASC                                         -- rule 12
    ) AS survivor_rank,
    count(DISTINCT c.attribute_value)
        OVER (PARTITION BY c.customer_key, c.attribute_name) AS distinct_value_count
FROM v_survivorship_candidates c
JOIN silver.ref_survivorship_rule r
  ON r.attribute_name = c.attribute_name
 AND r.source_system  = c.source_system
WHERE c.attribute_value IS NOT NULL;                                        -- rules 6–8: nulls never win


-- Attribute-level lineage: which source won, and whether sources agreed (rule 3)
INSERT OVERWRITE silver.customer_attribute_lineage
SELECT
    customer_key,
    attribute_name,
    source_system           AS winning_source_system,
    source_record_id        AS winning_source_record_id,
    strategy                AS survivorship_strategy,
    (distinct_value_count = 1 AND candidate_count > 1) AS is_corroborated,
    (distinct_value_count > 1)                         AS has_source_mismatch,
    to_date('${run_date}')  AS snapshot_date
FROM (
    SELECT r.*,
           count(*) OVER (PARTITION BY customer_key, attribute_name) AS candidate_count
    FROM v_survivorship_ranked r
) ranked
WHERE survivor_rank = 1;


-- Mismatches go to the same Ops queue (rules 4 and 5)
INSERT INTO silver.idr_exception_queue
SELECT DISTINCT
    sha2(concat_ws('|', 'ATTRIBUTE_MISMATCH', customer_key, attribute_name, '${run_date}'), 256),
    CASE WHEN attribute_name LIKE 'primary_%' THEN 'CONTACT_MISMATCH' ELSE 'KYC_MISMATCH' END,
    'C360', customer_key, array(customer_key),
    concat('attribute=', attribute_name),
    to_date('${run_date}'), 'OPEN', CAST(NULL AS STRING), CAST(NULL AS TIMESTAMP)
FROM v_survivorship_ranked
WHERE distinct_value_count > 1
  AND attribute_name IN ('full_name', 'date_of_birth', 'primary_email', 'primary_mobile');


-- Pivot survivors into the golden record. dbt's custom SCD2 macro then compares this
-- snapshot with silver.dim_customer and versions changed rows (valid_from_ts / valid_to_ts /
-- current_record_indicator), exactly like every other SCD2 dimension.
CREATE OR REPLACE TEMPORARY VIEW v_dim_customer_snapshot AS
SELECT
    s.customer_key,
    max(CASE WHEN attribute_name = 'full_name'              THEN attribute_value END) AS full_name,
    CAST(max(CASE WHEN attribute_name = 'date_of_birth'     THEN attribute_value END) AS DATE) AS date_of_birth,
    max(CASE WHEN attribute_name = 'nationality_code'       THEN attribute_value END) AS nationality_code,
    max(CASE WHEN attribute_name = 'gender_code'            THEN attribute_value END) AS gender_code,
    max(CASE WHEN attribute_name = 'language_code'          THEN attribute_value END) AS language_code,
    max(CASE WHEN attribute_name = 'marketing_channel_code' THEN attribute_value END) AS marketing_channel_code,
    max(CASE WHEN attribute_name = 'primary_email'          THEN attribute_value END) AS primary_email,
    max(CASE WHEN attribute_name = 'primary_mobile'         THEN attribute_value END) AS primary_mobile,
    -- C3 identifiers are carried ONLY as tokens from here on
    max(a.anchor_token)                                                              AS emirates_id_token,
    max(x.source_id)                                                                 AS primary_cif_id,
    CAST(1.00 AS DECIMAL(5,4))                                                       AS idr_confidence_score,
    FALSE                                                                            AS idr_is_entity_conflict
FROM v_survivorship_ranked s
JOIN silver.xref_customer_identity x
  ON x.customer_key = s.customer_key AND x.source_system = 'COREBANKING'
 AND x.current_record_indicator = TRUE
LEFT JOIN v_idr_r1_primary_anchor a
  ON a.cif_id = x.source_id AND a.doc_type_code = 'EMIRATES_ID'
WHERE s.survivor_rank = 1
GROUP BY s.customer_key;
-- Quarantined customers are still loaded (from xref, is_quarantined = TRUE) with
-- idr_is_entity_conflict = TRUE and idr_confidence_score = 0, so they are visible in
-- Customer 360 and excluded from CAR training sets by the AI data contract filter.


/* -------------------------------------------------------------------------------------
   STEP 9 — Amplitude device stitching (behavioural signals → customer)
   Before login, events carry only device_id. At login, a user_id is attached.
   We link the device to the customer from the first login, and back-fill that device's
   anonymous events from the 3-day late-arrival window ONLY if the device has never been
   linked to anyone else (shared or second-hand phones must not leak behaviour).
   ------------------------------------------------------------------------------------- */

MERGE INTO silver.bridge_customer_device t
USING (
    SELECT
        x.customer_key,
        e.device_key,
        min(e.event_ts) AS first_linked_ts,
        max(e.event_ts) AS last_seen_ts
    FROM silver.fact_app_event e
    JOIN silver.xref_customer_identity x
      ON x.source_system = 'AMPLITUDE'
     AND x.source_id = e.amplitude_user_id
     AND x.current_record_indicator = TRUE
    WHERE e.event_date BETWEEN date_sub(to_date('${run_date}'), 3) AND to_date('${run_date}')
    GROUP BY x.customer_key, e.device_key
) s
ON t.customer_key = s.customer_key AND t.device_key = s.device_key
WHEN MATCHED THEN UPDATE SET t.last_seen_ts = greatest(t.last_seen_ts, s.last_seen_ts)
WHEN NOT MATCHED THEN INSERT (customer_key, device_key, first_linked_ts, last_seen_ts)
                      VALUES (s.customer_key, s.device_key, s.first_linked_ts, s.last_seen_ts);

MERGE INTO silver.fact_app_event t
USING (
    SELECT b.device_key, max(b.customer_key) AS customer_key
    FROM silver.bridge_customer_device b
    GROUP BY b.device_key
    HAVING count(DISTINCT b.customer_key) = 1          -- single-owner devices only
) s
ON  t.device_key = s.device_key
AND t.customer_key IS NULL
AND t.event_date BETWEEN date_sub(to_date('${run_date}'), 3) AND to_date('${run_date}')
WHEN MATCHED THEN UPDATE SET
    t.customer_key = s.customer_key,
    t.is_stitched  = TRUE;                             -- stitched events stay distinguishable


/* =====================================================================================
   POST-LAUNCH (Phase 2) — probabilistic matching for Salesforce Leads
   Not in Q2 scope by design. Leads stay in fact_onboarding until they get a CIF. Phase 2
   adds Fellegi–Sunter scoring (Splink on Spark) so marketing can see likely existing
   customers among new Leads. Sketch of the logic, for review:

   1. Block   : candidate pairs only where (mobile_e164 equal) OR (email equal)
                OR (date_of_birth equal AND soundex(last_name) equal)
   2. Compare : per field level → exact / Jaro-Winkler ≥ 0.92 / ≥ 0.80 / else / null
   3. Score   : match_weight = Σ log2(m/u) for agreeing levels + Σ log2((1-m)/(1-u)) for
                disagreeing ones; m and u estimated by EM (Splink), u by random sampling
   4. Classify: probability ≥ 0.99 → suggested link (still reviewed in v2)
                0.80–0.99           → steward review queue
                < 0.80              → no link
   5. Never auto-merge: a false merge exposes one customer's data to another and
      corrupts KYC/AML views, so precision beats recall.
   ===================================================================================== */
