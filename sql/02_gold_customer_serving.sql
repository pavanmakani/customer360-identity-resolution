/* =====================================================================================
   Mal | Customer 360 — Gold serving layer (Amazon Redshift)
   Engine     : Amazon Redshift (built by dbt-redshift; shown here as plain SQL)
   Purpose    : Serve the golden record and CAR with PII masking and consent controls
   Author     : Makani Pavan

   Classification → protection (Architecture Document, Section 3)
     C1 Internal        : clear for everyone with access
     C2 Personal        : clear in Gold, masked by Redshift Dynamic Data Masking per role
     C3 Sensitive       : never clear in Gold — HMAC tokens only (tokenised in Silver)
     C4 Restricted      : not in Customer 360 / CAR at all (Compliance mart, Phase 2)

   Access tiers (Redshift roles, mapped 1:1 to IAM Identity Center groups; with Identity
   Center integration the role names are prefixed, e.g. "AWSIDC:c360-t2-operational")
     t0_aggregate       : BI consumers           → aggregates only, all PII masked
     t1_pseudonymised   : Product, AI team        → tokens + masked C2
     t2_operational     : Customer support        → clear C2, last-4 of C3
     t3_privileged      : KYC / compliance        → clear C2; C3 detokenisation via vault service

   PK/FK in Redshift are informational, not enforced. Integrity is enforced by dbt tests
   (unique, not_null, relationships, accepted_values) that fail the pipeline.
   ===================================================================================== */


/* -------------------------------------------------------------------------------------
   1. Silver (Iceberg on S3) exposed to Redshift through the Glue Data Catalog
   ------------------------------------------------------------------------------------- */
CREATE EXTERNAL SCHEMA IF NOT EXISTS silver_ext
FROM DATA CATALOG
DATABASE 'silver'
IAM_ROLE 'arn:aws:iam::<account_id>:role/c360-redshift-spectrum-reader';


/* -------------------------------------------------------------------------------------
   2. Golden record table
   ------------------------------------------------------------------------------------- */
CREATE TABLE IF NOT EXISTS gold.dim_customer (
    customer_key              VARCHAR(40)   NOT NULL,   -- PK (informational)
    primary_cif_id            VARCHAR(256),             -- C2: internal reference, masked for T0/T1
    emirates_id_token         VARCHAR(256),             -- C3: token only
    full_name                 VARCHAR(256),             -- C2
    date_of_birth             DATE,                     -- C2 (year only for T1)
    nationality_code          VARCHAR(3),               -- C2, allowed_for_credit_decisioning = false
    gender_code               VARCHAR(1),               -- C2, allowed_for_credit_decisioning = false
    language_code             VARCHAR(5),               -- C1
    marketing_channel_code    VARCHAR(20),              -- C1
    primary_email             VARCHAR(256),             -- C2
    primary_mobile            VARCHAR(256),             -- C2
    idr_confidence_score      DECIMAL(5,4),
    idr_is_entity_conflict    BOOLEAN,
    valid_from_ts             TIMESTAMP     NOT NULL,
    valid_to_ts               TIMESTAMP     NOT NULL,
    current_record_indicator  BOOLEAN       NOT NULL,
    PRIMARY KEY (customer_key, valid_from_ts)
)
DISTSTYLE AUTO
SORTKEY (customer_key);


-- Daily refresh (dbt-redshift incremental model). Silver owns the SCD2 logic; Gold mirrors
-- every version that was opened or closed in the last 3 days (covers late re-runs).
-- MERGE keeps the table object, so masking policies stay attached (a table swap would drop them).
MERGE INTO gold.dim_customer
USING (
    SELECT customer_key, primary_cif_id, emirates_id_token, full_name, date_of_birth,
           nationality_code, gender_code, language_code, marketing_channel_code,
           primary_email, primary_mobile, idr_confidence_score, idr_is_entity_conflict,
           valid_from_ts, valid_to_ts, current_record_indicator
    FROM silver_ext.dim_customer
    WHERE valid_from_ts >= DATEADD(day, -3, '${run_date}'::DATE)
       OR valid_to_ts   BETWEEN DATEADD(day, -3, '${run_date}'::DATE) AND '${run_date}'::DATE
) s
ON  gold.dim_customer.customer_key  = s.customer_key
AND gold.dim_customer.valid_from_ts = s.valid_from_ts
WHEN MATCHED THEN UPDATE SET
    valid_to_ts              = s.valid_to_ts,
    current_record_indicator = s.current_record_indicator
WHEN NOT MATCHED THEN INSERT VALUES (
    s.customer_key, s.primary_cif_id, s.emirates_id_token, s.full_name, s.date_of_birth,
    s.nationality_code, s.gender_code, s.language_code, s.marketing_channel_code,
    s.primary_email, s.primary_mobile, s.idr_confidence_score, s.idr_is_entity_conflict,
    s.valid_from_ts, s.valid_to_ts, s.current_record_indicator);


/* -------------------------------------------------------------------------------------
   3. Dynamic Data Masking policies
   Pattern: attach the MASK policy to PUBLIC (safe default), then attach a higher-priority
   policy to each role that is allowed to see more. A new user with no role sees masks.
   In production these statements are generated by CI from the dbt column meta
   (classification-as-code) — not hand-written per column.
   ------------------------------------------------------------------------------------- */
CREATE ROLE t0_aggregate;
CREATE ROLE t1_pseudonymised;
CREATE ROLE t2_operational;
CREATE ROLE t3_privileged;

-- Masks
CREATE MASKING POLICY mask_email
WITH (val VARCHAR(256))
USING (('****' || SUBSTRING(val, POSITION('@' IN val)))::VARCHAR(256));   -- ****@gmail.com

CREATE MASKING POLICY mask_mobile
WITH (val VARCHAR(256))
USING (('+971*****' || RIGHT(val, 3))::VARCHAR(256));                      -- +971*****567

CREATE MASKING POLICY mask_name
WITH (val VARCHAR(256))
USING ((LEFT(val, 1) || '****')::VARCHAR(256));                            -- M****

CREATE MASKING POLICY mask_dob_year
WITH (val DATE)
USING (DATE_TRUNC('year', val)::DATE);                                     -- 1990-01-01

CREATE MASKING POLICY redact_varchar
WITH (val VARCHAR(256))
USING (NULL::VARCHAR(256));

-- Pass-through ("unmask") policies for privileged roles
CREATE MASKING POLICY show_varchar WITH (val VARCHAR(256)) USING (val);
CREATE MASKING POLICY show_date    WITH (val DATE)         USING (val);

-- Defaults for everyone (PUBLIC = T0)
ATTACH MASKING POLICY mask_name      ON gold.dim_customer(full_name)          TO PUBLIC;
ATTACH MASKING POLICY mask_email     ON gold.dim_customer(primary_email)      TO PUBLIC;
ATTACH MASKING POLICY mask_mobile    ON gold.dim_customer(primary_mobile)     TO PUBLIC;
ATTACH MASKING POLICY mask_dob_year  ON gold.dim_customer(date_of_birth)      TO PUBLIC;
ATTACH MASKING POLICY redact_varchar ON gold.dim_customer(primary_cif_id)     TO PUBLIC;
ATTACH MASKING POLICY redact_varchar ON gold.dim_customer(emirates_id_token)  TO PUBLIC;

-- T1 (Product, AI): tokens are visible so joins work; C2 stays masked (inherits PUBLIC)
ATTACH MASKING POLICY show_varchar ON gold.dim_customer(emirates_id_token) TO ROLE t1_pseudonymised PRIORITY 10;

-- T2 (Support): clear contact details and CIF to serve the customer
ATTACH MASKING POLICY show_varchar ON gold.dim_customer(full_name)       TO ROLE t2_operational PRIORITY 20;
ATTACH MASKING POLICY show_varchar ON gold.dim_customer(primary_email)   TO ROLE t2_operational PRIORITY 20;
ATTACH MASKING POLICY show_varchar ON gold.dim_customer(primary_mobile)  TO ROLE t2_operational PRIORITY 20;
ATTACH MASKING POLICY show_varchar ON gold.dim_customer(primary_cif_id)  TO ROLE t2_operational PRIORITY 20;

-- T3 (KYC / compliance): everything clear in Gold; C3 clear values only via the
-- audited detokenisation service against pii_vault (separate KMS key, every call logged)
ATTACH MASKING POLICY show_varchar ON gold.dim_customer(full_name)          TO ROLE t3_privileged PRIORITY 30;
ATTACH MASKING POLICY show_varchar ON gold.dim_customer(primary_email)      TO ROLE t3_privileged PRIORITY 30;
ATTACH MASKING POLICY show_varchar ON gold.dim_customer(primary_mobile)     TO ROLE t3_privileged PRIORITY 30;
ATTACH MASKING POLICY show_varchar ON gold.dim_customer(primary_cif_id)     TO ROLE t3_privileged PRIORITY 30;
ATTACH MASKING POLICY show_varchar ON gold.dim_customer(emirates_id_token)  TO ROLE t3_privileged PRIORITY 30;
ATTACH MASKING POLICY show_date    ON gold.dim_customer(date_of_birth)      TO ROLE t3_privileged PRIORITY 30;


/* -------------------------------------------------------------------------------------
   4. Consent-gated serving views (default deny)
   Consent is enforced in the data layer, so no consumer can bypass it in application code.
   Note the legal-basis split:
     - Personalisation / marketing   → requires GRANTED consent for that purpose
     - Credit and fraud models       → contract / legal obligation, NOT consent-gated,
                                        but nationality and gender are excluded
                                        (allowed_for_credit_decisioning = false)
   ------------------------------------------------------------------------------------- */
CREATE OR REPLACE VIEW gold.v_car_personalisation AS
SELECT c.*
FROM gold.mart_personalisation__car_daily c
JOIN gold.consent_current cc
  ON  cc.customer_key  = c.customer_key
  AND cc.purpose_code  = 'PERSONALISATION'
  AND cc.status_code   = 'GRANTED'
  AND cc.current_record_indicator = TRUE
  AND (cc.expires_ts IS NULL OR cc.expires_ts > GETDATE())
WHERE c.snapshot_date = (SELECT MAX(snapshot_date) FROM gold.mart_personalisation__car_daily)
  AND c.idr_is_entity_conflict = FALSE;                 -- unresolved identities never personalised

CREATE OR REPLACE VIEW gold.v_car_risk_model_features AS
SELECT
    c.customer_key, c.snapshot_date, c.car_version, c.idr_confidence_score,
    c.demo_age_band_code, c.demo_residency_type_code, c.demo_tenure_days,
    c.onb_channel_code, c.onb_kyc_status_code, c.onb_id_doc_expiry_days,
    c.prd_active_account_count, c.prd_product_count,
    c.bal_eod_aed, c.bal_avg_30d_aed, c.bal_min_30d_aed, c.bal_trend_30d_pct,
    c.txn_count_30d, c.txn_inflow_sum_30d_aed, c.txn_outflow_sum_30d_aed,
    c.txn_has_salary_credit_30d, c.txn_intl_ratio_30d_pct, c.txn_recency_days,
    c.eng_login_recency_days, c.eng_active_days_30d
    -- demo_nationality_code and demo_gender_code deliberately excluded (ethical credit decisioning)
FROM gold.mart_personalisation__car_daily c
WHERE c.idr_is_entity_conflict = FALSE;                 -- point-in-time: training jobs filter snapshot_date

GRANT SELECT ON gold.v_car_personalisation     TO ROLE t1_pseudonymised;
GRANT SELECT ON gold.v_car_risk_model_features TO ROLE t1_pseudonymised;
-- No direct grant on gold.mart_personalisation__car_daily to T1: consumers go through the governed views.
