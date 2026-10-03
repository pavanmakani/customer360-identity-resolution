# Customer 360 Identity Resolution (code sample)

Code sample for the **Customer 360 & CAR Platform Design** assessment. It implements the identity resolution approach described in Section 1 of the architecture document: deterministic-first matching, a stable owned `customer_key`, config-driven survivorship, and an Operations exception queue in place of automatic merges.

## Files

| File | Engine | What it does |
|---|---|---|
| `sql/01_silver_identity_resolution.sql` | Spark SQL on Apache Iceberg (dbt-glue) | Standardises anchors, applies match rules R1–R3, mints `customer_key`, maintains the SCD2 xref, raises exceptions, runs survivorship, stitches Amplitude devices |
| `sql/02_gold_customer_serving.sql` | Amazon Redshift (dbt-redshift) | Golden-record serving table, Dynamic Data Masking per access tier, consent-gated views for personalisation and risk models |
| `seeds/ref_survivorship_rule.csv` | dbt seed | Survivorship rules as configuration: which source wins which attribute, and by which strategy |

## Match rules

| Rule | Link | Key | Confidence |
|---|---|---|---|
| R1 | Core banking ↔ core banking | Verified Emirates ID; passport (issuing country + number) as fallback | 1.0 |
| R2 | Salesforce ↔ core banking | CIF written to Salesforce as an external ID at onboarding | 1.0 |
| R3 | Amplitude ↔ customer | `user_id` = app user ID set at login, mapped to CIF | 1.0 |
| Device stitching | Anonymous Amplitude events ↔ customer | Device first seen at login; back-fill only for single-owner devices, within a 3-day late-arrival window | — |
| Phase 2 | Salesforce Leads ↔ customer | Probabilistic (Fellegi–Sunter via Splink), always reviewed | scored |

**Conflicts are never auto-merged.** Two CIFs sharing an Emirates ID, a Salesforce external-ID collision, or a Salesforce record with an unknown CIF is loaded, flagged (`is_quarantined`, `idr_is_entity_conflict`) and written to `idr_exception_queue` for the daily Operations reconciliation.

## Survivorship

| Attribute group | Strategy | Order |
|---|---|---|
| Identity / KYC (name, DOB, nationality, gender) | `PRIORITY` | Core banking → Salesforce (gap fill only; differences raise `KYC_MISMATCH`) |
| Contact (primary email, mobile) | `VERIFIED_RECENCY` | Verified → most recent verified (source effective time) → core banking |
| Preferences (language, marketing channel) | `PRIORITY` | Salesforce → core banking |
| Device / behaviour | — | Amplitude only; never competes for identity or contact |

Every strategy ends with the lowest `source_record_id` as the final tie-break, so re-runs are idempotent. Which source won each attribute is stored in `customer_attribute_lineage`.

## Conventions

- **SCD2:** `valid_from_ts`, `valid_to_ts`, `current_record_indicator` (BOOLEAN)
- **Suffixes:** `_key` surrogate, `_id` source business key, `_token` HMAC token, `_code` reference code, `is_`/`has_` booleans, `_aed` amounts, `_days` durations
- **Tokenisation:** `pii_token(type, value)` is a PySpark UDF computing HMAC-SHA256 with a key held in AWS Secrets Manager under a dedicated KMS key. Tokens carry a type and key version (`EID_v1_…`) so the key can be rotated.
- **Integrity:** Redshift and Iceberg do not enforce PK/FK. Uniqueness, not-null and referential integrity are enforced by dbt tests that fail the pipeline.

`${run_date}` is the T-1 business date, passed in by the Airflow (MWAA) DAG after the core banking end-of-day sensor completes.
