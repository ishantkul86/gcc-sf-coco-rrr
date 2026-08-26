from copy import deepcopy


AML_RULE_QUERIES = {
    "aml_structuring": {
        "finding": "Checking for potential structuring by aggregating multiple sub-threshold trades for the same account on the same day. Accounts with repeated trades below common AML reporting thresholds but high combined value are flagged for review.",
        "regulation": "AML / BSA / FATF — Structuring and Suspicious Transaction Monitoring",
        "severity": "HIGH",
        "rule_key": "aml_structuring",
        "category": "AML Monitoring",
        "sql": """SELECT da.ACCOUNT_ID, da.ACCOUNT_NAME, dd.CALENDAR_DATE AS TRADE_DATE,
    COUNT(*) AS SUB_THRESHOLD_TXN_COUNT,
    SUM(ft.GROSS_AMOUNT) AS TOTAL_GROSS_AMOUNT,
    MAX(ft.GROSS_AMOUNT) AS MAX_SINGLE_TXN_AMOUNT,
    MIN(ft.GROSS_AMOUNT) AS MIN_SINGLE_TXN_AMOUNT,
    LISTAGG(ft.TRANSACTION_ID, ', ') WITHIN GROUP (ORDER BY ft.TRANSACTION_ID) AS TRANSACTION_IDS,
    'POTENTIAL_STRUCTURING' AS AML_ALERT_TYPE
FROM REGULATORY_DW.REG_MODEL.FACT_TRANSACTION ft
JOIN REGULATORY_DW.REG_MODEL.DIM_ACCOUNT da ON ft.ACCOUNT_KEY = da.ACCOUNT_KEY
JOIN REGULATORY_DW.REG_MODEL.DIM_DATE dd ON ft.TRADE_DATE_KEY = dd.DATE_KEY
WHERE da.IS_CURRENT = TRUE
  AND ABS(ft.GROSS_AMOUNT) < 10000
GROUP BY da.ACCOUNT_ID, da.ACCOUNT_NAME, dd.CALENDAR_DATE
HAVING COUNT(*) >= 3
   AND SUM(ABS(ft.GROSS_AMOUNT)) >= 20000
ORDER BY TOTAL_GROSS_AMOUNT DESC, SUB_THRESHOLD_TXN_COUNT DESC""",
        "policy_refs": ["MAS AML Notice", "Internal AML EDD Standard"],
        "remediation": "Review grouped transactions for common beneficial ownership, shared purpose, and reporting-threshold avoidance. Escalate repeated patterns into AML case management.",
        "audit_note": "AML structuring detection rule executed",
        "alert_generation": {
            "alert_title": "Potential Structuring Activity",
            "alert_severity": "HIGH",
            "queue": "AML_TIER2",
            "status": "OPEN",
            "disposition_hint": "Review threshold avoidance and linked transactions",
        },
    },
    "aml_velocity": {
        "finding": "Checking for unusual transaction velocity by identifying accounts with dense bursts of activity inside a 24-hour window. This is a practical proxy for layering or sudden changes in customer behavior when richer payment telemetry is unavailable.",
        "regulation": "AML / FATF — Ongoing Monitoring and Unusual Activity Detection",
        "severity": "MEDIUM",
        "rule_key": "aml_velocity",
        "category": "AML Monitoring",
        "sql": """SELECT da.ACCOUNT_ID, da.ACCOUNT_NAME,
    DATE_TRUNC('day', ft.TRADE_TIMESTAMP) AS ACTIVITY_DAY,
    COUNT(*) AS TRANSACTION_COUNT,
    SUM(ABS(ft.GROSS_AMOUNT)) AS TOTAL_GROSS_AMOUNT,
    COUNT(DISTINCT ft.COUNTERPARTY_KEY) AS DISTINCT_COUNTERPARTIES,
    COUNT(DISTINCT ft.TRADE_CURRENCY) AS DISTINCT_CURRENCIES,
    'HIGH_VELOCITY_ACTIVITY' AS AML_ALERT_TYPE
FROM REGULATORY_DW.REG_MODEL.FACT_TRANSACTION ft
JOIN REGULATORY_DW.REG_MODEL.DIM_ACCOUNT da ON ft.ACCOUNT_KEY = da.ACCOUNT_KEY
WHERE da.IS_CURRENT = TRUE
GROUP BY da.ACCOUNT_ID, da.ACCOUNT_NAME, DATE_TRUNC('day', ft.TRADE_TIMESTAMP)
HAVING COUNT(*) >= 10
   AND SUM(ABS(ft.GROSS_AMOUNT)) >= 1000000
ORDER BY TRANSACTION_COUNT DESC, TOTAL_GROSS_AMOUNT DESC""",
        "policy_refs": ["MAS AML Notice", "Internal AML EDD Standard"],
        "remediation": "Investigate whether the activity aligns with the account mandate, historical profile, and known strategy. Tighten review thresholds for repeat offenders or high-risk client segments.",
        "audit_note": "AML velocity monitoring rule executed",
        "alert_generation": {
            "alert_title": "Unusual Transaction Velocity",
            "alert_severity": "MEDIUM",
            "queue": "AML_TIER1",
            "status": "OPEN",
            "disposition_hint": "Compare burst behavior against historical account activity",
        },
    },
    "aml_round_amount": {
        "finding": "Checking for suspicious round-amount trades, which can indicate non-economic activity, manual staging, or attempted masking of illicit flows. The rule prioritizes exact high-value rounded amounts.",
        "regulation": "AML / FATF — Suspicious Transaction Pattern Detection",
        "severity": "MEDIUM",
        "rule_key": "aml_round_amount",
        "category": "AML Monitoring",
        "sql": """SELECT ft.TRANSACTION_ID, da.ACCOUNT_ID, da.ACCOUNT_NAME,
    ft.TRADE_TIMESTAMP, ft.GROSS_AMOUNT, ft.TRADE_CURRENCY,
    ft.COUNTERPARTY_KEY, ft.TRANSACTION_TYPE,
    CASE
        WHEN MOD(ABS(ft.GROSS_AMOUNT), 1000000) = 0 THEN 'EXACT_MILLION'
        WHEN MOD(ABS(ft.GROSS_AMOUNT), 500000) = 0 THEN 'EXACT_500K'
        WHEN MOD(ABS(ft.GROSS_AMOUNT), 100000) = 0 THEN 'EXACT_100K'
        ELSE 'OTHER_ROUND_PATTERN'
    END AS ROUND_PATTERN
FROM REGULATORY_DW.REG_MODEL.FACT_TRANSACTION ft
JOIN REGULATORY_DW.REG_MODEL.DIM_ACCOUNT da ON ft.ACCOUNT_KEY = da.ACCOUNT_KEY
WHERE da.IS_CURRENT = TRUE
  AND ABS(ft.GROSS_AMOUNT) >= 100000
  AND (
      MOD(ABS(ft.GROSS_AMOUNT), 1000000) = 0
      OR MOD(ABS(ft.GROSS_AMOUNT), 500000) = 0
      OR MOD(ABS(ft.GROSS_AMOUNT), 100000) = 0
  )
ORDER BY ABS(ft.GROSS_AMOUNT) DESC, ft.TRADE_TIMESTAMP DESC""",
        "policy_refs": ["MAS AML Notice", "Internal AML EDD Standard"],
        "remediation": "Validate commercial rationale, supporting documentation, and source of funds for high-value round transactions. Combine with counterparty and jurisdiction context before escalation.",
        "audit_note": "AML round-amount rule executed",
        "alert_generation": {
            "alert_title": "Suspicious Round-Amount Transaction",
            "alert_severity": "MEDIUM",
            "queue": "AML_TIER1",
            "status": "OPEN",
            "disposition_hint": "Check source of funds and payment rationale",
        },
    },
    "aml_dormancy": {
        "finding": "Checking for dormant-account reactivation by comparing recent trading activity against a prolonged inactivity gap. Large trades after extended silence are prioritized as potential AML alerts.",
        "regulation": "AML / FATF — Ongoing Customer Due Diligence",
        "severity": "HIGH",
        "rule_key": "aml_dormancy",
        "category": "AML Monitoring",
        "sql": """WITH latest_activity AS (
    SELECT ft.ACCOUNT_KEY,
        MAX(dd.CALENDAR_DATE) AS LAST_TRADE_DATE
    FROM REGULATORY_DW.REG_MODEL.FACT_TRANSACTION ft
    JOIN REGULATORY_DW.REG_MODEL.DIM_DATE dd ON ft.TRADE_DATE_KEY = dd.DATE_KEY
    GROUP BY ft.ACCOUNT_KEY
),
recent_large_trades AS (
    SELECT ft.ACCOUNT_KEY, ft.TRANSACTION_ID, dd.CALENDAR_DATE, ft.GROSS_AMOUNT, ft.TRADE_CURRENCY
    FROM REGULATORY_DW.REG_MODEL.FACT_TRANSACTION ft
    JOIN REGULATORY_DW.REG_MODEL.DIM_DATE dd ON ft.TRADE_DATE_KEY = dd.DATE_KEY
    WHERE dd.CALENDAR_DATE >= DATEADD('day', -30, CURRENT_DATE())
      AND ABS(ft.GROSS_AMOUNT) >= 250000
)
SELECT da.ACCOUNT_ID, da.ACCOUNT_NAME, rlt.TRANSACTION_ID, rlt.CALENDAR_DATE AS RECENT_TRADE_DATE,
    rlt.GROSS_AMOUNT, rlt.TRADE_CURRENCY,
    DATEDIFF('day', COALESCE(prev_dd.CALENDAR_DATE, DATEADD('day', -9999, rlt.CALENDAR_DATE)), rlt.CALENDAR_DATE) AS DAYS_SINCE_PRIOR_TRADE,
    'DORMANT_ACCOUNT_REACTIVATION' AS AML_ALERT_TYPE
FROM recent_large_trades rlt
JOIN REGULATORY_DW.REG_MODEL.DIM_ACCOUNT da ON rlt.ACCOUNT_KEY = da.ACCOUNT_KEY
LEFT JOIN REGULATORY_DW.REG_MODEL.FACT_TRANSACTION prev_ft
    ON prev_ft.ACCOUNT_KEY = rlt.ACCOUNT_KEY
   AND prev_ft.TRANSACTION_ID != rlt.TRANSACTION_ID
   AND prev_ft.TRADE_DATE_KEY < TO_NUMBER(TO_CHAR(rlt.CALENDAR_DATE, 'YYYYMMDD'))
LEFT JOIN REGULATORY_DW.REG_MODEL.DIM_DATE prev_dd ON prev_ft.TRADE_DATE_KEY = prev_dd.DATE_KEY
WHERE da.IS_CURRENT = TRUE
QUALIFY ROW_NUMBER() OVER (PARTITION BY rlt.TRANSACTION_ID ORDER BY prev_dd.CALENDAR_DATE DESC NULLS LAST) = 1
   AND DATEDIFF('day', COALESCE(prev_dd.CALENDAR_DATE, DATEADD('day', -9999, rlt.CALENDAR_DATE)), rlt.CALENDAR_DATE) >= 90
ORDER BY DAYS_SINCE_PRIOR_TRADE DESC, ABS(rlt.GROSS_AMOUNT) DESC""",
        "policy_refs": ["MAS AML Notice", "Internal AML EDD Standard"],
        "remediation": "Reconfirm customer profile, recent KYC refresh, and source-of-funds documentation before permitting further activity on reactivated dormant accounts.",
        "audit_note": "AML dormant account reactivation rule executed",
        "alert_generation": {
            "alert_title": "Dormant Account Reactivation",
            "alert_severity": "HIGH",
            "queue": "AML_TIER2",
            "status": "OPEN",
            "disposition_hint": "Refresh KYC and verify source of funds before further activity",
        },
    },
    "aml_sanctions": {
        "finding": "Checking sanctions-screening hygiene using the current counterparty screening status and recency of the last screen. Counterparties with stale screening or non-clear statuses are prioritized.",
        "regulation": "OFAC / EU / UK Sanctions — Screening and Ongoing Monitoring",
        "severity": "HIGH",
        "rule_key": "aml_sanctions",
        "category": "AML Monitoring",
        "sql": """SELECT cp.COUNTERPARTY_NAME, cp.COUNTERPARTY_TYPE, cp.LEI_CODE,
    cp.SANCTIONS_STATUS, cp.SANCTIONS_SCREENED_DATE, cp.CREDIT_RATING,
    DATEDIFF('day', cp.SANCTIONS_SCREENED_DATE, CURRENT_DATE()) AS DAYS_SINCE_SCREENING,
    CASE
        WHEN cp.SANCTIONS_STATUS IS NULL THEN 'SCREENING_STATUS_MISSING'
        WHEN UPPER(cp.SANCTIONS_STATUS) NOT IN ('CLEAR', 'PASSED', 'NO_HIT') THEN 'SCREENING_REQUIRES_REVIEW'
        WHEN DATEDIFF('day', cp.SANCTIONS_SCREENED_DATE, CURRENT_DATE()) > 30 THEN 'SCREENING_STALE'
        ELSE 'CURRENT'
    END AS SCREENING_RISK
FROM REGULATORY_DW.REG_MODEL.DIM_COUNTERPARTY cp
WHERE cp.IS_CURRENT = TRUE
  AND (
      cp.SANCTIONS_STATUS IS NULL
      OR UPPER(cp.SANCTIONS_STATUS) NOT IN ('CLEAR', 'PASSED', 'NO_HIT')
      OR DATEDIFF('day', cp.SANCTIONS_SCREENED_DATE, CURRENT_DATE()) > 30
  )
ORDER BY DAYS_SINCE_SCREENING DESC NULLS LAST, cp.COUNTERPARTY_NAME""",
        "policy_refs": ["MAS AML Notice", "Internal AML EDD Standard"],
        "remediation": "Re-screen stale or unresolved counterparties immediately and route non-clear outcomes to sanctions operations for adjudication and documented disposition.",
        "audit_note": "AML sanctions-screening hygiene rule executed",
        "alert_generation": {
            "alert_title": "Sanctions Screening Exception",
            "alert_severity": "HIGH",
            "queue": "SANCTIONS_OPS",
            "status": "OPEN",
            "disposition_hint": "Immediate screening refresh and analyst adjudication required",
        },
    },
}


def get_aml_rule_queries():
    return deepcopy(AML_RULE_QUERIES)


def get_aml_alert_rule_library():
    return {
        rule_key: {"alert_generation": deepcopy(config["alert_generation"])}
        for rule_key, config in AML_RULE_QUERIES.items()
    }
