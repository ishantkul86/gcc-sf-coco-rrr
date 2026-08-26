import json
import re
from copy import deepcopy
from datetime import datetime


POLICY_LIBRARY = {
    "MAS AML Notice": {
        "title": "MAS Notice SFA04-N02 — Prevention of Money Laundering and Countering the Financing of Terrorism",
        "excerpt": "Financial institutions must perform risk-based customer due diligence, keep customer information current, and apply enhanced due diligence where higher-risk customers or cross-border activity are identified.",
        "source_type": "Regulator Notice",
    },
    "Internal AML EDD Standard": {
        "title": "Internal AML EDD Standard — High-Risk Customer Reviews",
        "excerpt": "High-risk customers must undergo at least annual KYC refresh, source-of-funds validation for material cross-border flows, and documented escalation where overdue reviews coincide with transaction anomalies.",
        "source_type": "Internal Policy",
    },
    "MiFID Reporting Control Standard": {
        "title": "MiFID II Reporting Control Standard",
        "excerpt": "Transaction reporting exceptions, missing MIC codes, and best-execution control failures must be investigated and documented with root cause and remediation evidence.",
        "source_type": "Control Standard",
    },
    "Regulatory Filing Governance": {
        "title": "Regulatory Filing Governance Playbook",
        "excerpt": "Late or overdue filings require documented root-cause analysis, accountable owner assignment, and audit-ready evidence retained with the submission timeline.",
        "source_type": "Filing Guidance",
    },
}


FALLBACK_HELP_TEXT = (
    "Try asking about: Basel III leverage, MiFID II reporting, AIFMD Annex IV, "
    "AML/KYC reviews, AML structuring, AML velocity, sanctions screening, round-amount transactions, "
    "dormant account reactivation, EMIR derivatives, UCITS compliance, Form PF, regulatory filings, "
    "counterparty exposure, concentration limits, critical breaches, top risks, Basel liquidity, "
    "Basel capital metrics, or AML schema design."
)


LIVE_TABLES = {
    "DIM_ACCOUNT",
    "DIM_SECURITY",
    "DIM_FUND",
    "DIM_TRADE_MODEL",
    "DIM_COUNTERPARTY",
    "DIM_REGULATORY_JURISDICTION",
    "DIM_GEOGRAPHY",
    "DIM_DATE",
    "FACT_TRANSACTION",
    "FACT_POSITION",
    "FACT_REGULATORY_REPORT",
}


PLANNED_SCHEMA_ONLY_RULES = {
    "aml_alerts": {
        "missing_tables": ["FACT_AML_ALERT"],
        "schema_rule": "aml_alert_schema",
    },
    "breach_explain": {
        "missing_tables": ["FACT_COMPLIANCE_BREACH"],
        "schema_rule": "compliance_breach_schema",
    },
    "breach_evidence": {
        "missing_tables": ["FACT_COMPLIANCE_BREACH"],
        "schema_rule": "compliance_breach_schema",
    },
    "suitability_exceptions": {
        "missing_tables": ["DIM_CLIENT_SUITABILITY_ASSESSMENT"],
        "schema_rule": "suitability_schema",
    },
    "transaction_audit_trail": {
        "missing_tables": ["FACT_TRANSACTION_AUDIT_TRAIL"],
        "schema_rule": "transaction_audit_trail_schema",
    },
}


SUPPORTED_RULE_CATEGORIES = {
    "AML Monitoring": [
        "KYC periodic reviews",
        "Structuring / smurfing",
        "Transaction velocity spikes",
        "Round-amount anomalies",
        "Dormant account reactivation",
        "Sanctions screening hygiene",
        "AML alert schema design",
    ],
    "Regulatory Reporting": [
        "MiFID II reporting gaps",
        "AIFMD Annex IV status",
        "Form PF status",
        "Late or overdue filings",
    ],
    "Exposure & Portfolio": [
        "Basel III leverage",
        "Basel III capital and liquidity proxy metrics",
        "Counterparty concentration",
        "UCITS concentration limits",
        "EMIR derivatives / clearing",
        "Top enterprise risks",
        "Critical breach inventory",
    ],
    "Schema Design": [
        "DIM_AML_RULE design",
        "FACT_AML_ALERT design",
        "FACT_COMPLIANCE_BREACH design",
        "FACT_TRANSACTION_AUDIT_TRAIL design",
        "DIM_CLIENT_SUITABILITY_ASSESSMENT design",
    ],
}


CORE_RULE_BASED_QUERIES = {
    "leverage": {
        "finding": "Checking Basel III leverage ratio compliance across all funds. Funds exceeding 3.0x leverage are flagged.",
        "regulation": "Basel III — Leverage Ratio Framework",
        "severity": "HIGH",
        "rule_key": "leverage",
        "category": "Exposure & Portfolio",
        "sql": """SELECT FUND_ID, FUND_NAME, FUND_TYPE, LEVERAGE_RATIO, TOTAL_AUM, BASE_CURRENCY,
    CASE WHEN LEVERAGE_RATIO > 3.0 THEN 'BREACH' ELSE 'COMPLIANT' END AS STATUS
FROM REGULATORY_DW.REG_MODEL.DIM_FUND
WHERE IS_CURRENT = TRUE
ORDER BY LEVERAGE_RATIO DESC""",
        "remediation": "Funds with leverage > 3.0x require immediate deleveraging plan or additional capital buffers.",
        "audit_note": "Basel III leverage ratio check executed"
    },
    "mifid": {
        "finding": "Checking MiFID II transaction reporting compliance — venue MIC codes, algo flagging, and reporting timeliness.",
        "regulation": "MiFID II / MiFIR — RTS 25, Transaction Reporting",
        "severity": "MEDIUM",
        "rule_key": "mifid",
        "category": "Regulatory Reporting",
        "sql": """SELECT ft.TRANSACTION_ID, ft.EXECUTION_VENUE, ft.EXECUTION_VENUE_MIC,
    ft.ALGO_EXECUTION_FLAG, ft.BEST_EXECUTION_FLAG, ft.REPORTING_STATUS,
    ft.IS_CROSS_BORDER, ft.GROSS_AMOUNT, ft.TRADE_CURRENCY,
    tm.TRADE_MODEL_NAME, tm.ALGO_INDICATOR AS MODEL_IS_ALGO,
    CASE
        WHEN ft.EXECUTION_VENUE_MIC IS NULL AND ft.EXECUTION_VENUE != 'OTC' THEN 'MISSING_VENUE_MIC'
        WHEN tm.ALGO_INDICATOR = TRUE AND ft.ALGO_EXECUTION_FLAG = FALSE THEN 'ALGO_FLAG_MISMATCH'
        WHEN ft.REPORTING_STATUS != 'REPORTED' THEN 'NOT_REPORTED'
        WHEN ft.BEST_EXECUTION_FLAG = FALSE THEN 'BEST_EXEC_FAILURE'
        ELSE 'COMPLIANT'
    END AS COMPLIANCE_STATUS
FROM REGULATORY_DW.REG_MODEL.FACT_TRANSACTION ft
LEFT JOIN REGULATORY_DW.REG_MODEL.DIM_TRADE_MODEL tm ON ft.TRADE_MODEL_KEY = tm.TRADE_MODEL_KEY
ORDER BY ft.GROSS_AMOUNT DESC""",
        "remediation": "Review flagged transactions — ensure MIC codes are populated, algo flags match model config, and all trades are reported within T+1.",
        "audit_note": "MiFID II compliance gap analysis executed"
    },
    "kyc": {
        "finding": "Checking AML/KYC review status for all active accounts. Reviews overdue beyond 365 days are flagged.",
        "regulation": "AML 4th/5th Directive — Customer Due Diligence",
        "severity": "HIGH",
        "rule_key": "kyc",
        "category": "AML Monitoring",
        "sql": """SELECT ACCOUNT_ID, ACCOUNT_NAME, ACCOUNT_TYPE, CLIENT_CLASSIFICATION, AML_RISK_RATING, KYC_STATUS,
    KYC_LAST_REVIEWED, DATEDIFF('day', KYC_LAST_REVIEWED, CURRENT_DATE()) AS DAYS_SINCE_REVIEW,
    CASE
        WHEN DATEDIFF('day', KYC_LAST_REVIEWED, CURRENT_DATE()) > 365 THEN 'OVERDUE'
        WHEN DATEDIFF('day', KYC_LAST_REVIEWED, CURRENT_DATE()) > 270 THEN 'DUE_SOON'
        ELSE 'CURRENT'
    END AS REVIEW_STATUS
FROM REGULATORY_DW.REG_MODEL.DIM_ACCOUNT
WHERE IS_CURRENT = TRUE
ORDER BY DAYS_SINCE_REVIEW DESC""",
    "policy_refs": ["MAS AML Notice", "Internal AML EDD Standard"],
        "remediation": "Initiate enhanced due diligence reviews for overdue accounts, prioritizing those with MEDIUM/HIGH AML risk ratings.",
        "audit_note": "AML/KYC periodic review status check executed"
    },
    "emir": {
        "finding": "Checking EMIR derivative reporting — OTC exposure, clearing eligibility, and CSA coverage.",
        "regulation": "EMIR — OTC Derivatives, Central Clearing",
        "severity": "MEDIUM",
        "rule_key": "emir",
        "category": "Exposure & Portfolio",
        "sql": """SELECT s.SECURITY_NAME, s.SECURITY_TYPE, s.SUB_ASSET_CLASS, s.IS_OTC,
    cp.COUNTERPARTY_NAME, cp.CENTRAL_CLEARING_ELIGIBLE, cp.CSA_IN_PLACE, cp.NETTING_AGREEMENT,
    p.MARKET_VALUE_BASE AS EXPOSURE, f.FUND_NAME,
    CASE
        WHEN s.IS_OTC = TRUE AND cp.CENTRAL_CLEARING_ELIGIBLE = TRUE AND cp.CCP_MEMBER = FALSE THEN 'SHOULD_BE_CLEARED'
        WHEN s.IS_OTC = TRUE AND cp.CSA_IN_PLACE = FALSE THEN 'MISSING_CSA'
        WHEN p.COUNTERPARTY_KEY IS NULL THEN 'NO_COUNTERPARTY_MAPPED'
        ELSE 'COMPLIANT'
    END AS EMIR_STATUS
FROM REGULATORY_DW.REG_MODEL.FACT_POSITION p
JOIN REGULATORY_DW.REG_MODEL.DIM_SECURITY s ON p.SECURITY_KEY = s.SECURITY_KEY
LEFT JOIN REGULATORY_DW.REG_MODEL.DIM_COUNTERPARTY cp ON p.COUNTERPARTY_KEY = cp.COUNTERPARTY_KEY
JOIN REGULATORY_DW.REG_MODEL.DIM_FUND f ON p.FUND_KEY = f.FUND_KEY
WHERE s.IS_DERIVATIVE = TRUE AND p.AS_OF_DATE = '2026-06-30'
ORDER BY p.MARKET_VALUE_BASE DESC""",
        "remediation": "Migrate clearing-eligible OTC positions to CCPs. Establish CSA agreements for remaining bilateral positions.",
        "audit_note": "EMIR derivative clearing and CSA compliance check executed"
    },
    "filing": {
        "finding": "Checking regulatory report submission status — identifying late, overdue, or not-started filings.",
        "regulation": "Multiple — AIFMD, Form PF, UCITS, MiFID II",
        "severity": "HIGH",
        "rule_key": "filing",
        "category": "Regulatory Reporting",
        "sql": """SELECT rr.REPORT_ID, rr.REPORT_TYPE, rr.REPORT_STATUS,
    rr.REPORTING_PERIOD_START, rr.REPORTING_PERIOD_END,
    rr.SUBMISSION_DEADLINE, rr.ACTUAL_SUBMISSION_DATE,
    CASE WHEN rr.ACTUAL_SUBMISSION_DATE > rr.SUBMISSION_DEADLINE THEN 'LATE'
         WHEN rr.ACTUAL_SUBMISSION_DATE IS NULL AND rr.SUBMISSION_DEADLINE < CURRENT_DATE() THEN 'OVERDUE'
         ELSE rr.REPORT_STATUS END AS EFFECTIVE_STATUS,
    rj.JURISDICTION_NAME, rj.REGULATION_FRAMEWORK, f.FUND_NAME,
    rr.BREACHES_REPORTED, rr.VALIDATION_ERRORS
FROM REGULATORY_DW.REG_MODEL.FACT_REGULATORY_REPORT rr
JOIN REGULATORY_DW.REG_MODEL.DIM_REGULATORY_JURISDICTION rj ON rr.JURISDICTION_KEY = rj.JURISDICTION_KEY
LEFT JOIN REGULATORY_DW.REG_MODEL.DIM_FUND f ON rr.FUND_KEY = f.FUND_KEY
ORDER BY rr.SUBMISSION_DEADLINE ASC""",
    "policy_refs": ["Regulatory Filing Governance"],
        "remediation": "Escalate overdue filings to compliance officer. Submit late reports with explanatory cover letters to regulators.",
        "audit_note": "Regulatory filing status review executed"
    },
    "counterparty": {
        "finding": "Checking counterparty concentration exposure against Basel III large exposure limits (25% Tier 1 capital).",
        "regulation": "Basel III — Large Exposures Framework (LEX)",
        "severity": "MEDIUM",
        "rule_key": "counterparty",
        "category": "Exposure & Portfolio",
        "sql": """SELECT cp.COUNTERPARTY_NAME, cp.COUNTERPARTY_TYPE, cp.CREDIT_RATING,
    SUM(p.MARKET_VALUE_BASE) AS TOTAL_EXPOSURE,
    COUNT(*) AS POSITION_COUNT,
    cp.NETTING_AGREEMENT, cp.CSA_IN_PLACE,
    cp.SANCTIONS_STATUS, cp.SANCTIONS_SCREENED_DATE
FROM REGULATORY_DW.REG_MODEL.FACT_POSITION p
JOIN REGULATORY_DW.REG_MODEL.DIM_COUNTERPARTY cp ON p.COUNTERPARTY_KEY = cp.COUNTERPARTY_KEY
WHERE p.AS_OF_DATE = '2026-06-30'
GROUP BY cp.COUNTERPARTY_NAME, cp.COUNTERPARTY_TYPE, cp.CREDIT_RATING,
         cp.NETTING_AGREEMENT, cp.CSA_IN_PLACE, cp.SANCTIONS_STATUS, cp.SANCTIONS_SCREENED_DATE
ORDER BY TOTAL_EXPOSURE DESC""",
        "remediation": "Review top counterparty exposures against internal limits. Ensure netting agreements and CSA documentation is current.",
        "audit_note": "Counterparty concentration risk check executed"
    },
    "compliance_attestation": {
        "finding": "Preparing a compliance attestation support view summarizing filing timeliness, reported breaches, validation issues, and accountable jurisdictions. This output is structured to support management sign-off, but it is not itself an executed legal attestation document.",
        "regulation": "Multi-Regulation Governance — Filing and Control Attestation Support",
        "severity": "MEDIUM",
        "rule_key": "compliance_attestation",
        "category": "Regulatory Reporting",
        "sql": """SELECT rr.REPORT_ID, rr.REPORT_TYPE, rr.REPORT_STATUS,
    rr.REPORTING_PERIOD_START, rr.REPORTING_PERIOD_END,
    rr.SUBMISSION_DEADLINE, rr.ACTUAL_SUBMISSION_DATE,
    CASE
        WHEN rr.ACTUAL_SUBMISSION_DATE > rr.SUBMISSION_DEADLINE THEN 'LATE'
        WHEN rr.ACTUAL_SUBMISSION_DATE IS NULL AND rr.SUBMISSION_DEADLINE < CURRENT_DATE() THEN 'OVERDUE'
        ELSE 'ON_TIME_OR_IN_PROGRESS'
    END AS TIMELINESS_STATUS,
    rr.BREACHES_REPORTED,
    rr.VALIDATION_ERRORS,
    rj.JURISDICTION_NAME,
    rj.REGULATION_FRAMEWORK,
    f.FUND_NAME
FROM REGULATORY_DW.REG_MODEL.FACT_REGULATORY_REPORT rr
JOIN REGULATORY_DW.REG_MODEL.DIM_REGULATORY_JURISDICTION rj
    ON rr.JURISDICTION_KEY = rj.JURISDICTION_KEY
LEFT JOIN REGULATORY_DW.REG_MODEL.DIM_FUND f
    ON rr.FUND_KEY = f.FUND_KEY
ORDER BY rr.SUBMISSION_DEADLINE ASC, rr.REPORT_TYPE""",
        "policy_refs": ["Regulatory Filing Governance"],
        "remediation": "Use the result set as attestation evidence support, then add named signatories, review timestamps, and control-owner confirmations in the final governance workflow outside the query layer.",
        "audit_note": "Compliance attestation support package generated"
    },
    "submission_package": {
        "finding": "Preparing a regulator submission support package by consolidating report status, deadlines, submission dates, validation errors, and reported breaches. This helps operations assemble the filing packet, supporting evidence, and escalation notes for regulator delivery.",
        "regulation": "Multi-Regulation Submission Operations — AIFMD, MiFID II, Form PF, UCITS",
        "severity": "MEDIUM",
        "rule_key": "submission_package",
        "category": "Regulatory Reporting",
        "sql": """SELECT rr.REPORT_ID, rr.REPORT_TYPE, rr.REPORT_STATUS,
    rr.REPORTING_PERIOD_START, rr.REPORTING_PERIOD_END,
    rr.SUBMISSION_DEADLINE, rr.ACTUAL_SUBMISSION_DATE,
    rr.VALIDATION_ERRORS, rr.BREACHES_REPORTED,
    rr.TOTAL_AUM_REPORTED, rr.GROSS_LEVERAGE_REPORTED,
    rj.JURISDICTION_NAME, rj.REGULATION_FRAMEWORK, rj.REPORTING_FREQUENCY,
    f.FUND_NAME, f.FUND_TYPE
FROM REGULATORY_DW.REG_MODEL.FACT_REGULATORY_REPORT rr
JOIN REGULATORY_DW.REG_MODEL.DIM_REGULATORY_JURISDICTION rj
    ON rr.JURISDICTION_KEY = rj.JURISDICTION_KEY
LEFT JOIN REGULATORY_DW.REG_MODEL.DIM_FUND f
    ON rr.FUND_KEY = f.FUND_KEY
ORDER BY rr.SUBMISSION_DEADLINE ASC, rr.REPORT_TYPE, f.FUND_NAME""",
        "policy_refs": ["Regulatory Filing Governance"],
        "remediation": "Attach the exported results to the filing checklist, add supporting workpapers and reconciliations, and route any overdue, late, or validation-failed items through compliance escalation before submission.",
        "audit_note": "Regulator submission support package generated"
    },
    "aifmd": {
        "finding": "Checking AIFMD Annex IV reporting compliance — fund leverage, AUM disclosure, and submission status for Alternative Investment Funds.",
        "regulation": "AIFMD — Annex IV Reporting (Articles 3, 24)",
        "severity": "HIGH",
        "rule_key": "aifmd",
        "category": "Regulatory Reporting",
        "sql": """SELECT f.FUND_ID, f.FUND_NAME, f.FUND_TYPE, f.FUND_STRUCTURE, f.TOTAL_AUM,
    f.LEVERAGE_RATIO AS GROSS_LEVERAGE, f.BASE_CURRENCY, f.AIFMD_REPORTING_REQUIRED,
    g.COUNTRY_NAME AS DOMICILE,
    rr.REPORT_TYPE, rr.REPORT_STATUS, rr.REPORTING_PERIOD_START, rr.REPORTING_PERIOD_END,
    rr.SUBMISSION_DEADLINE, rr.ACTUAL_SUBMISSION_DATE, rr.BREACHES_REPORTED,
    rr.GROSS_LEVERAGE_REPORTED, rr.TOTAL_AUM_REPORTED
FROM REGULATORY_DW.REG_MODEL.DIM_FUND f
LEFT JOIN REGULATORY_DW.REG_MODEL.DIM_GEOGRAPHY g ON f.DOMICILE_GEOGRAPHY_KEY = g.GEOGRAPHY_KEY
LEFT JOIN REGULATORY_DW.REG_MODEL.FACT_REGULATORY_REPORT rr
    ON rr.FUND_KEY = f.FUND_KEY AND rr.REPORT_TYPE = 'AIFMD_ANNEX_IV'
WHERE f.AIFMD_REPORTING_REQUIRED = TRUE AND f.IS_CURRENT = TRUE
ORDER BY f.TOTAL_AUM DESC""",
        "remediation": "Ensure all AIFMD-reporting funds have submitted Annex IV within the quarterly deadline. Escalate any late or not-started reports.",
        "audit_note": "AIFMD Annex IV reporting compliance check executed"
    },
    "ucits": {
        "finding": "Checking UCITS fund compliance — concentration limits, leverage constraints, and derivative exposure caps.",
        "regulation": "UCITS Directive — Articles 52-56, Eligible Assets",
        "severity": "MEDIUM",
        "rule_key": "ucits",
        "category": "Exposure & Portfolio",
        "sql": """SELECT f.FUND_ID, f.FUND_NAME, f.TOTAL_AUM, f.LEVERAGE_RATIO, f.BASE_CURRENCY,
    COUNT(p.POSITION_KEY) AS POSITIONS,
    SUM(p.MARKET_VALUE_BASE) AS TOTAL_MV,
    MAX(p.WEIGHT_IN_FUND_PCT) AS MAX_SINGLE_POSITION_PCT,
    SUM(CASE WHEN p.CONCENTRATION_BREACH = TRUE THEN 1 ELSE 0 END) AS BREACHES,
    SUM(CASE WHEN s.ASSET_CLASS = 'DERIVATIVE' THEN p.MARKET_VALUE_BASE ELSE 0 END) AS DERIVATIVE_EXPOSURE
FROM REGULATORY_DW.REG_MODEL.DIM_FUND f
LEFT JOIN REGULATORY_DW.REG_MODEL.FACT_POSITION p ON f.FUND_KEY = p.FUND_KEY AND p.AS_OF_DATE = '2026-06-30'
LEFT JOIN REGULATORY_DW.REG_MODEL.DIM_SECURITY s ON p.SECURITY_KEY = s.SECURITY_KEY
WHERE f.UCITS_COMPLIANT = TRUE AND f.IS_CURRENT = TRUE
GROUP BY f.FUND_ID, f.FUND_NAME, f.TOTAL_AUM, f.LEVERAGE_RATIO, f.BASE_CURRENCY
ORDER BY f.TOTAL_AUM DESC""",
        "remediation": "Reduce positions exceeding 10% NAV single-issuer limit. Ensure total derivative exposure remains below 100% NAV.",
        "audit_note": "UCITS directive compliance check executed"
    },
    "form_pf": {
        "finding": "Checking SEC Form PF reporting status for qualifying hedge funds and private funds.",
        "regulation": "Dodd-Frank — Form PF (SEC/CFTC)",
        "severity": "HIGH",
        "rule_key": "form_pf",
        "category": "Regulatory Reporting",
        "sql": """SELECT f.FUND_ID, f.FUND_NAME, f.FUND_TYPE, f.TOTAL_AUM, f.LEVERAGE_RATIO,
    f.FORM_PF_REPORTING_REQUIRED, f.BASE_CURRENCY,
    rr.REPORT_TYPE, rr.REPORT_STATUS, rr.REPORTING_PERIOD_START, rr.REPORTING_PERIOD_END,
    rr.SUBMISSION_DEADLINE, rr.ACTUAL_SUBMISSION_DATE,
    rr.TOTAL_AUM_REPORTED, rr.GROSS_LEVERAGE_REPORTED, rr.BREACHES_REPORTED
FROM REGULATORY_DW.REG_MODEL.DIM_FUND f
LEFT JOIN REGULATORY_DW.REG_MODEL.FACT_REGULATORY_REPORT rr
    ON rr.FUND_KEY = f.FUND_KEY AND rr.REPORT_TYPE = 'FORM_PF'
WHERE f.FORM_PF_REPORTING_REQUIRED = TRUE AND f.IS_CURRENT = TRUE
ORDER BY f.TOTAL_AUM DESC""",
        "remediation": "Ensure Form PF is filed within 60 days of quarter-end for large hedge fund advisers. Verify AUM and leverage figures match position data.",
        "audit_note": "SEC Form PF reporting status check executed"
    },
    "concentration": {
        "finding": "Checking position concentration breaches — positions exceeding fund-level limits.",
        "regulation": "UCITS / Basel III — Concentration Limits",
        "severity": "HIGH",
        "rule_key": "concentration",
        "category": "Exposure & Portfolio",
        "sql": """SELECT p.POSITION_KEY, s.SECURITY_NAME, f.FUND_NAME, f.FUND_TYPE,
    p.MARKET_VALUE_BASE, p.WEIGHT_IN_FUND_PCT, p.CONCENTRATION_BREACH,
    p.LEVERAGE_CONTRIBUTION, p.POSITION_TYPE
FROM REGULATORY_DW.REG_MODEL.FACT_POSITION p
JOIN REGULATORY_DW.REG_MODEL.DIM_SECURITY s ON p.SECURITY_KEY = s.SECURITY_KEY
JOIN REGULATORY_DW.REG_MODEL.DIM_FUND f ON p.FUND_KEY = f.FUND_KEY
WHERE p.AS_OF_DATE = '2026-06-30'
ORDER BY p.WEIGHT_IN_FUND_PCT DESC NULLS LAST""",
        "remediation": "Reduce oversized positions to within regulatory limits. For UCITS funds, no single position should exceed 10% of NAV.",
        "audit_note": "Position concentration limit check executed"
    },
    "aml_alerts": {
        "finding": "Querying live AML alerts from the operational alert table so analysts can review open, escalated, and recently closed alerts with ownership and disposition context.",
        "regulation": "AML Operations — Alert and Case Monitoring",
        "severity": "MEDIUM",
        "rule_key": "aml_alerts",
        "category": "AML Monitoring",
        "sql": """SELECT ALERT_ID, ALERT_TITLE, ALERT_STATUS, ALERT_SEVERITY, ALERT_SCORE,
    EVENT_DATE, ACCOUNT_KEY, COUNTERPARTY_KEY, FUND_KEY,
    ASSIGNED_ANALYST, CASE_ID, DISPOSITION, SAR_FILED_FLAG,
    ALERT_CREATED_AT, CLOSED_AT
FROM REGULATORY_DW.REG_MODEL.FACT_AML_ALERT
ORDER BY ALERT_CREATED_AT DESC, ALERT_SEVERITY DESC""",
        "remediation": "Review open and escalated alerts first, confirm analyst assignment and disposition timeliness, and reconcile any missing case IDs before governance review.",
        "audit_note": "Live AML alert inventory query prepared"
    },
    "breach_explain": {
        "finding": "Explaining persisted compliance breach <BREACH_ID> by retrieving its control context, severity, regulation, entity, and remediation guidance from the breach registry.",
        "regulation": "Breach Management — Persisted Compliance Breach Registry",
        "severity": "MEDIUM",
        "rule_key": "breach_explain",
        "category": "Regulatory Reporting",
        "sql": """SELECT BREACH_ID, BREACH_TYPE, BREACH_SEVERITY, REGULATION, CONTROL_NAME,
    ENTITY_TYPE, ENTITY_ID, ENTITY_NAME, BREACH_STATUS,
    BREACH_REASON, BREACH_VALUE, BREACH_THRESHOLD,
    DETECTED_AT, DUE_DATE, OWNER_TEAM, REMEDIATION_ACTION,
    ROOT_CAUSE_NOTE
FROM REGULATORY_DW.REG_MODEL.FACT_COMPLIANCE_BREACH
WHERE BREACH_ID = '<BREACH_ID>'""",
        "remediation": "Review the persisted breach record, validate root cause and ownership, and confirm that remediation milestones and due dates are current.",
        "audit_note": "Breach explanation query prepared"
    },
    "breach_evidence": {
        "finding": "Retrieving evidence for persisted compliance breach <BREACH_ID>, including the stored evidence SQL, payload, and supporting timestamps from the breach registry.",
        "regulation": "Breach Management — Evidence Retrieval",
        "severity": "MEDIUM",
        "rule_key": "breach_evidence",
        "category": "Regulatory Reporting",
        "sql": """SELECT BREACH_ID, BREACH_TYPE, BREACH_SEVERITY,
    EVIDENCE_SQL, EVIDENCE_PAYLOAD, SOURCE_RULE_ID,
    DETECTED_AT, LAST_REVALIDATED_AT, SUPPORTING_REFERENCE
FROM REGULATORY_DW.REG_MODEL.FACT_COMPLIANCE_BREACH
WHERE BREACH_ID = '<BREACH_ID>'""",
        "remediation": "Validate that the stored evidence still reflects the current control state and re-run the underlying query if the breach has been reopened or amended.",
        "audit_note": "Breach evidence query prepared"
    },
    "suitability_exceptions": {
        "finding": "Checking for client suitability exceptions using persisted suitability assessments, product risk bands, and client mandate constraints.",
        "regulation": "MiFID II / Suitability Governance — Client Appropriateness and Suitability",
        "severity": "HIGH",
        "rule_key": "suitability_exceptions",
        "category": "Regulatory Reporting",
        "sql": """SELECT se.ASSESSMENT_ID, se.ACCOUNT_ID, se.ACCOUNT_NAME,
    se.PRODUCT_ID, se.PRODUCT_NAME, se.PRODUCT_RISK_RATING,
    se.CLIENT_RISK_TOLERANCE, se.MANDATE_RESTRICTION,
    se.SUITABILITY_STATUS, se.EXCEPTION_REASON,
    se.REVIEWED_AT, se.REMEDIATION_REQUIRED
FROM REGULATORY_DW.REG_MODEL.DIM_CLIENT_SUITABILITY_ASSESSMENT se
WHERE UPPER(se.SUITABILITY_STATUS) IN ('EXCEPTION', 'BREACH', 'REJECTED')
ORDER BY se.REVIEWED_AT DESC, se.ACCOUNT_NAME""",
        "remediation": "Escalate any suitability breaches for investment review, reconcile mandate restrictions against executed activity, and block further unsuitable recommendations until cleared.",
        "audit_note": "Client suitability exception query prepared"
    },
    "transaction_audit_trail": {
        "finding": "Retrieving the audit trail for transaction <TRANSACTION_ID> from the persisted transaction audit table, including status changes, control evaluations, and user/system actions.",
        "regulation": "Operational Controls — Transaction Audit Trail",
        "severity": "INFO",
        "rule_key": "transaction_audit_trail",
        "category": "Regulatory Reporting",
        "sql": """SELECT TRANSACTION_ID, EVENT_SEQUENCE, EVENT_TIMESTAMP, EVENT_TYPE,
    ACTOR_TYPE, ACTOR_ID, CONTROL_NAME, PREVIOUS_STATUS,
    NEW_STATUS, EVENT_NOTE, EVIDENCE_REFERENCE
FROM REGULATORY_DW.REG_MODEL.FACT_TRANSACTION_AUDIT_TRAIL
WHERE TRANSACTION_ID = '<TRANSACTION_ID>'
ORDER BY EVENT_SEQUENCE ASC, EVENT_TIMESTAMP ASC""",
        "remediation": "Review the ordered audit events to confirm which control fired, who changed the status, and whether the documented evidence aligns with the final transaction outcome.",
        "audit_note": "Transaction audit trail query prepared"
    },
    "critical_breaches": {
        "finding": "Aggregating the most material current breaches across leverage, concentration, KYC recency, and overdue filings. This view prioritizes issues that are already breached, overdue, or explicitly marked late for immediate triage.",
        "regulation": "Multi-Regulation — Basel III, AML/KYC, UCITS, AIFMD, MiFID II",
        "severity": "HIGH",
        "rule_key": "critical_breaches",
        "category": "Exposure & Portfolio",
        "sql": """SELECT *
FROM (
    SELECT 'LEVERAGE_BREACH' AS BREACH_TYPE, f.FUND_ID AS ENTITY_ID, f.FUND_NAME AS ENTITY_NAME,
        'HIGH' AS BREACH_SEVERITY,
        'Basel III leverage ratio exceeds 3.0x' AS BREACH_REASON,
        f.LEVERAGE_RATIO::VARCHAR AS BREACH_VALUE,
        'Basel III' AS REGULATION
    FROM REGULATORY_DW.REG_MODEL.DIM_FUND f
    WHERE f.IS_CURRENT = TRUE AND f.LEVERAGE_RATIO > 3.0

    UNION ALL

    SELECT 'KYC_OVERDUE' AS BREACH_TYPE, da.ACCOUNT_ID AS ENTITY_ID, da.ACCOUNT_NAME AS ENTITY_NAME,
        'HIGH' AS BREACH_SEVERITY,
        'KYC review overdue by more than 365 days' AS BREACH_REASON,
        DATEDIFF('day', da.KYC_LAST_REVIEWED, CURRENT_DATE())::VARCHAR AS BREACH_VALUE,
        'AML/KYC' AS REGULATION
    FROM REGULATORY_DW.REG_MODEL.DIM_ACCOUNT da
    WHERE da.IS_CURRENT = TRUE
      AND DATEDIFF('day', da.KYC_LAST_REVIEWED, CURRENT_DATE()) > 365

    UNION ALL

    SELECT 'CONCENTRATION_BREACH' AS BREACH_TYPE, f.FUND_ID AS ENTITY_ID, f.FUND_NAME AS ENTITY_NAME,
        'HIGH' AS BREACH_SEVERITY,
        'Position exceeds concentration limit' AS BREACH_REASON,
        p.WEIGHT_IN_FUND_PCT::VARCHAR AS BREACH_VALUE,
        'UCITS / Basel III' AS REGULATION
    FROM REGULATORY_DW.REG_MODEL.FACT_POSITION p
    JOIN REGULATORY_DW.REG_MODEL.DIM_FUND f ON p.FUND_KEY = f.FUND_KEY
    WHERE p.AS_OF_DATE = '2026-06-30' AND p.CONCENTRATION_BREACH = TRUE

    UNION ALL

    SELECT 'OVERDUE_FILING' AS BREACH_TYPE, rr.REPORT_ID AS ENTITY_ID, rr.REPORT_TYPE AS ENTITY_NAME,
        'HIGH' AS BREACH_SEVERITY,
        'Regulatory report is late or overdue' AS BREACH_REASON,
        COALESCE(TO_VARCHAR(rr.ACTUAL_SUBMISSION_DATE), 'NOT_SUBMITTED') AS BREACH_VALUE,
        rj.REGULATION_FRAMEWORK AS REGULATION
    FROM REGULATORY_DW.REG_MODEL.FACT_REGULATORY_REPORT rr
    JOIN REGULATORY_DW.REG_MODEL.DIM_REGULATORY_JURISDICTION rj ON rr.JURISDICTION_KEY = rj.JURISDICTION_KEY
    WHERE rr.ACTUAL_SUBMISSION_DATE > rr.SUBMISSION_DEADLINE
       OR (rr.ACTUAL_SUBMISSION_DATE IS NULL AND rr.SUBMISSION_DEADLINE < CURRENT_DATE())
) critical_items
ORDER BY BREACH_SEVERITY DESC, BREACH_TYPE, ENTITY_NAME""",
        "remediation": "Route the returned breaches into immediate triage. Prioritize overdue filings, stale KYC, leverage excesses, and concentration breaches before lower-severity exceptions.",
        "audit_note": "Critical breach inventory compiled"
    },
    "top_risks": {
        "finding": "Summarizing the top current risk themes across leverage, KYC, reporting, concentration, and trade reporting exceptions. This gives a management-style view of where the highest issue volumes sit today.",
        "regulation": "Enterprise Risk Summary — Basel III, AML/KYC, MiFID II, AIFMD, UCITS",
        "severity": "MEDIUM",
        "rule_key": "top_risks",
        "category": "Exposure & Portfolio",
        "sql": """SELECT RISK_THEME, ISSUE_COUNT, RISK_LEVEL
FROM (
    SELECT 'Leverage Breaches' AS RISK_THEME,
        COUNT(*) AS ISSUE_COUNT,
        'HIGH' AS RISK_LEVEL
    FROM REGULATORY_DW.REG_MODEL.DIM_FUND
    WHERE IS_CURRENT = TRUE AND LEVERAGE_RATIO > 3.0

    UNION ALL

    SELECT 'KYC Overdue Reviews' AS RISK_THEME,
        COUNT(*) AS ISSUE_COUNT,
        'HIGH' AS RISK_LEVEL
    FROM REGULATORY_DW.REG_MODEL.DIM_ACCOUNT
    WHERE IS_CURRENT = TRUE AND DATEDIFF('day', KYC_LAST_REVIEWED, CURRENT_DATE()) > 365

    UNION ALL

    SELECT 'Late or Overdue Filings' AS RISK_THEME,
        COUNT(*) AS ISSUE_COUNT,
        'HIGH' AS RISK_LEVEL
    FROM REGULATORY_DW.REG_MODEL.FACT_REGULATORY_REPORT
    WHERE ACTUAL_SUBMISSION_DATE > SUBMISSION_DEADLINE
       OR (ACTUAL_SUBMISSION_DATE IS NULL AND SUBMISSION_DEADLINE < CURRENT_DATE())

    UNION ALL

    SELECT 'Concentration Breaches' AS RISK_THEME,
        COUNT(*) AS ISSUE_COUNT,
        'HIGH' AS RISK_LEVEL
    FROM REGULATORY_DW.REG_MODEL.FACT_POSITION
    WHERE AS_OF_DATE = '2026-06-30' AND CONCENTRATION_BREACH = TRUE

    UNION ALL

    SELECT 'Unreported or Failed Trades' AS RISK_THEME,
        COUNT(*) AS ISSUE_COUNT,
        'MEDIUM' AS RISK_LEVEL
    FROM REGULATORY_DW.REG_MODEL.FACT_TRANSACTION
    WHERE REPORTING_STATUS != 'REPORTED'
) risk_summary
ORDER BY ISSUE_COUNT DESC, RISK_THEME""",
        "remediation": "Use the summary to rank daily triage queues. Focus remediation on the highest-volume high-risk themes first, then drill into supporting exception queries.",
        "audit_note": "Top enterprise risk summary generated"
    },
    "basel_capital": {
        "finding": "Producing a Basel III capital adequacy proxy using the available fund leverage and position risk fields. Because the current schema does not contain a prudential capital fact table, this is a management proxy rather than a formal regulatory capital return.",
        "regulation": "Basel III — Capital Adequacy Proxy View",
        "severity": "MEDIUM",
        "rule_key": "basel_capital",
        "category": "Exposure & Portfolio",
        "sql": """SELECT f.FUND_ID, f.FUND_NAME, f.LEVERAGE_RATIO,
    SUM(COALESCE(p.VAR_99, 0)) AS PORTFOLIO_VAR_99,
    SUM(COALESCE(p.LEVERAGE_CONTRIBUTION, 0)) AS TOTAL_LEVERAGE_CONTRIBUTION,
    CASE
        WHEN f.LEVERAGE_RATIO > 3.0 THEN 'CAPITAL_PRESSURE'
        WHEN SUM(COALESCE(p.VAR_99, 0)) > 0 THEN 'MONITOR'
        ELSE 'STABLE'
    END AS BASEL_CAPITAL_PROXY_STATUS
FROM REGULATORY_DW.REG_MODEL.DIM_FUND f
LEFT JOIN REGULATORY_DW.REG_MODEL.FACT_POSITION p
    ON f.FUND_KEY = p.FUND_KEY AND p.AS_OF_DATE = '2026-06-30'
WHERE f.IS_CURRENT = TRUE
GROUP BY f.FUND_ID, f.FUND_NAME, f.LEVERAGE_RATIO
ORDER BY f.LEVERAGE_RATIO DESC, PORTFOLIO_VAR_99 DESC""",
        "remediation": "Do not use this output as a filed capital ratio. Use it as a proxy monitoring report until CET1, Tier 1 capital, RWA, and total capital measures are modeled explicitly.",
        "audit_note": "Basel capital proxy report generated"
    },
    "lcr": {
        "finding": "Producing a Liquidity Coverage Ratio proxy using available liquidity-days and pledged collateral fields. This is not a formal LCR because contractual 30-day cash outflow tables are not present in the current schema.",
        "regulation": "Basel III — Liquidity Coverage Ratio Proxy",
        "severity": "MEDIUM",
        "rule_key": "lcr",
        "category": "Exposure & Portfolio",
        "sql": """SELECT f.FUND_ID, f.FUND_NAME,
    SUM(CASE WHEN COALESCE(p.LIQUIDITY_DAYS, 999) <= 30 THEN COALESCE(p.MARKET_VALUE_BASE, 0) ELSE 0 END) AS HIGH_QUALITY_LIQUID_ASSETS_PROXY,
    SUM(COALESCE(p.MARGIN_REQUIREMENT, 0) + COALESCE(p.COLLATERAL_PLEDGED, 0)) AS THIRTY_DAY_OUTFLOW_PROXY,
    CASE
        WHEN SUM(COALESCE(p.MARGIN_REQUIREMENT, 0) + COALESCE(p.COLLATERAL_PLEDGED, 0)) = 0 THEN NULL
        ELSE SUM(CASE WHEN COALESCE(p.LIQUIDITY_DAYS, 999) <= 30 THEN COALESCE(p.MARKET_VALUE_BASE, 0) ELSE 0 END)
             / NULLIF(SUM(COALESCE(p.MARGIN_REQUIREMENT, 0) + COALESCE(p.COLLATERAL_PLEDGED, 0)), 0)
    END AS LCR_PROXY
FROM REGULATORY_DW.REG_MODEL.DIM_FUND f
LEFT JOIN REGULATORY_DW.REG_MODEL.FACT_POSITION p
    ON f.FUND_KEY = p.FUND_KEY AND p.AS_OF_DATE = '2026-06-30'
WHERE f.IS_CURRENT = TRUE
GROUP BY f.FUND_ID, f.FUND_NAME
ORDER BY LCR_PROXY ASC NULLS LAST, f.FUND_NAME""",
        "remediation": "Treat this as directional liquidity monitoring only. To produce a filed LCR, add contractual inflow/outflow, HQLA classification, and 30-day stress runoff assumptions.",
        "audit_note": "Basel LCR proxy report generated"
    },
    "nsfr": {
        "finding": "Producing a Net Stable Funding Ratio proxy using position duration, liquidity horizon, and funding requirement fields that exist today. This is a proxy view because ASF and RSF components are not yet explicitly modeled.",
        "regulation": "Basel III — Net Stable Funding Ratio Proxy",
        "severity": "MEDIUM",
        "rule_key": "nsfr",
        "category": "Exposure & Portfolio",
        "sql": """SELECT f.FUND_ID, f.FUND_NAME,
    SUM(CASE WHEN COALESCE(p.LIQUIDITY_DAYS, 999) > 30 THEN COALESCE(p.MARKET_VALUE_BASE, 0) ELSE 0 END) AS REQUIRED_STABLE_FUNDING_PROXY,
    SUM(COALESCE(p.COST_BASIS_BASE, 0) + COALESCE(p.ACCRUED_INCOME, 0)) AS AVAILABLE_STABLE_FUNDING_PROXY,
    CASE
        WHEN SUM(COALESCE(p.MARKET_VALUE_BASE, 0)) = 0 THEN NULL
        ELSE SUM(COALESCE(p.COST_BASIS_BASE, 0) + COALESCE(p.ACCRUED_INCOME, 0))
             / NULLIF(SUM(CASE WHEN COALESCE(p.LIQUIDITY_DAYS, 999) > 30 THEN COALESCE(p.MARKET_VALUE_BASE, 0) ELSE 0 END), 0)
    END AS NSFR_PROXY
FROM REGULATORY_DW.REG_MODEL.DIM_FUND f
LEFT JOIN REGULATORY_DW.REG_MODEL.FACT_POSITION p
    ON f.FUND_KEY = p.FUND_KEY AND p.AS_OF_DATE = '2026-06-30'
WHERE f.IS_CURRENT = TRUE
GROUP BY f.FUND_ID, f.FUND_NAME
ORDER BY NSFR_PROXY ASC NULLS LAST, f.FUND_NAME""",
        "remediation": "Use this only for directional funding stability monitoring. A formal NSFR requires modeled available stable funding and required stable funding buckets.",
        "audit_note": "Basel NSFR proxy report generated"
    },
    "cet1": {
        "finding": "Producing a CET1 proxy view from the currently available leverage and portfolio risk fields. The current schema lacks explicit CET1 capital and risk-weighted asset tables, so this is only an indicative control view.",
        "regulation": "Basel III — CET1 Ratio Proxy",
        "severity": "MEDIUM",
        "rule_key": "cet1",
        "category": "Exposure & Portfolio",
        "sql": """SELECT f.FUND_ID, f.FUND_NAME,
    f.TOTAL_AUM,
    f.LEVERAGE_RATIO,
    SUM(COALESCE(p.VAR_95, 0) + COALESCE(p.VAR_99, 0)) AS RISK_WEIGHTED_PROXY,
    CASE
        WHEN SUM(COALESCE(p.VAR_95, 0) + COALESCE(p.VAR_99, 0)) = 0 THEN NULL
        ELSE f.TOTAL_AUM / NULLIF(SUM(COALESCE(p.VAR_95, 0) + COALESCE(p.VAR_99, 0)), 0)
    END AS CET1_PROXY_RATIO
FROM REGULATORY_DW.REG_MODEL.DIM_FUND f
LEFT JOIN REGULATORY_DW.REG_MODEL.FACT_POSITION p
    ON f.FUND_KEY = p.FUND_KEY AND p.AS_OF_DATE = '2026-06-30'
WHERE f.IS_CURRENT = TRUE
GROUP BY f.FUND_ID, f.FUND_NAME, f.TOTAL_AUM, f.LEVERAGE_RATIO
ORDER BY CET1_PROXY_RATIO ASC NULLS LAST, f.FUND_NAME""",
        "remediation": "Do not label this a filed CET1 ratio in regulator-facing output. Model explicit common equity capital and RWA tables before using this metric for formal reporting.",
        "audit_note": "Basel CET1 proxy report generated"
    },
}


AML_RULE_BASED_QUERIES = {
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
            "disposition_hint": "Review threshold avoidance and linked transactions"
        }
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
            "disposition_hint": "Compare burst behavior against historical account activity"
        }
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
            "disposition_hint": "Check source of funds and payment rationale"
        }
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
            "disposition_hint": "Refresh KYC and verify source of funds before further activity"
        }
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
            "disposition_hint": "Immediate screening refresh and analyst adjudication required"
        }
    },
}


AML_SCHEMA_RULE_BASED_QUERIES = {
    "aml_rule_schema": {
        "finding": "Designing a rule catalog table to operationalize AML detections outside the Python code path. This table stores rule metadata, thresholds, routing, status, and regulatory lineage so the monitoring engine can be configured without redeploying the app.",
        "regulation": "AML Governance / FATF Recommendations 10, 12, 20, 24",
        "severity": "INFO",
        "rule_key": "aml_rule_schema",
        "category": "Schema Design",
        "sql": "",
        "design_ddl": """CREATE OR REPLACE TABLE REGULATORY_DW.REG_MODEL.DIM_AML_RULE (
    AML_RULE_KEY NUMBER AUTOINCREMENT START 1 INCREMENT 1,
    RULE_ID VARCHAR(50) NOT NULL,
    RULE_NAME VARCHAR(200) NOT NULL,
    RULE_FAMILY VARCHAR(100) NOT NULL,
    RULE_CATEGORY VARCHAR(100) NOT NULL,
    SCENARIO_TYPE VARCHAR(100) NOT NULL,
    REGULATORY_BASIS VARCHAR(500),
    JURISDICTION_SCOPE VARCHAR(200),
    RISK_DOMAIN VARCHAR(100),
    SEVERITY_DEFAULT VARCHAR(20) NOT NULL,
    ENABLED_FLAG BOOLEAN NOT NULL DEFAULT TRUE,
    THRESHOLD_AMOUNT NUMBER(18,2),
    THRESHOLD_COUNT NUMBER(18,0),
    LOOKBACK_DAYS NUMBER(18,0),
    MIN_ACCOUNT_AGE_DAYS NUMBER(18,0),
    HIGH_RISK_ONLY_FLAG BOOLEAN DEFAULT FALSE,
    REQUIRE_PEP_FLAG BOOLEAN DEFAULT FALSE,
    RULE_SQL_TEMPLATE STRING,
    INVESTIGATION_PLAYBOOK VARCHAR(1000),
    ESCALATION_QUEUE VARCHAR(100),
    OWNER_TEAM VARCHAR(100),
    EFFECTIVE_START_DATE DATE NOT NULL DEFAULT CURRENT_DATE(),
    EFFECTIVE_END_DATE DATE,
    VERSION_NUMBER NUMBER(10,0) NOT NULL DEFAULT 1,
    LAST_TUNED_AT TIMESTAMP_NTZ,
    LAST_TUNED_BY VARCHAR(200),
    CREATED_AT TIMESTAMP_NTZ NOT NULL DEFAULT CURRENT_TIMESTAMP(),
    CREATED_BY VARCHAR(200) NOT NULL DEFAULT CURRENT_USER(),
    UPDATED_AT TIMESTAMP_NTZ,
    UPDATED_BY VARCHAR(200),
    IS_CURRENT BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT PK_DIM_AML_RULE PRIMARY KEY (AML_RULE_KEY),
    CONSTRAINT UQ_DIM_AML_RULE_RULE_ID_VERSION UNIQUE (RULE_ID, VERSION_NUMBER)
);""",
        "remediation": "Seed the table with baseline rules for KYC, structuring, velocity, sanctions hygiene, and dormant-account reactivation. Externalize tuning thresholds into this table before expanding the rules engine further.",
        "audit_note": "DIM_AML_RULE schema design returned"
    },
    "aml_alert_schema": {
        "finding": "Designing an alert fact table to persist triggered AML events, investigation ownership, and case outcomes. This moves the app from ad hoc query output toward an operational monitoring workflow.",
        "regulation": "AML Operations / FATF Recommendation 20 / Suspicious Activity Escalation",
        "severity": "INFO",
        "rule_key": "aml_alert_schema",
        "category": "Schema Design",
        "sql": "",
        "design_ddl": """CREATE OR REPLACE TABLE REGULATORY_DW.REG_MODEL.FACT_AML_ALERT (
    AML_ALERT_KEY NUMBER AUTOINCREMENT START 1 INCREMENT 1,
    ALERT_ID VARCHAR(50) NOT NULL,
    AML_RULE_KEY NUMBER NOT NULL,
    ALERT_CREATED_AT TIMESTAMP_NTZ NOT NULL DEFAULT CURRENT_TIMESTAMP(),
    ALERT_STATUS VARCHAR(30) NOT NULL DEFAULT 'OPEN',
    ALERT_SEVERITY VARCHAR(20) NOT NULL,
    ALERT_SCORE NUMBER(10,2),
    ACCOUNT_KEY NUMBER,
    COUNTERPARTY_KEY NUMBER,
    FUND_KEY NUMBER,
    SECURITY_KEY NUMBER,
    JURISDICTION_KEY NUMBER,
    GEOGRAPHY_KEY NUMBER,
    TRANSACTION_KEY NUMBER,
    POSITION_KEY NUMBER,
    EVENT_DATE DATE,
    EVENT_TIMESTAMP TIMESTAMP_NTZ,
    ALERT_TITLE VARCHAR(300) NOT NULL,
    ALERT_SUMMARY VARCHAR(2000),
    TRIGGER_VALUE NUMBER(18,2),
    THRESHOLD_VALUE NUMBER(18,2),
    BREACH_COUNT NUMBER(18,0),
    EVIDENCE_SQL STRING,
    EVIDENCE_PAYLOAD VARIANT,
    ASSIGNED_ANALYST VARCHAR(200),
    ESCALATED_AT TIMESTAMP_NTZ,
    CLOSED_AT TIMESTAMP_NTZ,
    CASE_ID VARCHAR(50),
    DISPOSITION VARCHAR(100),
    DISPOSITION_REASON VARCHAR(1000),
    SAR_FILED_FLAG BOOLEAN DEFAULT FALSE,
    SAR_REFERENCE_ID VARCHAR(100),
    CREATED_AT TIMESTAMP_NTZ NOT NULL DEFAULT CURRENT_TIMESTAMP(),
    CREATED_BY VARCHAR(200) NOT NULL DEFAULT CURRENT_USER(),
    UPDATED_AT TIMESTAMP_NTZ,
    UPDATED_BY VARCHAR(200),
    CONSTRAINT PK_FACT_AML_ALERT PRIMARY KEY (AML_ALERT_KEY),
    CONSTRAINT UQ_FACT_AML_ALERT_ALERT_ID UNIQUE (ALERT_ID),
    CONSTRAINT FK_FACT_AML_ALERT_RULE FOREIGN KEY (AML_RULE_KEY)
        REFERENCES REGULATORY_DW.REG_MODEL.DIM_AML_RULE (AML_RULE_KEY)
);""",
        "remediation": "Populate the alert table from scheduled AML rule executions and link alerts into case management using CASE_ID, analyst assignment, and disposition fields.",
        "audit_note": "FACT_AML_ALERT schema design returned"
    },
    "compliance_breach_schema": {
        "finding": "Designing a persisted compliance breach fact table so each breach has a stable identifier, evidence payload, owner, remediation state, and drill-down path for regulator and audit review.",
        "regulation": "Breach Governance — Persisted Control Exceptions",
        "severity": "INFO",
        "rule_key": "compliance_breach_schema",
        "category": "Schema Design",
        "sql": "",
        "design_ddl": """CREATE OR REPLACE TABLE REGULATORY_DW.REG_MODEL.FACT_COMPLIANCE_BREACH (
    COMPLIANCE_BREACH_KEY NUMBER AUTOINCREMENT START 1 INCREMENT 1,
    BREACH_ID VARCHAR(50) NOT NULL,
    SOURCE_RULE_ID VARCHAR(50) NOT NULL,
    BREACH_TYPE VARCHAR(100) NOT NULL,
    BREACH_SEVERITY VARCHAR(20) NOT NULL,
    REGULATION VARCHAR(300),
    CONTROL_NAME VARCHAR(300),
    ENTITY_TYPE VARCHAR(50),
    ENTITY_ID VARCHAR(100),
    ENTITY_NAME VARCHAR(300),
    BREACH_STATUS VARCHAR(30) NOT NULL DEFAULT 'OPEN',
    BREACH_REASON VARCHAR(2000),
    BREACH_VALUE VARCHAR(200),
    BREACH_THRESHOLD VARCHAR(200),
    OWNER_TEAM VARCHAR(100),
    DUE_DATE DATE,
    ROOT_CAUSE_NOTE VARCHAR(2000),
    REMEDIATION_ACTION VARCHAR(2000),
    EVIDENCE_SQL STRING,
    EVIDENCE_PAYLOAD VARIANT,
    SUPPORTING_REFERENCE VARCHAR(300),
    DETECTED_AT TIMESTAMP_NTZ NOT NULL DEFAULT CURRENT_TIMESTAMP(),
    LAST_REVALIDATED_AT TIMESTAMP_NTZ,
    CLOSED_AT TIMESTAMP_NTZ,
    CREATED_AT TIMESTAMP_NTZ NOT NULL DEFAULT CURRENT_TIMESTAMP(),
    CREATED_BY VARCHAR(200) NOT NULL DEFAULT CURRENT_USER(),
    UPDATED_AT TIMESTAMP_NTZ,
    UPDATED_BY VARCHAR(200),
    CONSTRAINT PK_FACT_COMPLIANCE_BREACH PRIMARY KEY (COMPLIANCE_BREACH_KEY),
    CONSTRAINT UQ_FACT_COMPLIANCE_BREACH_ID UNIQUE (BREACH_ID)
);""",
        "remediation": "Populate this table from scheduled control runs so breach drill-down questions can resolve against a stable persisted identifier and evidence package.",
        "audit_note": "FACT_COMPLIANCE_BREACH schema design returned"
    },
    "transaction_audit_trail_schema": {
        "finding": "Designing a persisted transaction audit trail table to record control actions, state changes, and user or system events for drill-down review.",
        "regulation": "Operational Governance — Transaction Auditability",
        "severity": "INFO",
        "rule_key": "transaction_audit_trail_schema",
        "category": "Schema Design",
        "sql": "",
        "design_ddl": """CREATE OR REPLACE TABLE REGULATORY_DW.REG_MODEL.FACT_TRANSACTION_AUDIT_TRAIL (
    TRANSACTION_AUDIT_KEY NUMBER AUTOINCREMENT START 1 INCREMENT 1,
    TRANSACTION_ID VARCHAR(100) NOT NULL,
    EVENT_SEQUENCE NUMBER(18,0) NOT NULL,
    EVENT_TIMESTAMP TIMESTAMP_NTZ NOT NULL,
    EVENT_TYPE VARCHAR(100) NOT NULL,
    ACTOR_TYPE VARCHAR(50),
    ACTOR_ID VARCHAR(200),
    CONTROL_NAME VARCHAR(300),
    PREVIOUS_STATUS VARCHAR(100),
    NEW_STATUS VARCHAR(100),
    EVENT_NOTE VARCHAR(2000),
    EVIDENCE_REFERENCE VARCHAR(300),
    CREATED_AT TIMESTAMP_NTZ NOT NULL DEFAULT CURRENT_TIMESTAMP(),
    CREATED_BY VARCHAR(200) NOT NULL DEFAULT CURRENT_USER(),
    CONSTRAINT PK_FACT_TRANSACTION_AUDIT_TRAIL PRIMARY KEY (TRANSACTION_AUDIT_KEY)
);""",
        "remediation": "Write user and system control events into this table at each workflow step so transaction-level audit trail questions can be answered directly.",
        "audit_note": "FACT_TRANSACTION_AUDIT_TRAIL schema design returned"
    },
    "suitability_schema": {
        "finding": "Designing a persisted suitability assessment table to store client risk tolerance, mandate limits, product risk, and exception outcomes for client suitability monitoring.",
        "regulation": "MiFID II Suitability and Appropriateness Governance",
        "severity": "INFO",
        "rule_key": "suitability_schema",
        "category": "Schema Design",
        "sql": "",
        "design_ddl": """CREATE OR REPLACE TABLE REGULATORY_DW.REG_MODEL.DIM_CLIENT_SUITABILITY_ASSESSMENT (
    SUITABILITY_KEY NUMBER AUTOINCREMENT START 1 INCREMENT 1,
    ASSESSMENT_ID VARCHAR(50) NOT NULL,
    ACCOUNT_ID VARCHAR(100) NOT NULL,
    ACCOUNT_NAME VARCHAR(300),
    PRODUCT_ID VARCHAR(100),
    PRODUCT_NAME VARCHAR(300),
    PRODUCT_RISK_RATING VARCHAR(50),
    CLIENT_RISK_TOLERANCE VARCHAR(50),
    MANDATE_RESTRICTION VARCHAR(500),
    SUITABILITY_STATUS VARCHAR(50) NOT NULL,
    EXCEPTION_REASON VARCHAR(2000),
    REMEDIATION_REQUIRED BOOLEAN DEFAULT FALSE,
    REVIEWED_AT TIMESTAMP_NTZ,
    REVIEWED_BY VARCHAR(200),
    IS_CURRENT BOOLEAN NOT NULL DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ NOT NULL DEFAULT CURRENT_TIMESTAMP(),
    CREATED_BY VARCHAR(200) NOT NULL DEFAULT CURRENT_USER(),
    UPDATED_AT TIMESTAMP_NTZ,
    UPDATED_BY VARCHAR(200),
    CONSTRAINT PK_DIM_CLIENT_SUITABILITY_ASSESSMENT PRIMARY KEY (SUITABILITY_KEY),
    CONSTRAINT UQ_DIM_CLIENT_SUITABILITY_ASSESSMENT_ID UNIQUE (ASSESSMENT_ID)
);""",
        "remediation": "Populate this table from suitability review workflows and product-governance checks so suitability exception reporting becomes operational.",
        "audit_note": "DIM_CLIENT_SUITABILITY_ASSESSMENT schema design returned"
    },
}


RULE_BASED_QUERIES = {
    **CORE_RULE_BASED_QUERIES,
    **AML_RULE_BASED_QUERIES,
    **AML_SCHEMA_RULE_BASED_QUERIES,
}


RULE_MATCHERS = [
    ("aml_rule_schema", ["dim_aml_rule", "aml rule schema", "aml rules table", "rule catalog", "rule table design"]),
    ("aml_alert_schema", ["fact_aml_alert", "aml alert schema", "alert table", "alert fact table", "aml case table"]),
    ("compliance_breach_schema", ["compliance breach schema", "fact_compliance_breach", "breach table", "breach registry"]),
    ("transaction_audit_trail_schema", ["transaction audit trail schema", "fact_transaction_audit_trail", "audit trail table"]),
    ("suitability_schema", ["suitability schema", "client suitability table", "dim_client_suitability_assessment"]),
    ("compliance_attestation", ["compliance attestation", "create compliance attestation", "attestation", "attest compliance"]),
    ("submission_package", ["prepare regulator submission package", "regulator submission package", "submission package", "prepare submission package"]),
    ("aml_alerts", ["show aml alerts", "aml alerts", "open aml alerts", "live aml alerts"]),
    ("suitability_exceptions", ["client suitability exceptions", "show client suitability exceptions", "suitability exceptions", "suitability breach"]),
    ("critical_breaches", ["critical breaches", "critical breach", "show critical breaches", "controls breached today", "breached today", "all regulatory breaches", "regulatory breaches"]),
    ("top_risks", ["top risks", "today's top risks", "todays top risks", "compliance posture", "summarize compliance posture", "top current risks", "what actions are recommended", "recommended actions"]),
    ("basel_capital", ["basel capital report", "generate basel iii report", "generate basel iii capital report", "basel iii capital", "capital report"]),
    ("lcr", ["lcr", "liquidity coverage ratio", "what is our lcr"]),
    ("nsfr", ["nsfr", "net stable funding ratio", "what is our nsfr"]),
    ("cet1", ["cet1", "cet1 ratio", "common equity tier 1", "what is our cet1 ratio"]),
    ("aifmd", ["aifmd", "annex iv", "annex 4", "alternative investment fund", "aif reporting", "generate aifmd report", "generate aifmd annex iv report"]),
    ("ucits", ["ucits", "ucit", "eligible assets", "5/10/40"]),
    ("form_pf", ["form pf", "form-pf", "dodd-frank", "dodd frank", "sec reporting"]),
    ("mifid", ["mifid", "mifir", "transaction report", "venue mic", "algo flag", "best execution", "best execution exceptions", "generate mifid report", "generate mifid transaction report", "rts 25"]),
    ("emir", ["emir", "otc derivative", "central clearing", "csa agreement", "swap reporting"]),
    ("aml_structuring", ["structuring", "smurfing", "sub-threshold", "sub threshold", "threshold avoidance", "suspicious transactions", "show suspicious transactions"]),
    ("aml_velocity", ["velocity", "spike in transactions", "burst activity", "high frequency aml", "rapid activity", "unusual trading activity", "show unusual trading activity"]),
    ("aml_round_amount", ["round amount", "exact million", "exact 100k", "rounded transaction"]),
    ("aml_dormancy", ["dormant account", "reactivation", "inactive account", "sudden activity after inactivity"]),
    ("aml_sanctions", ["sanctions screening", "ofac", "screening stale", "sanctions hit", "sanctions hygiene"]),
    ("leverage", ["leverage", "which funds exceed leverage limits", "leverage limits", "basel leverage", "capital adequacy", "rwa", "tier 1"]),
    ("kyc", ["kyc", "aml", "due diligence", "overdue review", "client risk", "money laundering", "customer due diligence"]),
    ("counterparty", ["counterparty", "single-counterparty", "large exposure", "broker exposure", "top counterparties", "show top counterparties"]),
    ("concentration", ["concentration", "position limit", "weight limit", "single position", "which exposures exceed limits", "show concentration risk"]),
    ("filing", ["filing", "late report", "overdue report", "submission", "report status", "deadline", "pending regulatory filings", "show pending regulatory filings"]),
    ("emir", ["derivative", "otc", "clearing"]),
]


def build_no_match_response():
    return {
        "finding": f"Could not match your question to a specific regulatory check. {FALLBACK_HELP_TEXT}",
        "regulation": "General",
        "severity": "INFO",
        "sql": "",
        "remediation": "Rephrase your question using a supported regulatory or AML scenario keyword.",
        "audit_note": "Rule-based fallback — no matching rule intent found"
    }


def keyword_match(question_text, keywords):
    return any(keyword in question_text for keyword in keywords)


def parameterize_rule(base_rule, replacements):
    rule = deepcopy(base_rule)
    for field in ("finding", "sql", "remediation", "audit_note"):
        if field in rule and isinstance(rule[field], str):
            for placeholder, value in replacements.items():
                rule[field] = rule[field].replace(placeholder, value)
    return rule


def build_planned_rule_response(rule_key):
    config = PLANNED_SCHEMA_ONLY_RULES[rule_key]
    schema_rule = RULE_BASED_QUERIES[config["schema_rule"]]
    missing_tables = ", ".join(config["missing_tables"])
    display_name = rule_key.replace("_", " ")
    return {
        "finding": f"This request is recognized, but {display_name} it is not available in live mode yet planned for PHASE-II release.",
        #"finding": f"This request is recognized, but it is not available in live mode yet planned for PHASE-II. The current warehouse model does not include the required Snowflake table(s): {missing_tables}.",
        "regulation": schema_rule.get("regulation", "Schema Design"),
        "severity": "INFO",
        "rule_key": rule_key,
        "category": "Schema Design",
        "sql": "",
        "design_ddl": schema_rule.get("design_ddl", ""),
        "remediation": f"Create and populate {missing_tables}, then enable the live {display_name} workflow.",
        "audit_note": f"Planned/schema-only workflow requested: {rule_key}",
    }


def extract_identifier(question, pattern, default_prefix):
    match = re.search(pattern, question, re.IGNORECASE)
    if not match:
        return None
    value = match.group(1).strip().rstrip(".?,")
    return value if value else f"<{default_prefix}>"


def match_rule_based(question):
    q = question.lower()

    breach_id = extract_identifier(question, r"breach\s+([A-Za-z0-9_\-]+)", "BREACH_ID")
    if breach_id and ("explain breach" in q or "show evidence for breach" in q or "evidence for breach" in q):
        if "evidence" in q:
            return build_planned_rule_response("breach_evidence")
        return build_planned_rule_response("breach_explain")

    transaction_id = extract_identifier(question, r"transaction\s+([A-Za-z0-9_\-]+)", "TRANSACTION_ID")
    if transaction_id and "audit trail" in q:
        return build_planned_rule_response("transaction_audit_trail")

    for rule_key, keywords in RULE_MATCHERS:
        if keyword_match(q, keywords):
            if rule_key in PLANNED_SCHEMA_ONLY_RULES:
                return build_planned_rule_response(rule_key)
            return RULE_BASED_QUERIES[rule_key]
    return None


def get_supported_rule_categories():
    return SUPPORTED_RULE_CATEGORIES


def get_policy_context(parsed):
    return [
        {"policy_name": name, **POLICY_LIBRARY[name]}
        for name in parsed.get("policy_refs", [])
        if name in POLICY_LIBRARY
    ]


def build_alert_payload(parsed, model_name):
    alert_config = parsed.get("alert_generation")
    if not alert_config:
        return None
    return {
        "alert_id": f"{parsed.get('rule_key', 'aml_rule').upper()}_SIMULATED",
        "rule_key": parsed.get("rule_key"),
        "alert_title": alert_config.get("alert_title"),
        "alert_status": alert_config.get("status", "OPEN"),
        "alert_severity": alert_config.get("alert_severity", parsed.get("severity", "MEDIUM")),
        "assignment_queue": alert_config.get("queue", "AML_REVIEW"),
        "disposition_hint": alert_config.get("disposition_hint"),
        "evidence_sql": parsed.get("sql", ""),
        "regulation": parsed.get("regulation"),
        "generated_by": model_name,
    }


def build_case_summary(parsed, model_name):
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    policy_context = get_policy_context(parsed)
    policy_lines = "\n".join(
        f"- {item['title']} ({item['source_type']}): {item['excerpt']}"
        for item in policy_context
    ) or "- No policy references attached."

    content = f"""AML / Regulatory Case Summary

Generated At: {generated_at}
Generated By: {model_name}
Rule Key: {parsed.get('rule_key', 'N/A')}
Category: {parsed.get('category', 'N/A')}
Severity: {parsed.get('severity', 'INFO')}
Regulation: {parsed.get('regulation', 'N/A')}

Finding
{parsed.get('finding', 'No finding available.')}

Recommended Action
{parsed.get('remediation', 'No remediation specified.')}

Evidence SQL
{parsed.get('sql', 'No SQL provided.')}

Policy and Filing References
{policy_lines}

Audit Note
{parsed.get('audit_note', 'No audit note provided.')}
"""
    return {
        "file_name": f"case_summary_{parsed.get('rule_key', 'finding')}.txt",
        "mime_type": "text/plain",
        "content": content,
    }


def get_workflow_steps():
    return [
        "Generate or ingest synthetic account, transaction, counterparty, and filing data.",
        "Transform raw data into governed risk and compliance entities for analysis.",
        "Apply deterministic rules to generate risk signals and exception findings.",
        "Attach policy and filing guidance excerpts to explain why the control fired.",
        "Export alerts and case summaries for investigation, audit, and reporting review.",
    ]


def response_to_json(response):
    return json.dumps(response)
