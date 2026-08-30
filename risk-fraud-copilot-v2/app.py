# Regulatory Risk & Compliance Copilot — NL chat interface for fraud, risk, and regulatory reporting
# Co-authored with CoCo
import os
import json
import streamlit as st
from datetime import datetime
from rules_engine import build_alert_payload, build_case_summary, build_no_match_response, get_policy_context, get_supported_rule_categories, get_workflow_steps, match_rule_based, response_to_json
#from rules_engine1 import build_alert_payload, build_case_summary, build_no_match_response, get_policy_context, get_supported_rule_categories, get_workflow_steps, match_rule_based, response_to_json
try:
    from snowflake.snowpark.context import get_active_session
    from snowflake.snowpark import Session
except ImportError:
    get_active_session = None
    Session = None

st.set_page_config(
    page_title="Risk & Regulatory Copilot",
    page_icon=":material/shield:",
    layout="wide",
)

DEMO_MODE = os.getenv("LOCAL_DEMO_MODE", "false").lower() in {"1", "true", "yes", "on"}
SNOWFLAKE_AVAILABLE = Session is not None
AUTO_DEMO_MODE = False
CONNECTION_ERROR = None
conn = None

if not DEMO_MODE and SNOWFLAKE_AVAILABLE:
    try:
        conn = st.connection("snowflake", ttl=os.getenv("SNOWFLAKE_CONNECTION_TTL"))
    except Exception as exc:
        AUTO_DEMO_MODE = True
        CONNECTION_ERROR = str(exc)

# ─── SCHEMA CONTEXT FOR THE LLM ──────────────────────────────────────────────
SCHEMA_CONTEXT = """
You are a regulatory compliance copilot for a multi-geographical investment management firm.
You have access to the REGULATORY_DW.REG_MODEL data warehouse with these tables:

DIMENSION TABLES:
- DIM_ACCOUNT: Institutional clients (ACCOUNT_KEY, ACCOUNT_ID, ACCOUNT_NAME, ACCOUNT_TYPE [PENSION_FUND, SOVEREIGN_WEALTH, ENDOWMENT, INSURANCE, ASSET_MANAGER], CLIENT_CLASSIFICATION, LEI_CODE, DOMICILE_GEOGRAPHY_KEY, PRIMARY_CURRENCY, AUM_BAND, RISK_PROFILE, KYC_STATUS, KYC_LAST_REVIEWED, AML_RISK_RATING [LOW/MEDIUM/HIGH], ONBOARDING_DATE, STATUS, IS_CURRENT)
- DIM_SECURITY: Instruments (SECURITY_KEY, SECURITY_ID, ISIN, CUSIP, SEDOL, TICKER, SECURITY_NAME, SECURITY_TYPE, ASSET_CLASS [EQUITY/FIXED_INCOME/DERIVATIVE/CREDIT], SUB_ASSET_CLASS, ISSUER_NAME, ISSUER_LEI, ISSUE_CURRENCY, MATURITY_DATE, COUPON_RATE, CREDIT_RATING, IS_OTC, IS_DERIVATIVE, EXCHANGE_CODE, TRADING_VENUE_MIC, LIQUIDITY_CLASSIFICATION, ESG_RATING, SFDR_CLASSIFICATION, IS_CURRENT)
- DIM_FUND: Funds (FUND_KEY, FUND_ID, FUND_NAME, FUND_TYPE [HEDGE_FUND/UCITS/MUTUAL_FUND/AIF/PRIVATE_FUND], FUND_STRUCTURE, INVESTMENT_STRATEGY, ASSET_CLASS_FOCUS, BENCHMARK_INDEX, BASE_CURRENCY, TOTAL_AUM, UCITS_COMPLIANT, AIFMD_REPORTING_REQUIRED, FORM_PF_REPORTING_REQUIRED, LEVERAGE_RATIO, IS_CURRENT)
- DIM_TRADE_MODEL: Execution models (TRADE_MODEL_KEY, TRADE_MODEL_NAME, MODEL_CATEGORY [QUANTITATIVE/DISCRETIONARY/PASSIVE/ILLIQUID], EXECUTION_METHOD [ALGORITHMIC/MANUAL/HYBRID], ALGO_INDICATOR, HFT_INDICATOR, SHORT_SELLING_PERMITTED, PRE_TRADE_TRANSPARENCY, POST_TRADE_TRANSPARENCY, RISK_LIMIT_TYPE, RISK_LIMIT_VALUE, IS_CURRENT)
- DIM_COUNTERPARTY: Brokers/CCPs (COUNTERPARTY_KEY, COUNTERPARTY_NAME, COUNTERPARTY_TYPE [INVESTMENT_BANK/CCP/MARKET_MAKER/COMMERCIAL_BANK], LEI_CODE, BIC_CODE, CREDIT_RATING, NETTING_AGREEMENT, CSA_IN_PLACE, INITIAL_MARGIN_REQUIRED, CENTRAL_CLEARING_ELIGIBLE, CCP_MEMBER, SANCTIONS_SCREENED_DATE, SANCTIONS_STATUS, IS_CURRENT)
- DIM_REGULATORY_JURISDICTION: Regulators (JURISDICTION_KEY, JURISDICTION_CODE [SEC/FCA/ESMA/MAS/SFC/JFSA/ASIC/CSSF/FINMA/CIMA], JURISDICTION_NAME, REGULATION_FRAMEWORK, REPORTING_FREQUENCY, REPORTING_DEADLINE_DAYS)
- DIM_GEOGRAPHY: Countries (GEOGRAPHY_KEY, COUNTRY_CODE, COUNTRY_NAME, REGION, REGULATORY_ZONE, IS_EU_MEMBER, IS_OECD_MEMBER)
- DIM_DATE: Calendar (DATE_KEY as YYYYMMDD, CALENDAR_DATE, IS_BUSINESS_DAY, IS_QUARTER_END, REGULATORY_REPORTING_PERIOD)

FACT TABLES:
- FACT_TRANSACTION: Trades (TRANSACTION_KEY, TRANSACTION_ID, TRADE_DATE_KEY->DIM_DATE, ACCOUNT_KEY->DIM_ACCOUNT, FUND_KEY->DIM_FUND, SECURITY_KEY->DIM_SECURITY, COUNTERPARTY_KEY->DIM_COUNTERPARTY, TRADE_MODEL_KEY->DIM_TRADE_MODEL, JURISDICTION_KEY->DIM_REGULATORY_JURISDICTION, EXECUTION_GEOGRAPHY_KEY->DIM_GEOGRAPHY, TRANSACTION_TYPE, BUY_SELL_INDICATOR, ORDER_TYPE, EXECUTION_VENUE, EXECUTION_VENUE_MIC, QUANTITY, PRICE, TRADE_CURRENCY, GROSS_AMOUNT, NET_AMOUNT, COMMISSION, FEES, SETTLEMENT_CURRENCY, SETTLEMENT_AMOUNT, FX_RATE, IS_SHORT_SALE, IS_CROSS_BORDER, IS_PRINCIPAL_TRADE, IS_AGENCY_TRADE, ALGO_EXECUTION_FLAG, BEST_EXECUTION_FLAG, REPORTING_STATUS [PENDING/REPORTED/FAILED], TRADE_TIMESTAMP, EXECUTION_TIMESTAMP, REPORTING_TIMESTAMP)
- FACT_POSITION: Holdings (POSITION_KEY, POSITION_DATE_KEY->DIM_DATE, ACCOUNT_KEY, FUND_KEY, SECURITY_KEY, COUNTERPARTY_KEY, JURISDICTION_KEY, GEOGRAPHY_KEY, QUANTITY, MARKET_VALUE_LOCAL, MARKET_VALUE_BASE, COST_BASIS_BASE, UNREALIZED_PNL, ACCRUED_INCOME, LOCAL_CURRENCY, BASE_CURRENCY, FX_RATE, WEIGHT_IN_FUND_PCT, DURATION, DELTA, GAMMA, VEGA, VAR_95, VAR_99, CONCENTRATION_LIMIT_PCT, CONCENTRATION_BREACH, LEVERAGE_CONTRIBUTION, COLLATERAL_PLEDGED, MARGIN_REQUIREMENT, LIQUIDITY_DAYS, POSITION_TYPE [LONG/SHORT], AS_OF_DATE)
- FACT_REGULATORY_REPORT: Filings (REPORT_KEY, REPORT_ID, JURISDICTION_KEY, FUND_KEY, REPORT_TYPE [FORM_PF/AIFMD_ANNEX_IV/MIFID_TRANSACTION_REPORT/UCITS_REPORTING/JFSA_QUARTERLY/CIMA_FAR/MAS_FORM_1A], REPORTING_PERIOD_START, REPORTING_PERIOD_END, SUBMISSION_DEADLINE, ACTUAL_SUBMISSION_DATE, REPORT_STATUS [NOT_STARTED/IN_PROGRESS/SUBMITTED/LATE/AMENDED], TOTAL_AUM_REPORTED, GROSS_LEVERAGE_REPORTED, BREACHES_REPORTED, LATE_REPORTS_COUNT, VALIDATION_ERRORS)

KEY REGULATORY THRESHOLDS:
- Basel III: Leverage ratio minimum 3%; Large exposure single counterparty max 25% of Tier 1 capital
- MiFID II: Transaction reported within T+1 (86400 seconds); Best execution required; Algo flagging mandatory
- UCITS: Single position max 10% of NAV; Total derivative exposure max 100% NAV; Max leverage typically 2x
- EMIR: Mandatory clearing for eligible OTC derivatives; CSA required for bilateral OTC
- AML/KYC: Review within 12 months (DATEDIFF day KYC_LAST_REVIEWED CURRENT_DATE > 365 = overdue)
- AIFMD: Quarterly Annex IV reporting; Leverage disclosure required

RESPONSE FORMAT:
You must respond with a valid JSON object (no markdown, no code fences) with these keys:
{
  "finding": "Clear 2-3 sentence summary of what you found",
  "regulation": "Which regulation(s) apply (e.g. Basel III, MiFID II, UCITS)",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW / INFO",
  "sql": "The exact Snowflake SQL query to execute for evidence. Use REGULATORY_DW.REG_MODEL.TABLE_NAME. Use AS_OF_DATE = '2026-06-30' for positions. Must be a single SELECT statement.",
  "remediation": "Specific recommended action to resolve the finding",
  "audit_note": "One-line note suitable for an audit log entry"
}

RULES:
- Always use fully-qualified table names: REGULATORY_DW.REG_MODEL.<TABLE>
- For current dimension data, filter IS_CURRENT = TRUE
- For positions, use AS_OF_DATE = '2026-06-30' (latest snapshot)
- SQL must be a single executable SELECT statement
- Be specific about which regulatory article/rule applies
- Severity: CRITICAL = immediate action needed, HIGH = material breach, MEDIUM = requires attention, LOW = minor gap, INFO = informational
"""


# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────
@st.cache_data(ttl=300)
def load_risk_signals():
    if DEMO_MODE or conn is None:
        return 3, 7, 2, 4, 5

    result = conn.query("""
        SELECT
            (SELECT COUNT(*) FROM REGULATORY_DW.REG_MODEL.DIM_FUND
             WHERE IS_CURRENT = TRUE AND LEVERAGE_RATIO > 3.0) AS LEVERAGE_BREACHES,
            (SELECT COUNT(*) FROM REGULATORY_DW.REG_MODEL.DIM_ACCOUNT
             WHERE IS_CURRENT = TRUE AND DATEDIFF('day', KYC_LAST_REVIEWED, CURRENT_DATE()) > 365) AS KYC_OVERDUE,
            (SELECT COUNT(*) FROM REGULATORY_DW.REG_MODEL.FACT_REGULATORY_REPORT
             WHERE REPORT_STATUS = 'LATE') AS LATE_REPORTS,
            (SELECT COUNT(*) FROM REGULATORY_DW.REG_MODEL.FACT_POSITION
             WHERE AS_OF_DATE = '2026-06-30' AND CONCENTRATION_BREACH = TRUE) AS CONCENTRATION_BREACHES,
            (SELECT COUNT(*) FROM REGULATORY_DW.REG_MODEL.FACT_TRANSACTION
             WHERE REPORTING_STATUS != 'REPORTED') AS UNREPORTED_TRADES
    """)
    row = result.iloc[0]
    return row["LEVERAGE_BREACHES"], row["KYC_OVERDUE"], row["LATE_REPORTS"], row["CONCENTRATION_BREACHES"], row["UNREPORTED_TRADES"]


def call_copilot(user_question, model):
    if DEMO_MODE or AUTO_DEMO_MODE:
        matched = match_rule_based(user_question)
        if matched:
            response = dict(matched)
        else:
            response = build_no_match_response()
        response["audit_note"] = "Local demo mode — deterministic rules engine"
        return response_to_json(response)

    # Skip LLM if we already know Cortex AI is unavailable (trial account)
    if st.session_state.get("cortex_unavailable", False):
        matched = match_rule_based(user_question)
        if matched:
            return response_to_json(matched)
        response = build_no_match_response()
        response["audit_note"] = "Rule-based fallback — Cortex AI not available on this account"
        return response_to_json(response)

    chat_history = ""
    if len(st.session_state.messages) > 1:
        recent = st.session_state.messages[-6:]
        for m in recent:
            role = m["role"]
            content = m["content"] if isinstance(m["content"], str) else json.dumps(m.get("parsed", ""))
            chat_history += f"{role}: {content[:200]}\n"

    full_prompt = f"""{SCHEMA_CONTEXT}

CHAT HISTORY:
{chat_history}

USER QUESTION: {user_question}

Respond with a JSON object only. No markdown fences. No explanation outside the JSON."""

    try:
        escaped_prompt = full_prompt.replace("'", "''")
        result_df = conn.query(
            f"SELECT SNOWFLAKE.CORTEX.COMPLETE('{model}', '{escaped_prompt}') AS RESPONSE"
        )
        return result_df.iloc[0]["RESPONSE"]
    except Exception as e:
        error_msg = str(e)
        # Fallback to rule-based matching when Cortex AI is unavailable (e.g. trial accounts)
        if "not available" in error_msg.lower() or "0A000" in error_msg:
            st.session_state["cortex_unavailable"] = True
            matched = match_rule_based(user_question)
            if matched:
                return response_to_json(matched)
            response = build_no_match_response()
            response["audit_note"] = "Rule-based fallback — Cortex AI not available on this account"
            return response_to_json(response)
        return json.dumps({
            "finding": f"Error calling model: {error_msg}",
            "regulation": "N/A",
            "severity": "INFO",
            "sql": "",
            "remediation": "Try a different model or rephrase your question.",
            "audit_note": "Model call failed"
        })


def parse_response(response_text):
    try:
        cleaned = response_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        return json.loads(cleaned)
    except (json.JSONDecodeError, IndexError):
        return None


def render_finding(parsed, model_name, show_evidence_flag, show_data_flag):
    severity = parsed.get("severity", "INFO")
    severity_icons = {
        "CRITICAL": ":red[:material/error:]",
        "HIGH": ":orange[:material/warning:]",
        "MEDIUM": ":yellow[:material/info:]",
        "LOW": ":blue[:material/check_circle:]",
        "INFO": ":gray[:material/info:]",
    }
    icon = severity_icons.get(severity, ":gray[:material/info:]")

    # Severity + Regulation badge
    st.markdown(f"{icon} **{severity}** | {parsed.get('regulation', 'N/A')}")

    # Finding
    st.markdown(f"**Finding:** {parsed.get('finding', 'No finding available.')}")

    # Remediation
    remediation = parsed.get("remediation", "")
    if remediation and remediation.lower() != "no action required":
        with st.container(border=True):
            st.markdown(f":material/build: **Recommended Action**")
            st.write(remediation)
    else:
        st.success(":material/check_circle: No action required — compliant.")

    design_ddl = parsed.get("design_ddl", "")
    if design_ddl:
        with st.expander(":material/schema: Proposed Schema DDL", expanded=True):
            st.code(design_ddl, language="sql")

    alert_payload = build_alert_payload(parsed, model_name)
    if alert_payload:
        with st.expander(":material/notification_important: Simulated AML Alert", expanded=True):
            st.json(alert_payload)

    policy_context = get_policy_context(parsed)
    if policy_context:
        with st.expander(":material/article: Policy & Filing References", expanded=True):
            for item in policy_context:
                st.markdown(f"**{item['title']}**")
                st.caption(item["source_type"])
                st.write(item["excerpt"])

    case_summary = build_case_summary(parsed, model_name)
    with st.expander(":material/description: Report-Grade Case Summary", expanded=True):
        st.text(case_summary["content"])
        st.download_button(
            ":material/download: Download Case Summary",
            case_summary["content"],
            case_summary["file_name"],
            case_summary["mime_type"],
        )

    # Evidence
    sql = parsed.get("sql", "")
    if sql and show_evidence_flag:
        with st.expander(":material/database: Evidence — SQL & Data", expanded=True):
            st.code(sql, language="sql")

            if DEMO_MODE or AUTO_DEMO_MODE:
                st.caption(":material/info: Local demo mode shows generated evidence SQL only. Live query execution is disabled.")
            elif show_data_flag and sql.strip().upper().startswith("SELECT"):
                try:
                    with st.spinner("Executing evidence query..."):
                        evidence_df = conn.query(sql)
                    if not evidence_df.empty:
                        st.dataframe(evidence_df, use_container_width=True, hide_index=True)
                        st.download_button(
                            ":material/download: Download Evidence (CSV)",
                            evidence_df.to_csv(index=False),
                            f"evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            "text/csv",
                        )
                    else:
                        st.info("Query returned no results — no issues found for this check.")
                except Exception as e:
                    st.error(f"Query execution error: {str(e)}")
    elif not sql:
        st.caption(":material/info: No SQL evidence query for this check.")

    # Audit trail
    audit_note = parsed.get("audit_note", "")
    if audit_note:
        st.caption(f":material/history: {audit_note} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Model: {model_name}")


def render_history_message(parsed):
    if not parsed or "raw" in parsed:
        st.write(parsed.get("raw", "") if parsed else "")
        return
    severity = parsed.get("severity", "INFO")
    severity_icons = {
        "CRITICAL": ":red[:material/error:]",
        "HIGH": ":orange[:material/warning:]",
        "MEDIUM": ":yellow[:material/info:]",
        "LOW": ":blue[:material/check_circle:]",
        "INFO": ":gray[:material/info:]",
    }
    icon = severity_icons.get(severity, ":gray[:material/info:]")
    st.markdown(f"{icon} **{severity}** | {parsed.get('regulation', 'N/A')}")
    st.markdown(f"{parsed.get('finding', '')}")
    remediation = parsed.get("remediation", "")
    if remediation and remediation.lower() != "no action required":
        st.caption(f":material/build: {remediation}")
    if parsed.get("design_ddl"):
        st.caption(":material/schema: Includes proposed AML schema DDL")


# ─── SIDEBAR: RISK SIGNALS ────────────────────────────────────────────────────
with st.sidebar:
    st.title(":material/shield: Risk Copilot")

    # Show mode indicator
    if DEMO_MODE or AUTO_DEMO_MODE:
        st.info(":material/laptop_windows: **Local Demo Mode**  \nRunning without Snowflake or Cortex. Using mock dashboard metrics and deterministic compliance workflows.", icon=":material/info:")
        if CONNECTION_ERROR:
            st.caption(f":material/info: Snowflake connection unavailable, using demo mode instead. {CONNECTION_ERROR}")
    elif st.session_state.get("cortex_unavailable", False):
        st.info(":material/rule: **Rules Engine Mode**  \nCortex AI unavailable on this account. Using deterministic compliance workflows.", icon=":material/info:")
    else:
        st.success(":material/smart_toy: **AI Mode**  \nPowered by Snowflake Cortex AI", icon=":material/check_circle:")

    st.divider()

    model_choice = st.selectbox(
        "LLM Model",
        ["claude-sonnet-4-6", "llama3.1-70b", "mistral-large2"],
        index=0,
    )
    show_evidence = st.toggle("Show SQL Evidence", value=True)
    show_raw_data = st.toggle("Show Data Tables", value=True)

    with st.expander(":material/category: Supported Rule Categories"):
        for category_name, rule_list in get_supported_rule_categories().items():
            if category_name == "Schema Design":
                continue
            st.markdown(f"**{category_name}**")
            for rule_name in rule_list:
                st.caption(rule_name)

    #with st.expander(":material/account_tree: End-to-End Workflow"):
    #    for step_number, step_text in enumerate(get_workflow_steps(), start=1):
    #        st.caption(f"{step_number}. {step_text}")

    st.divider()
    st.markdown("### :material/monitoring: Live Risk Signals")

    lev, kyc, late, conc, unrep = load_risk_signals()

    with st.container(horizontal=True):
        st.metric("Leverage", int(lev), delta=f"{int(lev)}" if lev > 0 else None, delta_color="inverse", border=True)
        st.metric("KYC Overdue", int(kyc), delta=f"{int(kyc)}" if kyc > 0 else None, delta_color="inverse", border=True)

    with st.container(horizontal=True):
        st.metric("Late Filings", int(late), delta=f"{int(late)}" if late > 0 else None, delta_color="inverse", border=True)
        st.metric("Unreported", int(unrep), delta=f"{int(unrep)}" if unrep > 0 else None, delta_color="inverse", border=True)

    st.divider()
    st.caption(f"Snapshot: 2026-06-30 | {datetime.now().strftime('%H:%M')}")

    if st.button("Clear Conversation"):
        st.session_state.messages = []
        st.rerun()


# ─── MAIN: CHAT INTERFACE ─────────────────────────────────────────────────────
st.title("Regulatory Compliance Copilot")
st.caption("Ask natural language questions about risk, fraud, and regulatory compliance. Get governed, evidence-backed, audit-ready answers.")

# Session state
if "messages" not in st.session_state:
    st.session_state.messages = []
if "pending_prompt" not in st.session_state:
    st.session_state.pending_prompt = None
if "last_selected_suggestion" not in st.session_state:
    st.session_state.last_selected_suggestion = None

# Pre-check Cortex AI availability once at startup
if "cortex_unavailable" not in st.session_state:
    if DEMO_MODE or AUTO_DEMO_MODE or conn is None:
        st.session_state["cortex_unavailable"] = True
    else:
        try:
            conn.query("SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-70b', 'Say OK') AS R")
            st.session_state["cortex_unavailable"] = False
        except Exception as e:
            if "not available" in str(e).lower() or "0A000" in str(e):
                st.session_state["cortex_unavailable"] = True
            else:
                st.session_state["cortex_unavailable"] = True

# Suggestion chips
SUGGESTIONS = {
    "Basel III leverage": "Show me all Basel III leverage ratio breaches across our funds. Which funds exceed safe leverage limits?",
    "MiFID II gaps": "Are there any MiFID II transaction reporting gaps? Check for missing venue MIC codes, algo flag mismatches, and unreported trades.",
    "AML/KYC overdue": "Which client accounts have overdue KYC reviews? Show their risk ratings and days since last review.",
    "AML structuring": "Check for AML structuring or smurfing patterns using repeated sub-threshold transactions by account and day.",
    "AML velocity": "Show me accounts with unusually high transaction velocity or burst activity within a short time window.",
    "EMIR derivatives": "What is our OTC derivative exposure under EMIR? Are there positions eligible for central clearing that are not cleared?",
    "Late filings": "Show me all late or overdue regulatory report filings with their deadlines and submission status.",
    "Counterparty risk": "What is our largest single-counterparty exposure? Are we within Basel III large exposure limits?",
    "AIFMD Annex IV": "Generate AIFMD Annex IV report.",
    "Compliance attestation": "Create compliance attestation.",
    "Submission package": "Prepare regulator submission package.",
    "Critical breaches": "Show critical breaches.",
    "Top risks": "What are today's top risks?",
    "Concentration risk": "Show concentration risk.",
    "Top counterparties": "Show top counterparties.",
    "Best execution exceptions": "Show best execution exceptions.",
    "Pending filings": "Show pending regulatory filings.",
    "Basel capital": "Generate Basel III capital report.",
    "LCR": "What is our LCR?",
    "NSFR": "What is our NSFR?",
    "CET1": "What is our CET1 ratio?",
#    "AML alerts (planned in PHASE-II)": "Show AML alerts.",
#    "Suitability exceptions (planned in PHASE-II)": "Show client suitability exceptions.",
}

with st.expander(":material/lightbulb: Suggested Questions", expanded=not st.session_state.messages):
    selected = st.pills("Try asking:", list(SUGGESTIONS.keys()), label_visibility="collapsed")
    if selected and st.session_state.last_selected_suggestion != selected:
        st.session_state.last_selected_suggestion = selected
        st.session_state.pending_prompt = SUGGESTIONS[selected]
        st.rerun()

    if st.session_state.messages and st.button("Start over and show suggestions", use_container_width=True):
        st.session_state.messages = []
        st.session_state.pending_prompt = None
        st.session_state.last_selected_suggestion = None
        st.rerun()

# Display chat history
for msg in st.session_state.messages:
    if msg["role"] == "user":
        with st.chat_message("user", avatar=":material/person:"):
            st.write(msg["content"])
    else:
        with st.chat_message("assistant", avatar=":material/shield:"):
            parsed = msg.get("parsed")
            if parsed and "raw" not in parsed:
                render_history_message(parsed)
            else:
                st.write(msg.get("content", ""))

# Chat input handler
prompt = st.chat_input("Ask about risk, fraud, or regulatory compliance...")
active_prompt = prompt or st.session_state.pending_prompt

if active_prompt:
    if not st.session_state.messages or st.session_state.messages[-1].get("content") != active_prompt or st.session_state.messages[-1].get("role") != "user":
        st.session_state.messages.append({"role": "user", "content": active_prompt})
    st.session_state.pending_prompt = None

    with st.chat_message("user", avatar=":material/person:"):
        st.write(active_prompt)

    with st.chat_message("assistant", avatar=":material/shield:"):
        # Show a visible progress indicator
        status_container = st.status("Analyzing regulatory data...", expanded=True)
        with status_container:
            st.write(":material/search: Matching question to regulatory framework...")
            response_text = call_copilot(active_prompt, model_choice)
            st.write(":material/check: Analysis complete. Rendering findings...")

        status_container.update(label="Analysis complete", state="complete", expanded=False)

        parsed = parse_response(response_text)
        if parsed:
            render_finding(parsed, model_choice, show_evidence, show_raw_data)
            st.session_state.messages.append({"role": "assistant", "content": response_text, "parsed": parsed})
        else:
            # If JSON parsing fails, try to show whatever we got
            st.warning("Could not parse structured response. Showing raw output:")
            st.code(response_text, language="json")
            st.session_state.messages.append({"role": "assistant", "content": response_text, "parsed": {"raw": response_text}})
