"""
Universal Keyword System for Anonymization Tracker QC Checks

This module centralizes all keyword definitions for the hierarchical detection framework.
Each check has keywords for:
1. PROVEN - Comment mentions that definitively confirm this identifier type (Step 1)
2. DISPROVEN - Automatically generated from other checks' PROVEN keywords (Step 1)
3. CONTEXT - Keywords for category/comment context confirmation (Step 3)
"""

# ============================================================================
# KEYWORD DEFINITIONS FOR ALL 15 CHECKS
# ============================================================================

CHECK_KEYWORDS = {
    "CIK": {
        "proven": [
            "CIK", "CENTRAL INDEX KEY", "CIK NUMBER", "CIK ID",
            "CIK CODE", "CIK IDENTIFIER"
        ],
        "context": [
            "COMPANY", "COMPANY INFO", "SEC", "SECURITY", "FINANCIAL",
            "ENTITY", "ISSUER", "FILER", "REGISTRANT", "SEC EDGAR", "EDGAR",
            "COMPANY ID", "COMPANY IDENTIFIER", "COMPANY CODE", "COMPANY NUMBER"
        ]
    },

    "EIN": {
        "proven": [
            "EIN", "TAX ID", "EMPLOYER IDENTIFICATION", "TAX ID NUMBER",
            "FEDERAL TAX ID", "IRS NUMBER", "EMPLOYER ID", "EIN NUMBER",
            "TAX IDENTIFICATION", "EMPLOYER IDENTIFICATION NUMBER"
        ],
        "context": [
            "COMPANY", "ENTITY", "TAX", "LEGAL", "IRS",
            "REGISTRATION", "INCORPORATION", "FEDERAL", "PAYROLL",
            "TAX AUTHORITY", "EMPLOYER", "TAX CODE"
        ]
    },

    "SEC_FILE": {
        "proven": [
            "SEC FILE", "FILE NUMBER", "FILE NO", "FILING NUMBER",
            "SEC FILE NO.", "SEC FILE NUMBER", "REGISTRATION NUMBER",
            "SEC FILE NO", "FILE #"
        ],
        "context": [
            "SEC", "FILING", "FORM", "COMPANY INFO",
            "REGISTRATION", "PROSPECTUS", "EDGAR",
            "10-K", "S-1", "8-K", "SEC DOCUMENT"
        ]
    },

    "CUSIP": {
        "proven": [
            "CUSIP", "CUSIP NUMBER", "CUSIP CODE", "CUSIP ID",
            "CUSIP IDENTIFIER"
        ],
        "context": [
            "COMPANY", "SEC", "SECURITY", "FINANCIAL", "ENTITY", "ISSUER",
            "BOND", "DEBT", "INSTRUMENT", "SECURITY ID",
            "NORTH AMERICAN", "US SECURITY", "DEBT INSTRUMENT",
            "SECURITY CODE", "SECURITY NUMBER", "SECURITY IDENTIFIER"
        ]
    },

    "ISIN": {
        "proven": [
            "ISIN", "ISIN CODE", "INTERNATIONAL SECURITY", "ISIN NUMBER",
            "ISIN IDENTIFIER"
        ],
        "context": [
            "COMPANY", "SEC", "SECURITY", "FINANCIAL", "ENTITY", "ISSUER",
            "GLOBAL", "INTERNATIONAL",
            "GLOBAL SECURITY", "FOREIGN", "WORLDWIDE",
            "SECURITY CODE", "SECURITY NUMBER", "SECURITY IDENTIFIER"
        ]
    },

    "SEDOL": {
        "proven": [
            "SEDOL", "SEDOL CODE", "LSE", "LONDON STOCK", "SEDOL NUMBER",
            "SEDOL IDENTIFIER"
        ],
        "context": [
            "COMPANY", "SEC", "SECURITY", "FINANCIAL", "ENTITY", "ISSUER",
            "UK", "BRITISH", "LSE",
            "LONDON", "UK SECURITY", "LONDON STOCK EXCHANGE",
            "SECURITY CODE", "SECURITY NUMBER"
        ]
    },

    "TICKER": {
        "proven": [
            "TICKER", "STOCK SYMBOL", "TRADING SYMBOL", "TICKER SYMBOL",
            "STOCK CODE", "TICKER CODE", "SYMBOL"
        ],
        "context": [
            # Inclusion-only for tickers (stricter)
            "TICKER", "STOCK", "EQUITY", "NASDAQ", "NYSE", "LISTED",
            "TRADING", "SECURITY SYMBOL", "EXCHANGE", "LISTED COMPANY",
            "STOCK SYMBOL", "TRADING CODE", "COMPANY", "SECURITY", "ISSUER"
        ]
    },

    "FIGI": {
        "proven": [
            "FIGI", "BLOOMBERG", "FIGI CODE", "BLOOMBERG ID", "BBG",
            "FIGI NUMBER", "FIGI IDENTIFIER"
        ],
        "context": [
            "COMPANY", "SEC", "SECURITY", "FINANCIAL", "ENTITY", "ISSUER",
            "BLOOMBERG TERMINAL", "BBG", "OPENFIGI", "BLOOMBERG CODE",
            "SECURITY CODE", "SECURITY IDENTIFIER"
        ]
    },

    "LEI": {
        "proven": [
            "LEI", "LEGAL ENTITY IDENTIFIER", "LEI CODE", "LEGAL ENTITY ID",
            "LEI NUMBER"
        ],
        "context": [
            "COMPANY", "SEC", "SECURITY", "FINANCIAL", "ENTITY", "ISSUER",
            "LEGAL ENTITY", "COUNTERPARTY",
            "GLEIF", "ENTITY IDENTIFIER", "LEGAL ID"
        ]
    },

    "PATENT": {
        "proven": [
            "PATENT", "PATENT NUMBER", "PATENT ID", "IP",
            "INTELLECTUAL PROPERTY", "PATENT CODE"
        ],
        "context": [
            # Optional (global detection by default)
            "PATENT", "IP", "INTELLECTUAL PROPERTY", "TECHNOLOGY", "INVENTION",
            "USPTO", "EPO", "WIPO", "PRIOR ART", "PATENT APPLICATION", "IP NUMBER"
        ]
    },

    "EMAIL": {
        "proven": [
            "EMAIL", "E-MAIL", "EMAIL ADDRESS", "CONTACT EMAIL",
            "EMAIL ID", "E-MAIL ADDRESS"
        ],
        "context": [
            # Optional (global detection by default)
            "CONTACT", "COMMUNICATION", "EMAIL", "CORRESPONDENCE", "COMPANY INFO",
            "@", "INBOX", "MAIL", "SENDER", "RECIPIENT", "MAILBOX"
        ]
    },

    "PHONE": {
        "proven": [
            "PHONE", "TELEPHONE", "PHONE NUMBER", "TEL", "MOBILE",
            "CELL", "FAX", "PHONE #", "TELEPHONE NUMBER"
        ],
        "context": [
            "CONTACT", "COMMUNICATION", "PHONE", "TELEPHONE", "COMPANY INFO",
            "EXTENSION", "EXT", "TOLL-FREE", "HOTLINE", "SUPPORT LINE",
            "PHONE LINE"
        ]
    },

    "ADDRESS": {
        "proven": [
            "ADDRESS", "STREET ADDRESS", "MAILING ADDRESS", "LOCATION",
            "OFFICE ADDRESS", "HEADQUARTERS", "PHYSICAL ADDRESS"
        ],
        "context": [
            "ADDRESS", "LOCATION", "OFFICE", "HEADQUARTERS", "CONTACT",
            "FACILITY", "PROPERTY",
            "STREET", "AVENUE", "ROAD", "CITY", "STATE", "ZIP", "POSTAL",
            "SUITE", "BUILDING", "FLOOR"
        ]
    },

    "COMPANY_NAME": {
        "proven": [
            "COMPANY NAME", "ORGANIZATION", "ENTITY NAME", "CORPORATION",
            "BUSINESS NAME", "FIRM", "ORGANIZATION NAME"
        ],
        "context": [
            "COMPANY", "COMPANY INFO", "ORGANIZATION", "ENTITY", "ISSUER",
            "COUNTERPARTY", "VENDOR", "CUSTOMER",
            "INC", "LLC", "CORP", "LTD", "CO", "CORPORATION", "LIMITED",
            "INCORPORATED", "LP", "LLP"
        ]
    }
}

# ============================================================================
# UNIVERSAL DISPROVEN KEYWORDS
# ============================================================================

def get_universal_disprovers(exclude_check: str = None) -> list:
    """
    Get all PROVEN keywords from all checks EXCEPT the specified check.
    This creates the universal disproven list.

    Args:
        exclude_check: Check name to exclude (e.g., "CIK")

    Returns:
        List of all keywords that would disprove the specified check
    """
    all_keywords = set()

    for check_name, keywords in CHECK_KEYWORDS.items():
        if check_name == exclude_check:
            continue  # Skip this check's own keywords

        # Add all proven keywords from other checks
        all_keywords.update(keywords["proven"])

    # Add generic disprover terms
    generic_disprovers = [
        "NARRATIVE", "TEXT", "DESCRIPTION", "PARAGRAPH",
        "EXAMPLE", "SAMPLE", "PLACEHOLDER", "N/A", "NOT APPLICABLE",
        "PERSON", "EXECUTIVE", "CEO", "CFO", "PRESIDENT",  # People, not IDs
        "NAME OF", "INDIVIDUAL"  # Descriptive language
    ]
    all_keywords.update(generic_disprovers)

    return list(all_keywords)

# ============================================================================
# HELPER: Get keywords for a specific check
# ============================================================================

def get_check_keywords(check_name: str) -> dict:
    """
    Get all keyword sets for a specific check.

    Args:
        check_name: Name of the check (e.g., "CIK", "EMAIL")

    Returns:
        Dictionary with 'proven', 'disproven', and 'context' keyword lists

    Raises:
        ValueError: If check_name is not recognized
    """
    if check_name not in CHECK_KEYWORDS:
        raise ValueError(f"Unknown check: {check_name}. Valid checks: {list(CHECK_KEYWORDS.keys())}")

    return {
        "proven": CHECK_KEYWORDS[check_name]["proven"],
        "disproven": get_universal_disprovers(exclude_check=check_name),
        "context": CHECK_KEYWORDS[check_name]["context"]
    }

# ============================================================================
# UTILITY: List all available checks
# ============================================================================

def list_all_checks() -> list:
    """Get list of all available check names"""
    return list(CHECK_KEYWORDS.keys())
