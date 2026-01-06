"""
Pattern Detection Functions for Anonymization Tracker QC Checks

This module contains all pattern detection functions for identifier types.
Each function returns the cleaned/normalized identifier if match found, None otherwise.

Pattern detectors are used in STEP 2 of the hierarchical detection framework.
"""

import re
from typing import Optional

# ============================================================================
# EXISTING PATTERN DETECTORS (Refactored from streamlit_app.py)
# ============================================================================

def detect_cik(val: str) -> Optional[str]:
    """
    Detect CIK (Central Index Key): 7-10 digit numbers.

    Args:
        val: Value to check

    Returns:
        Cleaned CIK if valid, None otherwise

    Examples:
        "0001018724" → "0001018724"
        "123456" → None (only 6 digits)
        "ABC123" → None (contains letters)
    """
    if not val:
        return None
    cleaned = re.sub(r'\s', '', val)  # Remove spaces
    return cleaned if re.match(r'^\d{7,10}$', cleaned) else None


def detect_ein(val: str) -> Optional[str]:
    """
    Detect EIN (Employer Identification Number): XX-XXXXXXX or XXXXXXXXX.

    Args:
        val: Value to check

    Returns:
        Cleaned EIN (9 digits) if valid, None otherwise

    Examples:
        "12-3456789" → "123456789"
        "123456789" → "123456789"
        "12345" → None (too short)
    """
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val)  # Remove spaces and hyphens
    return cleaned if re.match(r'^\d{9}$', cleaned) else None


def detect_sec_file_number(val: str) -> Optional[str]:
    """
    Detect SEC File Number: XXX-XXXXX format.

    Args:
        val: Value to check

    Returns:
        SEC file number if valid, None otherwise

    Examples:
        "001-12345" → "001-12345"
        "123-45678" → "123-45678"
        "12-3456" → None (wrong format)
    """
    if not val:
        return None
    cleaned = val.strip()
    return cleaned if re.match(r'^\d{3}-\d{5}$', cleaned) else None


def detect_cusip(val: str) -> Optional[str]:
    """
    Detect CUSIP: 9 characters (alphanumeric).
    Format: [0-9A-Z]{3}[0-9A-Z]{5}[0-9]

    Args:
        val: Value to check

    Returns:
        Normalized CUSIP (uppercase, no spaces) if valid, None otherwise

    Examples:
        "037833100" → "037833100"
        "037 833 100" → "037833100"
        "ABC12345" → None (wrong format)
    """
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val).upper()
    return cleaned if re.match(r'^[0-9A-Z]{3}[0-9A-Z]{5}[0-9]$', cleaned) else None


def detect_isin(val: str) -> Optional[str]:
    """
    Detect ISIN: 12 characters (2 letters + 9 alphanumeric + 1 digit).
    Format: [A-Z]{2}[A-Z0-9]{9}[0-9]

    Args:
        val: Value to check

    Returns:
        Normalized ISIN (uppercase, no spaces) if valid, None otherwise

    Examples:
        "US0378331005" → "US0378331005"
        "US 0378331005" → "US0378331005"
        "1234567890AB" → None (wrong format)
    """
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val).upper()
    return cleaned if re.match(r'^[A-Z]{2}[A-Z0-9]{9}[0-9]$', cleaned) else None


def detect_sedol(val: str) -> Optional[str]:
    """
    Detect SEDOL: 7 characters (6 alphanumeric excluding vowels + 1 digit).
    Format: [B-DF-HJ-NP-TV-Z0-9]{6}[0-9]

    Args:
        val: Value to check

    Returns:
        Normalized SEDOL (uppercase, no spaces) if valid, None otherwise

    Examples:
        "2046251" → "2046251"
        "B0YBKJ7" → "B0YBKJ7"
    """
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val).upper()
    return cleaned if re.match(r'^[B-DF-HJ-NP-TV-Z0-9]{6}[0-9]$', cleaned) else None


def detect_ticker(val: str) -> Optional[str]:
    """
    Detect Stock Ticker: 1-5 uppercase letters.

    Args:
        val: Value to check

    Returns:
        Normalized ticker (uppercase) if valid, None otherwise

    Examples:
        "AAPL" → "AAPL"
        "GOOGL" → "GOOGL"
        "A" → "A"
        "ABCDEF" → None (too long)
        "A1B" → None (contains digit)
    """
    if not val:
        return None
    cleaned = val.strip().upper()
    return cleaned if re.match(r'^[A-Z]{1,5}$', cleaned) else None


def detect_figi(val: str) -> Optional[str]:
    """
    Detect FIGI (Financial Instrument Global Identifier): BBG + 9 alphanumeric.
    Format: BBG[A-Z0-9]{9}

    Args:
        val: Value to check

    Returns:
        Normalized FIGI (uppercase, no spaces) if valid, None otherwise

    Examples:
        "BBG000BLNQ16" → "BBG000BLNQ16"
        "BBG 000BLNQ16" → "BBG000BLNQ16"
        "ABC000BLNQ16" → None (wrong prefix)
    """
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val).upper()
    return cleaned if re.match(r'^BBG[A-Z0-9]{9}$', cleaned) else None


def detect_lei(val: str) -> Optional[str]:
    """
    Detect LEI (Legal Entity Identifier): 20 alphanumeric characters.
    Format: [A-Z0-9]{20}

    Args:
        val: Value to check

    Returns:
        Normalized LEI (uppercase, no spaces) if valid, None otherwise

    Examples:
        "5493000IBP32UQZ0KL24" → "5493000IBP32UQZ0KL24"
    """
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val).upper()
    return cleaned if re.match(r'^[A-Z0-9]{20}$', cleaned) else None


def detect_patent(val: str) -> Optional[str]:
    """
    Detect Patent Number: Country code + 6-10 digits.
    Supported countries: US, EP, WO, JP, CN, DE, GB, FR

    Args:
        val: Value to check

    Returns:
        Patent number if found, None otherwise

    Examples:
        "US1234567" → "US1234567"
        "WO2020123456" → "WO2020123456"
        "US 1234567" → "US 1234567" (preserves spacing)
    """
    if not val:
        return None
    pattern = r'\b(US|EP|WO|JP|CN|DE|GB|FR)\s?\d{6,10}\b'
    match = re.search(pattern, val, re.IGNORECASE)
    return match.group(0) if match else None


# ============================================================================
# NEW PATTERN DETECTORS
# ============================================================================

def detect_email(val: str) -> Optional[str]:
    """
    Detect Email Address: standard email format.
    Pattern: local@domain.tld

    Args:
        val: Value to check

    Returns:
        Email address if found, None otherwise

    Examples:
        "user@example.com" → "user@example.com"
        "john.doe@company.org" → "john.doe@company.org"
        "not-an-email" → None
    """
    if not val:
        return None
    # Email pattern: local part + @ + domain + . + TLD
    pattern = r'[\w\.\-\+]+@[\w\.\-]+\.\w{2,}'
    match = re.search(pattern, val, re.IGNORECASE)
    return match.group(0) if match else None


def detect_phone(val: str) -> Optional[str]:
    """
    Detect Phone Number: US and international formats.

    Supported formats:
    - (123) 456-7890
    - 123-456-7890
    - 123.456.7890
    - +1 234 567 8900

    Args:
        val: Value to check

    Returns:
        Phone number if found, None otherwise

    Examples:
        "(555) 123-4567" → "(555) 123-4567"
        "555-123-4567" → "555-123-4567"
        "+1 555 123 4567" → "+1 555 123 4567"
    """
    if not val:
        return None

    # US format: (123) 456-7890, 123-456-7890, 123.456.7890
    us_pattern = r'\(?\d{3}\)?[\s\.\-]?\d{3}[\s\.\-]?\d{4}'

    # International format: +1 234 567 8900
    intl_pattern = r'\+?\d{1,3}[\s\.\-]?\(?\d{1,4}\)?[\s\.\-]?\d{1,4}[\s\.\-]?\d{1,9}'

    for pattern in [us_pattern, intl_pattern]:
        match = re.search(pattern, val)
        if match:
            return match.group(0)

    return None


def detect_address(val: str) -> Optional[str]:
    """
    Detect Address: street addresses, city/state, or PO boxes.

    Supported patterns:
    - Street: 123 Main Street
    - City/State: Springfield, IL 62701
    - PO Box: P.O. Box 123

    Args:
        val: Value to check

    Returns:
        Address component if found, None otherwise

    Examples:
        "123 Main Street" → "123 Main Street"
        "Springfield, IL 62701" → "Springfield, IL 62701"
        "P.O. Box 456" → "P.O. Box 456"
    """
    if not val:
        return None

    # Street address pattern
    street_pattern = r'\d+\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Circle|Cir|Parkway|Pkwy)'

    # City, State ZIP pattern
    city_state_pattern = r'[A-Z][a-z]+,\s*[A-Z]{2}\s+\d{5}'

    # PO Box pattern
    po_box_pattern = r'P\.?O\.?\s*Box\s+\d+'

    for pattern in [street_pattern, city_state_pattern, po_box_pattern]:
        match = re.search(pattern, val, re.IGNORECASE)
        if match:
            return match.group(0)

    return None


def detect_company_name(val: str) -> Optional[str]:
    """
    Detect Company Name: requires entity suffix or proper noun capitalization.

    Detection criteria:
    1. Contains legal entity suffix (Inc., LLC, Corp., etc.)
    2. Multi-word capitalized sequence (proper noun pattern)

    Args:
        val: Value to check

    Returns:
        Company name if detected, None otherwise

    Examples:
        "Apple Inc." → "Apple Inc."
        "Microsoft Corporation" → "Microsoft Corporation"
        "Acme LLC" → "Acme LLC"
        "John Smith" → "John Smith" (also matches, needs strict context)
    """
    if not val:
        return None

    # Entity suffix pattern (Inc., LLC, Corp., etc.)
    suffix_pattern = r'\b(Inc\.|LLC|Corp\.|Ltd\.|Co\.|Corporation|Limited|Incorporated|LP|LLP|L\.L\.C\.|L\.P\.)\b'

    if re.search(suffix_pattern, val, re.IGNORECASE):
        return val

    # Alternative: Multi-word capitalized sequence (proper noun)
    # This is more aggressive and should be used with strict context
    words = val.split()
    if len(words) >= 2:
        # Check if all words start with capital letter
        if all(w[0].isupper() for w in words if w and len(w) > 0):
            return val

    return None
