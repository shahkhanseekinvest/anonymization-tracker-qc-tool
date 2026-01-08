import streamlit as st
import pandas as pd
import re
from typing import List, Dict, Tuple, Optional
import spacy
from email_validator import validate_email, EmailNotValidError
import phonenumbers

# -------------------------
# Load spaCy model once (cached for performance, lazy-loaded)
# -------------------------
@st.cache_resource
def load_spacy_model():
    """Load spaCy model once and cache it"""
    try:
        return spacy.load("en_core_web_sm")
    except OSError:
        # Return None if model not found - we'll show error message later
        return None

# -------------------------
# Shared context gates
# -------------------------
def security_id_context_applies(category: str, comment: str = "") -> bool:
    """
    Context gate for first-class security / regulatory identifiers.
    Identifiers are enforced only when they appear in company /
    financial / issuer context.
    """
    context = f"{category} {comment}".upper()
    return any(
        token in context
        for token in [
            "COMPANY",
            "COMPANY INFO",
            "SEC",
            "SECURITY",
            "FINANCIAL",
            "ENTITY",
            "ISSUER"
        ]
    )

# -------------------------
# Ticker context gate (ticker-specific, less strict)
# -------------------------
def ticker_context_applies(category: str, comment: str = "") -> bool:
    """
    Context gate for stock ticker symbols.

    Tickers are short, human-readable, and highly ambiguous.
    They are enforced only when there is explicit market / security intent.
    """
    context = f"{category} {comment}".upper()
    return any(
        token in context
        for token in [
            "COMPANY",
            "SECURITY",
            "EQUITY",
            "STOCK",
            "TRADING",
            "ISSUER"
        ]
    )


#
# -------------------------
# EIN detection helpers
# -------------------------
EIN_REGEX_FORMATTED = re.compile(r"^\d{2}-\d{7}$")
EIN_REGEX_UNFORMATTED = re.compile(r"^\d{9}$")

def looks_like_ein(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    return bool(
        EIN_REGEX_FORMATTED.match(value) or
        EIN_REGEX_UNFORMATTED.match(value)
    )

def ein_context_applies(category: str, comment: str = "") -> bool:
    """
    Context gate for EIN with positive confirmation and cross-check blocking.
    
    Rules:
    1. POSITIVE CONFIRMATION: Comment explicitly mentions "EIN" → FORCE ALLOW
    2. EXPLICIT BLOCK: Comment mentions different identifier → FORCE BLOCK
    3. CATEGORY + KEYWORD: Standard allow (COMPANY/ENTITY/TAX context)
    """
    # Handle NaN
    if pd.isna(comment):
        comment = ""
    comment = str(comment).strip()
    
    comment_u = comment.upper()
    category_u = category.upper()
    
    # RULE 1: Positive confirmation - comment explicitly says EIN
    if any(term in comment_u for term in ["EIN", "TAX ID", "EMPLOYER IDENTIFICATION"]):
        return True
    
    # RULE 2: Block if comment mentions different identifier
    other_identifiers = ["CUSIP", "CIK", "ISIN", "SEDOL", "FIGI", "LEI", "TICKER", "SEC FILE"]
    if any(other_id in comment_u for other_id in other_identifiers):
        return False
    
    # RULE 3: Standard category-based check
    context = f"{category_u} {comment_u}"
    return any(
        token in context
        for token in ["COMPANY", "ENTITY", "TAX", "LEGAL", "IRS"]
    )

def validate_ein_anonymization(before: str, after: str) -> list[str]:
    issues = []

    if before == after:
        issues.append("EIN not anonymized (Before == After)")
        return issues

    before_formatted = bool(EIN_REGEX_FORMATTED.match(before))
    after_formatted = bool(EIN_REGEX_FORMATTED.match(after))

    if before_formatted != after_formatted:
        issues.append("EIN format not preserved (hyphen mismatch)")

    if not looks_like_ein(after):
        issues.append("Anonymized EIN has invalid format")

    if " " in after:
        issues.append("Anonymized EIN contains spaces")

    return issues

# -------------------------
# SEC file number helpers
# -------------------------
SEC_FILE_REGEX = re.compile(r"^\d{3}-\d{5}$")

def looks_like_sec_file_number(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    return bool(SEC_FILE_REGEX.match(value))

def sec_file_context_applies(category: str, comment: str = "") -> bool:
    """
    Context gate for SEC File Numbers with positive confirmation and cross-check blocking.
    
    Rules:
    1. POSITIVE CONFIRMATION: Comment explicitly mentions "SEC FILE" or "FILE NUMBER" → FORCE ALLOW
    2. EXPLICIT BLOCK: Comment mentions different identifier → FORCE BLOCK
    3. CATEGORY + KEYWORD: Standard allow (SEC/FILING context)
    """
    # Handle NaN
    if pd.isna(comment):
        comment = ""
    comment = str(comment).strip()
    
    comment_u = comment.upper()
    category_u = category.upper()
    
    # RULE 1: Positive confirmation - comment explicitly mentions SEC file number
    if any(term in comment_u for term in ["SEC FILE", "FILE NUMBER", "FILE NO", "FILING NUMBER"]):
        return True
    
    # RULE 2: Block if comment mentions different identifier
    other_identifiers = ["CUSIP", "CIK", "ISIN", "SEDOL", "FIGI", "LEI", "TICKER", "EIN", "TAX ID"]
    if any(other_id in comment_u for other_id in other_identifiers):
        return False
    
    # RULE 3: Standard category-based check
    context = f"{category_u} {comment_u}"
    return any(
        token in context
        for token in ["SEC", "FILING", "FORM", "COMPANY INFO"]
    )

def validate_sec_file_anonymization(before: str, after: str) -> list[str]:
    issues = []

    if before == after:
        issues.append("SEC file number not anonymized (Before == After)")
        return issues

    if not looks_like_sec_file_number(after):
        issues.append("Anonymized SEC file number has invalid format")

    if " " in after:
        issues.append("Anonymized SEC file number contains spaces")

    return issues


# -------------------------
# Canonical detection helpers (tolerant)
# -------------------------

def detect_isin(val: str) -> Optional[str]:
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val).upper()
    return cleaned if re.match(r'^[A-Z]{2}[A-Z0-9]{9}[0-9]$', cleaned) else None


def detect_cusip(val: str) -> Optional[str]:
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val).upper()
    # CUSIP: 9 characters total
    # Standard: [0-9]{3}[0-9A-Z]{5}[0-9] (US/Canada)
    # Regulation S: Can start with U, V, or Y for foreign issuers
    # Pattern: [0-9A-Z]{3}[0-9A-Z]{5}[0-9]
    return cleaned if re.match(r'^[0-9A-Z]{3}[0-9A-Z]{5}[0-9]$', cleaned) else None


def detect_sedol(val: str) -> Optional[str]:
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val).upper()
    return cleaned if re.match(r'^[B-DF-HJ-NP-TV-Z0-9]{6}[0-9]$', cleaned) else None


def detect_figi(val: str) -> Optional[str]:
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val).upper()
    return cleaned if re.match(r'^BBG[A-Z0-9]{9}$', cleaned) else None


def detect_lei(val: str) -> Optional[str]:
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val).upper()
    # LEI must be exactly 20 alphanumeric characters AND contain both letters and digits
    # Example: 529900T8BM49AURSDO55
    if re.match(r'^[A-Z0-9]{20}$', cleaned):
        has_letter = any(c.isalpha() for c in cleaned)
        has_digit = any(c.isdigit() for c in cleaned)
        if has_letter and has_digit:
            return cleaned
    return None


def detect_ein(val: str) -> Optional[str]:
    if not val:
        return None
    cleaned = re.sub(r'[\s\-]', '', val)
    return cleaned if re.match(r'^\d{9}$', cleaned) else None


def detect_cik(val: str) -> Optional[str]:
    if not val:
        return None
    cleaned = re.sub(r'\s', '', val)
    return cleaned if re.match(r'^\d{7,10}$', cleaned) else None


def detect_ticker(val: str) -> Optional[str]:
    if not val:
        return None
    cleaned = val.strip().upper()
    return cleaned if re.match(r'^[A-Z]{1,5}$', cleaned) else None


# -------------------------
# Blocking logic for Wave 1 checks (permissive with exceptions)
# -------------------------
def should_block_company_name_detection(category: str, comment: str) -> bool:
    """
    Returns True if category/comment indicates this is NOT a company name.
    Block if it's clearly about people, emails, phones, addresses, or security IDs.

    Philosophy: Detect everywhere UNLESS explicitly blocked.
    """
    if pd.isna(category):
        category = ""
    if pd.isna(comment):
        comment = ""

    context = f"{str(category)} {str(comment)}".upper()

    block_terms = [
        # People/Individuals
        "EXECUTIVE", "PERSON", "INDIVIDUAL", "NAME", "DIRECTOR", "OFFICER",
        # Contact info
        "EMAIL", "PHONE", "TELEPHONE", "FAX",
        # Addresses
        "ADDRESS", "STREET", "LOCATION",
        # Security IDs
        "CUSIP", "CIK", "ISIN", "SEDOL", "FIGI", "LEI", "EIN", "TICKER"
    ]

    return any(term in context for term in block_terms)


def should_block_address_detection(category: str, comment: str) -> bool:
    """
    Returns True if category/comment indicates this is NOT an address.
    Block if it's clearly about people, companies, emails, phones, or security IDs.

    Philosophy: Detect everywhere UNLESS explicitly blocked.
    """
    if pd.isna(category):
        category = ""
    if pd.isna(comment):
        comment = ""

    context = f"{str(category)} {str(comment)}".upper()

    block_terms = [
        # People/Individuals
        "EXECUTIVE", "PERSON", "INDIVIDUAL", "DIRECTOR", "OFFICER",
        # Companies (full entity names, not addresses)
        "COMPANY NAME", "ORGANIZATION NAME", "ENTITY NAME",
        # Contact info
        "EMAIL", "PHONE", "TELEPHONE", "FAX", "WEBSITE",
        # Security IDs
        "CUSIP", "CIK", "ISIN", "SEDOL", "FIGI", "LEI", "EIN", "TICKER"
    ]

    return any(term in context for term in block_terms)


def should_block_email_detection(category: str, comment: str) -> bool:
    """
    Returns True if category/comment indicates this is NOT an email.
    Block if it's clearly about security IDs, company names, or addresses.

    Philosophy: Detect everywhere UNLESS explicitly blocked.
    """
    if pd.isna(category):
        category = ""
    if pd.isna(comment):
        comment = ""

    context = f"{str(category)} {str(comment)}".upper()

    block_terms = [
        # Security IDs
        "CUSIP", "CIK", "ISIN", "SEDOL", "FIGI", "LEI", "EIN", "TICKER", "SEC FILE",
        # Addresses (physical locations, not email addresses)
        "STREET", "PHYSICAL ADDRESS", "MAILING ADDRESS", "OFFICE LOCATION",
        # Company names (entity names, not email domains)
        "COMPANY NAME", "ORGANIZATION NAME", "ENTITY NAME"
    ]

    return any(term in context for term in block_terms)


def should_block_phone_detection(category: str, comment: str) -> bool:
    """
    Returns True if category/comment indicates this is NOT a phone number.
    Block if it's clearly about security IDs, company names, or emails.

    Philosophy: Detect everywhere UNLESS explicitly blocked.
    """
    if pd.isna(category):
        category = ""
    if pd.isna(comment):
        comment = ""

    context = f"{str(category)} {str(comment)}".upper()

    block_terms = [
        # Security IDs
        "CUSIP", "CIK", "ISIN", "SEDOL", "FIGI", "LEI", "EIN", "TICKER", "SEC FILE",
        # Email
        "EMAIL", "E-MAIL",
        # Addresses (physical locations)
        "STREET ADDRESS", "PHYSICAL ADDRESS", "MAILING ADDRESS",
        # Company names
        "COMPANY NAME", "ORGANIZATION NAME", "ENTITY NAME"
    ]

    return any(term in context for term in block_terms)


st.set_page_config(
    page_title="Anonymization Tracker QC Tool",
    page_icon="𝕏",
    layout="wide"
)

# Title and description
st.title("Anonymization Tracker QC Tool")
st.markdown("**Validate anonymization trackers to detect data leakage and format issues**")
st.caption("Upload your tracker (Excel or CSV) to check Before/After columns for proper anonymization")

# File uploader
uploaded_file = st.file_uploader(
    "Upload Tracker File (Excel or CSV)", 
    type=['csv', 'xlsx', 'xls']
)

# File upload handling and DataFrame loading
# (Validation logic moved to validate_and_prepare_dataframe function)

def check_sec_links(df: pd.DataFrame) -> Dict:
    """Two-stage check: (1) Warn if no SEC links exist, (2) Flag After value problems if they do exist"""
    before_col = df['Before'].astype(str).str.lower()
    has_sec = before_col.str.contains('sec.gov', na=False).any()
    
    # Stage 1: Check if any SEC links exist and collect them
    detected = []
    for idx, row in df.iterrows():
        before_val = str(row['Before']).lower() if pd.notna(row['Before']) else ''
        if 'sec.gov' in before_val:
            detected.append({
                'excel_row': idx + 2,
                'category': row['Category'],
                'before': row['Before'],
                'after': row['After']
            })
    
    if not has_sec:
        return {
            'passed': False,
            'message': 'No SEC links detected in Before column',
            'severity': 'warning',
            'rows': []
        }
    
    # Stage 2: Check After values for problems
    issues = []
    before_values = set(df['Before'].dropna().astype(str).str.lower())
    
    for idx, row in df.iterrows():
        before_val = str(row['Before']).lower() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).lower() if pd.notna(row['After']) else ''
        
        if 'sec.gov' in before_val and after_val:
            problem = None
            
            # Check if After URL contains any real identifiers from Before column
            for before_term in before_values:
                if len(before_term) >= 4 and before_term != before_val and before_term in after_val:
                    problem = f"After URL contains real identifier: '{before_term}'"
                    break
            
            if problem:
                issues.append({
                    'excel_row': idx + 2,
                    'category': row['Category'],
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': problem
                })
    
    return {
        'passed': len(issues) == 0,
        'message': f'All SEC links properly anonymized ({len(detected)} found)' if len(issues) == 0 else f'Found {len(issues)} SEC link(s) with leakage in After column',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }

def check_after_link_leakage(df: pd.DataFrame) -> Dict:
    """Check if After column URLs contain any Before column identifiers"""
    issues = []
    validated_urls = []
    
    # Get all Before values (excluding NaN)
    before_terms = set(df['Before'].dropna().astype(str).str.lower())
    
    # Check After column for URLs
    for idx, row in df.iterrows():
        after_val = str(row['After']).lower() if pd.notna(row['After']) else ''
        
        # Check if it's a URL
        if 'http' in after_val or 'www.' in after_val:
            has_issue = False
            # Check if any Before term appears in this After URL
            for term in before_terms:
                # Skip very short terms (< 4 chars) to avoid false positives
                if len(term) >= 4 and term in after_val:
                    issues.append({
                        'excel_row': idx + 2,
                        'category': row['Category'],
                        'before_term_found': term,
                        'before': row['Before'],
                        'after': row['After']
                    })
                    has_issue = True
                    break
            
            if not has_issue:
                validated_urls.append({
                    'excel_row': idx + 2,
                    'category': row['Category'],
                    'before': row['Before'],
                    'after': row['After']
                })
    
    return {
        'passed': len(issues) == 0,
        'message': f'No identifying leakage detected in After URLs ({len(validated_urls)} URLs checked)' if len(issues) == 0 else f'Found {len(issues)} After URL(s) containing Before identifiers',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': validated_urls if len(issues) == 0 else issues
    }

def check_deletion_entries(df: pd.DataFrame) -> Dict:
    """Check if there are rows where Before has value but After is blank"""
    deletion_rows = df[df['Before'].notna() & df['After'].isna()]
    has_deletions = len(deletion_rows) > 0
    
    # Format for display
    deletion_details = []
    for idx, row in deletion_rows.iterrows():
        deletion_details.append({
            'excel_row': idx + 2,
            'category': row['Category'],
            'before': row['Before'],
            'after': '[BLANK - marked for deletion]'
        })
    
    return {
        'passed': has_deletions,
        'message': f'Found {len(deletion_rows)} deletion entry(ies) marked for removal' if has_deletions else 'No deletion entries found',
        'severity': 'pass' if has_deletions else 'warning',
        'rows': deletion_details
    }

def check_patent_ids(df: pd.DataFrame) -> Dict:
    """
    Two-stage check for patent identifiers.

    Patent IDs are detected globally (not category-gated) because they
    frequently appear in legal, technical, and narrative text outside
    COMPANY INFO. This is an intentional exception to the
    Detect → Context → Enforce pattern used for first-class identifiers.
    """
    patent_pattern = r'\b(US|EP|WO|JP|CN|DE|GB|FR)\s?\d{6,10}\b'
    
    # Stage 1: Check if any patent IDs exist
    has_patents = False
    detected = []
    for idx, row in df.iterrows():
        before_val = str(row['Before']) if pd.notna(row['Before']) else ''
        if re.search(patent_pattern, before_val, re.IGNORECASE):
            has_patents = True
            detected.append({
                'excel_row': idx + 2,
                'category': row['Category'],
                'before': row['Before'],
                'after': row['After']
            })
    
    if not has_patents:
        return {
            'passed': False,
            'message': 'No patent numbers detected (e.g., US1234567, WO2020123456)',
            'severity': 'warning',
            'rows': []
        }
    
    # Stage 2: Check After values for problems
    issues = []
    before_values = set(df['Before'].dropna().astype(str).str.upper())
    
    for idx, row in df.iterrows():
        before_val = str(row['Before']) if pd.notna(row['Before']) else ''
        after_val = str(row['After']) if pd.notna(row['After']) else ''
        
        if re.search(patent_pattern, before_val, re.IGNORECASE) and after_val:
            problem = None
            
            # Check 1: After contains a real patent ID from Before column
            if after_val.upper() in before_values and after_val.upper() != before_val.upper():
                problem = f"After value '{after_val}' is a real patent ID from Before column"
            
            # Check 2: Format mismatch - patent IDs should maintain structure
            before_match = re.search(patent_pattern, before_val, re.IGNORECASE)
            after_match = re.search(patent_pattern, after_val, re.IGNORECASE)
            
            if before_match and not after_match:
                problem = f"Format mismatch: After doesn't follow patent ID format"
            elif before_match and after_match:
                before_digits = re.findall(r'\d+', before_match.group())
                after_digits = re.findall(r'\d+', after_match.group())
                if before_digits and after_digits:
                    if len(before_digits[0]) != len(after_digits[0]):
                        problem = f"Format mismatch: Patent number length changed from {len(before_digits[0])} to {len(after_digits[0])} digits"
            
            if problem:
                issues.append({
                    'excel_row': idx + 2,
                    'category': row['Category'],
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': problem
                })
    
    return {
        'passed': len(issues) == 0,
        'message': f'All patent numbers anonymized correctly ({len(detected)} found)' if len(issues) == 0 else f'Found {len(issues)} patent number(s) with anonymization problems',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }

CIK_REGEX = re.compile(r"^\d{7,10}$")

def looks_like_cik(value: str) -> bool:
    return bool(value and CIK_REGEX.match(value))

def check_cik_ids(df: pd.DataFrame) -> Dict:
    """Two-stage check for CIK numbers"""
    
    # Stage 1: Check if any CIKs exist
    has_cik = False
    detected = []
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        
        if detect_cik(before_val) and security_id_context_applies(category) and security_id_comment_allows_detection(comment, "CIK"):
            has_cik = True
            detected.append({
                'excel_row': idx + 2,
                'category': category,
                'before': row['Before'],
                'after': row['After']
            })
    
    if not has_cik:
        return {
            'passed': False,
            'message': 'No CIK numbers detected (SEC company IDs like 0001018724)',
            'severity': 'warning',
            'rows': []
        }
    
    # Stage 2: Check After values
    issues = []
    before_values = set(df['Before'].dropna().astype(str).str.lower())
    
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        
        if detect_cik(before_val) and security_id_context_applies(category) and security_id_comment_allows_detection(comment, "CIK") and after_val:
            problem = None
            
            if after_val.lower() in before_values and after_val.lower() != before_val.lower():
                problem = f"After CIK '{after_val}' is a real identifier from Before column"
            elif not after_val.isdigit():
                problem = f"After value is not a valid CIK format (should be numeric)"
            elif len(before_val) != len(after_val):
                problem = f"CIK length mismatch: {len(before_val)} digits → {len(after_val)} digits"
            
            if problem:
                issues.append({
                    'excel_row': idx + 2,
                    'category': category,
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': problem
                })
    
    return {
        'passed': len(issues) == 0,
        'message': f'All CIK numbers anonymized correctly ({len(detected)} found)' if len(issues) == 0 else f'❌ Found {len(issues)} CIK(s) with problems',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }

def check_isin_ids(df: pd.DataFrame) -> Dict:
    """Two-stage check for ISIN codes - handles spaces in real-world formats"""
    
    # Stage 1: Check if any ISINs exist
    has_isin = False
    detected = []
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        
        if security_id_context_applies(category) and security_id_comment_allows_detection(comment, "ISIN") and detect_isin(before_val):
            has_isin = True
            detected.append({
                'excel_row': idx + 2,
                'category': category,
                'before': row['Before'],
                'after': row['After']
            })
    
    if not has_isin:
        return {
            'passed': False,
            'message': 'No ISIN codes detected (international security IDs like US0378331005)',
            'severity': 'warning',
            'rows': []
        }
    
    # Stage 2: Check After values
    issues = []
    before_values = set(detect_isin(str(v)) for v in df['Before'].dropna() if detect_isin(str(v)))
    
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        
        normalized_before = detect_isin(before_val)
        if security_id_context_applies(category) and normalized_before and after_val:
            problem = None
            normalized_after = detect_isin(after_val)
            
            if not normalized_after:
                problem = f"After value doesn't match ISIN format (should be 2 letters + 9 alphanumeric + 1 digit)"
            elif normalized_after in before_values and normalized_after != normalized_before:
                problem = f"After ISIN '{after_val}' is a real identifier from Before column"
            elif len(normalized_before) != len(normalized_after):
                problem = f"ISIN length mismatch: {len(normalized_before)} → {len(normalized_after)} characters"
            
            if problem:
                issues.append({
                    'excel_row': idx + 2,
                    'category': category,
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': problem
                })
    
    return {
        'passed': len(issues) == 0,
        'message': f'All ISIN codes validated successfully ({len(detected)} found)' if len(issues) == 0 else f'❌ Found {len(issues)} ISIN(s) with problems',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }

def check_cusip_ids(df: pd.DataFrame) -> Dict:
    """Two-stage check for CUSIP codes - handles spaces in real-world formats"""
    
    # Stage 1: Check if any CUSIPs exist
    has_cusip = False
    detected = []
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        
        if security_id_context_applies(category) and detect_cusip(before_val) and security_id_comment_allows_detection(comment, "CUSIP", category):
            has_cusip = True
            detected.append({
                'excel_row': idx + 2,
                'category': category,
                'before': row['Before'],
                'after': row['After']
            })
    
    if not has_cusip:
        return {
            'passed': False,
            'message': 'No CUSIP codes detected (US/Canada security IDs like 037833100)',
            'severity': 'warning',
            'rows': []
        }
    
    # Stage 2: Check After values
    issues = []
    before_values = set(detect_cusip(str(v)) for v in df['Before'].dropna() if detect_cusip(str(v)))
    
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        
        normalized_before = detect_cusip(before_val)
        if security_id_context_applies(category) and security_id_comment_allows_detection(comment, "CUSIP", category) and normalized_before and after_val:
            problem = None
            normalized_after = detect_cusip(after_val)
            
            if not normalized_after:
                problem = f"After value doesn't match CUSIP format (should be 9 characters: 3 digits + 5 alphanumeric + 1 digit)"
            elif normalized_after in before_values and normalized_after != normalized_before:
                problem = f"After CUSIP '{after_val}' is a real identifier from Before column"
            elif len(normalized_before) != len(normalized_after):
                problem = f"CUSIP length mismatch: {len(normalized_before)} → {len(normalized_after)} characters"
            
            if problem:
                issues.append({
                    'excel_row': idx + 2,
                    'category': category,
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': problem
                })
    
    return {
        'passed': len(issues) == 0,
        'message': f'All CUSIP codes validated successfully ({len(detected)} found)' if len(issues) == 0 else f'❌ Found {len(issues)} CUSIP(s) with problems',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }

def check_sedol_ids(df: pd.DataFrame) -> Dict:
    """Two-stage check for SEDOL codes"""
    
    # Stage 1: Check if any SEDOLs exist
    has_sedol = False
    detected = []
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        
        if security_id_context_applies(category) and security_id_comment_allows_detection(comment, "SEDOL") and detect_sedol(before_val):
            has_sedol = True
            detected.append({
                'excel_row': idx + 2,
                'category': category,
                'before': row['Before'],
                'after': row['After']
            })
    
    if not has_sedol:
        return {
            'passed': False,
            'message': 'No SEDOL codes detected (UK security IDs like 2046251)',
            'severity': 'warning',
            'rows': []
        }
    
    # Stage 2: Check After values
    issues = []
    before_values = set(df['Before'].dropna().astype(str).str.upper())
    
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        
        if security_id_context_applies(category) and detect_sedol(before_val) and after_val:
            problem = None
            
            if after_val.upper() in before_values and after_val.upper() != before_val.upper():
                problem = f"After SEDOL '{after_val}' is a real identifier from Before column"
            elif not re.match(r'^[B-DF-HJ-NP-TV-Z0-9]{6}[0-9]$', after_val):
                problem = f"After value doesn't match SEDOL format (7 characters)"
            elif len(before_val) != len(after_val):
                problem = f"SEDOL length mismatch: {len(before_val)} → {len(after_val)} characters"
            
            if problem:
                issues.append({
                    'excel_row': idx + 2,
                    'category': category,
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': problem
                })
    
    return {
        'passed': len(issues) == 0,
        'message': f'All SEDOL codes validated successfully ({len(detected)} found)' if len(issues) == 0 else f'❌ Found {len(issues)} SEDOL(s) with problems',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }

# -------------------------
# EIN and SEC File Number QC Checks
# -------------------------

def check_ein_ids(df: pd.DataFrame) -> Dict:
    """Two-stage check for EINs"""
    has_ein = False
    detected = []

    for idx, row in df.iterrows():
        before = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''

        if looks_like_ein(before) and ein_context_applies(category, comment):
            has_ein = True
            detected.append({
                'excel_row': idx + 2,
                'category': category,
                'before': row['Before'],
                'after': row['After']
            })

    if not has_ein:
        return {
            'passed': False,
            'message': 'No EIN numbers detected (tax IDs like 12-3456789)',
            'severity': 'warning',
            'rows': []
        }

    issues = []
    for idx, row in df.iterrows():
        before = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after = str(row['After']).strip() if pd.notna(row['After']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''

        if looks_like_ein(before) and ein_context_applies(category, comment) and after:
            for issue in validate_ein_anonymization(before, after):
                issues.append({
                    'excel_row': idx + 2,
                    'category': category,
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': issue
                })

    return {
        'passed': len(issues) == 0,
        'message': f'All EIN numbers anonymized correctly ({len(detected)} found)' if len(issues) == 0 else f'Found {len(issues)} EIN number(s) with format issues',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }

def check_sec_file_numbers(df: pd.DataFrame) -> Dict:
    """Two-stage check for SEC file numbers"""
    has_sec_file = False
    detected = []

    for idx, row in df.iterrows():
        before = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''

        if looks_like_sec_file_number(before) and sec_file_context_applies(category, comment):
            has_sec_file = True
            detected.append({
                'excel_row': idx + 2,
                'category': category,
                'before': row['Before'],
                'after': row['After']
            })

    if not has_sec_file:
        return {
            'passed': False,
            'message': 'No SEC file numbers detected (filing IDs like 001-12345)',
            'severity': 'warning',
            'rows': []
        }

    issues = []
    for idx, row in df.iterrows():
        before = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after = str(row['After']).strip() if pd.notna(row['After']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''

        if looks_like_sec_file_number(before) and sec_file_context_applies(category, comment) and after:
            for issue in validate_sec_file_anonymization(before, after):
                issues.append({
                    'excel_row': idx + 2,
                    'category': category,
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': issue
                })

    return {
        'passed': len(issues) == 0,
        'message': f'All SEC file numbers anonymized correctly ({len(detected)} found)' if len(issues) == 0 else f'Found {len(issues)} SEC file number(s) with format issues',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }

def ticker_comment_allows_detection(comment) -> bool:
    """
    Inclusion-only rule for ticker detection.
    - Empty comment → allow
    - Explicit ticker / market language → allow
    - Anything else → block
    """
    # Handle NaN values from pandas
    if pd.isna(comment):
        return True
    
    # Convert to string and check if empty
    comment_str = str(comment).strip()
    if not comment_str or comment_str.lower() == 'nan':
        return True

    comment_u = comment_str.upper()
    return any(
        token in comment_u
        for token in [
            "TICKER",
            "STOCK",
            "EQUITY",
            "NASDAQ",
            "NYSE",
            "LISTED",
            "TRADING",
            "SECURITY SYMBOL"
        ]
    )

def security_id_comment_allows_detection(comment, identifier_type: str = "security", category: str = "") -> bool:
    """
    Unified comment filter for security identifiers (CIK, CUSIP, ISIN, SEDOL, FIGI, LEI).
    
    Prevents false positives and double counting by blocking detection when comment/category
    suggests the value is something else (narrative text, names, addresses, other identifiers, etc.)
    
    Rules:
    1. POSITIVE CONFIRMATION: If comment explicitly mentions THIS identifier type → FORCE ALLOW
    2. EXPLICIT BLOCK: If comment/category explicitly mentions DIFFERENT identifier type → FORCE BLOCK
    3. SEC CONTEXT BLOCK: If category contains "SEC", block international IDs (ISIN, CUSIP, LEI, FIGI, SEDOL) but allow CIK
    4. NARRATIVE BLOCK: If comment contains narrative language → BLOCK
    5. NEUTRAL/EMPTY: Allow (category gate is sufficient)
    
    Args:
        comment: The comment field value
        identifier_type: The specific identifier being checked (e.g., "CUSIP", "CIK")
        category: The category field value (optional, used for additional context)
    """
    # Handle NaN values from pandas
    if pd.isna(comment):
        comment = ""
    if pd.isna(category):
        category = ""
    
    # Convert to string and check if empty
    comment_str = str(comment).strip()
    category_str = str(category).strip()
    if not comment_str or comment_str.lower() == 'nan':
        comment_str = ""
    if not category_str or category_str.lower() == 'nan':
        category_str = ""
    
    comment_u = comment_str.upper()
    category_u = category_str.upper()
    
    # Combine both for blocking checks
    combined_context = f"{category_u} {comment_u}"
    
    # RULE 1: POSITIVE CONFIRMATION - If comment explicitly mentions THIS identifier, FORCE ALLOW
    # This overrides everything else
    identifier_map = {
        "CUSIP": ["CUSIP"],
        "CIK": ["CIK"],
        "ISIN": ["ISIN"],
        "SEDOL": ["SEDOL"],
        "FIGI": ["FIGI", "BLOOMBERG"],
        "LEI": ["LEI", "LEGAL ENTITY IDENTIFIER"],
        "EIN": ["EIN", "TAX ID", "EMPLOYER IDENTIFICATION"],
        "SEC_FILE": ["SEC FILE", "FILE NUMBER", "FILE NO"],
        "security": []  # Generic fallback
    }
    
    # Check if comment/category mentions THIS specific identifier type
    if identifier_type.upper() in identifier_map or identifier_type in identifier_map:
        key = identifier_type.upper() if identifier_type.upper() in identifier_map else identifier_type
        for term in identifier_map.get(key, []):
            if term in combined_context:
                return True  # POSITIVE CONFIRMATION - explicitly mentioned
    
    # CUSIP-SPECIFIC: Positive confirmation approach
    # Only allow CUSIP detection if category/comment contains affirming terms
    if identifier_type.upper() == "CUSIP":
        cusip_affirming_terms = ["CUSIP", "COMPANY", "SECURITY", "FINANCIAL", "ISSUER"]
        if any(term in combined_context for term in cusip_affirming_terms):
            # Has affirming terms - proceed to other checks
            pass
        else:
            # No affirming terms - block CUSIP detection
            return False
    
    # RULE 2: EXPLICIT BLOCK - If comment/category mentions a DIFFERENT specific identifier type, BLOCK
    other_identifiers = ["EIN", "TAX ID", "CIK", "CUSIP", "ISIN", "SEDOL", "FIGI", "LEI", 
                         "TICKER", "STOCK SYMBOL", "SEC FILE", "FILE NUMBER", "REGISTRATION", "FILING"]
    
    for other_id in other_identifiers:
        if other_id in combined_context:
            # This is a different identifier type - block detection
            # Exception: generic terms that might appear in multiple contexts
            if other_id not in ["ID", "NUMBER", "CODE"]:
                return False
    
    # RULE 3: NARRATIVE BLOCK - Descriptive language that indicates this is NOT a security ID
    block_terms = [
        "NAME", "PERSON", "EXECUTIVE", "CEO", "CFO", "PRESIDENT",
        "ADDRESS", "STREET", "LOCATION", "CITY",
        "DESCRIPTION", "NARRATIVE", "TEXT", "PARAGRAPH",
        "TITLE", "ROLE", "POSITION",
        "EMAIL", "PHONE", "CONTACT",
        "SETTLEMENT", "LAWSUIT", "LEGAL CASE"
    ]
    
    if any(term in combined_context for term in block_terms):
        return False
    
    # RULE 4: NEUTRAL/EMPTY - ALLOW (generic security language or neutral)
    # If we got here, comment doesn't explicitly mention any identifier
    # and doesn't have blocking terms, so allow it
    return True

def check_ticker_symbols(df: pd.DataFrame) -> Dict:
    """Two-stage check for stock ticker symbols with strict context gating."""
    has_ticker = False
    detected = []

    # Stage 1: Detection with context + Comment gating (File no longer blocks detection)
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''

        if (
            ticker_context_applies(category)
            and re.match(r'^[A-Z]{1,5}$', before_val)
            and ticker_comment_allows_detection(comment)
        ):
            has_ticker = True
            detected.append({
                'excel_row': idx + 2,
                'category': category,
                'before': row['Before'],
                'after': row['After'],
            })

    if not has_ticker:
        return {
            'passed': False,
            'message': 'No stock tickers detected (e.g., AAPL, MSFT, GOOGL)',
            'severity': 'warning',
            'rows': []
        }

    # Stage 2: Enforcement
    issues = []
    before_values = set(df['Before'].dropna().astype(str).str.upper())

    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        file_val = str(row.get('File', '')) if 'File' in df.columns else ''

        if (
            ticker_context_applies(category)
            and re.match(r'^[A-Z]{1,5}$', before_val)
            and ticker_comment_allows_detection(comment)
            and after_val
        ):
            problem = None

            if after_val.upper() in before_values and after_val.upper() != before_val.upper():
                problem = f"After ticker '{after_val}' is a real identifier from Before column"
            elif not re.match(r'^[A-Z]{1,5}$', after_val):
                problem = f"After value doesn't match ticker format (1–5 uppercase letters)"
            elif abs(len(before_val) - len(after_val)) > 1:
                problem = f"Ticker length changed significantly: {len(before_val)} → {len(after_val)} characters"

            if problem:
                issues.append({
                    'excel_row': idx + 2,
                    'category': category,
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': problem
                })

    if issues:
        return {
            'passed': False,
            'message': f'Found {len(issues)} stock ticker(s) with anonymization problems',
            'severity': 'error',
            'rows': issues
        }

    return {
        'passed': True,
        'message': f'All stock tickers anonymized correctly ({len(detected)} found)',
        'severity': 'pass',
        'rows': detected
    }

def check_figi_ids(df: pd.DataFrame) -> Dict:
    """Two-stage check for FIGI codes (Financial Instrument Global Identifier) - BBG prefix"""
    # Stage 1: Check if any FIGIs exist
    has_figi = False
    detected = []
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        
        if security_id_context_applies(category) and detect_figi(before_val) and security_id_comment_allows_detection(comment, "FIGI"):
            has_figi = True
            detected.append({
                'excel_row': idx + 2,
                'category': category,
                'before': row['Before'],
                'after': row['After']
            })
    
    if not has_figi:
        return {
            'passed': False,
            'message': 'No FIGI codes detected (Bloomberg IDs like BBG000BLNQ16)',
            'severity': 'warning',
            'rows': []
        }
    
    # Stage 2: Check After values
    issues = []
    before_values = set(df['Before'].dropna().astype(str).str.upper())
    
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        
        if security_id_context_applies(category) and security_id_comment_allows_detection(comment, "FIGI") and detect_figi(before_val) and after_val:
            problem = None
            
            if after_val.upper() in before_values and after_val.upper() != before_val.upper():
                problem = f"After FIGI '{after_val}' is a real identifier from Before column"
            elif not re.match(r'^BBG[A-Z0-9]{9}$', after_val):
                problem = f"After value doesn't match FIGI format (BBG + 9 alphanumeric characters)"
            elif len(before_val) != len(after_val):
                problem = f"FIGI length mismatch: {len(before_val)} → {len(after_val)} characters"
            
            if problem:
                issues.append({
                    'excel_row': idx + 2,
                    'category': category,
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': problem
                })
    
    return {
        'passed': len(issues) == 0,
        'message': f'All FIGI codes validated successfully ({len(detected)} found)' if len(issues) == 0 else f'❌ Found {len(issues)} FIGI(s) with problems',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }

def check_lei_ids(df: pd.DataFrame) -> Dict:
    """Two-stage check for LEI codes (Legal Entity Identifier)"""
    
    # Stage 1: Check if any LEIs exist
    has_lei = False
    detected = []
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        
        if security_id_context_applies(category) and security_id_comment_allows_detection(comment, "LEI") and detect_lei(before_val):
            has_lei = True
            detected.append({
                'excel_row': idx + 2,
                'category': category,
                'before': row['Before'],
                'after': row['After']
            })
    
    if not has_lei:
        return {
            'passed': False,
            'message': 'No LEI codes detected (legal entity IDs, 20 characters)',
            'severity': 'warning',
            'rows': []
        }
    
    # Stage 2: Check After values
    issues = []
    before_values = set(df['Before'].dropna().astype(str).str.upper())
    
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
        
        if security_id_context_applies(category) and security_id_comment_allows_detection(comment, "LEI") and detect_lei(before_val) and after_val:
            problem = None
            
            if after_val.upper() in before_values and after_val.upper() != before_val.upper():
                problem = f"After LEI '{after_val}' is a real identifier from Before column"
            elif not re.match(r'^[A-Z0-9]{20}$', after_val):
                problem = f"After value doesn't match LEI format (20 alphanumeric characters)"
            elif len(before_val) != len(after_val):
                problem = f"LEI length mismatch: {len(before_val)} → {len(after_val)} characters"
            
            if problem:
                issues.append({
                    'excel_row': idx + 2,
                    'category': category,
                    'before': row['Before'],
                    'after': row['After'],
                    'problem': problem
                })
    
    return {
        'passed': len(issues) == 0,
        'message': f'All LEI codes validated successfully ({len(detected)} found)' if len(issues) == 0 else f'❌ Found {len(issues)} LEI(s) with problems',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }

def check_retail_labels(df: pd.DataFrame) -> Dict:
    """Check if retail-related labels exist - warn if none found"""
    retail_terms = ['retail', 'franchise', 'store', 'branch', 'outlet', 'shop']
    category_col = df['Category'].astype(str).str.lower()

    has_retail = any(category_col.str.contains(term, na=False).any() for term in retail_terms)

    return {
        'passed': has_retail,
        'message': f'Found {retail_count} retail/franchise categories' if has_retail else '⚠️ No retail/store/franchise categories found - consider if multi-location identifiers need anonymization',
        'severity': 'pass' if has_retail else 'warning',
        'rows': []
    }

def check_email_addresses(df: pd.DataFrame) -> Dict:
    """Detection check for email addresses in Before column"""
    detected = []

    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''

        # BLOCKING LOGIC: Skip if category/comment indicates this is NOT an email
        if should_block_email_detection(category, comment):
            continue

        if before_val and before_val.lower() != 'nan':
            # Try to validate as email
            try:
                validate_email(before_val, check_deliverability=False)
                detected.append({
                    'excel_row': idx + 2,
                    'category': row['Category'],
                    'email': before_val,
                    'after': row['After']
                })
            except EmailNotValidError:
                # Not an email, skip
                pass

    if len(detected) == 0:
        return {
            'passed': False,
            'message': 'No email addresses detected (e.g., user@example.com)',
            'severity': 'warning',
            'rows': []
        }

    return {
        'passed': True,
        'message': f'Found {len(detected)} email address(es) in tracker',
        'severity': 'pass',
        'rows': detected
    }

def check_phone_numbers(df: pd.DataFrame) -> Dict:
    """Detection check for phone numbers in Before column"""
    detected = []

    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''

        # BLOCKING LOGIC: Skip if category/comment indicates this is NOT a phone number
        if should_block_phone_detection(category, comment):
            continue

        if before_val and before_val.lower() != 'nan':
            # Try to find phone numbers (default to US region)
            try:
                for match in phonenumbers.PhoneNumberMatcher(before_val, "US"):
                    detected.append({
                        'excel_row': idx + 2,
                        'category': row['Category'],
                        'phone_number': match.raw_string,
                        'after': row['After']
                    })
                    break  # Only capture first match per row
            except:
                # If parsing fails, skip
                pass

    if len(detected) == 0:
        return {
            'passed': False,
            'message': 'No phone numbers detected (e.g., 555-123-4567)',
            'severity': 'warning',
            'rows': []
        }

    return {
        'passed': True,
        'message': f'Found {len(detected)} phone number(s) in tracker',
        'severity': 'pass',
        'rows': detected
    }

def check_addresses(df: pd.DataFrame) -> Dict:
    """Detection check for addresses using spaCy GPE/LOC entities"""
    # Lazy-load spaCy model
    nlp = load_spacy_model()

    if nlp is None:
        return {
            'passed': False,
            'message': '⚠️ spaCy model not loaded - cannot detect addresses',
            'severity': 'warning',
            'rows': []
        }

    detected = []

    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''

        # BLOCKING LOGIC: Skip if category/comment indicates this is NOT an address
        if should_block_address_detection(category, comment):
            continue

        if before_val and before_val.lower() != 'nan' and len(before_val) > 10:
            # Use spaCy to detect location entities (cities, states, countries)
            doc = nlp(before_val)
            has_location = False
            location_entities = []

            for ent in doc.ents:
                if ent.label_ in ["GPE", "LOC"]:  # Geopolitical entity or location
                    has_location = True
                    location_entities.append(ent.text)

            if has_location:
                detected.append({
                    'excel_row': idx + 2,
                    'category': row['Category'],
                    'address_text': before_val,
                    'locations_found': ', '.join(location_entities),
                    'after': row['After']
                })

    if len(detected) == 0:
        return {
            'passed': False,
            'message': 'No addresses detected (city/state/location indicators)',
            'severity': 'warning',
            'rows': []
        }

    return {
        'passed': True,
        'message': f'Found {len(detected)} address(es) with location indicators',
        'severity': 'pass',
        'rows': detected
    }

def check_company_names(df: pd.DataFrame) -> Dict:
    """Detection check for company/organization names using spaCy NER"""
    # Lazy-load spaCy model
    nlp = load_spacy_model()

    if nlp is None:
        return {
            'passed': False,
            'message': '⚠️ spaCy model not loaded - cannot detect company names',
            'severity': 'warning',
            'rows': []
        }

    detected = []

    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''

        # BLOCKING LOGIC: Skip if category/comment indicates this is NOT a company name
        if should_block_company_name_detection(category, comment):
            continue

        if before_val and before_val.lower() != 'nan':
            # Use spaCy NER to detect organizations
            doc = nlp(before_val)
            companies_found = []

            for ent in doc.ents:
                if ent.label_ == "ORG":
                    companies_found.append(ent.text)

            if companies_found:
                detected.append({
                    'excel_row': idx + 2,
                    'category': row['Category'],
                    'company_name': ', '.join(companies_found),
                    'after': row['After']
                })

    if len(detected) == 0:
        return {
            'passed': False,
            'message': 'No company/organization names detected',
            'severity': 'warning',
            'rows': []
        }

    return {
        'passed': True,
        'message': f'Found {len(detected)} company/organization name(s) in tracker',
        'severity': 'pass',
        'rows': detected
    }

def check_executive_honorifics(df: pd.DataFrame) -> Dict:
    """
    Semantic integrity check for executive naming conventions.

    This is not a structural identifier check. It ensures narrative and
    anonymization completeness for people-related entries and is
    intentionally excluded from the Detect → Context → Enforce framework.
    """
    issues = []

    # Get all executive rows
    exec_df = df[df['Category'].str.upper() == 'EXECUTIVES']

    # Extract full names (assuming format: "FirstName LastName")
    full_names = []
    for idx, row in exec_df.iterrows():
        before_val = str(row['Before']) if pd.notna(row['Before']) else ''
        # Check if it's a full name (at least 2 words, no honorifics)
        words = before_val.split()
        if len(words) >= 2 and not any(h in before_val for h in ['Mr.', 'Mrs.', 'Ms.', 'Dr.', 'Mr', 'Mrs', 'Ms', 'Dr']):
            full_names.append({
                'excel_row': idx + 2,
                'name': before_val,
                'last_name': words[-1],
                'after': row['After']
            })

    # For each full name, check if honorific variant exists
    for name_info in full_names:
        last_name = name_info['last_name']
        # Check if any Before value has honorific + this last name
        has_honorific = exec_df['Before'].astype(str).str.contains(
            f'(Mr|Mrs|Ms|Dr)\.?\s+{last_name}',
            case=False,
            na=False
        ).any()

        if not has_honorific:
            issues.append({
                'excel_row': name_info['excel_row'],
                'before': name_info['name'],
                'after': name_info['after'],
                'missing': f'Need: Mr./Mrs./Ms. {last_name} variant'
            })

    return {
        'passed': len(issues) == 0,
        'message': f'All executive names have proper title variants' if len(issues) == 0 else f'❌ Found {len(issues)} executive(s) missing honorific entries (Mr./Mrs./Ms. LastName)',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': issues
    }

def check_first_names_separate_rows(df: pd.DataFrame) -> Dict:
    """
    Check if first names from full names have separate tracker rows.

    For EXECUTIVES category only: ensures that if "John Smith" appears,
    "John" should also have its own row for complete anonymization coverage.
    """
    issues = []

    # Get all executive rows
    exec_df = df[df['Category'].str.upper() == 'EXECUTIVES']

    if len(exec_df) == 0:
        return {
            'passed': False,
            'message': 'No EXECUTIVES category found to check',
            'severity': 'warning',
            'rows': []
        }

    # Build set of all first names that appear standalone in Before column
    standalone_first_names = set()
    for before_val in exec_df['Before'].dropna():
        before_str = str(before_val).strip()
        words = before_str.split()

        # Clean words - remove honorifics and middle initials
        clean_words = []
        for w in words:
            w_clean = w.strip('.,()').upper()
            # Skip honorifics
            if w_clean in ['MR', 'MRS', 'MS', 'DR', 'MR.', 'MRS.', 'MS.', 'DR.']:
                continue
            # Skip middle initials (single letter with optional period)
            if len(w_clean.rstrip('.')) == 1:
                continue
            clean_words.append(w_clean)

        # If only one word remains, it's a standalone first name
        if len(clean_words) == 1:
            standalone_first_names.add(clean_words[0])

    # Extract full names and check if their first names have standalone rows
    for idx, row in exec_df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        words = before_val.split()

        # Clean words - remove honorifics and middle initials
        clean_words = []
        for w in words:
            w_clean = w.strip('.,()').upper()
            # Skip honorifics
            if w_clean in ['MR', 'MRS', 'MS', 'DR', 'MR.', 'MRS.', 'MS.', 'DR.']:
                continue
            # Skip middle initials
            if len(w_clean.rstrip('.')) == 1:
                continue
            clean_words.append(w_clean)

        # If this is a full name (2+ words after cleaning)
        if len(clean_words) >= 2:
            first_name = clean_words[0]

            # Check if this first name has a standalone row
            if first_name not in standalone_first_names:
                issues.append({
                    'excel_row': idx + 2,
                    'category': 'EXECUTIVES',
                    'full_name': before_val,
                    'missing_first_name': first_name.title(),
                    'after': row['After'],
                    'problem': f'First name "{first_name.title()}" should have separate tracker row'
                })

    return {
        'passed': len(issues) == 0,
        'message': f'All executive first names have separate rows' if len(issues) == 0 else f'❌ Found {len(issues)} full name(s) missing first-name-only entries',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': issues
    }

def check_name_recycling(df: pd.DataFrame) -> Dict:
    """Check if first or last names from Before appear in After"""
    issues = []
    
    # Get executive rows
    exec_df = df[df['Category'].str.upper() == 'EXECUTIVES']
    
    # Extract names from Before column
    before_names = set()
    for before_val in exec_df['Before'].dropna():
        before_str = str(before_val).strip()
        
        # Skip 'nan' string values
        if before_str.lower() == 'nan':
            continue
            
        words = before_str.split()
        # Extract first and last names (skip honorifics, middle initials, prefixes, suffixes)
        for w in words:
            w_clean = w.strip('.,()"\'')
            
            # Skip if empty after cleaning
            if not w_clean:
                continue
                
            # Skip honorifics
            if w_clean.upper() in ['MR', 'MRS', 'MS', 'DR', 'MR.', 'MRS.', 'MS.', 'DR.']:
                continue
            
            # Skip single letters (middle initials like "B.", "J.", "L.")
            if len(w_clean.rstrip('.')) == 1:
                continue
            
            # Skip common suffixes
            if w_clean.upper() in ['JR', 'JR.', 'SR', 'SR.', 'II', 'III', 'IV']:
                continue
                
            # Only add names with 2+ characters
            if len(w_clean) >= 2:
                before_names.add(w_clean)
    
    # Check if any Before names appear in After
    for idx, row in exec_df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''
        
        # Skip rows where Before or After is 'nan'
        if before_val.lower() == 'nan' or after_val.lower() == 'nan':
            continue
        
        if not after_val:
            continue
            
        after_words = after_val.split()
        after_clean = []
        
        for w in after_words:
            w_clean = w.strip('.,()"\'')
            
            # Skip if empty
            if not w_clean:
                continue
                
            # Skip honorifics
            if w_clean.upper() in ['MR', 'MRS', 'MS', 'DR', 'MR.', 'MRS.', 'MS.', 'DR.']:
                continue
            
            # Skip single letters
            if len(w_clean.rstrip('.')) == 1:
                continue
            
            # Skip suffixes
            if w_clean.upper() in ['JR', 'JR.', 'SR', 'SR.', 'II', 'III', 'IV']:
                continue
                
            # Only check names with 2+ characters
            if len(w_clean) >= 2:
                after_clean.append(w_clean)
        
        # Check for recycled names
        recycled = [name for name in after_clean if name in before_names]
        if recycled:
            # Format each name clearly
            recycled_display = ' | '.join([f'"{name}"' for name in recycled])
            
            issues.append({
                'excel_row': idx + 2,
                'before': row['Before'],
                'after': row['After'],
                'recycled_names': recycled_display
            })
    
    return {
        'passed': len(issues) == 0,
        'message': f'No name recycling detected (Before names not reused in After)' if len(issues) == 0 else f'❌ Found {len(issues)} instance(s) where After names appear in Before column',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': issues
    }

def check_after_in_before(df: pd.DataFrame) -> Dict:
    """Check if any After values appear in Before column"""
    issues = []

    # Get all Before values, excluding 'nan' strings
    before_set = set()
    for val in df['Before'].dropna():
        val_str = str(val).strip()
        # Skip 'nan' string values (empty cells)
        if val_str.lower() != 'nan':
            before_set.add(val_str)

    for idx, row in df.iterrows():
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''
        
        # Skip if after_val is empty or 'nan'
        if not after_val or after_val.lower() == 'nan':
            continue
            
        if after_val in before_set:
            issues.append({
                'excel_row': idx + 2,
                'category': row['Category'],
                'before': row['Before'],
                'after': row['After'],
                'problem': f'After value "{after_val}" also appears in Before column'
            })

    return {
        'passed': len(issues) == 0,
        'message': f'No cross-contamination detected (After values unique)' if len(issues) == 0 else f'❌ Found {len(issues)} After value(s) that also appear in Before (not anonymizing)',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': issues
    }

def check_blank_before_populated_after(df: pd.DataFrame) -> Dict:
    """Check if Before column is blank but After column has a value"""
    issues = []

    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''

        # Check if Before is blank/empty but After has a value
        # Handle 'nan' string representation from pandas
        if before_val.lower() in ['', 'nan'] and after_val and after_val.lower() != 'nan':
            issues.append({
                'excel_row': idx + 2,
                'category': row['Category'],
                'before': '[BLANK]',
                'after': row['After'],
                'problem': 'Cannot anonymize blank/missing Before value'
            })

    return {
        'passed': len(issues) == 0,
        'message': f'All rows have valid Before values' if len(issues) == 0 else f'❌ Found {len(issues)} row(s) with blank Before but populated After',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': issues
    }

def check_numeric_consistency(df: pd.DataFrame) -> Dict:
    """
    Heuristic consistency check for structured numeric identifiers.

    This is NOT a first-class identifier check. It acts as a backstop to
    detect structural breakage introduced during anonymization and is
    intentionally heuristic and category-limited.
    """
    
    def is_structured_id(val):
        """Determine if value looks like a structured ID (not an address or narrative text)"""
        if not val or len(val) > 30:
            return False
        
        # Remove spaces and hyphens for analysis
        cleaned = re.sub(r'[\s\-]', '', val)
        
        if len(cleaned) == 0:
            return False
        
        # Structured IDs are mostly alphanumeric (>80%)
        alphanum_count = sum(c.isalnum() for c in cleaned)
        alphanum_ratio = alphanum_count / len(cleaned)
        
        # Also check it's not too long (structured IDs are typically < 20 chars after cleaning)
        return alphanum_ratio > 0.8 and len(cleaned) <= 20
    
    issues = []
    
    for idx, row in df.iterrows():
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        
        # Only check COMPANY INFO category where format consistency matters
        if 'COMPANY INFO' not in category.upper():
            continue
        
        before_val = str(row['Before']) if pd.notna(row['Before']) else ''
        after_val = str(row['After']) if pd.notna(row['After']) else ''
        
        # Only check if both values look like structured IDs
        if not (is_structured_id(before_val) and is_structured_id(after_val)):
            continue
        
        # Extract digit sequences
        before_digits = re.findall(r'\d+', before_val)
        after_digits = re.findall(r'\d+', after_val)
        
        # Check if both have numbers and digit counts don't match
        if before_digits and after_digits:
            before_lens = [len(d) for d in before_digits]
            after_lens = [len(d) for d in after_digits]
            
            # Check if digit pattern lengths are preserved
            if len(before_lens) == len(after_lens):
                mismatch = False
                for b_len, a_len in zip(before_lens, after_lens):
                    if b_len != a_len:
                        mismatch = True
                        break
                
                if mismatch:
                    issues.append({
                        'excel_row': idx + 2,
                        'category': category,
                        'before': row['Before'],
                        'after': row['After'],
                        'problem': 'Security ID format appears inconsistent - Before has different structure than After'
                    })
    
    return {
        'passed': len(issues) == 0,
        'message': f'All security ID formats preserved correctly' if len(issues) == 0 else f'⚠️ Found {len(issues)} security ID(s) with inconsistent formats',
        'severity': 'pass' if len(issues) == 0 else 'warning',
        'rows': issues
    }

def build_simple_summary(results: List[Dict], check_categories: Dict[str, str], filename: str) -> str:
    """
    Build a simple text summary of errors and warnings for download.
    
    Args:
        results: List of check results from run_all_checks()
        check_categories: Dict mapping check names to category labels
        filename: Name of the uploaded file
    
    Returns:
        Plain text summary string
    """
    # Count severities
    total_checks = len(results)
    errors = sum(1 for r in results if r['severity'] == 'error')
    warnings = sum(1 for r in results if r['severity'] == 'warning')
    passed = sum(1 for r in results if r['severity'] == 'pass')
    
    # Build summary text
    lines = []
    lines.append("Anonymization Tracker QC Summary")
    lines.append(f"File: {filename}")
    lines.append("")
    lines.append("Summary:")
    lines.append(f"- Total Checks: {total_checks}")
    lines.append(f"- Errors: {errors}")
    lines.append(f"- Warnings: {warnings}")
    lines.append(f"- Passed: {passed}")
    lines.append("")
    
    # Add errors section if any
    error_results = [r for r in results if r['severity'] == 'error']
    if error_results:
        lines.append("==== ERRORS (Must Fix) ====")
        for result in error_results:
            check_name = result['check_name']
            message = result['message']
            # Strip emoji and special characters from message
            clean_message = message.replace('❌', '').replace('⚠️', '').replace('✅', '').strip()
            lines.append(f"- {check_name}: {clean_message}")
        lines.append("")
    
    # Add warnings section if any
    warning_results = [r for r in results if r['severity'] == 'warning']
    if warning_results:
        lines.append("==== WARNINGS (Review Recommended) ====")
        for result in warning_results:
            check_name = result['check_name']
            message = result['message']
            # Strip emoji and special characters from message
            clean_message = message.replace('❌', '').replace('⚠️', '').replace('✅', '').strip()
            lines.append(f"- {check_name}: {clean_message}")
        lines.append("")
    
    # Add footer
    if errors == 0 and warnings == 0:
        lines.append("✓ All checks passed - no issues found.")
        lines.append("")
    
    lines.append("---")
    lines.append("Note: This is a high-level summary. For detailed row-by-row information, see the full QC report in the web interface.")
    
    return "\n".join(lines)

def validate_and_prepare_dataframe(df: pd.DataFrame) -> tuple[bool, str, pd.DataFrame]:
    """
    Validate and prepare DataFrame for QC checks.
    
    Args:
        df: Raw DataFrame from file upload
    
    Returns:
        (is_valid, error_message, normalized_df)
    """
    # Step 1: Check if DataFrame is empty
    if df is None or len(df) == 0 or len(df.columns) == 0:
        return (False, "The uploaded file is empty. Please upload a tracker with data.", df)
    
    # Step 2: Check minimum column count (need at least Category and Before)
    if len(df.columns) < 2:
        return (False, "The file must have at least 2 columns. Please check your file format.", df)
    
    # Step 3: Normalize column names by position
    # Map columns 0-4 to expected names, keep extra columns as-is
    expected_columns = ['Category', 'Before', 'After', 'File', 'Comment']
    df = df.copy()
    
    # Rename only the first 5 columns (or fewer if file has < 5 columns)
    num_cols_to_rename = min(len(df.columns), len(expected_columns))
    new_column_names = list(df.columns)  # Keep existing names
    for i in range(num_cols_to_rename):
        new_column_names[i] = expected_columns[i]
    df.columns = new_column_names
    
    # Step 4: Check for minimum required data
    # At least one of Before or After must have non-empty values
    has_before_data = df['Before'].notna().any() if 'Before' in df.columns else False
    has_after_data = df['After'].notna().any() if 'After' in df.columns else False
    
    if not (has_before_data or has_after_data):
        return (False, "The tracker has no data in Before or After columns. Please add data to run QC checks.", df)
    
    # Step 5: Normalize column types to string
    for col in ['Category', 'Before', 'After', 'File', 'Comment']:
        if col in df.columns:
            df[col] = df[col].astype(str)
    
    # Step 6: Success
    return (True, "", df)

def run_all_checks(df: pd.DataFrame) -> List[Dict]:
    """Run all QC checks and return results"""

    checks = [
        # Links & URLs
        ("SEC Links", check_sec_links),
        ("After URL Leakage", check_after_link_leakage),

        # Financial Identifiers
        ("CIK Numbers", check_cik_ids),
        ("EIN Numbers", check_ein_ids),
        ("SEC File Numbers", check_sec_file_numbers),

        # Security Identifiers
        ("CUSIP Codes", check_cusip_ids),
        ("ISIN Codes", check_isin_ids),
        ("SEDOL Codes", check_sedol_ids),
        ("Stock Tickers", check_ticker_symbols),
        ("FIGI Codes", check_figi_ids),
        ("LEI Codes", check_lei_ids),

        # Content Validation
        ("Patent Numbers", check_patent_ids),
        ("Retail Labels", check_retail_labels),
        ("Email Addresses", check_email_addresses),
        ("Phone Numbers", check_phone_numbers),
        ("Addresses", check_addresses),
        ("Company Names", check_company_names),
        ("Executive Names", check_executive_honorifics),
        ("First Names Separate", check_first_names_separate_rows),

        # Cross-Validation
        ("Name Recycling", check_name_recycling),
        ("After in Before", check_after_in_before),
        ("Blank Before Check", check_blank_before_populated_after),
        ("Deletion Entries", check_deletion_entries),
        ("Format Consistency", check_numeric_consistency)
    ]
    
    results = []
    for check_name, check_func in checks:
        result = check_func(df)
        result['check_name'] = check_name
        results.append(result)
    
    return results

# Main app logic
if uploaded_file:
    try:
        # Load file
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        
        # Validate and prepare DataFrame
        is_valid, error_msg, df = validate_and_prepare_dataframe(df)
        
        if not is_valid:
            st.error(f"❌ {error_msg}")
            st.stop()  # Stop execution gracefully
        
        st.success(f"✅ File loaded: {len(df)} rows, {len(df.columns)} columns")
        
        # Show file preview
        with st.expander("📄 Preview Data (all rows)"):
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                height=min(800, 35 * len(df))  # dynamic height with sensible cap
            )
        
        # Run checks
        st.markdown("---")
        st.header("🔍 QC Results")
        
        results = run_all_checks(df)
        
        # Count issues
        errors = sum(1 for r in results if r['severity'] == 'error')
        warnings = sum(1 for r in results if r['severity'] == 'warning')
        passed = sum(1 for r in results if r['severity'] == 'pass')
        
        # Overall status banner
        if errors > 0:
            st.error(f"🔴 **{errors} Critical Issue(s) Found** - Must fix before proceeding")
        elif warnings > 0:
            st.warning(f"🟡 **{warnings} Warning(s)** - Review recommended but not required")
        else:
            st.success(f"🟢 **All Checks Passed** - Document appears properly anonymized")
        
        # Summary metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("✅ Passed", passed)
        col2.metric("⚠️ Warnings", warnings)
        col3.metric("❌ Errors", errors)
        
        # Map check names to categories for display tags
        check_categories = {
            "SEC Links": "Links & URLs",
            "After URL Leakage": "Links & URLs",
            "CIK Numbers": "Financial Identifiers",
            "EIN Numbers": "Financial Identifiers",
            "SEC File Numbers": "Financial Identifiers",
            "CUSIP Codes": "Security Identifiers",
            "ISIN Codes": "Security Identifiers",
            "SEDOL Codes": "Security Identifiers",
            "Stock Tickers": "Security Identifiers",
            "FIGI Codes": "Security Identifiers",
            "LEI Codes": "Security Identifiers",
            "Patent Numbers": "Content Validation",
            "Retail Labels": "Content Validation",
            "Email Addresses": "Content Validation",
            "Phone Numbers": "Content Validation",
            "Addresses": "Content Validation",
            "Company Names": "Content Validation",
            "Executive Names": "Content Validation",
            "First Names Separate": "Content Validation",
            "Name Recycling": "Cross-Validation",
            "After in Before": "Cross-Validation",
            "Blank Before Check": "Cross-Validation",
            "Deletion Entries": "Cross-Validation",
            "Format Consistency": "Cross-Validation"
        }
        
        # Generate text summary and provide download button
        summary_text = build_simple_summary(results, check_categories, uploaded_file.name)
        st.download_button(
            label="📥 Download Summary (Errors & Warnings)",
            data=summary_text,
            file_name="qc_summary.txt",
            mime="text/plain",
            help="Download a text file with high-level summary of all errors and warnings"
        )
        
        st.markdown("---")

        # Group results by severity (maintaining original check order)
        error_results = [r for r in results if r['severity'] == 'error']
        warning_results = [r for r in results if r['severity'] == 'warning']
        pass_results = [r for r in results if r['severity'] == 'pass']

        # Sort pass_results: Company Names first, then all others in original order
        company_names_result = [r for r in pass_results if r['check_name'] == 'Company Names']
        other_pass_results = [r for r in pass_results if r['check_name'] != 'Company Names']
        pass_results = company_names_result + other_pass_results

        # Helper function to display a single check result
        def display_check_result(result, use_expander=True):
            category_tag = check_categories.get(result['check_name'], '')

            # Determine icon and styling
            if result['severity'] == 'error':
                icon = "❌"
                st.error(f"**{icon} {result['check_name']}** `{category_tag}`: {result['message']}")
            elif result['severity'] == 'warning':
                icon = "⚠️"
                st.warning(f"**{icon} {result['check_name']}** `{category_tag}`: {result['message']}")
            else:
                icon = "✅"
                st.success(f"**{icon} {result['check_name']}** `{category_tag}`: {result['message']}")

            # Show details if there are issues
            if result['rows'] and len(result['rows']) > 0:
                issue_count = len(result['rows'])

                # Prepare row details display
                def show_row_details():
                    if result['severity'] == 'error':
                        st.caption("⚠️ **Action Required**: Fix these issues in your tracker and re-upload")

                    if isinstance(result['rows'][0], dict):
                        # Create a cleaner DataFrame for display
                        display_df = pd.DataFrame(result['rows'])

                        # Rename excel_row to something clearer
                        if 'excel_row' in display_df.columns:
                            display_df = display_df.rename(columns={'excel_row': '📍 Excel Row'})
                            # Move Excel Row to first column
                            cols = ['📍 Excel Row'] + [col for col in display_df.columns if col != '📍 Excel Row']
                            display_df = display_df[cols]

                        # Check-specific column reordering
                        if result['check_name'] == 'First Names Separate':
                            # Desired order: Excel Row, category, full_name, after, missing_first_name, problem
                            desired_order = ['📍 Excel Row', 'category', 'full_name', 'after', 'missing_first_name', 'problem']
                            # Only reorder columns that exist
                            cols = [c for c in desired_order if c in display_df.columns]
                            # Add any remaining columns not in desired_order
                            cols += [c for c in display_df.columns if c not in cols]
                            display_df = display_df[cols]

                        st.dataframe(
                            display_df,
                            use_container_width=True,
                            hide_index=True
                        )
                    else:
                        st.write(f"Excel Rows: {', '.join(map(str, result['rows']))}")

                # Use expander only if allowed (avoid nested expanders)
                if use_expander:
                    if result['severity'] == 'error':
                        expander_label = f"🔴 View {issue_count} issue(s) requiring attention"
                    elif result['severity'] == 'warning':
                        expander_label = f"⚠️ View {issue_count} item(s) to review"
                    else:
                        expander_label = f"✓ View {issue_count} item(s) validated"

                    with st.expander(expander_label):
                        show_row_details()
                else:
                    # Display directly without expander
                    show_row_details()

        # 1. Display Critical Fixes (Errors) First
        if error_results:
            st.subheader(f"🔴 Critical Fixes Required ({len(error_results)})")
            st.caption("⚠️ These issues must be fixed before document release")
            st.markdown("")

            for result in error_results:
                display_check_result(result)

            st.markdown("---")

        # 2. Display Warnings Second
        if warning_results:
            st.subheader(f"🟡 Warnings ({len(warning_results)})")
            st.caption("ℹ️ Review recommended but not required")
            st.markdown("")

            for result in warning_results:
                display_check_result(result)

            st.markdown("---")

        # 3. Display Passes Last (Collapsible, Hidden by Default)
        if pass_results:
            with st.expander(f"🟢 View All Passed Checks ({len(pass_results)})", expanded=False):
                for result in pass_results:
                    display_check_result(result, use_expander=False)
        
    except Exception as e:
        st.error(f"❌ Error processing file: {str(e)}")
        st.exception(e)

else:
    st.info("👆 Upload an anonymization tracker file to begin QC checks")
    
    # Show example of what we're checking
    st.markdown("---")
    st.subheader("What this tool checks:")
    
    with st.expander("ℹ️ About This Tool"):
        st.markdown("""
        This tool validates anonymization trackers to ensure sensitive information has been 
        properly anonymized before document release.
        
        **How it works:**
        - **Before column**: Original sensitive values that need anonymization
        - **After column**: Replacement values (anonymized versions)
        - The tool checks format preservation, detects leakage, and validates consistency
        
        **Severity Levels:**
        - 🔴 **Error**: Critical issue that MUST be fixed (data leakage, format violations)
        - 🟡 **Warning**: Informational - expected identifiers not found (may be OK)
        - 🟢 **Pass**: Check completed successfully, no issues detected
        """)
    
    checks_info = """
    ### 🔗 Links & URLs (2 checks)
    1. **SEC Links** - Verifies SEC.gov URLs exist and are properly anonymized
    2. **After URL Leakage** - Ensures After URLs don't contain Before identifiers

    ### 🔑 Financial Identifiers (3 checks)
    3. **CIK Numbers** - SEC company identifiers (e.g., 0001018724)
    4. **EIN Numbers** - Tax identification numbers (e.g., 12-3456789)
    5. **SEC File Numbers** - SEC filing numbers (e.g., 001-12345)

    ### 📈 Security Identifiers (6 checks)
    6. **CUSIP Codes** - US/Canada securities (e.g., 037833100)
    7. **ISIN Codes** - International securities (e.g., US0378331005)
    8. **SEDOL Codes** - UK securities (e.g., 2046251)
    9. **Stock Tickers** - Trading symbols (e.g., AAPL, MSFT)
    10. **FIGI Codes** - Bloomberg identifiers (e.g., BBG000BLNQ16)
    11. **LEI Codes** - Legal entity identifiers (20 characters)

    ### 📝 Content Validation (8 checks)
    12. **Patent Numbers** - Patent identifiers (e.g., US1234567)
    13. **Retail Labels** - Store/franchise/retail categories
    14. **Email Addresses** - Email addresses in Before column (e.g., user@example.com)
    15. **Phone Numbers** - Phone numbers in Before column (e.g., 555-123-4567)
    16. **Addresses** - Address detection using city/state indicators
    17. **Company Names** - Organization names detected using NLP
    18. **Executive Names** - Executive titles and honorifics (Mr./Mrs.)
    19. **First Names Separate** - Ensures first names from full names have separate rows (EXECUTIVES)

    ### 🔄 Cross-Validation (5 checks)
    20. **Name Recycling** - Prevents reusing Before names in After column
    21. **After in Before** - Ensures After values don't appear in Before column
    22. **Blank Before Check** - Flags rows with blank Before but populated After values
    23. **Deletion Entries** - Confirms some terms are marked for deletion (blank After)
    24. **Format Consistency** - Validates digit patterns are preserved in anonymized IDs
    """
    
    st.markdown(checks_info)