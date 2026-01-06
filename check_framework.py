"""
Hierarchical Detection Framework for Anonymization Tracker QC Checks

This module implements the unified 3-step detection pattern:
    STEP 1: Comment Authority (Highest Priority)
    STEP 2: Pattern Match (Necessary Condition)
    STEP 3: Context Confirmation (Sufficient Condition)

All checks follow this pattern for consistent, predictable behavior.
"""

from typing import Dict, Optional, Callable, List
import pandas as pd
from check_keywords import get_check_keywords

# ============================================================================
# STEP 1: Comment Authority Check
# ============================================================================

def check_comment_authority(comment: str, check_name: str) -> str:
    """
    Check if comment definitively proves/disproves identifier type.

    This is the HIGHEST PRIORITY check. If comment explicitly states what
    the identifier is, we trust it over pattern matching or category context.

    Args:
        comment: The comment field value from the tracker row
        check_name: Name of the check (e.g., "CIK", "EMAIL")

    Returns:
        "PROVEN" - Comment explicitly confirms this identifier type
        "DISPROVEN" - Comment explicitly mentions a different identifier type
        "NEUTRAL" - No definitive evidence either way
    """
    # Handle empty/NaN comments
    if not comment or pd.isna(comment):
        return "NEUTRAL"

    comment_u = str(comment).strip().upper()

    # Handle pandas 'nan' string representation
    if not comment_u or comment_u == 'NAN':
        return "NEUTRAL"

    keywords = get_check_keywords(check_name)

    # ═══════════════════════════════════════════════════════════════════
    # RULE 1: POSITIVE CONFIRMATION (Comment explicitly confirms this ID)
    # ═══════════════════════════════════════════════════════════════════
    for proven_kw in keywords["proven"]:
        if proven_kw in comment_u:
            return "PROVEN"

    # ═══════════════════════════════════════════════════════════════════
    # RULE 2: NEGATIVE CONFIRMATION (Comment mentions a DIFFERENT ID type)
    # ═══════════════════════════════════════════════════════════════════
    for disproven_kw in keywords["disproven"]:
        if disproven_kw in comment_u:
            return "DISPROVEN"

    # ═══════════════════════════════════════════════════════════════════
    # RULE 3: NEUTRAL (No definitive evidence)
    # ═══════════════════════════════════════════════════════════════════
    return "NEUTRAL"

# ============================================================================
# STEP 3: Context Confirmation Check
# ============================================================================

def check_context_confirmation(category: str, comment: str, check_name: str) -> bool:
    """
    Check if category/comment combination supports identifier detection.

    Uses OPTION 3 (Combined String approach):
    - Combines category and comment into single context string
    - Checks if ANY context keyword appears ANYWHERE in combined string
    - Simple, flexible, and matches existing codebase patterns

    Args:
        category: The category field value from the tracker row
        comment: The comment field value from the tracker row
        check_name: Name of the check (e.g., "CIK", "EMAIL")

    Returns:
        True - Context supports this identifier type
        False - Context does not support
    """
    keywords = get_check_keywords(check_name)

    # Combine category and comment for context analysis
    # This naturally handles "category OR comment" logic
    context = f"{category} {comment}".upper()

    # Check if ANY context keyword appears in the combined string
    return any(kw in context for kw in keywords["context"])

# ============================================================================
# UNIFIED DETECTION FRAMEWORK
# ============================================================================

def detect_with_hierarchy(
    df: pd.DataFrame,
    check_name: str,
    pattern_detector: Callable[[str], Optional[str]],
    use_context: bool = True
) -> List[Dict]:
    """
    Unified hierarchical detection for all checks.

    This implements the 3-step detection pattern:
        STEP 1: Comment Authority (overrides everything)
        STEP 2: Pattern Match (necessary condition)
        STEP 3: Context Confirmation (sufficient condition, optional)

    Args:
        df: Input DataFrame with Before, After, Category, Comment columns
        check_name: Name of the check (e.g., "CIK", "EMAIL")
        pattern_detector: Function that detects pattern in Before value
                         Returns cleaned/normalized value if match, None otherwise
        use_context: Whether to use context confirmation (False for global checks)
                    Pattern A (context-based): True
                    Pattern B (global): False

    Returns:
        List of detected rows with metadata:
        [
            {
                'excel_row': int,        # Excel row number (idx + 2)
                'category': str,         # Category value
                'before': str,           # Before value
                'after': str,            # After value
                'detection_method': str  # How it was detected
            },
            ...
        ]
    """
    detected = []

    for idx, row in df.iterrows():
        # ═══════════════════════════════════════════════════════════════
        # Extract values from row (normalize to strings)
        # ═══════════════════════════════════════════════════════════════
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''
        comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''

        # ═══════════════════════════════════════════════════════════════
        # STEP 1: Comment Authority (HIGHEST PRIORITY)
        # ═══════════════════════════════════════════════════════════════
        comment_decision = check_comment_authority(comment, check_name)

        if comment_decision == "PROVEN":
            # Comment explicitly confirms this identifier type
            # → Add to detected immediately, skip pattern and context checks
            detected.append({
                'excel_row': idx + 2,  # +2 for Excel row number (0-indexed + header)
                'category': category,
                'before': row['Before'],
                'after': row['After'],
                'detection_method': 'comment_proven'
            })
            continue

        if comment_decision == "DISPROVEN":
            # Comment explicitly says this is a DIFFERENT identifier type
            # → Skip this row entirely
            continue

        # If we're here, comment_decision == "NEUTRAL"
        # → Continue to pattern and context checks

        # ═══════════════════════════════════════════════════════════════
        # STEP 2: Pattern Match (NECESSARY CONDITION)
        # ═══════════════════════════════════════════════════════════════
        if not pattern_detector(before_val):
            # Doesn't match identifier pattern → Skip row
            continue

        # ═══════════════════════════════════════════════════════════════
        # STEP 3: Context Confirmation (SUFFICIENT CONDITION, if required)
        # ═══════════════════════════════════════════════════════════════
        if use_context:
            # Pattern A: Requires context confirmation
            if not check_context_confirmation(category, comment, check_name):
                # Context doesn't support this identifier type → Skip row
                continue

        # ═══════════════════════════════════════════════════════════════
        # All checks passed → DETECTED!
        # ═══════════════════════════════════════════════════════════════
        detected.append({
            'excel_row': idx + 2,
            'category': category,
            'before': row['Before'],
            'after': row['After'],
            'detection_method': 'pattern_and_context' if use_context else 'pattern_only'
        })

    return detected

# ============================================================================
# STAGE 2 HELPERS: Common Validation Functions
# ============================================================================

def validate_not_in_before_column(after_val: str, before_values: set) -> Optional[str]:
    """
    Check if After value appears in Before column (cross-contamination).

    Args:
        after_val: The After value to check
        before_values: Set of all Before values (normalized)

    Returns:
        Error message if problem found, None otherwise
    """
    if after_val.lower() in before_values and after_val:
        return f"After value '{after_val}' is a real identifier from Before column"
    return None

def validate_not_equal(before_val: str, after_val: str, identifier_name: str) -> Optional[str]:
    """
    Check if Before and After are identical (not anonymized).

    Args:
        before_val: Before value
        after_val: After value
        identifier_name: Name for error message (e.g., "CIK", "email")

    Returns:
        Error message if problem found, None otherwise
    """
    if before_val == after_val:
        return f"{identifier_name} not anonymized (Before == After)"
    return None

def validate_length_preserved(before_val: str, after_val: str, identifier_name: str) -> Optional[str]:
    """
    Check if length/format is preserved in anonymization.

    Args:
        before_val: Before value
        after_val: After value
        identifier_name: Name for error message (e.g., "CUSIP", "CIK")

    Returns:
        Error message if problem found, None otherwise
    """
    if len(before_val) != len(after_val):
        return f"{identifier_name} length mismatch: {len(before_val)} → {len(after_val)} characters"
    return None
