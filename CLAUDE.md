# Anonymization Tracker QC Tool - Project Guide

## Project Overview

**Purpose**: Streamlit-based Quality Control tool for validating anonymization trackers used in document redaction workflows.

**Problem Solved**: Ensures sensitive identifiers (company names, executive names, security IDs, etc.) are properly anonymized before document release by detecting data leakage, format inconsistencies, and anonymization gaps.

**Tech Stack**:
- Python 3.x
- Streamlit (web UI framework)
- Pandas (data processing)
- Regex (pattern matching)

---

## Architecture & Key Patterns

### 1. Two-Stage Validation Pattern (Detect → Context → Enforce)

**Most checks follow this pattern**:

```python
# Stage 1: Detection
has_identifier = False
detected = []
for row in df:
    if detect_pattern(row['Before']) and context_applies(row['Category']):
        has_identifier = True
        detected.append(row)

if not has_identifier:
    return {'severity': 'warning', 'message': 'No X detected'}

# Stage 2: Enforcement
issues = []
for row in detected:
    if validate_after(row['After']):
        issues.append(row)

return {'severity': 'error' if issues else 'pass', 'rows': issues}
```

**Why**: Prevents false positives (only validates identifiers that actually exist) and provides context-aware results (warnings vs errors).

### 2. Context Gating System

**Functions** (streamlit_app.py:8-99):
- `security_id_context_applies()` - For CUSIP, ISIN, CIK, etc. (financial context)
- `ticker_context_applies()` - For stock tickers (more restrictive)
- `ein_context_applies()` - For EINs with positive confirmation rules
- `sec_file_context_applies()` - For SEC file numbers
- `security_id_comment_allows_detection()` - Unified comment filter

**Purpose**: Only flag identifiers when they appear in relevant contexts (e.g., don't flag 9-digit numbers as CUSIPs in address fields).

### 3. Check Return Format (Standard)

```python
{
    'passed': bool,           # True if check passed
    'message': str,           # User-facing message
    'severity': str,          # 'error', 'warning', or 'pass'
    'rows': list[dict],       # Rows with issues (or validated items)
    'check_name': str         # Added by run_all_checks()
}
```

---

## Code Structure

### Main File: `streamlit_app.py` (~1,700 lines)

**Sections**:
1. **Lines 1-244**: Detection helpers & context gates
2. **Lines 245-1173**: QC check functions (20 total)
3. **Lines 1174-1367**: Additional validation functions
4. **Lines 1368-1407**: `run_all_checks()` orchestrator
5. **Lines 1408-1688**: Streamlit UI & results display

### Key Functions

#### Check Functions (Return standard format)
```python
check_sec_links(df)                    # Lines 273-329
check_after_link_leakage(df)           # Lines 331-373
check_cik_ids(df)                      # Lines 479-541
check_ein_ids(df)                      # Lines 741-790
check_cusip_ids(df)                    # Lines 608-672
check_isin_ids(df)                     # Lines 543-606
check_ticker_symbols(df)               # Lines 952-1032
check_patent_ids(df)                   # Lines 397-472
check_executive_honorifics(df)         # Lines 1174-1224
check_first_names_separate_rows(df)    # Lines 1226-1305
check_name_recycling(df)               # Lines 1307-1365
check_after_in_before(df)              # Lines 1267-1290
check_blank_before_populated_after(df) # Lines 1292-1316
check_deletion_entries(df)             # Lines 375-395
```

#### Detection Helpers (Return cleaned/normalized identifier or None)
```python
detect_isin(val)       # Lines 186-190
detect_cusip(val)      # Lines 193-201
detect_sedol(val)      # Lines 204-208
detect_figi(val)       # Lines 211-215
detect_lei(val)        # Lines 218-222
detect_cik(val)        # Lines 232-236
detect_ticker(val)     # Lines 239-243
```

---

## Critical Implementation Patterns

### ✅ DO: Follow These Patterns

1. **Always normalize columns to string type** (Lines 268-271):
   ```python
   for col in ["Before", "After", "Category", "File", "Comment"]:
       if col in df.columns:
           df[col] = df[col].astype(str)
   ```

2. **Use Excel row numbers** (idx + 2):
   ```python
   'excel_row': idx + 2  # +2 because: 0-indexed + header row
   ```

3. **Handle NaN/empty values properly**:
   ```python
   before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
   if before_val.lower() in ['', 'nan']:  # Check both empty and 'nan' string
       # handle empty case
   ```

4. **Use category-specific tags in display**:
   ```python
   check_categories = {
       "Check Name": "Category Name",  # Must match check names exactly
       ...
   }
   ```

5. **Preserve format in anonymized values**:
   - EIN: Keep hyphen format (XX-XXXXXXX vs XXXXXXXXX)
   - CUSIP/ISIN: Keep length
   - Patent numbers: Keep digit pattern length

### ❌ DON'T: Avoid These Mistakes

1. **Don't create nested expanders** (Streamlit limitation):
   ```python
   # BAD - causes StreamlitAPIException
   with st.expander("Outer"):
       with st.expander("Inner"):  # ❌ NOT ALLOWED
           pass

   # GOOD - use use_expander parameter
   display_check_result(result, use_expander=False)  # When already in expander
   ```

2. **Don't flag every pattern match** - Use context gates:
   ```python
   # BAD
   if looks_like_cusip(val):
       flag_as_issue()

   # GOOD
   if looks_like_cusip(val) and security_id_context_applies(category):
       flag_as_issue()
   ```

3. **Don't assume columns exist**:
   ```python
   # BAD
   comment = row['Comment']

   # GOOD
   comment = str(row.get('Comment', '')) if 'Comment' in df.columns else ''
   ```

4. **Don't modify check order casually** - Order matters for user experience and column reordering logic.

---

## Recent Changes & Decisions

### Session History (Current Branch: claude/check-repo-access-H0GC7)

**Commit 1** (bbc53f0): Added 2 new QC checks
- Blank Before + Populated After check (ERROR severity)
- First Names in Separate Rows check (ERROR severity, EXECUTIVES only)

**Commit 2** (2204bcd): Reorganized results by severity
- Changed from category-based to severity-based grouping
- Display order: Errors → Warnings → Passes (collapsible)
- Added category tags to each check

**Commit 3** (1ebf657): Fixed nested expander error
- Added `use_expander` parameter to `display_check_result()`
- Passes display directly without nested expanders

**Commit 4** (d6c95cd): UX improvements
- Reordered "First Names Separate" columns (after before missing_first_name)
- Upgraded "Executive Names" from warning to error severity

### Key Decisions

1. **Why two-stage pattern?**
   - Stage 1 (detection) prevents false alarms
   - Stage 2 (enforcement) only runs when identifiers exist
   - Warnings indicate "not found" (may be OK), errors indicate "found problems"

2. **Why context gating?**
   - Reduces false positives (e.g., 9-digit phone numbers aren't CUSIPs)
   - Makes tool usable in real-world scenarios with messy data

3. **Why Executive Names is ERROR not WARNING?**
   - Missing honorific entries are critical for complete anonymization
   - Not optional - affects document completeness

4. **Why passes are collapsible?**
   - Focuses attention on action items (errors/warnings)
   - Reduces cognitive load
   - Still accessible when needed

---

## Testing Guidelines

### Local Testing
```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run streamlit_app.py
```

### Test Cases to Consider

1. **Empty/NaN handling**: Upload tracker with blank values
2. **Format preservation**: Check EIN hyphen format, CUSIP length
3. **Context gating**: Put CUSIP in narrative field (should not flag)
4. **Executive names**: Full names without first-name-only rows
5. **Cross-contamination**: After values appearing in Before column
6. **Nested expanders**: Passed checks with row details (should not error)

### Common Test Data Patterns

```csv
Category,Before,After,Comment
COMPANY INFO,037833100,123456789,CUSIP
EXECUTIVES,John Smith,Robert Abbey,
EXECUTIVES,John,Robert,First name only
```

---

## Adding New Checks

### Checklist

1. **Write check function** following two-stage pattern
2. **Return standard format** (passed, message, severity, rows)
3. **Add to `run_all_checks()`** in appropriate category section
4. **Add to `check_categories` dict** for display tag
5. **Update documentation section** (lines 1547-1577)
6. **Test with real data**
7. **Commit with clear message**

### Example Template

```python
def check_new_identifier(df: pd.DataFrame) -> Dict:
    """Check for [identifier type] proper anonymization"""

    # Stage 1: Detection
    has_identifier = False
    detected = []
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        category = str(row['Category']) if pd.notna(row['Category']) else ''

        if detect_pattern(before_val) and context_applies(category):
            has_identifier = True
            detected.append({
                'excel_row': idx + 2,
                'category': category,
                'before': row['Before'],
                'after': row['After']
            })

    if not has_identifier:
        return {
            'passed': False,
            'message': 'No [identifier type] detected',
            'severity': 'warning',
            'rows': []
        }

    # Stage 2: Enforcement
    issues = []
    for idx, row in df.iterrows():
        before_val = str(row['Before']).strip() if pd.notna(row['Before']) else ''
        after_val = str(row['After']).strip() if pd.notna(row['After']) else ''

        if detect_pattern(before_val) and after_val:
            problem = validate_anonymization(before_val, after_val)
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
        'message': f'All [identifier type] validated' if len(issues) == 0 else f'❌ Found {len(issues)} issue(s)',
        'severity': 'pass' if len(issues) == 0 else 'error',
        'rows': detected if len(issues) == 0 else issues
    }
```

---

## Common Issues & Solutions

### Issue: "Expanders may not be nested"
**Solution**: Pass `use_expander=False` when calling `display_check_result()` inside an expander

### Issue: Check not appearing in UI
**Solution**: Ensure check name is in both `run_all_checks()` AND `check_categories` dict

### Issue: Column order wrong in results
**Solution**: Add check-specific column reordering in `display_check_result()` (lines 1629-1637)

### Issue: Too many false positives
**Solution**: Tighten context gates or add comment filtering

### Issue: NaN/empty values causing errors
**Solution**: Always use `pd.notna()` checks and handle 'nan' string representation

---

## Performance Considerations

- **DataFrame operations**: Use vectorized pandas operations when possible
- **Regex compilation**: Pre-compile regex patterns at module level (lines 56-125)
- **Check independence**: All checks are independent and could be parallelized (future optimization)
- **Large files**: Currently processes all rows in memory (consider chunking for >100k rows)

---

## Future Enhancement Ideas

1. **Export functionality**: Generate PDF/Excel reports
2. **Bulk fixing**: Suggest anonymized replacements
3. **Custom rules**: User-defined identifier patterns
4. **API endpoint**: For automated QC pipelines
5. **Historical tracking**: Compare multiple tracker versions
6. **Additional patterns**: Email addresses, phone numbers, IP addresses
7. **Performance**: Parallel check execution for large files

---

## Questions? Common Tasks

**Q: How do I change a check's severity?**
A: Modify the return statement's `'severity'` value (line in check function)

**Q: How do I reorder columns in check results?**
A: Add check-specific reordering in `display_check_result()` (around line 1629)

**Q: How do I add a new category?**
A: Add to `check_categories` dict AND update documentation section

**Q: How do I test without uploading a file?**
A: Create a small CSV/Excel with test cases and upload via UI

---

## Contact & Maintenance

**Repository**: https://github.com/shahkhanseekinvest/anonymization-tracker-qc-tool

**Branch Strategy**:
- `main` - Production-ready code
- `claude/*` - Feature branches created during Claude Code sessions

**Commit Message Format**: Descriptive with "why" and impact explained

---

*Last updated: January 2026*
*Tool version: 20 checks (18 original + 2 new)*
