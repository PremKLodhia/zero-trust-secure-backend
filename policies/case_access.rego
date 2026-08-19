package case_access

import future.keywords.in

default allow = false

# Rule 1: Administrators have full access
allow {
    input.user.role == "admin"
}

# Rule 2: Auditors have read-only access
allow {
    input.user.role == "auditor"
    input.action in ["READ_CASE", "LIST_CASES"]
}

# Rule 3: Analysts can create cases and list cases
allow {
    input.user.role == "analyst"
    input.action in ["CREATE_CASE", "LIST_CASES"]
}

# Rule 4: Analysts can read non-RED cases, or RED cases assigned directly to them
allow {
    input.user.role == "analyst"
    input.action == "READ_CASE"
    input.case.classification in ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"]
}

allow {
    input.user.role == "analyst"
    input.action == "READ_CASE"
    input.case.classification == "TLP:RED"
    input.case.assigned_analyst_id == input.user.id
}

# Rule 5: ABAC - Analysts can only update cases that are explicitly assigned to them
allow {
    input.user.role == "analyst"
    input.action == "UPDATE_CASE"
    input.case.assigned_analyst_id == input.user.id
}
