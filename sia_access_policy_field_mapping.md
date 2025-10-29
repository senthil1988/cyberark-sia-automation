# SIA Access Policy CSV Field Mapping Guide

The access-policy helper reads `sia_access_policy_template.csv` to create recurring database (DB) and virtual machine (VM) access policies in CyberArk SIA. Each row describes one policy. Use this guide to map every column to its corresponding SIA concept and ensure templates are populated correctly.

> **Tip:** Leave optional fields blank if they are not needed. Required fields are noted.

---

## 1. Record Types

| record_type | Purpose | Notes |
|-------------|---------|-------|
| `db_policy` | Defines a recurring **Database Access Policy**. | Requires DB provider data and DB-specific `connect_as` settings. |
| `vm_policy` | Defines a recurring **VM Access Policy**. | Requires VM provider filters and VM-specific `connect_as` settings. |

Each row must include `record_type` to indicate which policy model to build.

---

## 2. Common Policy Columns

These columns are shared by both DB and VM policies:

| Column | Required | Description / Mapping |
|--------|----------|-----------------------|
| `record_type` | ✔ | `db_policy` or `vm_policy`. Determines which policy builder to use. |
| `policy_name` | ✔ | SIA policy display name (e.g., “Finance Night Access”). |
| `description` | – | Optional human-readable description of the policy. |
| `status` | – | Initial policy state. Accepted values: `Enabled`, `Disabled`, `Draft`, or `Expired`. Defaults to `Enabled` if blank. |
| `start_date` | – | When the policy becomes active (ISO 8601 date/time). Leave blank to activate immediately. |
| `end_date` | – | When the policy expires. Leave blank for no end date. |
| `providers_data` | ✔ | JSON object describing the resources the policy targets. Structure differs for DB vs VM policies (details below). |
| `rule_name` | ✔ | Name of the authorization rule included in the policy. |
| `user_roles`, `user_groups`, `user_users` | – | Comma/semicolon separated lists of Identity roles/groups/users allowed by the rule. Maps to `ArkSIAUserData`. Leave empty if unused. |
| `full_days` | – | `true`/`false`. If `true`, the rule applies 24 hours per selected day. |
| `days_of_week` | – | List of day abbreviations (`Mon`, `Tue`, etc.). If omitted, defaults to all days. |
| `hours_from`, `hours_to` | – | Time window for access (e.g., `22:00` / `02:00`). Required if `full_days` is not `true`. |
| `time_zone` | – | Time zone (IANA format, e.g., `America/Los_Angeles`). |
| `grant_access_hours` | – | Number of hours to grant per session (1–24). Defaults to SDK’s standard (2 hours). |
| `idle_time_minutes` | – | Allowed idle time (minutes) before session termination. |
| `connect_as` | ✔ | JSON object describing how connections are provisioned (differs for DB vs VM policies). |
| `comment` | – | Free-form note for administrators; ignored by the script. |

---

## 3. DB Policy-Specific Fields

Used when `record_type = db_policy`.

| Column | Required | Description |
|--------|----------|-------------|
| `providers_tags` | – | Comma/semicolon list of policy tags (e.g., `maintenance,postgres`). Stored as `providers_tags` in `ArkSIADBAddPolicy`. |
| `providers_data` | ✔ | JSON filtered by database engine. Example: `{"postgres":{"resources":["finance-rds.cluster.internal"]}}`. Must match `ArkSIADBProvidersData`; valid keys include `postgres`, `mysql`, `mssql`, `oracle`, `mongo`, `db2`. |
| `connect_as` | ✔ | JSON describing DB-specific connection settings (mapped to `ArkSIADBConnectAs`). Example: `{"db_auth":[{"roles":["rds_superuser"],"applied_to":[{"name":"finance-rds.cluster.internal","type":"resource"}]}]}`. Supports keys such as `db_auth`, `ldap_auth`, `oracle_auth`, `mongo_auth`, `sqlserver_auth`, `rds_iam_user_auth`. |

**Example (from template):**
```csv
record_type,policy_name,...,providers_data,...,connect_as,...
db_policy,Finance Night Access,...,"{""postgres"":{""resources"":[""finance-rds.cluster.internal""]}}",...,"{""db_auth"":[{""roles"":[""rds_superuser""],""applied_to"":[{""name"":""finance-rds.cluster.internal"",""type"":""resource""}]}]}"
```

---

## 4. VM Policy-Specific Fields

Used when `record_type = vm_policy`.

| Column | Required | Description |
|--------|----------|-------------|
| `providers_data` | ✔ | JSON describing VM filtering per workspace type. Keys correspond to `ArkWorkspaceType`: `aws`, `azure`, `gcp`, `onprem`. Each value must match the respective provider model (e.g., tags, regions, fqdn rules). Example: `{"onprem":{"fqdn_rules":[{"operator":"WILDCARD","computername_pattern":"*.corp.local","domain":"corp.local"}]}}`. |
| `connect_as` | ✔ | JSON describing connection profiles per workspace and protocol. Example: `{"onprem":{"RDP":{"local_ephemeral_user":{"assign_groups":["Workstation Operators"]}}}}`. Keys under each workspace (e.g., `RDP`, `SSH`) must match `ArkProtocolType`. |

**Example (from template):**
```csv
record_type,policy_name,...,providers_data,...,connect_as,...
vm_policy,Corp Workstations After Hours,...,"{""onprem"":{""fqdn_rules"":[{""operator"":""WILDCARD"",""computername_pattern"":""*.corp.local"",""domain"":""corp.local""}]}}",...,"{""onprem"":{""RDP"":{""local_ephemeral_user"":{""assign_groups"":[""Workstation Operators""]}}}}"
```

---

## 5. JSON Column Guidance

* **Formatting:** Use valid JSON objects with double quotes (`"`). Escape double quotes within CSV as `""`.
* **providers_data Validation:** The helper validates JSON via Pydantic; missing or empty objects raise an error.
* **connect_as Validation:** Must comply with the expected SIA schema:
  * **DB policies:** Use the keys defined in `ArkSIADBConnectAs` (e.g., `db_auth`, `ldap_auth`, `oracle_auth`, `mongo_auth`, `sqlserver_auth`, `rds_iam_user_auth`).
  * **VM policies:** Use workspace keys (e.g., `onprem`, `aws`) and under each, protocol keys (e.g., `RDP`, `SSH`). Values can be simple strings (target account names) or nested objects (e.g., ephemeral user settings).

If validation fails, the script reports the row number and error details; correct the JSON structure and rerun.

---

## 6. Scheduling Fields

| Field | Example | Notes |
|-------|---------|-------|
| `full_days` | `true` | If `true`, ignore hour window and grant access for entire selected days. |
| `days_of_week` | `Mon,Tue,Wed,Thu,Fri` | Accepts `Mon`…`Sun` (case-insensitive). |
| `hours_from` / `hours_to` | `22:00` / `02:00` | HH:MM (24-hour). Required when `full_days` is not `true`. Hours can wrap past midnight (e.g., 22:00 → 02:00). |
| `time_zone` | `America/Los_Angeles` | Use standard IANA names (e.g., `UTC`, `Europe/London`). |
| `grant_access_hours` | `4` | Duration (hours) for each granted session (1–24). |
| `idle_time_minutes` | `15` | Maximum idle time before session ends (minutes). |

All scheduling fields map to `ArkSIABaseConnectionInformation` in the SDK.

---

## 7. User Scope Fields

| Field | Maps to | Description |
|-------|---------|-------------|
| `user_roles` | `ArkSIAUserData.roles` | Roles that can invoke the policy (matches Identity roles). |
| `user_groups` | `ArkSIAUserData.groups` | Groups allowed to use the policy. |
| `user_users` | `ArkSIAUserData.users` | Specific users allowed. |

Values can be `name@domain` or other identifiers recognized by Identity. Leave empty to omit the dimension.

---

## 8. Example Rows

### DB Policy
*Targets a PostgreSQL resource, grants access 10pm–2am Pacific Monday–Friday, applies `rds_superuser` via DB auth.*
```
record_type,policy_name,status,providers_data,rule_name,user_roles,full_days,days_of_week,hours_from,hours_to,time_zone,grant_access_hours,idle_time_minutes,connect_as
db_policy,Finance Night Access,Enabled,"{""postgres"":{""resources"":[""finance-rds.cluster.internal""]}}","Finance maintenance",FinanceOps,false,"Mon,Tue,Wed,Thu,Fri","22:00","02:00","America/Los_Angeles",4,15,"{""db_auth"":[{""roles"":[""rds_superuser""],""applied_to"":[{""name"":""finance-rds.cluster.internal"",""type"":""resource""}]}]}"
```

### VM Policy
*Targets on-prem FQDNs in corp.local, allows RDP access with local ephemeral accounts after hours.*
```
record_type,policy_name,status,providers_data,rule_name,user_roles,full_days,days_of_week,hours_from,hours_to,time_zone,grant_access_hours,idle_time_minutes,connect_as
vm_policy,Corp Workstations After Hours,Enabled,"{""onprem"":{""fqdn_rules"":[{""operator"":""WILDCARD"",""computername_pattern"":""*.corp.local"",""domain"":""corp.local""}]}}","Support engineers",SupportEngineers,false,"Mon,Tue,Wed,Thu","18:00","23:00","America/New_York",3,10,"{""onprem"":{""RDP"":{""local_ephemeral_user"":{""assign_groups"":[""Workstation Operators""]}}}}"
```

---

## 9. Validation & Troubleshooting

* The script validates each row. Errors report the row number and column (e.g., invalid day, missing JSON).
* Remember to double-quote JSON in the CSV and escape inner quotes.
* If a policy fails validation, the run stops for that row; fix the template and rerun.
* Examine the log file (`logs/sia_helper_<timestamp>.log`) for full details.

---

By following this mapping, administrators can confidently convert policy requirements into CSV rows understood by the helper. Ensure Privilege Cloud accounts, SIA resources, and Identity roles referenced in the template exist before executing the script.***
