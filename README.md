# CyberArk SIA Onboarding & Access Policy Helper

This repository contains a Python helper that streamlines common CyberArk SIA tasks:

* **Workspace onboarding** – authenticates with MFA, verifies Privilege Cloud strong accounts, and onboards databases, secrets, and VM target sets from a CSV template.
* **Access policy provisioning** – creates recurring DB and VM access policies using a separate CSV template.

The script relies on the official [CyberArk ark-sdk-python](https://github.com/cyberark/ark-sdk-python) package (included here) to communicate with Identity Security Platform (ISP), SIA services, and Privilege Cloud.

---

## Features

* Interactive login with MFA selection (pf/sms/email/otp/oath/auto) and identity hints.
* Optional reuse of existing secrets, databases, and target sets.
* Privilege Cloud validation for `PCloudAccount` VM secrets using the Accounts API; invalid entries are logged and skipped so the run continues.
* Access policy creation for both DB and VM services, including scheduling and connection rules.
* Timestamped execution logs (default: `logs/sia_helper_<timestamp>.log`).
* Input validation with clear error reporting (row/column) based on CSVs.

---

## Prerequisites

1. **Python 3.9+**
2. **CyberArk credentials** with rights to:
   * Authenticate to ISP (Identity user/service user).
   * Manage SIA resources (Databases, VM target sets, Secrets, Access Policies).
   * Query Privilege Cloud accounts (`PCloudAccount` validation).
3. **Dependencies**
   * Install the SDK and helper requirements (from repository root):
     ```bash
     pip install -e ./ark-sdk-python-main
     # (Optional) ensure other runtime deps are installed (requests, pydantic etc.)
     ```

---

## Repository Layout

```
├── ark-sdk-python-main/         # CyberArk offical SDK (embedded for convenience)
├── sia_onboarding.py            # Main helper script
├── sia_onboarding_template.csv  # Sample workspace onboarding template
├── sia_access_policy_template.csv # Sample access policy template
├── sia_onboarding_field_mapping.md # Column-by-column mapping guide
└── README.md                    # This file
```

---

## Usage

1. **Prepare CSV templates**
   * `sia_onboarding_template.csv` – describes DB/VM secrets, databases, and VM target sets.
   * `sia_access_policy_template.csv` – describes DB/VM access policies (providers, time windows, rules).
   * Refer to `sia_onboarding_field_mapping.md` for detailed field descriptions and mapping guidance.

2. **Run the helper**
   ```bash
   python3 sia_onboarding.py
   ```

   * The script prompts you to choose **workspace onboarding** or **access policy provisioning**.
   * Provide ISP credentials, select MFA method, and specify template paths if different from defaults.
   * Logs are written to `logs/` with a timestamped filename.

3. **Review output**
   * Console output summarizes created resources and skipped items (e.g., missing Privilege Cloud accounts).
   * Check the log file for full details and troubleshooting data.

---

## Templates Overview

### Workspace Template (`sia_onboarding_template.csv`)

Supported record types:

| record_type     | Purpose                                      |
|-----------------|----------------------------------------------|
| `db_secret`     | Define DB strong accounts (PAM, IAM, etc.).  |
| `vm_secret`     | Define VM provisioning secrets (ProvisionerUser or PCloudAccount). |
| `database`      | Describe SIA DB workspaces to onboard.       |
| `vm_target_set` | Describe VM target sets to onboard.          |

See the sample template and `sia_onboarding_field_mapping.md` for required fields.

### Access Policy Template (`sia_access_policy_template.csv`)

Supported record types:

| record_type  | Purpose                                      |
|--------------|----------------------------------------------|
| `db_policy`  | Recurring DB access policies (rules + providers). |
| `vm_policy`  | Recurring VM access policies.                |

Each row includes policy metadata, provider filters, and authorization rule details (user data, schedule, connection behavior). JSON columns (`providers_data`, `connect_as`) must contain valid JSON objects compatible with the SDK models.

---

## Logging

The helper creates a new log file on each execution:

```
logs/
└── sia_helper_YYYYMMDD_HHMMSS.log
```

Logs include identity authentication steps, object creation messages, and warnings about skipped items (e.g., missing Privilege Cloud accounts).

---

## Skipped Items & Error Handling

* Privilege Cloud accounts that cannot be validated (safe/account not found) are logged and skipped.
* VM target sets referencing skipped secrets are also skipped automatically.
* CSV parsing issues (e.g., invalid day-of-week, missing JSON fields) report the offending row/column.

Review the log output to identify which entries were skipped and why; correct the template and rerun if needed.

---

## Extending the Script

The helper is designed to be modular:

* Add new CSV columns by extending the relevant dataclasses (`DbSecretConfig`, `DatabaseConfig`, `DbPolicyConfig`, etc.) and parsing helpers.
* Integrate additional SIA services by importing the corresponding SDK models/services.
* Enhance logging or authentication logic (e.g., service user token reuse) to match your environment.

---

## Troubleshooting

| Issue | Possible Cause / Fix |
|-------|----------------------|
| `Authentication failed` | Verify ISP username/password/MFA selection; ensure your user has SIA permissions. |
| `Privilege Cloud account ... was not found` | Safe/account name mismatch or insufficient Privilege Cloud permissions. The row is skipped; correct the template or credentials. |
| `JSON payload must represent an object` | JSON field (e.g., `providers_data`) is malformed. Use valid JSON (double quotes, key/value pairs). |
| `policy should contain at least one provider` | For policies, ensure `providers_data` selects at least one provider resource. |

Enable verbose logging or inspect the timestamped log for detailed stack traces.

---

## License

This project bundles CyberArk’s ark-sdk-python; refer to its [LICENSE](ark-sdk-python-main/LICENSE.txt) for terms. Additional helper code is provided under the same license conditions.

---

## Contributions

Contributions and feedback are welcome. Please open an issue or submit a PR with details about the enhancement or bug fix.

---

## Disclaimer

This helper is intended as a guided automation aid. Always review changes before applying them in production, and ensure the CSV templates match your organizational policies and naming standards.
