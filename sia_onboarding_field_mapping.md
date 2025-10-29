# SIA Onboarding CSV Field Mapping Guide

The onboarding helper reads a single CSV file (`sia_onboarding_template.csv`) containing multiple record types. Each row describes either a secret, a database workspace, or a VM target set. Use this guide to understand what each column represents and how it maps to SIA concepts.

> **Tip:** Leave optional fields empty if they do not apply. Required fields are marked.

---

## 1. Record Types

| record_type value | Purpose |
| --- | --- |
| `db_secret` | Defines a database strong account or credential set (CyberArk PAM, IAM user, Mongo Atlas keys, etc.). |
| `vm_secret` | Defines a VM provisioning secret (Privilege Cloud account or local provisioner). |
| `database` | Describes a database workspace to onboard in SIA. References DB secrets. |
| `vm_target_set` | Describes a VM target set workspace. References VM secrets. |

---

## 2. Common Columns

These columns appear on several record types and have consistent meaning:

| Column | Applies to | Meaning |
| --- | --- | --- |
| `record_type` *(required)* | All | Identifies which record type the row describes. |
| `name` *(required for database & target set)* | database, vm_target_set | Display name of the workspace or target set. |
| `alias` *(required for secrets)* | db_secret, vm_secret | Local identifier used by other rows to reference this secret (e.g., `db_admin_secret`). Must be unique within the record type. |
| `comment` | All | Free-form notes to document why or how the entry is used. |
| `tags` | db_secret, database | Semi-colon separated `key=value` pairs (e.g., `env=prod;team=finance`). |
| `enable_certificate_validation` | database, vm_target_set | `true/false` or `yes/no` to control TLS certificate validation. |

---

## 3. Database Secret Fields (`record_type = db_secret`)

Think of a DB secret as the strong account SIA will use for database onboarding or rotation.

| Column | Description |
| --- | --- |
| `secret_name` *(required)* | Friendly name of the strong account inside SIA (e.g., **Finance-Prod-Admin**). |
| `secret_type` *(required)* | Credential type. Valid values: `cyberark_pam`, `username_password`, `iam_user`, `atlas_access_keys`. |
| `description`, `purpose` | Free-text metadata. |
| `store_type` | Override for the target vault when needed. Usually omitted. |
| `username`, `password` | Required for `username_password`. Provide the login and static password. |
| `pam_safe`, `pam_account_name` | Required for `cyberark_pam`. Identify the CyberArk Privileged Access Manager safe and account name. |
| `iam_account`, `iam_username`, `iam_access_key_id`, `iam_secret_access_key` | Required for `iam_user` secrets. Provide AWS IAM details. |
| `atlas_public_key`, `atlas_private_key` | Required for `atlas_access_keys` (Mongo Atlas). |

---

## 4. VM Secret Fields (`record_type = vm_secret`)

VM secrets represent strong accounts for VM provisioning or Privilege Cloud integration.

| Column | Description |
| --- | --- |
| `secret_name` | Friendly label shown in SIA. |
| `secret_type` *(required)* | Either `ProvisionerUser` (local credentials) or `PCloudAccount` (Privilege Cloud strong account). |
| `provisioner_username`, `provisioner_password` | Required when `secret_type = ProvisionerUser`. |
| `pcloud_account_safe`, `pcloud_account_name` | Required when `secret_type = PCloudAccount`. Equivalent to **safe** and **strong account name** in Privilege Cloud. |
| `secret_details` | JSON object for additional metadata (e.g., `{"owner":"Workspace Platform"}`). |
| `is_disabled` | `true/false` to disable the secret on creation. |

---

## 5. Database Workspace Fields (`record_type = database`)

Each row represents one database workspace to onboard in SIA.

| Column | Description |
| --- | --- |
| `name` *(required)* | Workspace name (often the DB hostname). |
| `provider_engine` *(required)* | The SIA engine identifier (e.g., `postgres-aws-rds`, `mongo-atlas-managed`). See `ArkSIADBDatabaseEngineType`. |
| `platform` | Hosting platform (`aws`, `azure`, `onprem`, `atlas`, etc.). Defaults to `ON-PREMISE`. |
| `network_name` | Logical network label. Defaults to `ON-PREMISE`. |
| `auth_database` | Database used for authentication (e.g., `postgres`, `admin`). |
| `read_write_endpoint`, `read_only_endpoint` | Connection endpoints. Optional. |
| `region` | Region hint for cloud databases. |
| `secret_alias` | Alias of a `db_secret` row. Resolves to the strong account (`secret_id`) SIA should attach. |
| `secret_id` | Directly provide an existing secret ID instead of `secret_alias`. |
| `domain` | Associated domain (for AD-integrated services). |
| `domain_controller_*` fields | Optional domain controller configuration and certificate settings. |
| `services` | Semi-colon list of service definitions `name:port:secretAlias[:secretId]`. Use to override port or attach per-service secrets. |
| `configured_auth_method_type` | Overrides the authentication method (e.g., `local_ephemeral_user`, `ad_ephemeral_user`). |
| `account` | Account ID (used by some cloud engines; optional). |

---

## 6. VM Target Set Fields (`record_type = vm_target_set`)

Target sets group VM resources by domain, suffix, or specific targets.

| Column | Description |
| --- | --- |
| `name` *(required)* | Name of the target set (often the domain). |
| `target_set_type` | One of `Domain`, `Suffix`, or `Target`. Defaults to `Domain`. |
| `description` | Free-text summary. |
| `provision_format` | Format string for generated accounts, e.g., `{user}@corp.local`. |
| `enable_certificate_validation` | Toggle certificate validation on connector communication. |
| `secret_type` | Secret type to enforce (`PCloudAccount`, `ProvisionerUser`, etc.). |
| `secret_alias` | Alias pointing to a `vm_secret` entry (strong account). |
| `secret_id` | Direct reference to an existing VM secret ID instead of `secret_alias`. |

---

## 7. Working with Aliases

- Define each secret once with an `alias`.
- Reference the alias from database or target set rows via `secret_alias` (or inside `services`).
- The helper resolves aliases to actual secret IDs during execution.

If an alias is used but not defined, the script stops with a validation error. This ensures strong accounts (e.g., `secret_name`) are always linked to a real secret row.

---

## 8. Example Mapping

| Use Case | Fields to Fill | Example Values |
| --- | --- | --- |
| PAM-backed strong account | `record_type=db_secret`, `alias=db_admin_secret`, `secret_name=Finance-Prod-Admin`, `secret_type=cyberark_pam`, `pam_safe=Finance-Prod`, `pam_account_name=FINANCE-RDS-ADMIN` | Creates a PAM-linked strong account for the finance database. |
| Database referencing the strong account | `record_type=database`, `name=finance-rds.cluster.internal`, `provider_engine=postgres-aws-rds`, `secret_alias=db_admin_secret`, `services=primary:5432:db_admin_secret` | Onboards the RDS workspace and attaches the PAM strong account. |
| Target set with Privilege Cloud account | `record_type=vm_target_set`, `name=corp.local`, `secret_alias=workstations_admin_secret`, `secret_type=PCloudAccount`, `provision_format={user}@corp.local` | Creates a VM target set using the Privilege Cloud strong account defined in `vm_secret`. |

---

## 9. Validating the Template

1. Populate the CSV with your tenant-specific data.
2. Run `python3 sia_onboarding.py` and follow the prompts.
3. The helper validates aliases and required fields before calling SIA APIs.

For questions about engine names or secret types, consult the CyberArk SIA SDK documentation (`ArkSIADBDatabaseEngineType`, `ArkSIAVMSecretType`, etc.).

---

By following this mapping, end users can confidently match each column in the CSV to the corresponding SIA concept—especially strong accounts such as `secret_name`—while onboarding databases and VM workspaces.
