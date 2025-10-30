================================================================================
CyberArk SIA DB Onboarding Reference
================================================================================

This guide explains how to populate the onboarding templates used by `sia_onboarding.py`.
All tables use fixed-width columns for readability in any editor.

--------------------------------------------------------------------------------
1. Template Files
--------------------------------------------------------------------------------
| File Name                      | Contents                                                      |
|-------------------------------|---------------------------------------------------------------|
| sia_db_onboarding_template.csv | DB strong-account rows (`db_secret`) and database rows (`database`). |

--------------------------------------------------------------------------------
2. Record Types
--------------------------------------------------------------------------------
| Template | record_type    | Purpose                                                            |
|----------|----------------|--------------------------------------------------------------------|
| DB       | db_secret      | Defines a database strong account (PAM, IAM, Atlas keys, etc.).     |
| DB       | database       | Describes a database workspace to onboard; references DB secrets.   |

--------------------------------------------------------------------------------
3. Common Columns
--------------------------------------------------------------------------------
| Column        | Applies To                       | Notes                                                                  |
|---------------|----------------------------------|------------------------------------------------------------------------|
| record_type * | All rows                         | Identifies the row type; do not change the value provided in samples.  |
| name *        | database          | Display name of the workspace/target set.                              |
| alias         | db_secret             | Friendly ID used by other rows. If omitted the script falls back to `secret_name` (must still be unique). |
| comment       | All rows                         | Free-text notes for admins.                                            |
| tags          | db_secret, database              | Semi-colon separated `key=value` pairs (example: `env=prod;team=finance`). |
| enable_certificate_validation | database | `true/false` or `yes/no`; controls TLS certificate enforcement.        |

(*) required.

--------------------------------------------------------------------------------
4. DB Strong-Account Columns (`record_type = db_secret`)
--------------------------------------------------------------------------------
| Column                | Required | Description / Usage                                               |
|-----------------------|----------|-------------------------------------------------------------------|
| secret_name           | Yes      | Friendly name stored in SIA.                                      |
| secret_type           | Yes      | `cyberark_pam`, `username_password`, `iam_user`, `atlas_access_keys`. |
| description, purpose  | No       | Metadata strings.                                                 |
| store_type            | No       | Override vault store if needed.                                   |
| username, password    | Cond.    | Required when `secret_type = username_password`.                  |
| pam_safe, pam_account_name | Cond. | Required when `secret_type = cyberark_pam`.                        |
| iam_account, iam_username, iam_access_key_id, iam_secret_access_key | Cond. | Required for `secret_type = iam_user`.                          |
| atlas_public_key, atlas_private_key | Cond. | Required for `secret_type = atlas_access_keys`.                      |

--------------------------------------------------------------------------------
6. Database Workspace Columns (`record_type = database`)
--------------------------------------------------------------------------------
| Column                     | Required | Description / Usage                                             |
|----------------------------|----------|-----------------------------------------------------------------|
| name                       | Yes      | Database workspace name (typically the host/FQDN).              |
| provider_engine            | Yes      | Engine identifier (see Section 7).                              |
| platform                   | No       | Hosting platform (`aws`, `azure`, `onprem`, `atlas`, etc.). Defaults to `ON-PREMISE`. |
| network_name               | No       | Logical network label. Defaults to `ON-PREMISE`.                |
| auth_database              | No       | Authentication DB (e.g., `postgres`, `admin`).                  |
| read_write_endpoint        | No       | Connection endpoint (required for managed/hosted engines).      |
| read_only_endpoint         | No       | Optional secondary endpoint.                                    |
| region                     | No       | Region hint for cloud resources.                                |
| secret_alias               | Cond.    | References a `db_secret`; required unless `secret_id` is provided. |
| secret_id                  | Cond.    | Directly reference an existing SIA secret instead of alias.     |
| domain / domain_controller_* | No    | AD domain integration settings (name, NetBIOS, LDAPS, certificate). |
| services                   | No       | Semicolon-separated entries `name:port:secretAlias[:secretId]`.  |
| configured_auth_method_type | No      | Overrides auth method (e.g., `local_ephemeral_user`).           |
| account                    | No       | Optional account ID (used by some engines).                      |

--------------------------------------------------------------------------------
7. Provider Engine Reference (`provider_engine`)
--------------------------------------------------------------------------------
The table below lists every engine identifier exposed by the SDK. Entries are sorted alphabetically to make lookup quick; apply the noted requirements in addition to the standard workspace fields.

| Engine Value | Description | Key Fields / Expectations |
|--------------|-------------|---------------------------|
| aurora-mysql | Amazon Aurora MySQL cluster | Set platform=aws, provide cluster endpoint in read_write_endpoint, region, and reference DB secret via secret_alias. |
| aurora-postgresql | Amazon Aurora PostgreSQL cluster | Set platform=aws, supply cluster endpoint in read_write_endpoint, region, and DB secret alias; auth_database often "postgres". |
| custom-sqlserver-ee | Custom self-hosted SQL Server edition | Keep platform=onprem, set read_write_endpoint to host:port, and include domain_controller_* fields when joining to AD. |
| custom-sqlserver-se | Custom self-hosted SQL Server edition | Keep platform=onprem, set read_write_endpoint to host:port, and include domain_controller_* fields when joining to AD. |
| custom-sqlserver-web | Custom self-hosted SQL Server edition | Keep platform=onprem, set read_write_endpoint to host:port, and include domain_controller_* fields when joining to AD. |
| db2 | Self-hosted IBM Db2 | Platform defaults to onprem; set read_write_endpoint or services with host, port, and secret alias. |
| db2-aws-rds | Amazon RDS for Db2 | Set platform=aws, populate read_write_endpoint with RDS endpoint, include region and secret alias. |
| db2-sh | Self-hosted IBM Db2 (explicit self-hosted flavor) | Same as db2 but enforces self-hosted workspace; include host/port and secret alias. |
| db2-sh-vm | IBM Db2 on virtual machine | Set read_write_endpoint to VM host or IP, include domain/network context if applicable. |
| mariadb | Self-hosted MariaDB | Keep platform=onprem, provide host and port via read_write_endpoint or services, and map secret alias. |
| mariadb-aws-aurora | Amazon Aurora (MariaDB-compatible) | Set platform=aws, cluster endpoint in read_write_endpoint, include region; reference appropriate secret alias. |
| mariadb-aws-rds | Amazon RDS for MariaDB | Set platform=aws, read_write_endpoint to RDS endpoint, include region and secret alias. |
| mariadb-aws-vm | MariaDB on AWS EC2/VM | Set platform=aws, populate read_write_endpoint or services with host and port, include region. |
| mariadb-azure-managed | Azure Database for MariaDB | Set platform=azure, managed endpoint in read_write_endpoint, include region; configure TLS validation if needed. |
| mariadb-azure-vm | MariaDB on Azure VM | Set platform=azure, read_write_endpoint to VM host/IP, include region and secret alias. |
| mariadb-sh | Self-hosted MariaDB (explicit flavor) | Same as mariadb; enforces self-hosted defaults. |
| mariadb-sh-vm | MariaDB hosted on VM | Set read_write_endpoint to VM host, optionally provide domain metadata and tags. |
| mongo | Self-hosted MongoDB replica or standalone | Provide host list in read_write_endpoint or services, add replica set info via services if applicable, and secret alias. |
| mongo-atlas-managed | MongoDB Atlas managed cluster | Set platform=atlas, SRV connection string in read_write_endpoint, include Atlas project/org references in account if required. |
| mongo-aws-docdb | Amazon DocumentDB (Mongo-compatible) | Set platform=aws, HTTPS cluster endpoint in read_write_endpoint, include region; enable certificate validation for TLS. |
| mongo-sh | Self-hosted MongoDB (explicit flavor) | Same as mongo but forces self-hosted defaults; include TLS settings as needed. |
| mongo-sh-vm | MongoDB on virtual machine | Set read_write_endpoint to VM host/IP, include port and secret alias; use enable_certificate_validation when TLS is required. |
| mssql | Generic Microsoft SQL Server | Platform default onprem; supply host:port, secret alias, and AD domain controller details when using Kerberos. |
| mssql-aws-ec2 | SQL Server running on AWS EC2 | Set platform=aws, VM host/IP in read_write_endpoint, include region and domain controller fields if joined to AD. |
| mssql-aws-rds | Amazon RDS for SQL Server | Set platform=aws, RDS endpoint in read_write_endpoint, include region, and ensure secret alias/ID points to SQL auth secret. |
| mssql-azure-managed | Azure SQL Managed Instance | Set platform=azure, MI endpoint in read_write_endpoint, include region; configure domain controller if using AD auth. |
| mssql-azure-vm | SQL Server on Azure VM | Set platform=azure, host/IP in read_write_endpoint, region, and optional domain controller metadata. |
| mssql-sh | Self-hosted Microsoft SQL Server (explicit flavor) | Same as mssql; enforces self-hosted defaults. |
| mssql-sh-vm | Microsoft SQL Server on VM | Set read_write_endpoint to VM host, include domain controller metadata if joined to AD, and secret alias. |
| mysql | Self-hosted MySQL | Platform default onprem; provide host and port via read_write_endpoint or services, and map secret alias. |
| mysql-aws-aurora | Amazon Aurora MySQL | Set platform=aws, cluster endpoint in read_write_endpoint, include region; secret alias often points to IAM or PAM credential. |
| mysql-aws-rds | Amazon RDS for MySQL | Set platform=aws, RDS endpoint in read_write_endpoint, include region and secret alias. |
| mysql-aws-vm | MySQL on AWS EC2/VM | Set platform=aws, host/IP in read_write_endpoint, include region and TLS requirements. |
| mysql-azure-managed | Azure Database for MySQL | Set platform=azure, managed endpoint in read_write_endpoint, include region and TLS settings. |
| mysql-azure-vm | MySQL on Azure VM | Set platform=azure, host/IP in read_write_endpoint, region, and secret alias. |
| mysql-sh | Self-hosted MySQL (explicit flavor) | Same as mysql; enforces self-hosted defaults. |
| mysql-sh-vm | MySQL on virtual machine | Set read_write_endpoint to VM host/IP, include port, secret alias, and TLS flag if required. |
| oracle | Generic Oracle Database (self-hosted) | Platform default onprem; specify listener via read_write_endpoint or services, include secret alias and optional domain controller. |
| oracle-aws-rds | Amazon RDS for Oracle | Set platform=aws, RDS endpoint in read_write_endpoint, include region and Oracle secret alias. |
| oracle-aws-vm | Oracle on AWS EC2/VM | Set platform=aws, host/IP in read_write_endpoint, region, and optional domain/TLS settings. |
| oracle-ee | Oracle Enterprise Edition | Platform onprem; provide listener and SID/service, include domain controller metadata when using Kerberos. |
| oracle-ee-cdb | Oracle Enterprise Edition (Container DB) | Same as oracle-ee plus include PDB/service entries in services for container-specific access. |
| oracle-se2 | Oracle Standard Edition 2 | Platform onprem; specify listener host/service and secret alias. |
| oracle-se2-cdb | Oracle Standard Edition 2 (Container DB) | Same as oracle-se2 with container/PDB service defined in services. |
| oracle-sh | Self-hosted Oracle (explicit flavor) | Same as oracle but enforces self-hosted workspace. |
| oracle-sh-vm | Oracle Database on VM | Set read_write_endpoint to VM host, include listener port/service, and domain/TLS details as needed. |
| postgres | Self-hosted PostgreSQL | Platform default onprem; provide host and port via read_write_endpoint or services, and secret alias. |
| postgres-aws-aurora | Amazon Aurora PostgreSQL | Set platform=aws, cluster endpoint in read_write_endpoint, include region and TLS flag if required. |
| postgres-aws-rds | Amazon RDS for PostgreSQL | Set platform=aws, RDS endpoint in read_write_endpoint, include region and secret alias. |
| postgres-aws-vm | PostgreSQL on AWS EC2/VM | Set platform=aws, host/IP in read_write_endpoint, include region and TLS requirements. |
| postgres-azure-managed | Azure Database for PostgreSQL | Set platform=azure, managed endpoint in read_write_endpoint, include region; configure TLS validation if required. |
| postgres-azure-vm | PostgreSQL on Azure VM | Set platform=azure, host/IP in read_write_endpoint, region, and secret alias. |
| postgres-sh | Self-hosted PostgreSQL (explicit flavor) | Same as postgres; enforces self-hosted defaults. |
| postgres-sh-vm | PostgreSQL on virtual machine | Set read_write_endpoint to VM host/IP, include port and secret alias. |
| sqlserver | Generic SQL Server workspace (legacy alias) | Same as mssql; provide host, port, secret alias, and domain controller metadata if needed. |
| sqlserver-sh | Self-hosted SQL Server (legacy alias) | Same as sqlserver but enforces self-hosted defaults. |

--------------------------------------------------------------------------------
9. Working with Aliases
--------------------------------------------------------------------------------
- Define each `db_secret` once and reuse via `secret_alias`.
- If an alias is missing, the script stops with a validation error.
- When `alias` is blank, the helper falls back to `secret_name`; ensure uniqueness.

--------------------------------------------------------------------------------
10. Example Mapping
--------------------------------------------------------------------------------
| Scenario                            | Example Columns                                                                           |
|------------------------------------|-------------------------------------------------------------------------------------------|
| PAM-backed DB account              | `record_type=db_secret`, `alias=db_admin_secret`, `secret_type=cyberark_pam`, `pam_safe=Finance-Prod`. |
| Database referencing the PAM secret| `record_type=database`, `name=finance-rds.cluster.internal`, `provider_engine=postgres-aws-rds`, `secret_alias=db_admin_secret`. |

--------------------------------------------------------------------------------
11. Validation Checklist
--------------------------------------------------------------------------------
1. Populate the DB and/or VM CSV templates with tenant-specific data.
2. Run `python3 sia_onboarding.py` and follow the prompts (choose DB, VM, or both).
3. Review the console/log output for skipped entries (e.g., missing Privilege Cloud accounts).
4. Correct any reported issues and rerun as needed.

================================================================================
