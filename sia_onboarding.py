#!/usr/bin/env python3
"""CSV-powered CyberArk SIA onboarding helper."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from pydantic import BaseModel, Field, ValidationError, model_validator

from ark_sdk_python.auth import ArkISPAuth
from ark_sdk_python.common import ArkSystemConfig
from ark_sdk_python.models import ArkAuthException, ArkServiceException
from ark_sdk_python.models.auth import ArkAuthMethod, ArkAuthProfile, ArkSecret, IdentityArkAuthMethodSettings
from ark_sdk_python.models.common import ArkWorkspaceType
from ark_sdk_python.models.services.pcloud.accounts import ArkPCloudAccountsFilter
from ark_sdk_python.models.services.sia.policies.common.ark_sia_base_connection_information import ArkSIADaysOfWeek
from ark_sdk_python.models.services.sia.policies.common.ark_sia_rule_status import ArkSIARuleStatus
from ark_sdk_python.models.services.sia.policies.common.ark_sia_user_data import ArkSIAUserData
from ark_sdk_python.models.services.sia.policies.db import ArkSIADBAddPolicy
from ark_sdk_python.models.services.sia.policies.db.ark_sia_db_authorization_rule import (
    ArkSIADBAuthorizationRule,
    ArkSIADBConnectionInformation,
)
from ark_sdk_python.models.services.sia.policies.db.ark_sia_db_providers import ArkSIADBProvidersData
from ark_sdk_python.models.services.sia.policies.vm import ArkSIAVMAddPolicy
from ark_sdk_python.models.services.sia.policies.vm.ark_sia_vm_authorization_rule import (
    ArkSIAVMAuthorizationRule,
    ArkSIAVMConnectionInformation,
)
from ark_sdk_python.models.services.sia.policies.vm.ark_sia_vm_providers import ArkSIAVMProvidersDict
from ark_sdk_python.models.services.sia.secrets.db import (
    ArkSIADBAddSecret,
    ArkSIADBSecretsFilter,
    ArkSIADBSecretType,
    ArkSIADBStoreType,
)
from ark_sdk_python.models.services.sia.secrets.vm import (
    ArkSIAVMAddSecret,
    ArkSIAVMSecretType,
    ArkSIAVMSecretsFilter,
)
from ark_sdk_python.models.services.sia.workspaces.db import (
    ArkSIADBAddDatabase,
    ArkSIADBAuthMethodType,
    ArkSIADBDatabaseEngineType,
    ArkSIADBDatabaseTargetService,
    ArkSIADBDatabasesFilter,
    ArkSIADBTag,
)
from ark_sdk_python.models.services.sia.workspaces.targetsets import (
    ArkSIAAddTargetSet,
    ArkSIATargetSetType,
    ArkSIATargetSetsFilter,
)
from ark_sdk_python.services.pcloud import ArkPCloudAPI
from ark_sdk_python.services.sia import ArkSIAAPI

LOGGER = logging.getLogger("sia_onboarding")
SUPPORTED_MFA_METHODS: List[str] = ["pf", "sms", "email", "otp", "oath", "auto"]

DAY_ALIAS_MAP: Dict[str, str] = {}
for _day in ArkSIADaysOfWeek:
    DAY_ALIAS_MAP[_day.value.lower()] = _day.value
    DAY_ALIAS_MAP[_day.name.lower()] = _day.value


class TagConfig(BaseModel):
    key: str
    value: str


class DomainControllerConfig(BaseModel):
    name: Optional[str] = None
    netbios: Optional[str] = None
    use_ldaps: Optional[bool] = None
    enable_certificate_validation: Optional[bool] = None
    ldaps_certificate: Optional[str] = None


class DatabaseServiceConfig(BaseModel):
    service_name: str = Field(description="Friendly service identifier inside the database")
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    secret_ref: Optional[str] = Field(default=None, description="Alias of a DB secret defined in the template")
    secret_id: Optional[str] = Field(default=None, description="Explicit secret identifier override")


class DbSecretConfig(BaseModel):
    alias: str = Field(description="In-template identifier used by databases")
    secret_name: str = Field(description="Name that will be visible inside SIA")
    description: str = Field(default="", description="Secret description")
    purpose: str = Field(default="", description="Purpose of the secret")
    secret_type: ArkSIADBSecretType
    store_type: Optional[ArkSIADBStoreType] = Field(default=None)
    tags: List[TagConfig] = Field(default_factory=list)

    username: Optional[str] = None
    password: Optional[str] = None
    pam_safe: Optional[str] = None
    pam_account_name: Optional[str] = None
    iam_account: Optional[str] = None
    iam_username: Optional[str] = None
    iam_access_key_id: Optional[str] = None
    iam_secret_access_key: Optional[str] = None
    atlas_public_key: Optional[str] = None
    atlas_private_key: Optional[str] = None

    def to_model(self) -> ArkSIADBAddSecret:
        return ArkSIADBAddSecret(
            secret_name=self.secret_name,
            description=self.description,
            purpose=self.purpose,
            secret_type=self.secret_type,
            store_type=self.store_type,
            tags=[ArkSIADBTag(key=t.key, value=t.value) for t in self.tags],
            username=self.username,
            password=self.password,
            pam_safe=self.pam_safe,
            pam_account_name=self.pam_account_name,
            iam_account=self.iam_account,
            iam_username=self.iam_username,
            iam_access_key_id=self.iam_access_key_id,
            iam_secret_access_key=self.iam_secret_access_key,
            atlas_public_key=self.atlas_public_key,
            atlas_private_key=self.atlas_private_key,
        )


class VmSecretConfig(BaseModel):
    alias: str = Field(description="In-template identifier used by VM target sets")
    secret_type: ArkSIAVMSecretType
    secret_name: Optional[str] = Field(default=None)
    secret_details: Dict[str, Any] = Field(default_factory=dict)
    is_disabled: bool = Field(default=False)
    provisioner_username: Optional[str] = None
    provisioner_password: Optional[str] = None
    pcloud_account_safe: Optional[str] = None
    pcloud_account_name: Optional[str] = None

    def to_model(self) -> ArkSIAVMAddSecret:
        return ArkSIAVMAddSecret(
            secret_name=self.secret_name,
            secret_details=self.secret_details or None,
            secret_type=self.secret_type,
            is_disabled=self.is_disabled,
            provisioner_username=self.provisioner_username,
            provisioner_password=self.provisioner_password,
            pcloud_account_safe=self.pcloud_account_safe,
            pcloud_account_name=self.pcloud_account_name,
        )

    @model_validator(mode="after")
    def _validate_secret_requirements(cls, model: "VmSecretConfig") -> "VmSecretConfig":
        if model.secret_type == ArkSIAVMSecretType.PCloudAccount:
            if not model.pcloud_account_safe or not model.pcloud_account_name:
                raise ValueError(
                    f"VM secret alias '{model.alias}' requires both pcloud_account_safe and pcloud_account_name when secret_type is PCloudAccount."
                )
        elif model.secret_type == ArkSIAVMSecretType.ProvisionerUser:
            if not model.provisioner_username or not model.provisioner_password:
                raise ValueError(
                    f"VM secret alias '{model.alias}' requires both provisioner_username and provisioner_password when secret_type is ProvisionerUser."
                )
        return model


class DatabaseConfig(BaseModel):
    name: str
    provider_engine: ArkSIADBDatabaseEngineType
    platform: ArkWorkspaceType = Field(default=ArkWorkspaceType.ONPREM)
    network_name: str = Field(default="ON-PREMISE")
    auth_database: str = Field(default="admin")
    read_write_endpoint: Optional[str] = None
    read_only_endpoint: Optional[str] = None
    region: Optional[str] = None
    secret_ref: Optional[str] = Field(default=None, description="Alias of a DB secret defined in the template")
    secret_id: Optional[str] = Field(default=None, description="Explicit secret identifier override")
    enable_certificate_validation: Optional[bool] = Field(default=True)
    domain: Optional[str] = None
    domain_controller: Optional[DomainControllerConfig] = None
    services: List[DatabaseServiceConfig] = Field(default_factory=list)
    tags: List[TagConfig] = Field(default_factory=list)
    configured_auth_method_type: Optional[ArkSIADBAuthMethodType] = None
    account: Optional[str] = None


class VmTargetSetConfig(BaseModel):
    name: str
    type: ArkSIATargetSetType = Field(default=ArkSIATargetSetType.DOMAIN)
    description: Optional[str] = None
    provision_format: Optional[str] = None
    enable_certificate_validation: Optional[bool] = None
    secret_type: Optional[ArkSIAVMSecretType] = None
    secret_ref: Optional[str] = Field(default=None, description="Alias of a VM secret defined in the template")
    secret_id: Optional[str] = Field(default=None, description="Explicit secret identifier override")


@dataclass
class DbTemplateData:
    database_secrets: List[DbSecretConfig] = field(default_factory=list)
    databases: List[DatabaseConfig] = field(default_factory=list)


@dataclass
class VmTemplateData:
    vm_secrets: List[VmSecretConfig] = field(default_factory=list)
    vm_target_sets: List[VmTargetSetConfig] = field(default_factory=list)


@dataclass
class DbPolicyConfig:
    policy_name: str
    description: Optional[str]
    status: ArkSIARuleStatus
    start_date: Optional[str]
    end_date: Optional[str]
    providers_tags: List[str]
    providers_data: Dict[str, Any]
    rule_name: str
    user_roles: List[str]
    user_groups: List[str]
    user_users: List[str]
    full_days: Optional[bool]
    days_of_week: List[str]
    hours_from: Optional[str]
    hours_to: Optional[str]
    time_zone: Optional[str]
    grant_access_hours: Optional[int]
    idle_time_minutes: Optional[int]
    connect_as: Dict[str, Any]
    line_number: int


@dataclass
class VmPolicyConfig:
    policy_name: str
    description: Optional[str]
    status: ArkSIARuleStatus
    start_date: Optional[str]
    end_date: Optional[str]
    providers_data: Dict[str, Any]
    rule_name: str
    user_roles: List[str]
    user_groups: List[str]
    user_users: List[str]
    full_days: Optional[bool]
    days_of_week: List[str]
    hours_from: Optional[str]
    hours_to: Optional[str]
    time_zone: Optional[str]
    grant_access_hours: Optional[int]
    idle_time_minutes: Optional[int]
    connect_as: Dict[str, Any]
    line_number: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CyberArk SIA helper for onboarding workspaces and access policies.")
    parser.add_argument(
        "--db-template",
        type=Path,
        default=Path("sia_db_onboarding_template.csv"),
        help="Path to the database onboarding template CSV file.",
    )
    parser.add_argument(
        "--vm-template",
        type=Path,
        default=Path("sia_vm_onboarding_template.csv"),
        help="Path to the VM onboarding template CSV file.",
    )
    parser.add_argument(
        "--db-policy-template",
        type=Path,
        default=Path("sia_db_access_policy_template.csv"),
        help="Path to the DB access policy template CSV file.",
    )
    parser.add_argument(
        "--vm-policy-template",
        type=Path,
        default=Path("sia_vm_access_policy_template.csv"),
        help="Path to the VM access policy template CSV file.",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=Path("logs"),
        help="Directory where execution logs should be written.",
    )
    return parser.parse_args()


def strip_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = value.strip()
    return text or None


def parse_bool(value: Optional[str]) -> Optional[bool]:
    text = strip_value(value)
    if text is None:
        return None
    truthy = {"true", "yes", "y", "1"}
    falsy = {"false", "no", "n", "0"}
    lowered = text.lower()
    if lowered in truthy:
        return True
    if lowered in falsy:
        return False
    raise ValueError(f"Unable to parse boolean value '{value}'")


def parse_list(value: Optional[str]) -> List[str]:
    text = strip_value(value)
    if not text:
        return []
    normalized = text.replace(";", ",")
    return [item.strip() for item in normalized.split(",") if item and item.strip()]


def parse_days_of_week(value: Optional[str], line_no: int, column: str = "days_of_week") -> List[str]:
    entries = parse_list(value)
    days: List[str] = []
    for entry in entries:
        key = entry.lower()
        if key not in DAY_ALIAS_MAP:
            valid_values = ", ".join(sorted({v for v in DAY_ALIAS_MAP.values()}))
            raise ValueError(f"Row {line_no}: column '{column}' contains invalid day '{entry}'. Expected one of: {valid_values}")
        days.append(DAY_ALIAS_MAP[key])
    return days


def parse_int(value: Optional[str], column: str, line_no: int) -> Optional[int]:
    text = strip_value(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError as exc:
        raise ValueError(f"Row {line_no}: column '{column}' must be an integer.") from exc


def parse_rule_status(value: Optional[str], line_no: int, column: str = "status") -> ArkSIARuleStatus:
    if not value:
        return ArkSIARuleStatus.Enabled
    text = value.strip().lower()
    for status in ArkSIARuleStatus:
        if status.value.lower() == text or status.name.lower() == text:
            return status
    allowed = ", ".join([status.value for status in ArkSIARuleStatus])
    raise ValueError(f"Row {line_no}: column '{column}' must be one of {allowed}.")


def parse_json_required(value: Optional[str], column: str, line_no: int) -> Dict[str, Any]:
    data = parse_json_object(value)
    if not data:
        raise ValueError(f"Row {line_no}: column '{column}' must contain a JSON object.")
    return data


def compact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    compacted: Dict[str, Any] = {}
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, list) and len(value) == 0:
            continue
        if isinstance(value, dict) and len(value) == 0:
            continue
        compacted[key] = value
    return compacted


def parse_tags(value: Optional[str]) -> List[TagConfig]:
    text = strip_value(value)
    if not text:
        return []
    tags: List[TagConfig] = []
    for chunk in text.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise ValueError(f"Tag '{chunk}' must be in key=value format")
        key, val = chunk.split("=", 1)
        tags.append(TagConfig(key=key.strip(), value=val.strip()))
    return tags


def parse_services(value: Optional[str]) -> List[DatabaseServiceConfig]:
    text = strip_value(value)
    if not text:
        return []
    services: List[DatabaseServiceConfig] = []
    for chunk in text.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = [part.strip() or None for part in chunk.split(":")]
        if not parts[0]:
            raise ValueError(f"Service descriptor '{chunk}' is missing a service name")
        port: Optional[int] = None
        if len(parts) > 1 and parts[1]:
            try:
                port = int(parts[1])
            except ValueError as exc:
                raise ValueError(f"Service descriptor '{chunk}' has an invalid port") from exc
        secret_alias = parts[2] if len(parts) > 2 else None
        secret_id = parts[3] if len(parts) > 3 else None
        services.append(
            DatabaseServiceConfig(service_name=parts[0], port=port, secret_ref=secret_alias, secret_id=secret_id)
        )
    return services


def parse_json_object(value: Optional[str]) -> Dict[str, Any]:
    text = strip_value(value)
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON payload '{value}'") from exc
    if not isinstance(parsed, dict):
        raise ValueError("JSON payload must represent an object")
    return parsed


def require_value(row: Dict[str, str], column: str, line_no: int) -> str:
    value = strip_value(row.get(column))
    if value is None:
        raise ValueError(f"Row {line_no}: column '{column}' is required")
    return value


def load_db_template_csv(path: Path) -> DbTemplateData:
    if not path.exists():
        raise FileNotFoundError(f"DB onboarding template file '{path}' does not exist")
    template = DbTemplateData()
    db_aliases: set[str] = set()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "record_type" not in reader.fieldnames:
            raise ValueError("The DB onboarding CSV must include a 'record_type' header column.")
        for index, row in enumerate(reader, start=2):  # account for header
            if not row:
                continue
            record_type = strip_value(row.get("record_type"))
            if not record_type:
                continue
            try:
                record_key = record_type.lower()
                if record_key == "db_secret":
                    alias = strip_value(row.get("alias")) or strip_value(row.get("secret_name"))
                    if not alias:
                        raise ValueError(f"Row {index}: either 'alias' or 'secret_name' must be provided for db_secret entries.")
                    if alias in db_aliases:
                        raise ValueError(f"Row {index}: duplicate DB secret alias '{alias}'")
                    secret = DbSecretConfig(
                        alias=alias,
                        secret_name=require_value(row, "secret_name", index),
                        description=strip_value(row.get("description")) or "",
                        purpose=strip_value(row.get("purpose")) or "",
                        secret_type=require_value(row, "secret_type", index),
                        store_type=strip_value(row.get("store_type")),
                        username=strip_value(row.get("username")),
                        password=strip_value(row.get("password")),
                        pam_safe=strip_value(row.get("pam_safe")),
                        pam_account_name=strip_value(row.get("pam_account_name")),
                        iam_account=strip_value(row.get("iam_account")),
                        iam_username=strip_value(row.get("iam_username")),
                        iam_access_key_id=strip_value(row.get("iam_access_key_id")),
                        iam_secret_access_key=strip_value(row.get("iam_secret_access_key")),
                        atlas_public_key=strip_value(row.get("atlas_public_key")),
                        atlas_private_key=strip_value(row.get("atlas_private_key")),
                        tags=parse_tags(row.get("tags")),
                    )
                    template.database_secrets.append(secret)
                    db_aliases.add(alias)
                elif record_key == "database":
                    domain_controller = DomainControllerConfig(
                        name=strip_value(row.get("domain_controller_name")),
                        netbios=strip_value(row.get("domain_controller_netbios")),
                        use_ldaps=parse_bool(row.get("domain_controller_use_ldaps")),
                        enable_certificate_validation=parse_bool(row.get("domain_controller_enable_certificate_validation")),
                        ldaps_certificate=strip_value(row.get("domain_controller_ldaps_certificate")),
                    )
                    if all(value is None for value in domain_controller.model_dump().values()):
                        domain_controller = None
                    db_config = DatabaseConfig(
                        name=require_value(row, "name", index),
                        provider_engine=require_value(row, "provider_engine", index),
                        platform=strip_value(row.get("platform")) or ArkWorkspaceType.ONPREM,
                        network_name=strip_value(row.get("network_name")) or "ON-PREMISE",
                        auth_database=strip_value(row.get("auth_database")) or "admin",
                        read_write_endpoint=strip_value(row.get("read_write_endpoint")),
                        read_only_endpoint=strip_value(row.get("read_only_endpoint")),
                        region=strip_value(row.get("region")),
                        secret_ref=strip_value(row.get("secret_alias")),
                        secret_id=strip_value(row.get("secret_id")),
                        enable_certificate_validation=parse_bool(row.get("enable_certificate_validation")),
                        domain=strip_value(row.get("domain")),
                        domain_controller=domain_controller,
                        services=parse_services(row.get("services")),
                        tags=parse_tags(row.get("tags")),
                        configured_auth_method_type=strip_value(row.get("configured_auth_method_type")),
                        account=strip_value(row.get("account")),
                    )
                    template.databases.append(db_config)
                else:
                    raise ValueError(f"Row {index}: unsupported record_type '{record_type}'")
            except (ValidationError, ValueError) as exc:
                raise ValueError(f"Error while parsing row {index}: {exc}") from exc
    if not template.database_secrets and not template.databases:
        raise ValueError("DB onboarding template did not contain any db_secret or database records.")
    return template


def load_vm_template_csv(path: Path) -> VmTemplateData:
    if not path.exists():
        raise FileNotFoundError(f"VM onboarding template file '{path}' does not exist")
    template = VmTemplateData()
    vm_aliases: set[str] = set()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "record_type" not in reader.fieldnames:
            raise ValueError("The VM onboarding CSV must include a 'record_type' header column.")
        for index, row in enumerate(reader, start=2):
            if not row:
                continue
            record_type = strip_value(row.get("record_type"))
            if not record_type:
                continue
            try:
                record_key = record_type.lower()
                if record_key == "vm_secret":
                    alias = strip_value(row.get("alias")) or strip_value(row.get("secret_name"))
                    if not alias:
                        raise ValueError(f"Row {index}: either 'alias' or 'secret_name' must be provided for vm_secret entries.")
                    if alias in vm_aliases:
                        raise ValueError(f"Row {index}: duplicate VM secret alias '{alias}'")
                    secret = VmSecretConfig(
                        alias=alias,
                        secret_type=require_value(row, "secret_type", index),
                        secret_name=strip_value(row.get("secret_name")),
                        secret_details=parse_json_object(row.get("secret_details")),
                        provisioner_username=strip_value(row.get("provisioner_username")),
                        provisioner_password=strip_value(row.get("provisioner_password")),
                        pcloud_account_safe=strip_value(row.get("pcloud_account_safe")),
                        pcloud_account_name=strip_value(row.get("pcloud_account_name")),
                        is_disabled=parse_bool(row.get("is_disabled")) or False,
                    )
                    template.vm_secrets.append(secret)
                    vm_aliases.add(alias)
                elif record_key == "vm_target_set":
                    target_set = VmTargetSetConfig(
                        name=require_value(row, "name", index),
                        type=strip_value(row.get("target_set_type")) or ArkSIATargetSetType.DOMAIN,
                        description=strip_value(row.get("description")),
                        provision_format=strip_value(row.get("provision_format")),
                        enable_certificate_validation=parse_bool(row.get("enable_certificate_validation")),
                        secret_type=strip_value(row.get("secret_type")),
                        secret_ref=strip_value(row.get("secret_alias")),
                        secret_id=strip_value(row.get("secret_id")),
                    )
                    template.vm_target_sets.append(target_set)
                else:
                    raise ValueError(f"Row {index}: unsupported record_type '{record_type}'")
            except (ValidationError, ValueError) as exc:
                raise ValueError(f"Error while parsing row {index}: {exc}") from exc
    if not template.vm_secrets and not template.vm_target_sets:
        raise ValueError("VM onboarding template did not contain any vm_secret or vm_target_set records.")
    return template


def prompt_identity_inputs() -> Dict[str, Any]:
    print("\nIdentity authentication")
    print("-----------------------")
    username = ""
    while not username:
        username = strip_value(input("Identity username: "))
        if not username:
            print("  Username is required.")
    password = ""
    while not password:
        password = getpass("Identity password: ")
        if not password:
            print("  Password is required.")
    mfa_method = prompt_mfa_method()
    interactive = prompt_yes_no("Enable interactive MFA prompts (passcodes/device approvals)?", default=True)
    identity_url = strip_value(input("Identity URL (optional, e.g. https://tenant.id.cyberark.cloud): "))
    tenant_subdomain = strip_value(input("Tenant subdomain (optional): "))
    default_app = "__idaptive_cybr_user_oidc"
    identity_app = strip_value(input(f"Identity application [{default_app}]: ")) or default_app
    return {
        "username": username,
        "password": password,
        "mfa_method": mfa_method,
        "interactive_mfa": interactive,
        "identity_url": identity_url,
        "tenant_subdomain": tenant_subdomain,
        "identity_application": identity_app,
    }


def prompt_mfa_method() -> str:
    methods = SUPPORTED_MFA_METHODS
    default = "pf"
    print("\nAvailable MFA methods:")
    for idx, method in enumerate(methods, start=1):
        label = "auto (use Identity profile default)" if method == "auto" else method
        print(f"  {idx}. {label}")
    while True:
        choice = strip_value(input(f"Choose MFA method [{default}]: "))
        if not choice:
            return default
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(methods):
                return methods[idx - 1]
        lowered = choice.lower()
        if lowered in methods:
            return lowered
        print("  Invalid selection. Please enter the option number or method name.")


def prompt_yes_no(message: str, *, default: bool) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        answer = strip_value(input(f"{message} {suffix}: "))
        if not answer:
            return default
        lowered = answer.lower()
        if lowered in {"y", "yes"}:
            return True
        if lowered in {"n", "no"}:
            return False
        print("  Please answer with yes or no.")


def prompt_main_action() -> str:
    print("\nSelect operation")
    print("-----------------")
    print("1. Onboard SIA workspaces")
    print("2. Create SIA access policies")
    while True:
        choice = strip_value(input("Choose an option [1]: "))
        if not choice or choice == "1" or choice.lower() == "workspace":
            return "workspace"
        if choice == "2" or choice.lower() == "policy":
            return "policy"
        print("  Invalid selection. Please enter 1 for workspace onboarding or 2 for access policies.")


def prompt_template_path(default_path: Path, message: str) -> Path:
    prompt_default = str(default_path)
    response = strip_value(input(f"{message} [{prompt_default}]: "))
    selected = Path(response) if response else default_path
    return selected


def ensure_db_aliases(database_secrets: Iterable[DbSecretConfig], databases: Iterable[DatabaseConfig]) -> None:
    defined_aliases = {secret.alias for secret in database_secrets}

    def validate_alias(alias: Optional[str], label: str) -> None:
        if alias and alias not in defined_aliases:
            raise ValueError(f"{label} alias '{alias}' is referenced but not defined as a DB secret.")

    for db in databases:
        validate_alias(db.secret_ref, f"Database '{db.name}' secret")
        for service in db.services:
            validate_alias(
                service.secret_ref,
                f"Database '{db.name}' service '{service.service_name}' secret",
            )


def ensure_vm_aliases(vm_secrets: Iterable[VmSecretConfig], vm_target_sets: Iterable[VmTargetSetConfig]) -> None:
    defined_aliases = {secret.alias for secret in vm_secrets}

    def validate_alias(alias: Optional[str], label: str) -> None:
        if alias and alias not in defined_aliases:
            raise ValueError(f"{label} alias '{alias}' is referenced but not defined as a VM secret.")

    for target in vm_target_sets:
        validate_alias(target.secret_ref, f"Target set '{target.name}' secret")


def parse_db_policy_row(row: Dict[str, str], line_no: int) -> DbPolicyConfig:
    policy_name = require_value(row, "policy_name", line_no)
    rule_name = require_value(row, "rule_name", line_no)
    providers_data = parse_json_required(row.get("providers_data"), "providers_data", line_no)
    connect_as = parse_json_required(row.get("connect_as"), "connect_as", line_no)
    status = parse_rule_status(row.get("status"), line_no)
    description = strip_value(row.get("description"))
    providers_tags = parse_list(row.get("providers_tags"))
    start_date = strip_value(row.get("start_date"))
    end_date = strip_value(row.get("end_date"))
    user_roles = parse_list(row.get("user_roles"))
    user_groups = parse_list(row.get("user_groups"))
    user_users = parse_list(row.get("user_users"))
    full_days = parse_bool(row.get("full_days"))
    days_of_week = parse_days_of_week(row.get("days_of_week"), line_no) if strip_value(row.get("days_of_week")) else []
    hours_from = strip_value(row.get("hours_from"))
    hours_to = strip_value(row.get("hours_to"))
    time_zone = strip_value(row.get("time_zone"))
    grant_access_hours = parse_int(row.get("grant_access_hours"), "grant_access_hours", line_no) if strip_value(
        row.get("grant_access_hours")
    ) else None
    idle_time_minutes = parse_int(row.get("idle_time_minutes"), "idle_time_minutes", line_no) if strip_value(
        row.get("idle_time_minutes")
    ) else None

    if not providers_data:
        raise ValueError("DB access policy must include providers_data.")
    if not connect_as:
        raise ValueError("DB access policy must include connect_as configuration.")

    return DbPolicyConfig(
        policy_name=policy_name,
        description=description,
        status=status,
        start_date=start_date,
        end_date=end_date,
        providers_tags=providers_tags,
        providers_data=providers_data,
        rule_name=rule_name,
        user_roles=user_roles,
        user_groups=user_groups,
        user_users=user_users,
        full_days=full_days,
        days_of_week=days_of_week,
        hours_from=hours_from,
        hours_to=hours_to,
        time_zone=time_zone,
        grant_access_hours=grant_access_hours,
        idle_time_minutes=idle_time_minutes,
        connect_as=connect_as,
        line_number=line_no,
    )


def parse_vm_policy_row(row: Dict[str, str], line_no: int) -> VmPolicyConfig:
    policy_name = require_value(row, "policy_name", line_no)
    rule_name = require_value(row, "rule_name", line_no)
    providers_data = parse_json_required(row.get("providers_data"), "providers_data", line_no)
    connect_as = parse_json_required(row.get("connect_as"), "connect_as", line_no)
    status = parse_rule_status(row.get("status"), line_no)
    description = strip_value(row.get("description"))
    start_date = strip_value(row.get("start_date"))
    end_date = strip_value(row.get("end_date"))
    user_roles = parse_list(row.get("user_roles"))
    user_groups = parse_list(row.get("user_groups"))
    user_users = parse_list(row.get("user_users"))
    full_days = parse_bool(row.get("full_days"))
    days_of_week = parse_days_of_week(row.get("days_of_week"), line_no) if strip_value(row.get("days_of_week")) else []
    hours_from = strip_value(row.get("hours_from"))
    hours_to = strip_value(row.get("hours_to"))
    time_zone = strip_value(row.get("time_zone"))
    grant_access_hours = parse_int(row.get("grant_access_hours"), "grant_access_hours", line_no) if strip_value(
        row.get("grant_access_hours")
    ) else None
    idle_time_minutes = parse_int(row.get("idle_time_minutes"), "idle_time_minutes", line_no) if strip_value(
        row.get("idle_time_minutes")
    ) else None

    if not providers_data:
        raise ValueError("VM access policy must include providers_data.")
    if not connect_as:
        raise ValueError("VM access policy must include connect_as configuration.")

    return VmPolicyConfig(
        policy_name=policy_name,
        description=description,
        status=status,
        start_date=start_date,
        end_date=end_date,
        providers_data=providers_data,
        rule_name=rule_name,
        user_roles=user_roles,
        user_groups=user_groups,
        user_users=user_users,
        full_days=full_days,
        days_of_week=days_of_week,
        hours_from=hours_from,
        hours_to=hours_to,
        time_zone=time_zone,
        grant_access_hours=grant_access_hours,
        idle_time_minutes=idle_time_minutes,
        connect_as=connect_as,
        line_number=line_no,
    )


def load_db_policy_template_csv(path: Path) -> List[DbPolicyConfig]:
    if not path.exists():
        raise FileNotFoundError(f"DB policy template file '{path}' does not exist")
    policies: List[DbPolicyConfig] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "record_type" not in reader.fieldnames:
            raise ValueError("The DB policy CSV must include a 'record_type' header column.")
        for index, row in enumerate(reader, start=2):
            if not row:
                continue
            record_type = strip_value(row.get("record_type"))
            if not record_type:
                continue
            try:
                if record_type.lower() == "db_policy":
                    policies.append(parse_db_policy_row(row, index))
                else:
                    raise ValueError(f"Unsupported record_type '{record_type}' for DB policies")
            except ValueError as exc:
                raise ValueError(f"Error while parsing row {index}: {exc}") from exc
    if not policies:
        raise ValueError("No DB access policies were found in the template.")
    return policies


def load_vm_policy_template_csv(path: Path) -> List[VmPolicyConfig]:
    if not path.exists():
        raise FileNotFoundError(f"VM policy template file '{path}' does not exist")
    policies: List[VmPolicyConfig] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "record_type" not in reader.fieldnames:
            raise ValueError("The VM policy CSV must include a 'record_type' header column.")
        for index, row in enumerate(reader, start=2):
            if not row:
                continue
            record_type = strip_value(row.get("record_type"))
            if not record_type:
                continue
            try:
                if record_type.lower() == "vm_policy":
                    policies.append(parse_vm_policy_row(row, index))
                else:
                    raise ValueError(f"Unsupported record_type '{record_type}' for VM policies")
            except ValueError as exc:
                raise ValueError(f"Error while parsing row {index}: {exc}") from exc
    if not policies:
        raise ValueError("No VM access policies were found in the template.")
    return policies


class PCloudAccountValidator:
    def __init__(self, pcloud_api: ArkPCloudAPI) -> None:
        self._api = pcloud_api
        self._cache: Dict[Tuple[str, str], bool] = {}

    def ensure_exists(self, secret_cfg: VmSecretConfig) -> None:
        safe_name = secret_cfg.pcloud_account_safe or ""
        account_name = secret_cfg.pcloud_account_name or ""
        key = (safe_name.lower(), account_name.lower())
        if key in self._cache:
            if not self._cache[key]:
                raise ValueError(
                    f"Privilege Cloud account '{account_name}' in safe '{safe_name}' was not found previously; please verify the CSV entry."
                )
            return

        try:
            exists = self._account_exists(safe_name, account_name)
        except ArkServiceException as exc:
            raise ValueError(f"Unable to validate Privilege Cloud account '{account_name}' in safe '{safe_name}': {exc}") from exc

        self._cache[key] = exists
        if not exists:
            raise ValueError(
                f"Privilege Cloud account '{account_name}' in safe '{safe_name}' was not found or is not accessible with the current credentials."
            )

    def _account_exists(self, safe_name: str, account_name: str) -> bool:
        def match_accounts(pages: Iterable[Any]) -> bool:
            for page in pages:
                for account in getattr(page, "items", []):
                    if getattr(account, "safe_name", None) == safe_name and getattr(account, "name", None) == account_name:
                        return True
            return False

        try:
            if match_accounts(
                self._api.accounts.list_accounts_by(
                    ArkPCloudAccountsFilter(safe_name=safe_name, search=account_name, search_type="contains")
                )
            ):
                return True
        except ArkServiceException as exc:
            LOGGER.warning(
                "Failed to query Privilege Cloud accounts using filtered request for safe '%s': %s. Falling back to full listing.",
                safe_name,
                exc,
            )

        try:
            return match_accounts(self._api.accounts.list_accounts())
        except ArkServiceException as exc:
            raise exc


def build_db_policy_model(cfg: DbPolicyConfig) -> ArkSIADBAddPolicy:
    providers_data = ArkSIADBProvidersData.model_validate(cfg.providers_data)
    connection_info_data = compact_dict(
        {
            "full_days": cfg.full_days,
            "days_of_week": cfg.days_of_week,
            "hours_from": cfg.hours_from,
            "hours_to": cfg.hours_to,
            "time_zone": cfg.time_zone,
            "grant_access": cfg.grant_access_hours,
            "idle_time": cfg.idle_time_minutes,
            "connect_as": cfg.connect_as,
        }
    )
    connection_information = ArkSIADBConnectionInformation.model_validate(connection_info_data)
    user_data = ArkSIAUserData(roles=cfg.user_roles, groups=cfg.user_groups, users=cfg.user_users)
    rule = ArkSIADBAuthorizationRule(rule_name=cfg.rule_name, user_data=user_data, connection_information=connection_information)
    policy_kwargs = compact_dict(
        {
            "policy_name": cfg.policy_name,
            "description": cfg.description,
            "status": cfg.status,
            "start_date": cfg.start_date,
            "end_date": cfg.end_date,
            "providers_tags": cfg.providers_tags,
            "providers_data": providers_data,
            "user_access_rules": [rule],
        }
    )
    return ArkSIADBAddPolicy(**policy_kwargs)


def build_vm_policy_model(cfg: VmPolicyConfig) -> ArkSIAVMAddPolicy:
    connection_info_data = compact_dict(
        {
            "full_days": cfg.full_days,
            "days_of_week": cfg.days_of_week,
            "hours_from": cfg.hours_from,
            "hours_to": cfg.hours_to,
            "time_zone": cfg.time_zone,
            "grant_access": cfg.grant_access_hours,
            "idle_time": cfg.idle_time_minutes,
            "connect_as": cfg.connect_as,
        }
    )
    connection_information = ArkSIAVMConnectionInformation.model_validate(connection_info_data)
    user_data = ArkSIAUserData(roles=cfg.user_roles, groups=cfg.user_groups, users=cfg.user_users)
    rule = ArkSIAVMAuthorizationRule(rule_name=cfg.rule_name, user_data=user_data, connection_information=connection_information)
    policy_kwargs = compact_dict(
        {
            "policy_name": cfg.policy_name,
            "description": cfg.description,
            "status": cfg.status,
            "start_date": cfg.start_date,
            "end_date": cfg.end_date,
            "providers_data": cfg.providers_data,
            "user_access_rules": [rule],
        }
    )
    return ArkSIAVMAddPolicy(**policy_kwargs)


def process_db_policies(sia_api: ArkSIAAPI, configs: List[DbPolicyConfig]) -> List[str]:
    created: List[str] = []
    for cfg in configs:
        try:
            policy_model = build_db_policy_model(cfg)
        except ValidationError as exc:
            raise ValueError(f"Failed to validate DB policy '{cfg.policy_name}' (row {cfg.line_number}): {exc}") from exc
        LOGGER.info("Creating DB access policy '%s'", cfg.policy_name)
        policy = sia_api.policies_db.add_policy(policy_model)
        created.append(policy.policy_name)
    return created


def process_vm_policies(sia_api: ArkSIAAPI, configs: List[VmPolicyConfig]) -> List[str]:
    created: List[str] = []
    for cfg in configs:
        try:
            policy_model = build_vm_policy_model(cfg)
        except ValidationError as exc:
            raise ValueError(f"Failed to validate VM policy '{cfg.policy_name}' (row {cfg.line_number}): {exc}") from exc
        LOGGER.info("Creating VM access policy '%s'", cfg.policy_name)
        policy = sia_api.policies_vm.add_policy(policy_model)
        created.append(policy.policy_name)
    return created


def process_access_policies(
    sia_api: ArkSIAAPI, db_policies: List[DbPolicyConfig], vm_policies: List[VmPolicyConfig]
) -> Tuple[List[str], List[str]]:
    created_db: List[str] = []
    created_vm: List[str] = []
    if db_policies:
        created_db = process_db_policies(sia_api, db_policies)
    if vm_policies:
        created_vm = process_vm_policies(sia_api, vm_policies)
    return created_db, created_vm


def setup_logging(log_dir: Path) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"sia_helper_{timestamp}.log"
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_path, encoding="utf-8"),
    ]
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=handlers)
    return log_path

def ensure_db_secret(
    sia_api: ArkSIAAPI,
    cfg: DbSecretConfig,
    reuse_existing: bool,
) -> str:
    if reuse_existing:
        try:
            existing = sia_api.secrets_db.list_secrets_by(ArkSIADBSecretsFilter(secret_name=cfg.secret_name))
        except ArkServiceException as exc:
            LOGGER.warning("Unable to check existing DB secrets for '%s': %s", cfg.secret_name, exc)
        else:
            for secret in existing.secrets:
                if secret.secret_name == cfg.secret_name:
                    LOGGER.info("Reusing existing DB secret '%s' (%s)", cfg.secret_name, secret.secret_id)
                    return secret.secret_id
    LOGGER.info("Creating DB secret '%s'", cfg.secret_name)
    created = sia_api.secrets_db.add_secret(cfg.to_model())
    return created.secret_id


def ensure_vm_secret(
    sia_api: ArkSIAAPI,
    cfg: VmSecretConfig,
    reuse_existing: bool,
) -> str:
    if reuse_existing and cfg.secret_name:
        try:
            matches = sia_api.secrets_vm.list_secrets_by(ArkSIAVMSecretsFilter(name=cfg.secret_name))
        except ArkServiceException as exc:
            LOGGER.warning("Unable to check existing VM secrets for '%s': %s", cfg.secret_name, exc)
        else:
            for secret in matches:
                if secret.secret_name == cfg.secret_name:
                    LOGGER.info("Reusing existing VM secret '%s' (%s)", cfg.secret_name, secret.secret_id)
                    return secret.secret_id
    LOGGER.info("Creating VM secret%s", f" '{cfg.secret_name}'" if cfg.secret_name else "")
    created = sia_api.secrets_vm.add_secret(cfg.to_model())
    return created.secret_id


def build_database_model(cfg: DatabaseConfig, db_secret_ids: Dict[str, str]) -> ArkSIADBAddDatabase:
    secret_id = cfg.secret_id
    if cfg.secret_ref:
        secret_id = db_secret_ids[cfg.secret_ref]

    service_models: List[ArkSIADBDatabaseTargetService] = []
    for service_cfg in cfg.services:
        service_secret = service_cfg.secret_id
        if service_cfg.secret_ref:
            service_secret = db_secret_ids[service_cfg.secret_ref]
        service_models.append(
            ArkSIADBDatabaseTargetService(service_name=service_cfg.service_name, port=service_cfg.port, secret_id=service_secret)
        )

    kwargs: Dict[str, Any] = {
        "name": cfg.name,
        "network_name": cfg.network_name,
        "platform": cfg.platform,
        "auth_database": cfg.auth_database,
        "services": service_models,
        "domain": cfg.domain,
        "account": cfg.account,
        "enable_certificate_validation": cfg.enable_certificate_validation,
        "certificate": None,
        "read_write_endpoint": cfg.read_write_endpoint,
        "read_only_endpoint": cfg.read_only_endpoint,
        "port": None,
        "secret_id": secret_id,
        "tags": [ArkSIADBTag(key=t.key, value=t.value) for t in cfg.tags] or None,
        "configured_auth_method_type": cfg.configured_auth_method_type,
        "region": cfg.region,
        "provider_engine": cfg.provider_engine,
    }

    if cfg.domain_controller:
        dc_payload = cfg.domain_controller.model_dump(exclude_none=True)
        if "name" in dc_payload:
            kwargs["domain_controller_name"] = dc_payload["name"]
        if "netbios" in dc_payload:
            kwargs["domain_controller_netbios"] = dc_payload["netbios"]
        if "use_ldaps" in dc_payload:
            kwargs["domain_controller_use_ldaps"] = dc_payload["use_ldaps"]
        if "enable_certificate_validation" in dc_payload:
            kwargs["domain_controller_enable_certificate_validation"] = dc_payload["enable_certificate_validation"]
        if "ldaps_certificate" in dc_payload:
            kwargs["domain_controller_ldaps_certificate"] = dc_payload["ldaps_certificate"]

    return ArkSIADBAddDatabase(**{k: v for k, v in kwargs.items() if v is not None})


def build_target_set_model(cfg: VmTargetSetConfig, vm_secret_ids: Dict[str, str]) -> ArkSIAAddTargetSet:
    secret_id = cfg.secret_id
    if cfg.secret_ref:
        secret_id = vm_secret_ids[cfg.secret_ref]
    return ArkSIAAddTargetSet(
        name=cfg.name,
        description=cfg.description,
        provision_format=cfg.provision_format,
        enable_certificate_validation=cfg.enable_certificate_validation,
        secret_type=cfg.secret_type,
        secret_id=secret_id,
        type=cfg.type,
    )


def process_db_secrets(sia_api: ArkSIAAPI, configs: List[DbSecretConfig], reuse_existing: bool) -> Dict[str, str]:
    secret_ids: Dict[str, str] = {}
    for cfg in configs:
        secret_ids[cfg.alias] = ensure_db_secret(sia_api, cfg, reuse_existing)
    return secret_ids


def process_vm_secrets(
    sia_api: ArkSIAAPI,
    configs: List[VmSecretConfig],
    reuse_existing: bool,
    pcloud_validator: Optional[PCloudAccountValidator] = None,
) -> Tuple[Dict[str, str], Set[str]]:
    secret_ids: Dict[str, str] = {}
    skipped_aliases: Set[str] = set()
    for cfg in configs:
        if pcloud_validator and cfg.secret_type == ArkSIAVMSecretType.PCloudAccount:
            try:
                pcloud_validator.ensure_exists(cfg)
            except ValueError as exc:
                LOGGER.warning("Skipping VM secret alias '%s': %s", cfg.alias, exc)
                skipped_aliases.add(cfg.alias)
                continue
        secret_ids[cfg.alias] = ensure_vm_secret(sia_api, cfg, reuse_existing)
    return secret_ids, skipped_aliases


def process_databases(
    sia_api: ArkSIAAPI,
    configs: List[DatabaseConfig],
    db_secret_ids: Dict[str, str],
    reuse_existing: bool,
) -> List[str]:
    created: List[str] = []
    for cfg in configs:
        if reuse_existing:
            try:
                existing = sia_api.workspace_db.list_databases_by(ArkSIADBDatabasesFilter(name=cfg.name))
            except ArkServiceException as exc:
                LOGGER.warning("Unable to check existing databases for '%s': %s", cfg.name, exc)
            else:
                if existing.items:
                    LOGGER.info("Database '%s' already exists (id=%s), skipping creation", cfg.name, existing.items[0].id)
                    continue
        model = build_database_model(cfg, db_secret_ids)
        LOGGER.info("Adding SIA database '%s'", cfg.name)
        sia_api.workspace_db.add_database(model)
        created.append(cfg.name)
    return created


def process_target_sets(
    sia_api: ArkSIAAPI,
    configs: List[VmTargetSetConfig],
    vm_secret_ids: Dict[str, str],
    reuse_existing: bool,
    skipped_aliases: Set[str],
) -> List[str]:
    created: List[str] = []
    for cfg in configs:
        if cfg.secret_ref and cfg.secret_ref in skipped_aliases:
            LOGGER.warning(
                "Skipping target set '%s' because VM secret alias '%s' was previously skipped.",
                cfg.name,
                cfg.secret_ref,
            )
            continue
        if cfg.secret_ref and cfg.secret_ref not in vm_secret_ids:
            LOGGER.warning(
                "Skipping target set '%s' because VM secret alias '%s' is unavailable.",
                cfg.name,
                cfg.secret_ref,
            )
            continue
        if reuse_existing:
            try:
                existing = sia_api.workspace_target_sets.list_target_sets_by(ArkSIATargetSetsFilter(name=cfg.name))
            except ArkServiceException as exc:
                LOGGER.warning("Unable to check existing target sets for '%s': %s", cfg.name, exc)
            else:
                if existing:
                    LOGGER.info("Target set '%s' already exists, skipping creation", cfg.name)
                    continue
        model = build_target_set_model(cfg, vm_secret_ids)
        LOGGER.info("Adding SIA VM target set '%s'", cfg.name)
        sia_api.workspace_target_sets.add_target_set(model)
        created.append(cfg.name)
    return created


def authenticate_identity(auth: ArkISPAuth, inputs: Dict[str, Any], force_login: bool) -> None:
    method = inputs["mfa_method"]
    method_settings = IdentityArkAuthMethodSettings(
        identity_mfa_method="" if method == "auto" else method,
        identity_mfa_interactive=inputs["interactive_mfa"],
        identity_url=inputs["identity_url"],
        identity_tenant_subdomain=inputs["tenant_subdomain"],
        identity_application=inputs["identity_application"],
    )
    profile = ArkAuthProfile(username=inputs["username"], auth_method=ArkAuthMethod.Identity, auth_method_settings=method_settings)
    LOGGER.info("Authenticating to Identity as %s", inputs["username"])
    auth.authenticate(auth_profile=profile, secret=ArkSecret(secret=inputs["password"]), force=force_login, refresh_auth=True)


def main() -> None:
    args = parse_args()
    log_path = setup_logging(args.log_dir)
    LOGGER.info("Execution log file: %s", log_path)
    ArkSystemConfig.disable_verbose_logging()

    action = prompt_main_action()

    identity_inputs = prompt_identity_inputs()
    force_login = prompt_yes_no("Force a fresh Identity login (ignore cached tokens)?", default=False)

    isp_auth = ArkISPAuth()
    try:
        authenticate_identity(isp_auth, identity_inputs, force_login)
    except ArkAuthException as exc:
        raise SystemExit(f"Authentication failed: {exc}") from exc

    sia_api = ArkSIAAPI(isp_auth)

    if action == "workspace":
        process_db = prompt_yes_no("Process DB onboarding template?", default=True)
        process_vm = prompt_yes_no("Process VM onboarding template?", default=True)
        if not process_db and not process_vm:
            LOGGER.info("No onboarding templates selected. Nothing to do.")
            return

        reuse_existing = prompt_yes_no("Reuse existing SIA objects when matches are found?", default=True)

        db_secret_ids: Dict[str, str] = {}
        created_databases: List[str] = []
        if process_db:
            db_template_path = prompt_template_path(args.db_template, "DB onboarding template path")
            LOGGER.info("Using DB onboarding template: %s", db_template_path)
            db_template = load_db_template_csv(db_template_path)
            ensure_db_aliases(db_template.database_secrets, db_template.databases)
            db_secret_ids = process_db_secrets(sia_api, db_template.database_secrets, reuse_existing)
            created_databases = process_databases(sia_api, db_template.databases, db_secret_ids, reuse_existing)

        vm_secret_ids: Dict[str, str] = {}
        skipped_vm_aliases: Set[str] = set()
        created_target_sets: List[str] = []
        if process_vm:
            vm_template_path = prompt_template_path(args.vm_template, "VM onboarding template path")
            LOGGER.info("Using VM onboarding template: %s", vm_template_path)
            vm_template = load_vm_template_csv(vm_template_path)
            ensure_vm_aliases(vm_template.vm_secrets, vm_template.vm_target_sets)
            pcloud_validator: Optional[PCloudAccountValidator] = None
            if any(secret.secret_type == ArkSIAVMSecretType.PCloudAccount for secret in vm_template.vm_secrets):
                pcloud_validator = PCloudAccountValidator(ArkPCloudAPI(isp_auth))
            vm_secret_ids, skipped_vm_aliases = process_vm_secrets(
                sia_api, vm_template.vm_secrets, reuse_existing, pcloud_validator
            )
            created_target_sets = process_target_sets(
                sia_api,
                vm_template.vm_target_sets,
                vm_secret_ids,
                reuse_existing,
                skipped_vm_aliases,
            )

        LOGGER.info("Workspace onboarding finished.")
        if db_secret_ids:
            LOGGER.info("DB secrets loaded: %s", ", ".join(f"{alias}={sid}" for alias, sid in db_secret_ids.items()))
        if vm_secret_ids:
            LOGGER.info("VM secrets loaded: %s", ", ".join(f"{alias}={sid}" for alias, sid in vm_secret_ids.items()))
        if skipped_vm_aliases:
            LOGGER.warning("VM secrets skipped (not created): %s", ", ".join(sorted(skipped_vm_aliases)))
        if created_databases:
            LOGGER.info("Databases created: %s", ", ".join(created_databases))
        if created_target_sets:
            LOGGER.info("Target sets created: %s", ", ".join(created_target_sets))
        if not (created_databases or created_target_sets):
            LOGGER.info("No new workspaces were created.")
    else:
        process_db_policies_flag = prompt_yes_no("Process DB access policy template?", default=True)
        process_vm_policies_flag = prompt_yes_no("Process VM access policy template?", default=True)
        if not process_db_policies_flag and not process_vm_policies_flag:
            LOGGER.info("No access policy templates selected. Nothing to do.")
            return

        db_policies: List[DbPolicyConfig] = []
        if process_db_policies_flag:
            db_policy_template_path = prompt_template_path(args.db_policy_template, "DB access policy template path")
            LOGGER.info("Using DB access policy template: %s", db_policy_template_path)
            db_policies = load_db_policy_template_csv(db_policy_template_path)

        vm_policies: List[VmPolicyConfig] = []
        if process_vm_policies_flag:
            vm_policy_template_path = prompt_template_path(args.vm_policy_template, "VM access policy template path")
            LOGGER.info("Using VM access policy template: %s", vm_policy_template_path)
            vm_policies = load_vm_policy_template_csv(vm_policy_template_path)

        created_db_policies, created_vm_policies = process_access_policies(sia_api, db_policies, vm_policies)

        LOGGER.info("Access policy provisioning finished.")
        if created_db_policies:
            LOGGER.info("DB policies created: %s", ", ".join(created_db_policies))
        if created_vm_policies:
            LOGGER.info("VM policies created: %s", ", ".join(created_vm_policies))
        if not (created_db_policies or created_vm_policies):
            LOGGER.info("No new access policies were created.")

    LOGGER.info("All tasks completed successfully.")


if __name__ == "__main__":
    try:
        main()
    except (ArkServiceException, ValueError, FileNotFoundError) as error:
        raise SystemExit(f"Error: {error}") from error
