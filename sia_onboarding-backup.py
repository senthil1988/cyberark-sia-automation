#!/usr/bin/env python3
"""CSV-powered CyberArk SIA onboarding helper."""

from __future__ import annotations

import argparse
import csv
import json
import logging
from dataclasses import dataclass, field
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, Field, ValidationError

from ark_sdk_python.auth import ArkISPAuth
from ark_sdk_python.common import ArkSystemConfig
from ark_sdk_python.models import ArkAuthException, ArkServiceException
from ark_sdk_python.models.auth import ArkAuthMethod, ArkAuthProfile, ArkSecret, IdentityArkAuthMethodSettings
from ark_sdk_python.models.common import ArkWorkspaceType
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
from ark_sdk_python.services.sia import ArkSIAAPI

LOGGER = logging.getLogger("sia_onboarding")
SUPPORTED_MFA_METHODS: List[str] = ["pf", "sms", "email", "otp", "oath", "auto"]


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
class TemplateData:
    database_secrets: List[DbSecretConfig] = field(default_factory=list)
    vm_secrets: List[VmSecretConfig] = field(default_factory=list)
    databases: List[DatabaseConfig] = field(default_factory=list)
    vm_target_sets: List[VmTargetSetConfig] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Onboard CyberArk SIA databases and VMs from a CSV template.")
    parser.add_argument(
        "-t",
        "--template",
        type=Path,
        default=Path("sia_onboarding_template.csv"),
        help="Path to the onboarding template CSV file.",
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


def load_template_csv(path: Path) -> TemplateData:
    if not path.exists():
        raise FileNotFoundError(f"Template file '{path}' does not exist")
    template = TemplateData()
    db_aliases: set[str] = set()
    vm_aliases: set[str] = set()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "record_type" not in reader.fieldnames:
            raise ValueError("The CSV file must include a 'record_type' header column.")
        for index, row in enumerate(reader, start=2):  # account for header
            if not row:
                continue
            record_type = strip_value(row.get("record_type"))
            if not record_type:
                continue
            try:
                record_key = record_type.lower()
                if record_key == "db_secret":
                    alias = require_value(row, "alias", index)
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
                elif record_key == "vm_secret":
                    alias = require_value(row, "alias", index)
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


def ensure_aliases(template: TemplateData) -> None:
    defined_db_aliases = {secret.alias for secret in template.database_secrets}
    defined_vm_aliases = {secret.alias for secret in template.vm_secrets}

    def validate_alias(alias: Optional[str], known_aliases: Iterable[str], label: str) -> None:
        if alias and alias not in known_aliases:
            raise ValueError(f"{label} alias '{alias}' is referenced but not defined as a secret.")

    for db in template.databases:
        validate_alias(db.secret_ref, defined_db_aliases, f"Database '{db.name}' secret")
        for service in db.services:
            validate_alias(service.secret_ref, defined_db_aliases, f"Database '{db.name}' service '{service.service_name}' secret")
    for target in template.vm_target_sets:
        validate_alias(target.secret_ref, defined_vm_aliases, f"Target set '{target.name}' secret")


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


def process_vm_secrets(sia_api: ArkSIAAPI, configs: List[VmSecretConfig], reuse_existing: bool) -> Dict[str, str]:
    secret_ids: Dict[str, str] = {}
    for cfg in configs:
        secret_ids[cfg.alias] = ensure_vm_secret(sia_api, cfg, reuse_existing)
    return secret_ids


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
) -> List[str]:
    created: List[str] = []
    for cfg in configs:
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
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    ArkSystemConfig.disable_verbose_logging()

    template = load_template_csv(args.template)
    ensure_aliases(template)

    identity_inputs = prompt_identity_inputs()
    force_login = prompt_yes_no("Force a fresh Identity login (ignore cached tokens)?", default=False)
    reuse_existing = prompt_yes_no("Reuse existing SIA objects when matches are found?", default=True)

    isp_auth = ArkISPAuth()
    try:
        authenticate_identity(isp_auth, identity_inputs, force_login)
    except ArkAuthException as exc:
        raise SystemExit(f"Authentication failed: {exc}") from exc

    sia_api = ArkSIAAPI(isp_auth)

    db_secret_ids = process_db_secrets(sia_api, template.database_secrets, reuse_existing)
    vm_secret_ids = process_vm_secrets(sia_api, template.vm_secrets, reuse_existing)
    created_databases = process_databases(sia_api, template.databases, db_secret_ids, reuse_existing)
    created_target_sets = process_target_sets(sia_api, template.vm_target_sets, vm_secret_ids, reuse_existing)

    LOGGER.info("\nOnboarding finished.")
    if db_secret_ids:
        LOGGER.info("DB secrets loaded: %s", ", ".join(f"{alias}={sid}" for alias, sid in db_secret_ids.items()))
    if vm_secret_ids:
        LOGGER.info("VM secrets loaded: %s", ", ".join(f"{alias}={sid}" for alias, sid in vm_secret_ids.items()))
    LOGGER.info("Databases created: %s", ", ".join(created_databases) or "none")
    LOGGER.info("Target sets created: %s", ", ".join(created_target_sets) or "none")


if __name__ == "__main__":
    try:
        main()
    except (ArkServiceException, ValueError, FileNotFoundError) as error:
        raise SystemExit(f"Error: {error}") from error
