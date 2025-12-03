from __future__ import annotations

import base64
import re
from ipaddress import ip_address
from typing import Any, Dict, List
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.schemas import AdvancedCertConfig, CustomExtension, SimpleCertConfig
from app.services.crypto_service import (
    generate_self_signed_cert_advanced,
    generate_self_signed_cert_simple,
)
from app.services.quick_cert_service import save_quick_cert_to_db
from app.templating import get_templates

router = APIRouter(tags=["quick-cert"])

templates = get_templates()

VALIDITY_MIN_DAYS = 1
VALIDITY_MAX_DAYS = 3650
CUSTOM_EXTENSION_SLOTS = 3

DEFAULT_SIMPLE_FORM_VALUES: Dict[str, Any] = {
    "common_name": "",
    "dns_sans": "",
    "ip_sans": "",
    "organization": "",
    "organizational_unit": "",
    "country": "",
    "state": "",
    "locality": "",
    "key_algorithm": "RSA",
    "key_size": 2048,
    "curve": "P-256",
    "hash_algorithm": "SHA256",
    "validity_days": 90,
    "usage_preset": "server_tls",
    "output_pem_cert": True,
    "output_pem_key": True,
    "output_combined_pem": False,
    "output_pfx": False,
    "pfx_password": "",
    "pfx_password_confirm": "",
    "label": "",
    "store_in_labca": False,
}

DEFAULT_ADVANCED_FORM_VALUES: Dict[str, Any] = {
    "common_name": "",
    "dns_sans": "",
    "ip_sans": "",
    "organization": "",
    "organizational_unit": "",
    "country": "",
    "state": "",
    "locality": "",
    "key_algorithm": "RSA",
    "key_size": 2048,
    "curve": "P-256",
    "hash_algorithm": "SHA256",
    "validity_days": 365,
    "output_pem_cert": True,
    "output_pem_key": True,
    "output_combined_pem": False,
    "output_pfx": False,
    "pfx_password": "",
    "pfx_password_confirm": "",
    "label": "",
    "store_in_labca": False,
    "is_ca": False,
    "path_length": "",
    "key_usage_digital_signature": True,
    "key_usage_non_repudiation": False,
    "key_usage_key_encipherment": True,
    "key_usage_data_encipherment": False,
    "key_usage_key_agreement": False,
    "key_usage_key_cert_sign": False,
    "key_usage_crl_sign": False,
    "key_usage_encipher_only": False,
    "key_usage_decipher_only": False,
    "eku_server_auth": True,
    "eku_client_auth": False,
    "eku_code_signing": False,
    "eku_email_protection": False,
    "eku_time_stamping": False,
    "eku_ocsp_signing": False,
    "eku_custom_oids": "",
    "subject_key_identifier": "auto",
    "authority_key_identifier": "match_subject",
    "crl_distribution_points": "",
    "ocsp_urls": "",
    "custom_extensions": [
        {"oid": "", "critical": False, "value": ""},
        {"oid": "", "critical": False, "value": ""},
        {"oid": "", "critical": False, "value": ""},
    ],
}

OID_PATTERN = re.compile(r"^\d+(\.\d+)*$")


@router.get("/quick-cert", response_class=HTMLResponse)
def quick_cert_form(request: Request) -> HTMLResponse:
    current_mode = request.query_params.get("mode", "simple")
    if current_mode not in {"simple", "advanced"}:
        current_mode = "simple"
    form_values = _prefill_form_from_query(request, current_mode)
    context = {
        "request": request,
        "current_mode": current_mode,
        "form_values": form_values,
        "form_errors": [],
        "validity_min": VALIDITY_MIN_DAYS,
        "validity_max": VALIDITY_MAX_DAYS,
        "custom_extension_slots": CUSTOM_EXTENSION_SLOTS,
    }
    return templates.TemplateResponse("quick_cert.html", context)


@router.post("/quick-cert", response_class=HTMLResponse)
async def quick_cert_generate(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    form = await request.form()
    mode = form.get("mode", "simple")
    if mode == "advanced":
        return await _handle_advanced_submission(request, form, db)
    return await _handle_simple_submission(request, form, db)


async def _handle_simple_submission(request: Request, form: Any, db: Session) -> HTMLResponse:
    form_errors: list[str] = []
    sanitized_common_name = form.get("common_name", "").strip()
    if not sanitized_common_name:
        form_errors.append("Common name (CN) is required.")

    validity = _parse_int(form.get("validity_days", DEFAULT_SIMPLE_FORM_VALUES["validity_days"]))
    if validity is None or not (VALIDITY_MIN_DAYS <= validity <= VALIDITY_MAX_DAYS):
        form_errors.append(f"Validity must be between {VALIDITY_MIN_DAYS} and {VALIDITY_MAX_DAYS} days.")
        validity = DEFAULT_SIMPLE_FORM_VALUES["validity_days"]

    sanitized_dns = _split_csv(form.get("dns_sans", ""))
    sanitized_ip, ip_errors = _parse_ip_list(form.get("ip_sans", ""))
    form_errors.extend(ip_errors)

    outputs = _extract_output_flags(form)
    if not any(outputs.values()):
        form_errors.append("Select at least one output format to generate.")
    store_in_labca = _parse_checkbox(form, "store_in_labca")

    sanitized_password = form.get("pfx_password", "").strip()
    password_confirm = form.get("pfx_password_confirm", "").strip()
    if outputs["output_pfx"]:
        if not sanitized_password:
            form_errors.append("PFX password is required when exporting PFX.")
        elif sanitized_password != password_confirm:
            form_errors.append("PFX password confirmation does not match.")

    sanitized_form_values = {
        **DEFAULT_SIMPLE_FORM_VALUES,
        "common_name": sanitized_common_name,
        "dns_sans": ",".join(sanitized_dns),
        "ip_sans": ",".join(sanitized_ip),
        "organization": form.get("organization", "").strip(),
        "organizational_unit": form.get("organizational_unit", "").strip(),
        "country": form.get("country", "").strip(),
        "state": form.get("state", "").strip(),
        "locality": form.get("locality", "").strip(),
        "key_algorithm": form.get("key_algorithm", "RSA"),
        "key_size": _parse_int(form.get("key_size", 2048)) or 2048,
        "curve": form.get("curve", "P-256"),
        "hash_algorithm": form.get("hash_algorithm", "SHA256"),
        "validity_days": validity,
        "usage_preset": form.get("usage_preset", "server_tls"),
        "output_pem_cert": outputs["output_pem_cert"],
        "output_pem_key": outputs["output_pem_key"],
        "output_combined_pem": outputs["output_combined_pem"],
        "output_pfx": outputs["output_pfx"],
        "pfx_password": sanitized_password if form_errors else "",
        "pfx_password_confirm": password_confirm if form_errors else "",
        "label": form.get("label", "").strip(),
        "store_in_labca": store_in_labca,
    }

    if form_errors:
        return _render_form(
            request,
            mode="simple",
            form_values=sanitized_form_values,
            form_errors=form_errors,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    try:
        config = SimpleCertConfig(
            common_name=sanitized_common_name,
            dns_sans=sanitized_dns,
            ip_sans=sanitized_ip,
            organization=sanitized_form_values["organization"] or None,
            organizational_unit=sanitized_form_values["organizational_unit"] or None,
            country=sanitized_form_values["country"] or None,
            state=sanitized_form_values["state"] or None,
            locality=sanitized_form_values["locality"] or None,
            key_algorithm=sanitized_form_values["key_algorithm"],
            key_size=sanitized_form_values["key_size"] if sanitized_form_values["key_algorithm"] == "RSA" else None,
            curve=sanitized_form_values["curve"] if sanitized_form_values["key_algorithm"] == "ECDSA" else None,
            hash_algorithm=sanitized_form_values["hash_algorithm"],
            validity_days=validity,
            usage_preset=sanitized_form_values["usage_preset"],
            output_pem_cert=outputs["output_pem_cert"],
            output_pem_key=outputs["output_pem_key"],
            output_combined_pem=outputs["output_combined_pem"],
            output_pfx=outputs["output_pfx"],
            pfx_password=sanitized_password or None,
            label=sanitized_form_values["label"] or None,
        )
        bundle = generate_self_signed_cert_simple(config)
    except ValueError as exc:
        return _render_form(
            request,
            mode="simple",
            form_values=sanitized_form_values,
            form_errors=[str(exc)],
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if store_in_labca:
        try:
            certificate = save_quick_cert_to_db(bundle, config, db, store_in_labca=True)
        except ValueError as exc:
            return _render_form(
                request,
                mode="simple",
                form_values=sanitized_form_values,
                form_errors=[str(exc)],
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return RedirectResponse(
            url=f"/certificates/{certificate.id}?source=quick",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    artefacts = _build_download_links(bundle)
    text_blocks = _build_text_blocks(bundle)
    prefill_url = _build_prefill_url("simple", sanitized_form_values)

    context = {
        "request": request,
        "bundle": bundle,
        "artefacts": artefacts,
        "text_blocks": text_blocks,
        "validity_days": validity,
        "prefill_url": prefill_url,
    }
    return templates.TemplateResponse("quick_cert_result.html", context)


async def _handle_advanced_submission(request: Request, form: Any, db: Session) -> HTMLResponse:
    form_errors: list[str] = []
    sanitized_common_name = form.get("common_name", "").strip()
    if not sanitized_common_name:
        form_errors.append("Common name (CN) is required.")

    validity = _parse_int(form.get("validity_days", DEFAULT_ADVANCED_FORM_VALUES["validity_days"]))
    if validity is None or not (VALIDITY_MIN_DAYS <= validity <= VALIDITY_MAX_DAYS):
        form_errors.append(f"Validity must be between {VALIDITY_MIN_DAYS} and {VALIDITY_MAX_DAYS} days.")
        validity = DEFAULT_ADVANCED_FORM_VALUES["validity_days"]

    sanitized_dns = _split_csv(form.get("dns_sans", ""))
    sanitized_ip, ip_errors = _parse_ip_list(form.get("ip_sans", ""))
    form_errors.extend(ip_errors)

    outputs = _extract_output_flags(form)
    if not any(outputs.values()):
        form_errors.append("Select at least one output format to generate.")
    store_in_labca = _parse_checkbox(form, "store_in_labca")

    sanitized_password = form.get("pfx_password", "").strip()
    password_confirm = form.get("pfx_password_confirm", "").strip()
    if outputs["output_pfx"]:
        if not sanitized_password:
            form_errors.append("PFX password is required when exporting PFX.")
        elif sanitized_password != password_confirm:
            form_errors.append("PFX password confirmation does not match.")

    is_ca = _parse_checkbox(form, "is_ca")
    path_length_value = form.get("path_length", "").strip()
    path_length = _parse_int(path_length_value) if path_length_value else None

    key_usage_flags = {
        "key_usage_digital_signature": _parse_checkbox(form, "key_usage_digital_signature"),
        "key_usage_non_repudiation": _parse_checkbox(form, "key_usage_non_repudiation"),
        "key_usage_key_encipherment": _parse_checkbox(form, "key_usage_key_encipherment"),
        "key_usage_data_encipherment": _parse_checkbox(form, "key_usage_data_encipherment"),
        "key_usage_key_agreement": _parse_checkbox(form, "key_usage_key_agreement"),
        "key_usage_key_cert_sign": _parse_checkbox(form, "key_usage_key_cert_sign"),
        "key_usage_crl_sign": _parse_checkbox(form, "key_usage_crl_sign"),
        "key_usage_encipher_only": _parse_checkbox(form, "key_usage_encipher_only"),
        "key_usage_decipher_only": _parse_checkbox(form, "key_usage_decipher_only"),
    }

    if is_ca and not key_usage_flags["key_usage_key_cert_sign"]:
        form_errors.append("CA certificates must enable the Key Cert Sign usage.")

    eku_flags = {
        "eku_server_auth": _parse_checkbox(form, "eku_server_auth"),
        "eku_client_auth": _parse_checkbox(form, "eku_client_auth"),
        "eku_code_signing": _parse_checkbox(form, "eku_code_signing"),
        "eku_email_protection": _parse_checkbox(form, "eku_email_protection"),
        "eku_time_stamping": _parse_checkbox(form, "eku_time_stamping"),
        "eku_ocsp_signing": _parse_checkbox(form, "eku_ocsp_signing"),
    }
    eku_custom_oids = _split_csv(form.get("eku_custom_oids", ""))
    for oid in eku_custom_oids:
        if not OID_PATTERN.match(oid):
            form_errors.append(f"Custom EKU OID '{oid}' must be a dotted numeric string.")

    crl_points = _split_multiline(form.get("crl_distribution_points", ""))
    ocsp_urls = _split_multiline(form.get("ocsp_urls", ""))

    custom_extensions, custom_extension_values, custom_ext_errors = _extract_custom_extensions(form)
    form_errors.extend(custom_ext_errors)

    sanitized_form_values = {
        **DEFAULT_ADVANCED_FORM_VALUES,
        "common_name": sanitized_common_name,
        "dns_sans": ",".join(sanitized_dns),
        "ip_sans": ",".join(sanitized_ip),
        "organization": form.get("organization", "").strip(),
        "organizational_unit": form.get("organizational_unit", "").strip(),
        "country": form.get("country", "").strip(),
        "state": form.get("state", "").strip(),
        "locality": form.get("locality", "").strip(),
        "key_algorithm": form.get("key_algorithm", "RSA"),
        "key_size": _parse_int(form.get("key_size", 2048)) or 2048,
        "curve": form.get("curve", "P-256"),
        "hash_algorithm": form.get("hash_algorithm", "SHA256"),
        "validity_days": validity,
        "output_pem_cert": outputs["output_pem_cert"],
        "output_pem_key": outputs["output_pem_key"],
        "output_combined_pem": outputs["output_combined_pem"],
        "output_pfx": outputs["output_pfx"],
        "pfx_password": sanitized_password if form_errors else "",
        "pfx_password_confirm": password_confirm if form_errors else "",
        "label": form.get("label", "").strip(),
        "store_in_labca": store_in_labca,
        "is_ca": is_ca,
        "path_length": path_length_value,
        **key_usage_flags,
        **eku_flags,
        "eku_custom_oids": ",".join(eku_custom_oids),
        "subject_key_identifier": form.get("subject_key_identifier", "auto"),
        "authority_key_identifier": form.get("authority_key_identifier", "match_subject"),
        "crl_distribution_points": "\n".join(crl_points),
        "ocsp_urls": "\n".join(ocsp_urls),
        "custom_extensions": custom_extension_values,
    }

    if form_errors:
        return _render_form(
            request,
            mode="advanced",
            form_values=sanitized_form_values,
            form_errors=form_errors,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    try:
        config = AdvancedCertConfig(
            common_name=sanitized_common_name,
            dns_sans=sanitized_dns,
            ip_sans=sanitized_ip,
            organization=sanitized_form_values["organization"] or None,
            organizational_unit=sanitized_form_values["organizational_unit"] or None,
            country=sanitized_form_values["country"] or None,
            state=sanitized_form_values["state"] or None,
            locality=sanitized_form_values["locality"] or None,
            key_algorithm=sanitized_form_values["key_algorithm"],
            key_size=sanitized_form_values["key_size"] if sanitized_form_values["key_algorithm"] == "RSA" else None,
            curve=sanitized_form_values["curve"] if sanitized_form_values["key_algorithm"] == "ECDSA" else None,
            hash_algorithm=sanitized_form_values["hash_algorithm"],
            validity_days=validity,
            usage_preset="advanced",
            output_pem_cert=outputs["output_pem_cert"],
            output_pem_key=outputs["output_pem_key"],
            output_combined_pem=outputs["output_combined_pem"],
            output_pfx=outputs["output_pfx"],
            pfx_password=sanitized_password or None,
            label=sanitized_form_values["label"] or None,
            is_ca=is_ca,
            path_length=path_length if is_ca else None,
            key_usage_digital_signature=key_usage_flags["key_usage_digital_signature"],
            key_usage_non_repudiation=key_usage_flags["key_usage_non_repudiation"],
            key_usage_key_encipherment=key_usage_flags["key_usage_key_encipherment"],
            key_usage_data_encipherment=key_usage_flags["key_usage_data_encipherment"],
            key_usage_key_agreement=key_usage_flags["key_usage_key_agreement"],
            key_usage_key_cert_sign=key_usage_flags["key_usage_key_cert_sign"],
            key_usage_crl_sign=key_usage_flags["key_usage_crl_sign"],
            key_usage_encipher_only=key_usage_flags["key_usage_encipher_only"],
            key_usage_decipher_only=key_usage_flags["key_usage_decipher_only"],
            eku_server_auth=eku_flags["eku_server_auth"],
            eku_client_auth=eku_flags["eku_client_auth"],
            eku_code_signing=eku_flags["eku_code_signing"],
            eku_email_protection=eku_flags["eku_email_protection"],
            eku_time_stamping=eku_flags["eku_time_stamping"],
            eku_ocsp_signing=eku_flags["eku_ocsp_signing"],
            eku_custom_oids=eku_custom_oids,
            subject_key_identifier=sanitized_form_values["subject_key_identifier"],
            authority_key_identifier=sanitized_form_values["authority_key_identifier"],
            crl_distribution_points=crl_points,
            ocsp_urls=ocsp_urls,
            custom_extensions=custom_extensions,
        )
        bundle = generate_self_signed_cert_advanced(config)
    except ValueError as exc:
        return _render_form(
            request,
            mode="advanced",
            form_values=sanitized_form_values,
            form_errors=[str(exc)],
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if store_in_labca:
        try:
            certificate = save_quick_cert_to_db(bundle, config, db, store_in_labca=True)
        except ValueError as exc:
            return _render_form(
                request,
                mode="advanced",
                form_values=sanitized_form_values,
                form_errors=[str(exc)],
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return RedirectResponse(
            url=f"/certificates/{certificate.id}?source=quick",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    artefacts = _build_download_links(bundle)
    text_blocks = _build_text_blocks(bundle)
    prefill_url = _build_prefill_url("advanced", sanitized_form_values)

    context = {
        "request": request,
        "bundle": bundle,
        "artefacts": artefacts,
        "text_blocks": text_blocks,
        "validity_days": validity,
        "prefill_url": prefill_url,
    }
    return templates.TemplateResponse("quick_cert_result.html", context)


def _render_form(
    request: Request,
    mode: str,
    form_values: Dict[str, Any],
    form_errors: List[str],
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    context = {
        "request": request,
        "current_mode": mode,
        "form_values": form_values,
        "form_errors": form_errors,
        "validity_min": VALIDITY_MIN_DAYS,
        "validity_max": VALIDITY_MAX_DAYS,
        "custom_extension_slots": CUSTOM_EXTENSION_SLOTS,
    }
    return templates.TemplateResponse("quick_cert.html", context, status_code=status_code)


def _prefill_form_from_query(request: Request, mode: str) -> Dict[str, Any]:
    defaults = DEFAULT_ADVANCED_FORM_VALUES if mode == "advanced" else DEFAULT_SIMPLE_FORM_VALUES
    form_values: Dict[str, Any] = {}
    for key, default in defaults.items():
        if key == "custom_extensions":
            form_values[key] = [entry.copy() for entry in default]
            continue
        raw_value = request.query_params.get(key)
        if raw_value is None:
            form_values[key] = default
            continue
        if isinstance(default, bool):
            form_values[key] = raw_value.lower() in {"1", "true", "on", "yes"}
        elif isinstance(default, int):
            try:
                form_values[key] = int(raw_value)
            except ValueError:
                form_values[key] = default
        else:
            form_values[key] = raw_value
    if mode == "advanced":
        form_values.setdefault(
            "custom_extensions",
            [entry.copy() for entry in DEFAULT_ADVANCED_FORM_VALUES["custom_extensions"]],
        )
    return form_values


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _split_multiline(value: str) -> list[str]:
    normalized = value.replace("\r", ",").replace("\n", ",")
    return _split_csv(normalized)


def _parse_ip_list(value: str) -> tuple[list[str], list[str]]:
    ips: list[str] = []
    errors: list[str] = []
    for raw in _split_csv(value):
        try:
            ip_address(raw)
            ips.append(raw)
        except ValueError:
            errors.append(f"Invalid IP address: {raw}")
    return ips, errors


def _parse_checkbox(form: Any, key: str) -> bool:
    value = form.get(key)
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "on", "yes"}


def _parse_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_output_flags(form: Any) -> Dict[str, bool]:
    return {
        "output_pem_cert": _parse_checkbox(form, "output_pem_cert"),
        "output_pem_key": _parse_checkbox(form, "output_pem_key"),
        "output_combined_pem": _parse_checkbox(form, "output_combined_pem"),
        "output_pfx": _parse_checkbox(form, "output_pfx"),
    }


def _extract_custom_extensions(form: Any) -> tuple[list[CustomExtension], list[dict[str, Any]], list[str]]:
    extensions: list[CustomExtension] = []
    ui_values: list[dict[str, Any]] = []
    errors: list[str] = []
    for idx in range(CUSTOM_EXTENSION_SLOTS):
        oid = form.get(f"custom_extensions-{idx}-oid", "").strip()
        critical = _parse_checkbox(form, f"custom_extensions-{idx}-critical")
        value = form.get(f"custom_extensions-{idx}-value", "").strip()
        ui_values.append({"oid": oid, "critical": critical, "value": value})
        if not oid and not value:
            continue
        if not oid:
            errors.append(f"Custom extension #{idx + 1} requires an OID when a value is provided.")
            continue
        if not OID_PATTERN.match(oid):
            errors.append(f"Custom extension OID '{oid}' is invalid.")
            continue
        extensions.append(CustomExtension(oid=oid, critical=critical, value=value))
    return extensions, ui_values, errors


def _build_download_links(bundle) -> list[dict[str, str]]:
    links: list[dict[str, str]] = []
    if bundle.cert_pem:
        links.append(
            {
                "label": "Download certificate (.pem)",
                "filename": "labca-cert.pem",
                "href": _bytes_to_data_uri(bundle.cert_pem, "application/x-pem-file"),
            }
        )
    if bundle.key_pem:
        links.append(
            {
                "label": "Download private key (.pem)",
                "filename": "labca-key.pem",
                "href": _bytes_to_data_uri(bundle.key_pem, "application/x-pem-file"),
            }
        )
    if bundle.combined_pem:
        links.append(
            {
                "label": "Download combined PEM",
                "filename": "labca-bundle.pem",
                "href": _bytes_to_data_uri(bundle.combined_pem, "application/x-pem-file"),
            }
        )
    if bundle.pfx:
        links.append(
            {
                "label": "Download PFX (.p12)",
                "filename": "labca-cert.p12",
                "href": _bytes_to_data_uri(bundle.pfx, "application/x-pkcs12"),
            }
        )
    return links


def _build_text_blocks(bundle) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    if bundle.cert_pem:
        blocks.append({"id": "cert-pem", "label": "Certificate (PEM)", "content": bundle.cert_pem.decode("utf-8")})
    if bundle.key_pem:
        blocks.append({"id": "key-pem", "label": "Private key (PEM)", "content": bundle.key_pem.decode("utf-8")})
    if bundle.combined_pem:
        blocks.append({"id": "combined-pem", "label": "Combined PEM", "content": bundle.combined_pem.decode("utf-8")})
    return blocks


def _bytes_to_data_uri(content: bytes, mime_type: str) -> str:
    encoded = base64.b64encode(content).decode("ascii")
    return f"data:{mime_type};base64,{encoded}"


def _build_prefill_url(mode: str, form_values: Dict[str, Any]) -> str:
    params = {"mode": mode}
    for key, value in form_values.items():
        if key in {
            "output_pem_cert",
            "output_pem_key",
            "output_combined_pem",
            "output_pfx",
            "pfx_password",
            "pfx_password_confirm",
            "custom_extensions",
        }:
            continue
        if isinstance(value, bool):
            params[key] = "true" if value else "false"
        elif isinstance(value, int):
            params[key] = str(value)
        elif isinstance(value, str) and value:
            params[key] = value
    query = urlencode(params)
    return f"/quick-cert?{query}" if query else "/quick-cert"
