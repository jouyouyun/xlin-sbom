# Copyright 2024 Linx Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Linx SBOM → SPDX 2.2/2.3 Document / SPDX 3.0 Payload 转换与写出。"""

from __future__ import annotations

import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Union

from actions import ASSIST_DIR
from actions.common.spdx_licensing import get_spdx_licensing
from actions.data_helper import read_data_from_json
from actions.spdx.model import (
    Actor,
    ActorType,
    Checksum,
    ChecksumAlgorithm,
    CreationInfo,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    ExtractedLicensingInfo,
    File,
    Package,
    Relationship,
    RelationshipType,
    SpdxNoAssertion,
    SpdxNone,
)
from actions.spdx.validation.document_validator import validate_full_spdx_document
from actions.spdx.writer.json.json_writer import write_document_to_file
from actions.spdx3.bump_from_spdx2.spdx_document import bump_spdx_document
from actions.spdx3.payload import Payload
from actions.spdx3.writer.json_ld.json_ld_writer import write_payload

_ALGORITHM_MAP = {
    "SHA1": ChecksumAlgorithm.SHA1,
    "SHA-1": ChecksumAlgorithm.SHA1,
    "SHA224": ChecksumAlgorithm.SHA224,
    "SHA256": ChecksumAlgorithm.SHA256,
    "SHA-256": ChecksumAlgorithm.SHA256,
    "SHA384": ChecksumAlgorithm.SHA384,
    "SHA512": ChecksumAlgorithm.SHA512,
    "SHA-512": ChecksumAlgorithm.SHA512,
    "SHA3_256": ChecksumAlgorithm.SHA3_256,
    "SHA3-256": ChecksumAlgorithm.SHA3_256,
    "SHA3_384": ChecksumAlgorithm.SHA3_384,
    "SHA3-384": ChecksumAlgorithm.SHA3_384,
    "SHA3_512": ChecksumAlgorithm.SHA3_512,
    "SHA3-512": ChecksumAlgorithm.SHA3_512,
    "MD5": ChecksumAlgorithm.MD5,
    "MD2": ChecksumAlgorithm.MD2,
    "MD4": ChecksumAlgorithm.MD4,
    "MD6": ChecksumAlgorithm.MD6,
    "BLAKE2B_256": ChecksumAlgorithm.BLAKE2B_256,
    "BLAKE2B_384": ChecksumAlgorithm.BLAKE2B_384,
    "BLAKE2B_512": ChecksumAlgorithm.BLAKE2B_512,
    "BLAKE3": ChecksumAlgorithm.BLAKE3,
    "ADLER32": ChecksumAlgorithm.ADLER32,
}

# SPDX-2.2 拒绝的 checksum 算法（tools-python validation）
_SPDX22_UNSUPPORTED_ALGORITHMS = {
    ChecksumAlgorithm.SHA3_256,
    ChecksumAlgorithm.SHA3_384,
    ChecksumAlgorithm.SHA3_512,
    ChecksumAlgorithm.BLAKE2B_256,
    ChecksumAlgorithm.BLAKE2B_384,
    ChecksumAlgorithm.BLAKE2B_512,
    ChecksumAlgorithm.BLAKE3,
    ChecksumAlgorithm.ADLER32,
}

_SPDX22_UNSUPPORTED_RELATIONSHIPS = {
    RelationshipType.SPECIFICATION_FOR,
    RelationshipType.REQUIREMENT_DESCRIPTION_FOR,
}

_SPDX_ID_SAFE = re.compile(r"[^A-Za-z0-9.\-]")


def convert_to_spdx_document(
    linx_sbom: Dict[str, Any],
    filename: str,
    created_time: str,
    package_type: str,
    spdx_version: str = "SPDX-2.3",
) -> Document:
    """将 Linx SBOM 映射为符合目标版本校验规则的 SPDX Document。"""
    if spdx_version not in ("SPDX-2.2", "SPDX-2.3"):
        raise ValueError(f"不支持的 SPDX 版本: {spdx_version}")

    creators = _parse_creators()
    created = _parse_created_time(created_time)
    safe_name = _SPDX_ID_SAFE.sub("-", filename) or "document"
    document_namespace = (
        f"https://spdx.org/spdxdocs/xlin-sbom-{safe_name}-{uuid.uuid4()}"
    )

    creation_info = CreationInfo(
        spdx_version=spdx_version,
        spdx_id="SPDXRef-DOCUMENT",
        name=filename,
        document_namespace=document_namespace,
        creators=creators,
        created=created,
    )

    packages = [
        _build_package(package, package_type, spdx_version)
        for package in linx_sbom.get("packages_sbom", {}).get("packages", [])
    ]
    files: List[File] = []
    for file_info in linx_sbom.get("files_sbom", {}).get("files", []):
        built = _build_file(file_info, spdx_version)
        if built is not None:
            files.append(built)

    known_ids = (
        {creation_info.spdx_id}
        | {package.spdx_id for package in packages}
        | {file_elem.spdx_id for file_elem in files}
    )
    relationships = _build_relationships(linx_sbom, spdx_version)
    relationships = _ensure_describes(
        relationships, packages, files, creation_info.spdx_id
    )

    extracted = [
        _build_extracted_licensing_info(license_info)
        for license_info in linx_sbom.get("licenses_sbom", {}).get("licenses", [])
    ]

    return Document(
        creation_info=creation_info,
        packages=packages,
        files=files,
        relationships=relationships,
        extracted_licensing_info=extracted,
    )


def write_spdx23(document: Document, path: str) -> None:
    """校验并通过后写出 SPDX 2.3 JSON。失败抛出 ValueError，不落盘。"""
    _validate_or_raise(document, "SPDX-2.3")
    write_document_to_file(document, path, validate=False)


def write_spdx22(document: Document, path: str) -> None:
    """校验并通过后写出 SPDX 2.2 JSON。失败抛出 ValueError，不落盘。"""
    if document.creation_info.spdx_version != "SPDX-2.2":
        raise ValueError("write_spdx22 需要 spdx_version 为 SPDX-2.2 的 Document")
    _validate_or_raise(document, "SPDX-2.2")
    write_document_to_file(document, path, validate=False)


def convert_to_spdx3_payload(
    linx_sbom: Dict[str, Any],
    filename: str,
    created_time: str,
    package_type: str,
) -> Payload:
    """Linx → SPDX 2.3 Document（校验通过）→ SPDX 3.0 Payload。"""
    document = convert_to_spdx_document(
        linx_sbom, filename, created_time, package_type, spdx_version="SPDX-2.3"
    )
    _validate_or_raise(document, "SPDX-2.3")
    return bump_spdx_document(document)


def write_spdx3_payload(payload: Payload, path_without_ext: str) -> str:
    """写出 JSON-LD（write_payload 会追加 .jsonld）。返回最终路径。"""
    write_payload(payload, path_without_ext)
    return f"{path_without_ext}.jsonld"


def _validate_or_raise(document: Document, spdx_version: str) -> None:
    messages = validate_full_spdx_document(document, spdx_version)
    if messages:
        detail = "; ".join(str(message) for message in messages)
        logging.error(f"SPDX {spdx_version} 校验失败，不写出文件: {detail}")
        raise ValueError(f"SPDX {spdx_version} 校验失败: {detail}")


def _parse_created_time(created_time: str) -> datetime:
    text = created_time.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_creators() -> List[Actor]:
    creators_file_path = os.path.join(ASSIST_DIR, "creators.json")
    raw_creators = read_data_from_json(creators_file_path) or []
    actors: List[Actor] = []
    tool_version: Optional[str] = None
    pending_tool_name: Optional[str] = None

    for entry in raw_creators:
        if not isinstance(entry, str):
            continue
        if entry.startswith("Version:"):
            tool_version = entry.split(":", 1)[1].strip()
            continue
        if entry.startswith("Organization:"):
            name = entry.split(":", 1)[1].strip()
            actors.append(Actor(ActorType.ORGANIZATION, name))
        elif entry.startswith("Person:"):
            name = entry.split(":", 1)[1].strip()
            actors.append(Actor(ActorType.PERSON, name))
        elif entry.startswith("Tool:"):
            pending_tool_name = entry.split(":", 1)[1].strip()

    if pending_tool_name:
        tool_name = (
            f"{pending_tool_name}-{tool_version}"
            if tool_version
            else pending_tool_name
        )
        actors.append(Actor(ActorType.TOOL, tool_name))

    if not actors:
        actors.append(Actor(ActorType.TOOL, "XiLing SBOM Tool"))
    return actors


def _spdx_id(element_id: str) -> str:
    safe = _SPDX_ID_SAFE.sub("-", element_id)
    if not safe.startswith("SPDXRef-"):
        safe = f"SPDXRef-{safe}"
    return safe


def _license_or_noassertion(
    expression: Optional[str],
) -> Union[Any, SpdxNoAssertion, SpdxNone]:
    if expression is None or expression == "" or expression == "NOASSERTION":
        return SpdxNoAssertion()
    if expression == "NONE":
        return SpdxNone()
    try:
        return get_spdx_licensing().parse(expression)
    except Exception:
        logging.warning(f"无法解析许可证表达式，改用 NOASSERTION: {expression}")
        return SpdxNoAssertion()


def _map_checksum(
    algorithm: Optional[str], value: Optional[str], spdx_version: str
) -> Optional[Checksum]:
    if not algorithm or not value or algorithm == "NOASSERTION":
        return None
    normalized = algorithm.strip().upper().replace("-", "_")
    # SHA_256 → look up SHA256; keep SHA3_256 style keys intact
    if normalized.startswith("SHA_") and not normalized.startswith("SHA3_"):
        normalized = normalized.replace("SHA_", "SHA", 1)
    algo = _ALGORITHM_MAP.get(normalized) or _ALGORITHM_MAP.get(algorithm.strip().upper())
    if algo is None:
        logging.warning(f"未知 checksum 算法，跳过: {algorithm}")
        return None
    if spdx_version == "SPDX-2.2" and algo in _SPDX22_UNSUPPORTED_ALGORITHMS:
        logging.warning(f"SPDX-2.2 不支持算法 {algorithm}，跳过该 checksum")
        return None
    hex_value = value.lower()
    # 粗校验十六进制长度，避免写出后被 checksum_validator 拒绝
    expected_lens = {
        ChecksumAlgorithm.SHA1: 40,
        ChecksumAlgorithm.SHA224: 56,
        ChecksumAlgorithm.SHA256: 64,
        ChecksumAlgorithm.SHA384: 96,
        ChecksumAlgorithm.SHA512: 128,
        ChecksumAlgorithm.MD5: 32,
    }
    expected = expected_lens.get(algo)
    if expected is not None and len(hex_value) != expected:
        logging.warning(
            f"checksum 值长度不符合 {algo.name} 要求（期望 {expected}，实际 "
            f"{len(hex_value)}），跳过"
        )
        return None
    return Checksum(algo, hex_value)


def _build_package(
    package: Dict[str, Any], package_type: str, spdx_version: str
) -> Package:
    license_expression = " AND ".join(package.get("licenses", []) or [])
    suppliers = package.get("suppliers") or []
    supplier: Union[Actor, SpdxNoAssertion]
    if suppliers and suppliers[0].get("name") and suppliers[0]["name"] != "NOASSERTION":
        supplier = Actor(ActorType.ORGANIZATION, suppliers[0]["name"])
    else:
        supplier = SpdxNoAssertion()

    homepage_raw = suppliers[-1].get("link") if suppliers else None
    homepage: Union[str, SpdxNoAssertion]
    if (
        homepage_raw
        and homepage_raw != "NOASSERTION"
        and "://" in homepage_raw
        and not homepage_raw.startswith("/")
    ):
        homepage = homepage_raw
    else:
        homepage = SpdxNoAssertion()

    architecture = package.get("architecture", "") or ""
    purl_arch = f"?arch={architecture}" if architecture else ""
    purl_type = package.get("package_type") or package_type
    name = package.get("name") or "NOASSERTION"
    version = package.get("version") or None
    if version == "":
        version = None

    external_refs = [
        ExternalPackageRef(
            ExternalPackageRefCategory.PACKAGE_MANAGER,
            "purl",
            f"pkg:{purl_type}/{name}@{version or 'NOASSERTION'}{purl_arch}",
        )
    ]

    checksum = package.get("checksum", {}) or {}
    checksums: List[Checksum] = []
    mapped = _map_checksum(checksum.get("algorithm"), checksum.get("value"), spdx_version)
    if mapped is not None:
        checksums.append(mapped)

    # files_analyzed=False 时校验不要求 license_info_from_files / verification_code
    return Package(
        spdx_id=_spdx_id(str(package.get("id"))),
        name=name if name != "NOASSERTION" else "NOASSERTION",
        download_location=SpdxNoAssertion(),
        version=version if version else None,
        supplier=supplier,
        files_analyzed=False,
        checksums=checksums,
        homepage=homepage,
        license_concluded=SpdxNoAssertion(),
        license_declared=_license_or_noassertion(license_expression or None),
        copyright_text=SpdxNoAssertion(),
        description=package.get("description") or None,
        external_references=external_refs,
        # 2.2 禁止 primary_package_purpose / dates — 不设置即可
    )


def _build_file(
    file_info: Dict[str, Any], spdx_version: str
) -> Optional[File]:
    checksum_info = file_info.get("checksums", {}) or {}
    mapped = _map_checksum(
        checksum_info.get("algorithm"), checksum_info.get("value"), spdx_version
    )
    checksums: List[Checksum] = []
    if mapped is not None:
        checksums.append(mapped)

    has_sha1 = any(c.algorithm == ChecksumAlgorithm.SHA1 for c in checksums)
    if not has_sha1:
        # File 必须含 SHA1；无 SHA1 则跳过该文件以保证 validation 可通过
        logging.warning(
            f"文件缺少 SHA1 checksum，跳过 SPDX File 元素: {file_info.get('id')}"
        )
        return None

    file_name = file_info.get("path") or file_info.get("name") or "NOASSERTION"
    kwargs: Dict[str, Any] = {
        "name": file_name,
        "spdx_id": _spdx_id(str(file_info.get("id"))),
        "checksums": checksums,
        "license_concluded": SpdxNoAssertion(),
        "copyright_text": SpdxNoAssertion(),
        "license_info_in_file": [SpdxNoAssertion()],
    }
    return File(**kwargs)


def _build_relationships(
    linx_sbom: Dict[str, Any], spdx_version: str
) -> List[Relationship]:
    relationships: List[Relationship] = []
    for group_name, data_name in (
        ("file_relationships_sbom", "file_relationships"),
        ("package_relationships_sbom", "package_relationships"),
    ):
        for relationship in linx_sbom.get(group_name, {}).get(data_name, []):
            rel_type_name = relationship.get("relationship_type", "OTHER")
            try:
                rel_type = RelationshipType[rel_type_name]
            except KeyError:
                logging.warning(f"未知 relationship 类型 {rel_type_name}，使用 OTHER")
                rel_type = RelationshipType.OTHER
            if (
                spdx_version == "SPDX-2.2"
                and rel_type in _SPDX22_UNSUPPORTED_RELATIONSHIPS
            ):
                logging.warning(
                    f"SPDX-2.2 不支持关系 {rel_type_name}，跳过"
                )
                continue
            relationships.append(
                Relationship(
                    _spdx_id(str(relationship["id"])),
                    rel_type,
                    _spdx_id(str(relationship["related_element"])),
                )
            )
    return relationships


    files_by_id = {file_elem.spdx_id: file_elem for file_elem in files}
    contained_files: Dict[str, List[File]] = {package.spdx_id: [] for package in packages}

    for relationship in relationships:
        if (
            relationship.relationship_type == RelationshipType.CONTAINS
            and relationship.spdx_element_id in contained_files
            and relationship.related_spdx_element_id in files_by_id
        ):
            contained_files[relationship.spdx_element_id].append(
                files_by_id[relationship.related_spdx_element_id]
            )
        elif (
            relationship.relationship_type == RelationshipType.CONTAINED_BY
            and relationship.related_spdx_element_id in contained_files
            and relationship.spdx_element_id in files_by_id
        ):
            contained_files[relationship.related_spdx_element_id].append(
                files_by_id[relationship.spdx_element_id]
            )

    for package in packages:
        owned_files = contained_files.get(package.spdx_id) or []
        if not owned_files:
            continue
        package.files_analyzed = True
        package.verification_code = calculate_package_verification_code(owned_files)
        if not package.license_info_from_files:
            package.license_info_from_files = [SpdxNoAssertion()]
    return packages



def _ensure_describes(
    relationships: List[Relationship],
    packages: List[Package],
    files: List[File],
    document_id: str,
) -> List[Relationship]:
    only_single_package = len(packages) == 1 and not files
    if only_single_package:
        return relationships
    has_describes = any(
        (
            r.relationship_type == RelationshipType.DESCRIBES
            and r.spdx_element_id == document_id
        )
        or (
            r.relationship_type == RelationshipType.DESCRIBED_BY
            and r.related_spdx_element_id == document_id
        )
        for r in relationships
    )
    if has_describes:
        return relationships
    if packages:
        relationships = list(relationships)
        relationships.insert(
            0,
            Relationship(
                document_id, RelationshipType.DESCRIBES, packages[0].spdx_id
            ),
        )
    elif files:
        relationships = list(relationships)
        relationships.insert(
            0,
            Relationship(document_id, RelationshipType.DESCRIBES, files[0].spdx_id),
        )
    return relationships


def _build_extracted_licensing_info(
    license_info: Dict[str, Any],
) -> ExtractedLicensingInfo:
    license_name = license_info.get("name") or "NOASSERTION"
    raw_id = license_info.get("id") or ""
    if re.fullmatch(r"LicenseRef-[\da-zA-Z.\-]+", str(raw_id)):
        license_id = str(raw_id)
    else:
        safe = _SPDX_ID_SAFE.sub("-", str(raw_id) or uuid.uuid4().hex[:8])
        license_id = f"LicenseRef-{safe}" if not safe.startswith("LicenseRef-") else safe
    return ExtractedLicensingInfo(
        license_id=license_id,
        license_name=license_name,
        extracted_text=(
            "The license info found in the package meta data is: "
            f"{license_name}. See the specific package info in this SPDX "
            "document or the package itself for more details."
        ),
    )
