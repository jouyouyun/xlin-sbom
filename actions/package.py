# Copyright (c) 2025 Linx Software, Inc.
#
# xlin-sbom-analysis tool is licensed under Mulan PSL v2.

# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
# http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

import hashlib
import json
import logging
from typing import Iterable, List, Tuple

from actions.data_helper import remove_duplicate_files, remove_duplicate_relationships


class Package:
    """描述扫描得到的软件包及其 SBOM 关联数据。"""

    def __init__(self, name: str, version: str, release: str, arch: str,
                 package_type: str, checksum_algorithm: str, checksum_value: str):
        """初始化软件包对象。

        Args:
            name (str): 软件包名称。
            version (str): 软件包版本。
            release (str): RPM release 或等价发布字段。
            arch (str): 软件包架构。
            package_type (str): 包类型，例如 rpm、deb、source。
            checksum_algorithm (str): 校验和算法。
            checksum_value (str): 校验和值。
        """

        self.name = name
        self.version = version
        self.release = release
        self.arch = arch
        self.package_type = package_type
        self.checksum_algorithm = checksum_algorithm
        self.checksum_value = checksum_value
        identity = json.dumps(self.identity_key(), ensure_ascii=False, separators=(",", ":"))
        self.id = f"Package-{name}-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:32]}"
        self.licenses = []
        self.category = "NOASSERTION"
        self.vulnerabilities = []
        self.files = []
        self.concluded_dependencies = []
        self.declared_dependencies = []
        self.source = "NOASSERTION"
        self.suppliers = []
        self.description = "NOASSERTION"

    def identity_key(self) -> Tuple[str, ...]:
        """版本、架构和完整摘要共同确定包身份，不能仅用名称或摘要前缀。"""

        full_version = f"{self.version}-{self.release}" if self.release else self.version
        return (
            self.package_type or "", self.name or "", full_version or "", self.arch or "",
            (self.checksum_algorithm or "").upper().replace("-", ""),
            (self.checksum_value or "").lower(),
        )

    def set_category(self, category: str) -> None:
        """设置软件包分类。

        Args:
            category (str): 软件包分类。
        """

        self.category = category

    def add_vulnerability(self, id: str, severity_type: str, severity_level: str, fixed: str) -> None:
        """追加漏洞信息。

        Args:
            id (str): 漏洞编号。
            severity_type (str): 严重性类型。
            severity_level (str): 严重性级别。
            fixed (str): 修复版本或修复说明。
        """

        if any(vuln['id'] == id for vuln in self.vulnerabilities):
            return

        vulnerability = {
            "id": id,
            "severity_type": severity_type,
            "severity_level": severity_level,
            "fixed": fixed
        }
        self.vulnerabilities.append(vulnerability)

    def add_license(self, license: str) -> None:
        """追加许可证引用。

        Args:
            license (str): 许可证 ID 或名称。
        """

        self.licenses.append(license)

    def add_file(self, file: dict) -> None:
        """追加包内文件。

        Args:
            file (dict): Linx 文件对象。
        """

        self.files.append(file)

    def add_files(self, files: list) -> None:
        """批量追加包内文件。

        Args:
            files (list): Linx 文件对象列表。
        """

        self.files.extend(files)

    def add_declared_dep(self, dependency: str) -> None:
        """追加声明依赖。

        Args:
            dependency (str): 依赖名称或表达式。
        """

        self.declared_dependencies.append(dependency)

    def add_concluded_dep(self, dependency: object) -> None:
        """追加解析后的依赖对象。

        Args:
            dependency (object): 已匹配到的依赖包对象。
        """

        self.concluded_dependencies.append(dependency)

    def set_source(self, source: str) -> None:
        """设置源码包或来源包信息。

        Args:
            source (str): 来源包名称。
        """

        self.source = source

    def add_supplier(self, supplier: dict) -> None:
        """追加供应商信息。

        Args:
            supplier (dict): Linx supplier 对象。
        """

        self.suppliers.append(supplier)

    def set_description(self, description: str) -> None:
        """设置软件包描述。

        Args:
            description (str): 描述文本。
        """

        self.description = description
    
    def get_file_relationships(self) -> list:
        """生成包与文件之间的包含关系。

        Returns:
            list: Linx file_relationships 列表。
        """

        relationships = []
        for file in self.files:
            relationships.append({
                "id": self.id,
                "related_element": file['id'],
                "relationship_type": "CONTAINS"
            })
        return remove_duplicate_relationships(relationships)

    def get_json(self) -> dict:
        """转换为 Linx package JSON 对象。

        Returns:
            dict: Linx packages 列表中的单个 package 对象。
        """

        full_version = f"{self.version}-{self.release}" if self.release else self.version
        depends = [
            dep.name for dep in self.concluded_dependencies] if self.concluded_dependencies else self.declared_dependencies
        return {
            "id": self.id,
            "name": self.name,
            "version": full_version,
            "architecture": self.arch,
            "package_type": self.package_type,
            "depends": depends,
            "source": self.source,
            "licenses": self.licenses,
            "suppliers": self.suppliers,
            "description": self.description,
            "checksum": {
                "value": self.checksum_value,
                "algorithm": self.checksum_algorithm
            }
        }


def merge_packages(packages: Iterable[Package]) -> List[Package]:
    """共享的重复包合并：保留不同版本/架构/内容，合并副本关联的数据。"""

    unique = {}
    id_to_identity = {}
    duplicate_count = 0
    for package in packages:
        key = package.identity_key()
        if package.id in id_to_identity and id_to_identity[package.id] != key:
            raise ValueError(f"软件包编号冲突，包身份不同: {package.id}")
        id_to_identity[package.id] = key
        previous = unique.get(key)
        if previous is None:
            package.files = remove_duplicate_files(package.files)
            unique[key] = package
            continue
        if previous.id != package.id:
            raise ValueError(f"相同软件包身份出现不同编号: {previous.id}, {package.id}")
        duplicate_count += 1
        previous.files = remove_duplicate_files(previous.files + package.files)
        for attribute in ("licenses", "declared_dependencies", "suppliers", "vulnerabilities"):
            target = getattr(previous, attribute)
            for value in getattr(package, attribute):
                if value not in target:
                    target.append(value)
        known_dependencies = {dependency.id for dependency in previous.concluded_dependencies}
        for dependency in package.concluded_dependencies:
            if dependency.id not in known_dependencies:
                previous.concluded_dependencies.append(dependency)
                known_dependencies.add(dependency.id)
        for attribute in ("description", "source", "category"):
            if getattr(previous, attribute) in (None, "", "NOASSERTION"):
                setattr(previous, attribute, getattr(package, attribute))
    if duplicate_count:
        logging.info("已合并 %d 个重复软件包副本，保留 %d 个独立软件包", duplicate_count, len(unique))
    result = list(unique.values())
    _disambiguate_file_contents(result)
    return result


def _file_content_key(file: dict) -> Tuple[str, str]:
    # 归档库可能返回不可哈希的 str 子类；内容键只能使用普通字符串。
    path = str(file.get("path") or file.get("name") or "")
    checksums = (file.get("additional_checksums") or []) + [file.get("checksums", {})]
    for checksum in checksums:
        if checksum and checksum.get("algorithm", "").upper().replace("-", "") == "SHA1":
            value = checksum.get("value") or ""
            if len(value) == 40 and all(character in "0123456789abcdefABCDEF" for character in value):
                return path, value.lower()
    return path, ""


def _disambiguate_file_contents(packages: List[Package]) -> None:
    """同一文件编号对应不同真实内容时，分别保留并重建对应的包含关系。"""

    variants = {}
    for package in packages:
        for file in package.files:
            path, digest = _file_content_key(file)
            if digest:
                variants.setdefault(file["id"], set()).add((path, digest))
    for package in packages:
        files = []
        for file in package.files:
            key = _file_content_key(file)
            if key[1] and len(variants.get(file["id"], ())) > 1:
                identity = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
                file = {**file, "id": f"{file['id']}-{suffix}"}
            files.append(file)
        package.files = files
