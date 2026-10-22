# Copyright 2026 Linx Software, Inc.
# Licensed under the Apache License, Version 2.0.

"""Read RPM NDB package headers and import them into a temporary SQLite database.

The layout follows RPM's NDB v0 format (lib/backend/ndb/rpmpkg.c).
Only metadata is imported; no package payload or script is executed.
"""

import os
import struct
import subprocess
import tempfile
import zlib
from typing import BinaryIO


RPM_HEADER_MAGIC = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"
PAGE_SIZE = 4096
BLOCK_SIZE = 16


def export_ndb_headers(source: BinaryIO, target: BinaryIO) -> int:
    """Export live NDB v0 headers, rejecting invalid slots and checksums."""

    source.seek(0, os.SEEK_END)
    file_size = source.tell()
    source.seek(0)
    header = source.read(32)
    if len(header) != 32 or header[:4] != b"RpmP":
        raise ValueError("RPM NDB 数据库文件头无效")
    version, _, pages = struct.unpack_from("<III", header, 4)
    if version != 0:
        raise ValueError(f"暂不支持 RPM NDB 数据库版本 {version}")
    slot_end = pages * PAGE_SIZE
    if pages == 0 or slot_end > file_size or file_size % BLOCK_SIZE:
        raise ValueError("RPM NDB 数据库槽位区域无效或文件被截断")

    slots = []
    package_ids = set()
    for page in range(pages):
        source.seek(page * PAGE_SIZE)
        data = source.read(PAGE_SIZE)
        for offset in range(32 if page == 0 else 0, PAGE_SIZE, BLOCK_SIZE):
            magic, package_id, block_offset, block_count = struct.unpack_from(
                "<4sIII", data, offset)
            if magic != b"Slot":
                raise ValueError("RPM NDB 数据库槽位标识无效")
            if block_offset == 0:
                continue
            start = block_offset * BLOCK_SIZE
            end = start + block_count * BLOCK_SIZE
            if (package_id == 0 or package_id in package_ids or
                    block_count < 2 or start < slot_end or end > file_size):
                raise ValueError("RPM NDB 数据库软件包槽位无效或越界")
            package_ids.add(package_id)
            slots.append((start, end, package_id))

    previous_end = slot_end
    for start, end, package_id in sorted(slots):
        if start < previous_end:
            raise ValueError("RPM NDB 数据库软件包数据区域重叠")
        previous_end = end
        source.seek(start)
        blob_header = source.read(16)
        magic, blob_id, _, blob_size = struct.unpack("<4sIII", blob_header)
        expected_size = ((16 + blob_size + 12 + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
        if (magic != b"BlbS" or blob_id != package_id or
                blob_size < 8 or expected_size != end - start):
            raise ValueError("RPM NDB 数据库软件包数据头无效")

        dimensions = source.read(8)
        index_count, store_size = struct.unpack(">II", dimensions)
        if blob_size != 8 + index_count * 16 + store_size:
            raise ValueError("RPM NDB 数据库中的 RPM header 长度无效")
        target.write(RPM_HEADER_MAGIC)
        target.write(dimensions)
        checksum = zlib.adler32(dimensions, zlib.adler32(blob_header))
        remaining = blob_size - 8
        while remaining:
            chunk = source.read(min(remaining, 65536))
            if not chunk:
                raise ValueError("RPM NDB 数据库软件包数据被截断")
            checksum = zlib.adler32(chunk, checksum)
            target.write(chunk)
            remaining -= len(chunk)
        padding = source.read(end - start - 16 - blob_size - 12)
        checksum = zlib.adler32(padding, checksum)
        trailer = source.read(12)
        if len(trailer) != 12:
            raise ValueError("RPM NDB 数据库软件包数据尾被截断")
        stored_checksum, stored_size, magic = struct.unpack("<II4s", trailer)
        if magic != b"BlbE" or stored_size != blob_size or stored_checksum != checksum:
            raise ValueError("RPM NDB 数据库软件包数据校验失败")
    return len(slots)


def convert_ndb_database(database_path: str, target_dir: str) -> None:
    """Import verified NDB headers into a separate database for native queries."""

    with open(database_path, "rb") as source, tempfile.TemporaryFile() as headers:
        count = export_ndb_headers(source, headers)
        if count == 0:
            raise ValueError("Docker 镜像内的 RPM NDB 数据库未包含已安装软件包。")
        headers.seek(0)
        try:
            result = subprocess.run(
                ["rpmdb", "--dbpath", target_dir, "--define", "_db_backend sqlite", "--importdb"],
                stdin=headers, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            raise ValueError("当前运行环境缺少 rpmdb 命令，无法读取 RPM NDB 数据库。") from exc
    if result.returncode != 0:
        raise ValueError(f"RPM NDB 数据库转换失败: {result.stderr.strip()}")
    result = subprocess.run(
        ["rpm", "--dbpath", target_dir, "--define", "_db_backend sqlite", "-qa", "--qf", "%{NAME}\n"],
        capture_output=True, text=True, check=False)
    if result.returncode != 0 or len(result.stdout.splitlines()) != count:
        raise ValueError(f"RPM NDB 数据库转换后软件包数量不一致: {result.stderr.strip()}")
