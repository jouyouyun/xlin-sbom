# SPDX-FileCopyrightText: 2022 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from enum import auto

from actions.spdx.jsonschema.json_property import JsonProperty


class ChecksumProperty(JsonProperty):
    ALGORITHM = auto()
    CHECKSUM_VALUE = auto()
