# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from actions.common.typing.dataclass_with_properties import dataclass_with_properties
from actions.common.typing.type_checks import check_types_and_set_values


@dataclass_with_properties
class NamespaceMap:
    prefix: str
    namespace: str  # anyURI

    def __init__(self, prefix: str, namespace: str):
        check_types_and_set_values(self, locals())
