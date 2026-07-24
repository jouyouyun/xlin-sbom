# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from actions.common.typing.dataclass_with_properties import dataclass_with_properties
from actions.common.typing.type_checks import check_types_and_set_values
from actions.spdx3.model.licensing.any_license_info import AnyLicenseInfo
from actions.spdx3.model.licensing.license import License


@dataclass_with_properties
class OrLaterOperator(AnyLicenseInfo):
    subject_license: License

    def __init__(self, subject_license: License):
        check_types_and_set_values(self, locals())
