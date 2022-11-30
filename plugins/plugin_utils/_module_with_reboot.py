# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Run module with reboot handler

This code contains the skeleton needed for action plugins to run a module with
an automatic reboot handler. Right now it should only be used in this
collection as the interface is not final and count be subject to change.
"""

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import typing as t

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from ansible.utils.vars import merge_hash

from ._reboot import reboot_host

display = Display()


class ActionModuleWithReboot(ActionBase):
    def _ad_should_reboot(self, result: t.Dict[str, t.Any]) -> bool:
        return result.get("reboot_required", False)

    def _ad_should_rerun(self, result: t.Dict[str, t.Any]) -> bool:
        return False

    def _ad_process_result(self, result: t.Dict[str, t.Any]) -> t.Dict[str, t.Any]:
        return result

    def run(
        self,
        tmp: t.Optional[str] = None,
        task_vars: t.Optional[t.Dict[str, t.Any]] = None,
    ) -> t.Dict[str, t.Any]:
        self._supports_check_mode = True
        self._supports_async = True

        result = super().run(tmp=tmp, task_vars=task_vars)
        del tmp

        wrap_async = self._task.async_val and not self._connection.has_native_async
        reboot = self._task.args.get("reboot", False)

        if self._task.async_val > 0 and reboot:
            return {
                "failed": True,
                "msg": "async is not supported for this task when reboot=true",
                "changed": False,
            }

        invocation = None
        while True:
            module_res = self._execute_module(
                task_vars=task_vars,
                wrap_async=wrap_async,
            )
            invocation = module_res.pop("invocation", None)

            if reboot and self._ad_should_reboot(module_res):
                if self._task.check_mode:
                    reboot_res = {}
                else:
                    reboot_res = reboot_host(self._task.action, self._connection)

                if reboot_res.get("failed", False):
                    module_res = {
                        "changed": module_res.get("changed", False),
                        "failed": True,
                        "msg": "Failed to reboot after module returned reboot_required, see reboot_result and module_result for more details",
                        "reboot_result": reboot_res,
                        "module_result": module_res,
                    }
                    break

                # Regardless of the module result this needs to be True as a
                # reboot happened.
                module_res["changed"] = True

                if self._ad_should_rerun(module_res) and not self._task.check_mode:
                    display.vv(
                        "Module result has indicated it should rerun after a reboot has occured, rerunning"
                    )
                    continue

            break

        # Make sure the invocation details from the module are still present.
        if invocation is not None:
            module_res["invocation"] = invocation

        result = merge_hash(result, module_res)

        return self._ad_process_result(result)
