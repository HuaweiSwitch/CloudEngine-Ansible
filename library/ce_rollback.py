#!/usr/bin/python
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: ce_rollback
version_added: "2.3"
short_description: Set a checkpoint or rollback to a checkpoint.
description:
    - This module offers the ability to set a configuration checkpoint
      file or rollback to a configuration checkpoint file on CloudEngine switch.
extends_documentation_fragment: cloudengine
author:
    - Li Yanfeng (@CloudEngine-Ansible)
options:
    commit_id:
        description:
            - Specifies the label of the configuration rollback point to which system configurations are
              expected to roll back.
              The value is an integer that the system generates automatically.
        required: false
    label:
        description:
            - Specifies a user label for a configuration rollback point.
              The value is a string of 1 to 256 case-sensitive ASCII characters, spaces not supported.
              The value must start with a letter and cannot be presented in a single hyphen (-).
        required: false
        default: null
    filename:
        description:
            - Specifies a configuration file for configuration rollback.
              The value is a string of 5 to 64 case-sensitive characters in the format of *.zip, *.cfg, or *.dat,
              spaces not supported.
        required: false
        default: null
    last:
        description:
            - Specifies the number of configuration rollback points.
              The value is an integer that ranges from 1 to 80.
        required: false
        default: null
    oldest:
        description:
            - Specifies the number of configuration rollback points.
              The value is an integer that ranges from 1 to 80.
        required: false
        default: null
    action:
        description:
            - The operation of configuration rollback.
        required: true
        choices: ['rollback','clear','set','display','commit']
'''
EXAMPLES = '''
# Ensure commit_id is exist, and specifies the label of the configuration
# rollback point to which system configurations are expected to roll back.
- ce_rollback:
    commit_id: 1000000748
    action: rollback
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: sometimes
    type: dict
    sample: {"commit_id": "1000000748", "action": "rollback"}
existing:
    description:
        - k/v pairs of existing rollback
    returned: sometimes
    type: dict
    sample: {"commitId": "1000000748", "userLabel": "abc"}
updates:
    description: command sent to the device
    returned: always
    type: list
    sample: ["rollback configuration to file a.cfg",
             "set configuration commit 1000000783 label ddd",
             "clear configuration commit 1000000783 label",
             "display configuration commit list"]
changed:
    description: check to see if a change was made on the device
    returned: always
    type: boolean
    sample: true
end_state:
    description: k/v pairs of configuration after module execution
    returned: always
    type: dict
    sample: {"commitId": "1000000748", "userLabel": "abc"}
'''

import re
import sys
from ansible.module_utils.network import NetworkError, NetworkModule
from ansible.module_utils.cloudengine import get_netconf, get_cli_exception
from ansible.module_utils.netcli import CommandRunner, AddCommandError
from ansible.module_utils.basic import get_exception

try:
    from ncclient.operations.rpc import RPCError
    HAS_NCCLIENT = True
except ImportError:
    HAS_NCCLIENT = False


CE_NC_GET_CHECKPOINT = """
<filter type="subtree">
  <cfg xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <checkPointInfos>
      <checkPointInfo>
        <commitId></commitId>
        <userLabel></userLabel>
        <userName></userName>
        </checkPointInfo>
      </checkPointInfos>
  </cfg>
</filter>
"""

CE_NC_ACTION_ROLLBACK_COMMIT_ID = """
<action>
  <cfg xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <rollbackByCommitId>
      <commitId>%s</commitId>
    </rollbackByCommitId>
  </cfg>
</action>
"""

CE_NC_ACTION_ROLLBACK_LABEL = """
<action>
  <cfg xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <rollbackByUserLabel>
      <userLabel>%s</userLabel>
    </rollbackByUserLabel>
  </cfg>
</action>
"""

CE_NC_ACTION_ROLLBACK_LAST = """
<action>
  <cfg xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <rollbackByLastNum>
      <checkPointNum>%s</checkPointNum>
    </rollbackByLastNum>
  </cfg>
</action>
"""

CE_NC_ACTION_ROLLBACK_FILE = """
<action>
  <cfg xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <rollbackByFile>
      <fileName>%s</fileName>
    </rollbackByFile>
  </cfg>
</action>
"""

CE_NC_ACTION_SET_COMMIT_ID_LABEL = """
<action>
  <cfg xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <setUserLabelByCommitId>
      <commitId>%s</commitId>
      <userLabel>%s</userLabel>
    </setUserLabelByCommitId>
  </cfg>
</action>
"""

CE_NC_ACTION_CLEAR_COMMIT_ID_LABEL = """
<action>
  <cfg xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <resetUserLabelByCommitId>
      <commitId>%s</commitId>
    </resetUserLabelByCommitId>
  </cfg>
</action>
"""

CE_NC_ACTION_CLEAR_OLDEST_COMMIT_ID = """
<action>
  <cfg xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <delCheckPointByOldestNum>
      <checkPointNum>%s</checkPointNum>
    </delCheckPointByOldestNum>
  </cfg>
</action>
"""


class RollBack(object):
    """
    Manages rolls back the system from the current configuration state to a historical configuration state.
    """

    def __init__(self, argument_spec):
        self.spec = argument_spec
        self.module = None
        self.netconf = None
        self.init_module()

        # module input info
        self.commit_id = self.module.params['commit_id']
        self.label = self.module.params['label']
        self.filename = self.module.params['filename']
        self.last = self.module.params['last']
        self.oldest = self.module.params['oldest']
        self.action = self.module.params['action']

        # host info
        self.host = self.module.params['host']
        self.username = self.module.params['username']
        self.port = self.module.params['port']

        # state
        self.changed = False
        self.updates_cmd = list()
        self.results = dict()
        self.existing = dict()
        self.proposed = dict()
        self.end_state = dict()

        # configuration rollback points info
        self.rollback_info = None

        # init netconf connect
        self.init_netconf()

    def init_module(self):
        """ init module """

        self.module = NetworkModule(
            argument_spec=self.spec, supports_check_mode=True)

    def init_netconf(self):
        """ init netconf """

        if not HAS_NCCLIENT:
            raise Exception("the ncclient library is required")

        self.netconf = get_netconf(host=self.host,
                                   port=self.port,
                                   username=self.username,
                                   password=self.module.params['password'])
        if not self.netconf:
            self.module.fail_json(msg='Error: netconf init failed.')

    def excute_command(self, commands):
        """ excute_command"""

        runner = CommandRunner(self.module)
        for cmd in commands:
            try:
                runner.add_command(**cmd)
            except AddCommandError:
                exc = get_exception()
                self.module.fail_json(msg=get_cli_exception(exc))

        try:
            runner.run()
        except NetworkError:
            err = get_cli_exception()
            self.module.fail_json(msg=err)

    def check_response(self, con_obj, xml_name):
        """Check if response message is already succeed."""

        xml_str = con_obj.xml
        if "<ok/>" not in xml_str:
            self.module.fail_json(msg='Error: %s failed.' % xml_name)

    def netconf_get_config(self, xml_str):
        """ netconf get config """

        try:
            con_obj = self.netconf.get_config(filter=xml_str)
        except RPCError:
            err = sys.exc_info()[1]
            self.module.fail_json(msg='Error: %s' % err.message.replace("\r\n", ""))

        return con_obj

    def netconf_set_action(self, xml_str, xml_name):
        """ netconf set config """

        try:
            con_obj = self.netconf.execute_action(action=xml_str)
            self.check_response(con_obj, xml_name)
        except RPCError:
            err = sys.exc_info()[1]
            self.module.fail_json(msg='Error: %s' % err.message.replace("\r\n", ""))

        return con_obj

    def get_rollback_dict(self):
        """ get rollback attributes dict."""

        rollback_info = dict()
        conf_str = CE_NC_GET_CHECKPOINT
        try:
            con_obj = self.netconf.get_config(filter=conf_str)
        except RPCError:
            err = sys.exc_info()[1]
            self.module.fail_json(msg='Error: %s' % err.message.replace("\r\n", ""))
        xml_str = con_obj.xml
        rollback_info["RollBackInfos"] = list()
        if "<data/>" in xml_str:
            return rollback_info
        else:
            re_find = re.findall(r'.*<commitId>(.*)</commitId>.*\s*'
                                 r'<userName>(.*)</userName>.*\s*'
                                 r'<userLabel>(.*)</userLabel>.*', xml_str)

            for mem in re_find:
                rollback_info["RollBackInfos"].append(
                    dict(commitId=mem[0], userLabel=mem[2]))
            return rollback_info

    def get_filename_type(self, filename):
        """Gets the type of filename, such as cfg, zip, dat..."""

        if filename is None:
            return None
        if ' ' in filename:
            self.module.fail_json(
                msg='Error: Configuration file name include spaces.')

        iftype = None

        if filename.endswith('.cfg'):
            iftype = 'cfg'
        elif filename.endswith('.zip'):
            iftype = 'zip'
        elif filename.endswith('.dat'):
            iftype = 'dat'
        else:
            return None
        return iftype.lower()

    def rollback_commit_id(self):
        """rollback comit_id"""

        cfg_xml = ""
        self.updates_cmd.append(
            "rollback configuration to commit-id %s" % self.commit_id)
        cfg_xml = CE_NC_ACTION_ROLLBACK_COMMIT_ID % self.commit_id
        self.netconf_set_action(cfg_xml, "ROLLBACK_COMMITID")
        self.changed = True

    def rollback_label(self):
        """rollback label"""

        cfg_xml = ""
        self.updates_cmd.append(
            "rollback configuration to label %s" % self.label)
        cfg_xml = CE_NC_ACTION_ROLLBACK_LABEL % self.label
        self.netconf_set_action(cfg_xml, "ROLLBACK_LABEL")
        self.changed = True

    def rollback_filename(self):
        """rollback filename"""

        cfg_xml = ""
        self.updates_cmd.append(
            "rollback configuration to file %s" % self.filename)
        cfg_xml = CE_NC_ACTION_ROLLBACK_FILE % self.filename
        self.netconf_set_action(cfg_xml, "ROLLBACK_FILENAME")
        self.changed = True

    def rollback_last(self):
        """rollback last"""

        cfg_xml = ""
        self.updates_cmd.append(
            "rollback configuration to last %s" % self.last)
        cfg_xml = CE_NC_ACTION_ROLLBACK_LAST % self.last
        self.netconf_set_action(cfg_xml, "ROLLBACK_LAST")
        self.changed = True

    def set_commitid_label(self):
        """set commitid label"""

        cfg_xml = ""
        self.updates_cmd.append(
            "set configuration commit %s label %s" % (self.commit_id, self.label))
        cfg_xml = CE_NC_ACTION_SET_COMMIT_ID_LABEL % (
            self.commit_id, self.label)
        self.netconf_set_action(cfg_xml, "SET_COMIMIT_LABEL")
        self.changed = True

    def clear_commitid_label(self):
        """clear commitid label"""

        cfg_xml = ""
        self.updates_cmd.append(
            "clear configuration commit %s label" % self.commit_id)
        cfg_xml = CE_NC_ACTION_CLEAR_COMMIT_ID_LABEL % self.commit_id
        self.netconf_set_action(cfg_xml, "CLEAR_COMMIT_LABEL")
        self.changed = True

    def clear_oldest(self):
        """clear oldest"""

        cfg_xml = ""
        self.updates_cmd.append(
            "clear configuration commit oldest %s" % self.oldest)
        cfg_xml = CE_NC_ACTION_CLEAR_OLDEST_COMMIT_ID % self.oldest
        self.netconf_set_action(cfg_xml, "CLEAR_COMMIT_OLDEST")
        self.changed = True

    def commit_label(self):
        """commit label"""

        commands = list()
        cmd1 = {'output': None, 'command': 'system-view'}
        commands.append(cmd1)

        cmd2 = {'output': None, 'command': ''}
        cmd2['command'] = "commit label %s" % self.label
        commands.append(cmd2)
        self.updates_cmd.append(
            "commit label %s" % self.label)
        self.excute_command(commands)
        self.changed = True

    def check_params(self):
        """Check all input params"""

        # commit_id check
        if self.commit_id:
            if not self.commit_id.isdigit():
                self.module.fail_json(
                    msg='Error: The parameter of commit_id is invalid.')

        # label check
        if self.label:
            if self.label[0].isdigit():
                self.module.fail_json(
                    msg='Error: Commit label which should not start with a number.')
            if len(self.label.replace(' ', '')) == 1:
                if cmp(self.label, '-') == 0:
                    self.module.fail_json(
                        msg='Error: Commit label which should not be "-"')
            if len(self.label.replace(' ', '')) < 1 or len(self.label) > 256:
                self.module.fail_json(
                    msg='Error: Label of configuration checkpoints is a string of 1 to 256 characters.')

        # filename check
        if self.filename:
            if not self.get_filename_type(self.filename):
                self.module.fail_json(
                    msg='Error: Invalid file name or file name extension ( *.cfg, *.zip, *.dat ).')
        # last check
        if self.last:
            if not self.last.isdigit():
                self.module.fail_json(
                    msg='Error: Number of configuration checkpoints is not digit.')
            if int(self.last) <= 0 or int(self.last) > 80:
                self.module.fail_json(
                    msg='Error: Number of configuration checkpoints is not in the range from 1 to 80.')

        # oldest check
        if self.oldest:
            if not self.oldest.isdigit():
                self.module.fail_json(
                    msg='Error: Number of configuration checkpoints is not digit.')
            if int(self.oldest) <= 0 or int(self.oldest) > 80:
                self.module.fail_json(
                    msg='Error: Number of configuration checkpoints is not in the range from 1 to 80.')

    def get_proposed(self):
        """get proposed info"""

        if self.commit_id:
            self.proposed["commit_id"] = self.commit_id
        if self.label:
            self.proposed["label"] = self.label
        if self.filename:
            self.proposed["filename"] = self.filename
        if self.last:
            self.proposed["last"] = self.last
        if self.oldest:
            self.proposed["oldest"] = self.oldest

    def get_existing(self):
        """get existing info"""

        if not self.rollback_info:
            return
        self.existing["RollBackInfos"] = self.rollback_info["RollBackInfos"]

    def get_end_state(self):
        """get end state info"""

        self.end_state = None

    def work(self):
        """worker"""

        self.check_params()
        self.get_proposed()
        # action mode
        if self.action == "rollback":
            if self.commit_id:
                self.rollback_commit_id()
            if self.label:
                self.rollback_label()
            if self.filename:
                self.rollback_filename()
            if self.last:
                self.rollback_last()
        elif self.action == "set":
            if self.commit_id and self.label:
                self.set_commitid_label()
        elif self.action == "clear":
            if self.commit_id:
                self.clear_commitid_label()
            if self.oldest:
                self.clear_oldest()
        elif self.action == "commit":
            if self.label:
                self.commit_label()
        elif self.action == "display":
            self.rollback_info = self.get_rollback_dict()

        self.get_existing()
        self.get_end_state()
        self.results['changed'] = self.changed
        self.results['proposed'] = self.proposed
        self.results['existing'] = self.existing
        self.results['end_state'] = self.end_state
        if self.changed:
            self.results['updates'] = self.updates_cmd
        else:
            self.results['updates'] = list()

        self.module.exit_json(**self.results)


def main():
    """Module main"""

    argument_spec = dict(
        commit_id=dict(required=False),
        label=dict(required=False, type='str'),
        filename=dict(required=False, type='str'),
        last=dict(required=False, type='str'),
        oldest=dict(required=False, type='str'),
        action=dict(required=False, type='str', choices=[
            'rollback', 'clear', 'set', 'commit', 'display']),
    )

    module = RollBack(argument_spec)
    module.work()


if __name__ == '__main__':
    main()
