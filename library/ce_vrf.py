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
module: ce_vrf
version_added: "2.3"
short_description: Manages VPN instance.
description:
    - Manages VPN instance of Huawei CloudEngine switches.
author: Yang yang (@CloudEngine-Ansible)
notes:
    - If no vrf is supplied, vrf is set to default.
      If state==absent, the route will be removed, regardless of the
      non-required parameters.
options:
    vrf:
        description:
            - VPN instance,the length of vrf name is 1 - 31,i.e. "test",but can not be _public_.
        required: true
    description:
        description:
            - Description of the vrf,the string length is 1 - 242 .
        required: false
        default: null
    state:
        description:
            - Manage the state of the resource.
        required: false
        choices: ['present','absent']
        default: present
'''

EXAMPLES = '''
- name: vrf module test
  hosts: cloudengine
  connection: local
  gather_facts: no
  vars:
    cli:
      host: "{{ inventory_hostname }}"
      port: "{{ ansible_ssh_port }}"
      username: "{{ username }}"
      password: "{{ password }}"
      transport: cli

  tasks:

- name: Config a vpn install named vpna, description is test
  ce_vrf:
    vrf: vpna
    description: test
    state: present
    provider: "{{ cli }}"
- name: Delete a vpn install named vpna
  ce_vrf:
    vrf: vpna
    state: absent
    provider: "{{ cli }}"
'''
RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"vrf": "vpna",
             "description": "test",
             "state": "present"}
existing:
    description: k/v pairs of existing switchport
    type: dict
    sample:  {}
end_state:
    description: k/v pairs of switchport after module execution
    returned: always
    type: dict or null
    sample:  {"vrf": "vpna",
              "description": "test",
              "present": "present"}
updates:
    description: command list sent to the device
    returned: always
    type: list
    sample: ["ip vpn-instance vpna",
             "description test"]
changed:
    description: check to see if a change was made on the device
    returned: always
    type: boolean
    sample: true
'''

import sys
from xml.etree import ElementTree
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ce import get_netconf, ce_argument_spec

HAS_NCCLIENT = False
try:
    from ncclient.operations.rpc import RPCError
    HAS_NCCLIENT = True
except ImportError:
    HAS_NCCLIENT = False


CE_NC_GET_VRF = """
<filter type="subtree">
      <l3vpn xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <l3vpncomm>
          <l3vpnInstances>
            <l3vpnInstance>
              <vrfName></vrfName>
              <vrfDescription></vrfDescription>
            </l3vpnInstance>
          </l3vpnInstances>
        </l3vpncomm>
      </l3vpn>
    </filter>
"""

CE_NC_CREATE_VRF = """
<l3vpn xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <l3vpncomm>
          <l3vpnInstances>
            <l3vpnInstance operation="merge">
              <vrfName>%s</vrfName>
              <vrfDescription>%s</vrfDescription>
            </l3vpnInstance>
          </l3vpnInstances>
        </l3vpncomm>
      </l3vpn>
"""

CE_NC_DELETE_VRF = """
<l3vpn xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <l3vpncomm>
          <l3vpnInstances>
            <l3vpnInstance operation="delete">
              <vrfName>%s</vrfName>
              <vrfDescription>%s</vrfDescription>
            </l3vpnInstance>
          </l3vpnInstances>
        </l3vpncomm>
      </l3vpn>
"""


def build_config_xml(xmlstr):
    """build_config_xml"""

    return '<config> ' + xmlstr + ' </config>'

class Vrf(object):
    """Manange vpn instance"""

    def __init__(self, argument_spec, ):
        self.spec = argument_spec
        self.module = None
        self.netconf = None
        self.init_module()

        # vpn instance info
        self.vrf = self.module.params['vrf']
        self.description = self.module.params['description']
        self.state = self.module.params['state']

        # host info
        self.host = self.module.params['provider']['host']
        self.username = self.module.params['provider']['username']
        self.port = self.module.params['provider']['port']

        # state
        self.changed = False
        self.updates_cmd = list()
        self.results = dict()
        self.proposed = dict()
        self.existing = dict()
        self.end_state = dict()

        # init netconf connect
        self.init_netconf()

    def init_module(self):
        """init_module"""

        self.module = AnsibleModule(
            argument_spec=self.spec, supports_check_mode=True)

    def init_netconf(self):
        """init_netconf"""

        if not HAS_NCCLIENT:
            raise Exception("the ncclient library is required")

        self.netconf = get_netconf(host=self.host,
                                   port=self.port,
                                   username=self.username,
                                   password=self.module.params['provider']['password'])
        if not self.netconf:
            self.module.fail_json(msg='Error: netconf init failed')

    def check_response(self, con_obj, xml_name):
        """Check if response message is already succeed."""

        xml_str = con_obj.xml
        if "<ok/>" not in xml_str:
            self.module.fail_json(msg='Error: %s failed.' % xml_name)

    def set_update_cmd(self):
        """ set update command"""
        if not self.changed:
            return
        if self.state == "present":
            self.updates_cmd.append('ip vpn-instance %s' % (self.vrf))
            if self.description:
                self.updates_cmd.append('description %s' % (self.description))
        else:
            self.updates_cmd.append('undo ip vpn-instance %s' % (self.vrf))

    def get_vrf(self):
        """ check if vrf is need to change"""

        getxmlstr = CE_NC_GET_VRF

        try:
            get_obj = self.netconf.get_config(filter=getxmlstr)
        except RPCError:
            err = sys.exc_info()[1]
            self.module.fail_json(msg='Error: %s' % err.message.replace("\r\n", ""))

        xml_str = get_obj.xml.replace('\r', '').replace('\n', '').\
            replace('xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"', "").\
            replace('xmlns="http://www.huawei.com/netconf/vrp"', "")

        root = ElementTree.fromstring(xml_str)
        vpn_instances = root.findall(
            "data/l3vpn/l3vpncomm/l3vpnInstances/l3vpnInstance")
        if vpn_instances:
            for vpn_instance in vpn_instances:
                if vpn_instance.find('vrfName').text == self.vrf:
                    if vpn_instance.find('vrfDescription').text == self.description:
                        if self.state == "present":
                            return False
                        else:
                            return True
                    else:
                        return True
            return self.state == "present"
        else:
            return self.state == "present"

    def check_params(self):
        """Check all input params"""
        # vrf check
        if not self.vrf:
            self.module.fail_json(
                msg='Error: The vrf name must be set.')
        # vrf and description check
        if self.vrf == '_public_':
            self.module.fail_json(
                msg='Error: The vrf name _public_ is reserved.')
        if len(self.vrf) < 1 or len(self.vrf) > 31:
            self.module.fail_json(
                msg='Error: The vrf name length must between 1 and 242.')
        if self.description:
            if len(self.description) < 1 or len(self.description) > 242:
                self.module.fail_json(
                    msg='Error: The vrf description length must between 1 and 242.')

    def operate_vrf(self):
        """config/delete vrf"""
        if not self.changed:
            return
        if self.state == "present":
            if self.description is None:
                configxmlstr = CE_NC_CREATE_VRF % (self.vrf, '')
            else:
                configxmlstr = CE_NC_CREATE_VRF % (self.vrf, self.description)
        else:
            configxmlstr = CE_NC_DELETE_VRF % (self.vrf, self.description)

        conf_str = build_config_xml(configxmlstr)

        try:
            con_obj = self.netconf.set_config(config=conf_str)
            self.check_response(con_obj, "OPERATE_VRF")
        except RPCError:
            err = sys.exc_info()[1]
            self.module.fail_json(msg='Error: %s' % err.message.replace("\r\n", ""))

    def get_proposed(self):
        """get_proposed"""

        if self.state == 'present':
            self.proposed['vrf'] = self.vrf
            if self.description:
                self.proposed['description'] = self.description

        else:
            self.proposed = dict()
        self.proposed['state'] = self.state

    def get_existing(self):
        """get_existing"""

        change = self.get_vrf()
        if change:
            if self.state == 'present':
                self.existing = dict()
            else:
                self.existing['vrf'] = self.vrf
                if self.description:
                    self.existing['description'] = self.description
            self.changed = True
        else:
            if self.state == 'absent':
                self.existing = dict()
            else:
                self.existing['vrf'] = self.vrf
                if self.description:
                    self.existing['description'] = self.description
            self.changed = False

    def get_end_state(self):
        """get_end_state"""

        change = self.get_vrf()
        if not change:
            if self.state == 'present':
                self.end_state['vrf'] = self.vrf
                if self.description:
                    self.end_state['description'] = self.description
            else:
                self.end_state = dict()
        else:
            if self.state == 'present':
                self.end_state = dict()
            else:
                self.end_state['vrf'] = self.vrf
                if self.description:
                    self.end_state['description'] = self.description

    def work(self):
        """worker"""

        self.check_params()
        self.get_existing()
        self.get_proposed()
        self.operate_vrf()
        self.set_update_cmd()
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
    """main"""

    argument_spec = dict(
        vrf=dict(required=True, type='str'),
        description=dict(required=False, type='str'),
        state=dict(choices=['absent', 'present'],
                   default='present', required=False),
    )
    argument_spec.update(ce_argument_spec)
    interface = Vrf(argument_spec)
    interface.work()


if __name__ == '__main__':
    main()
