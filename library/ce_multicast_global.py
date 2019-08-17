#!/usr/bin/python
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

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ce_multicast_global
version_added: "2.4"
short_description: Manages multicast global configuration on HUAWEI CloudEngine switches.
description:
    - Manages multicast global on HUAWEI CloudEngine switches.
author:   (@CloudEngine-Ansible)
notes:
    - If no vrf is supplied, vrf is set to default.
      If I(state=absent), the route will be removed, regardless of the
      non-required parameters.
options:
    aftype:
        description:
            - Destination ip address family type of static route.
        required: true
        choices: ['v4','v6']
    vrf:
        description:
            - VPN instance of destination ip address.
        required: false
        default: null
    state:
        description:
            - Specify desired state of the resource.
        required: false
        choices: ['present','absent']
        default: present
'''

EXAMPLES = '''
---

- name: sample playbook
  gather_facts: no
  connection: local
  hosts: device1
  vars:
    cli:
      host: "{{ inventory_hostname }}"
      port: "{{ ansible_ssh_port }}"
      username: "{{ username }}"
      password: "{{ password }}"
      transport: cli

  tasks:
  - name: multicast routing-enable
    ce_multicast_global:
      aftype: v4
      state: absent
      provider: "{{ cli }}"
  - name: multicast routing-enable
    ce_multicast_global:
      aftype: v4
      state: present
      provider: "{{ cli }}"
  - name: multicast routing-enable
    ce_multicast_global:
      aftype: v4
      vrf: vrf1
      provider: "{{ cli }}"

'''
RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"addressFamily": "ipv4unicast", "state": "present", "vrfName": "_public_"}
existing:
    description: k/v pairs of existing switchport
    returned: always
    type: dict
    sample: {}
end_state:
    description: k/v pairs of switchport after module execution
    returned: always
    type: dict
    sample: {"addressFamily": "ipv4unicast", "state": "present", "vrfName": "_public_"}
updates:
    description: command list sent to the device
    returned: always
    type: list
    sample: ["multicast routing-enable"]
changed:
    description: check to see if a change was made on the device
    returned: always
    type: boolean
    sample: true
'''

from xml.etree import ElementTree
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.cloudengine.ce import get_nc_config, set_nc_config, ce_argument_spec

CE_NC_GET_MULTICAST_GLOBAL = """
<filter type="subtree">
  <mcastbase xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <mcastAfsEnables>
      <mcastAfsEnable>
        <addressFamily>%s</addressFamily>
        <vrfName>%s</vrfName>
       </mcastAfsEnable>
    </mcastAfsEnables>
  </mcastbase>
</filter>
"""
CE_NC_MERGE_MULTICAST_GLOBAL = """
<mcastbase xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <mcastAfsEnables>
      <mcastAfsEnable operation="merge">
        <vrfName>%s</vrfName>
        <addressFamily>%s</addressFamily>
      </mcastAfsEnable>
    </mcastAfsEnables>
</mcastbase>
"""
CE_NC_DELETE_MULTICAST_GLOBAL = """
<mcastbase xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <mcastAfsEnables>
      <mcastAfsEnable operation="delete">
        <vrfName>%s</vrfName>
        <addressFamily>%s</addressFamily>
      </mcastAfsEnable>
    </mcastAfsEnables>
</mcastbase>
"""


def build_config_xml(xmlstr):
    """build config xml"""

    return '<config> ' + xmlstr + ' </config>'


class MulticastGlobal(object):
    """multicast global module"""

    def __init__(self, argument_spec):
        """multicast global info"""
        self.spec = argument_spec
        self.module = None
        self._initmodule_()

        self.aftype = self.module.params['aftype']
        self.state = self.module.params['state']
        if self.aftype == "v4":
            self.version = "ipv4unicast"
        else:
            self.version = "ipv6unicast"
        # vpn instance info
        self.vrf = self.module.params['vrf']
        if self.vrf is None:
            self.vrf = "_public_"
        # state
        self.changed = False
        self.updates_cmd = list()
        self.results = dict()
        self.proposed = dict()
        self.existing = dict()
        self.end_state = dict()

        self.multicast_global_info = dict()

    def _initmodule_(self):
        """init module"""
        self.module = AnsibleModule(
            argument_spec=self.spec, supports_check_mode=False)

    def _checkresponse_(self, xml_str, xml_name):
        """check if response message is already succeed."""

        if "<ok/>" not in xml_str:
            self.module.fail_json(msg='Error: %s failed.' % xml_name)

    def set_change_state(self):
        """set change state"""
        state = self.state
        change = False
        self.get_multicast_global()
        # new or edit
        if state == 'present':
            if not self.multicast_global_info['multicast_global']:
                # self.multicast_global_info['multicast_global'] has not value
                change = True
        else:
            # delete
            if self.multicast_global_info['multicast_global']:
                # self.multicast_global_info['multicast_global'] has value
                change = True
        self.changed = change

    def get_multicast_global(self):
        """get one data"""
        self.multicast_global_info["multicast_global"] = list()
        getxmlstr = CE_NC_GET_MULTICAST_GLOBAL % (
            self.version, self.vrf)
        xml_str = get_nc_config(self.module, getxmlstr)
        if 'data/' in xml_str:
            return
        xml_str = xml_str.replace('\r', '').replace('\n', ''). \
            replace('xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"', ""). \
            replace('xmlns="http://www.huawei.com/netconf/vrp"', "")
        root = ElementTree.fromstring(xml_str)
        mcast_enable = root.findall(
            "mcastbase/mcastAfsEnables/mcastAfsEnable")
        if mcast_enable:
            # mcast_enable = [{vrfName:11,addressFamily:'xx'},{vrfName:22,addressFamily:'xx'}...]
            for mcast_enable_key in mcast_enable:
                # mcast_enable_key = {vrfName:11,addressFamily:'xx'}
                mcast_info = dict()
                for ele in mcast_enable_key:
                    if ele.tag in ["vrfName", "addressFamily"]:
                        mcast_info[ele.tag] = ele.text
            self.multicast_global_info['multicast_global'].append(mcast_info)

    def get_existing(self):
        """get existing information"""
        self.set_change_state()
        self.existing["multicast_global"] = self.multicast_global_info["multicast_global"]

    def get_proposed(self):
        """get proposed information"""
        self.proposed['addressFamily'] = self.version
        self.proposed['state'] = self.state
        self.proposed['vrfName'] = self.vrf

    def set_multicast_global(self):
        """set multicast global"""
        if not self.changed:
            return
        version = self.version
        state = self.state
        if state == "present":
            configxmlstr = CE_NC_MERGE_MULTICAST_GLOBAL % (self.vrf, version)
        else:
            configxmlstr = CE_NC_DELETE_MULTICAST_GLOBAL % (self.vrf, version)

        conf_str = build_config_xml(configxmlstr)
        recv_xml = set_nc_config(self.module, conf_str)
        self._checkresponse_(recv_xml, "SET_MULTICAST_GLOBAL")

    def set_update_cmd(self):
        """set update command"""
        if not self.changed:
            return
        if self.state == "present":
            self.updates_cmd.append('multicast routing-enable')
        else:
            self.updates_cmd.append('undo multicast routing-enable')

    def get_end_state(self):
        """get end state information"""
        self.get_multicast_global()
        self.end_state["multicast_global"] = self.multicast_global_info["multicast_global"]

    def work(self):
        """worker"""
        self.get_existing()
        self.get_proposed()
        self.set_multicast_global()
        self.set_update_cmd()
        self.get_end_state()
        self.results['changed'] = self.changed
        self.results['existing'] = self.existing
        self.results['proposed'] = self.proposed
        self.results['end_state'] = self.end_state
        if self.changed:
            self.results['updates'] = self.updates_cmd
        else:
            self.results['updates'] = list()
        self.module.exit_json(**self.results)


def main():
    """main"""

    argument_spec = dict(
        aftype=dict(choices=['v4', 'v6'], required=True),
        vrf=dict(required=False, type='str'),
        state=dict(choices=['absent', 'present'],
                   default='present', required=False),
    )
    argument_spec.update(ce_argument_spec)
    interface = MulticastGlobal(argument_spec)
    interface.work()


if __name__ == '__main__':
    main()
