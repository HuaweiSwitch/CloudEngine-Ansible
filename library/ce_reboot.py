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
module: ce_reboot
version_added: 2.3
short_description: Reboot a network device.
description:
    - Reboot a network device.
extends_documentation_fragment: cloudengine
author:
    - Gong Jianjun (@CloudEngine-Ansible)
notes:
    - The network device.
options:
    confirm:
        description:
            - Safeguard boolean. Set to true if you're sure you want to reboot.
        required: true
    save_config:
        description:
            - Flag indicating whether to save the configuration.
        required: false
        default: false
'''

EXAMPLES = '''
- ce_reboot:
    confirm: true
    save_config: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
'''

RETURN = '''
rebooted:
    description: Whether the device was instructed to reboot.
    returned: success
    type: boolean
    sample: true
'''


from ansible.module_utils.network import NetworkModule
from ansible.module_utils.cloudengine import get_netconf

HAS_NCCLIENT = False
try:
    from ncclient.operations.errors import TimeoutExpiredError
    HAS_NCCLIENT = True
except ImportError:
    HAS_NCCLIENT = False

CE_NC_XML_EXECUTE_REBOOT = """
    <action>
      <devm xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <reboot>
            <saveConfig>%s</saveConfig>
        </reboot>
      </devm>
    </action>
"""


class Reboot(object):
    """ Reboot a network device """

    def __init__(self, **kwargs):
        """ __init___ """

        self.network_module = None
        self.netconf = None
        self.init_network_module(**kwargs)

        # host info
        self.host = self.network_module.params['host']
        self.port = self.network_module.params['port']
        self.username = self.network_module.params['username']
        self.password = self.network_module.params['password']

        self.confirm = self.network_module.params['confirm']
        self.save_config = self.network_module.params['save_config']

        self.init_netconf(host=self.host, port=self.port,
                          username=self.username, password=self.password)

    def init_network_module(self, **kwargs):
        """ init network module """

        self.network_module = NetworkModule(**kwargs)

    def init_netconf(self, **kwargs):
        """ init netconf """

        if not HAS_NCCLIENT:
            raise Exception("the ncclient library is required")

        self.netconf = get_netconf(**kwargs)
        if not self.netconf:
            self.network_module.fail_json(msg='Error: Netconf init failed.')

    def netconf_set_action(self, xml_str):
        """ netconf execute action """

        try:
            self.netconf.execute_action(action=xml_str)
        except TimeoutExpiredError:
            pass

    def work(self):
        """ start to work """

        if not self.confirm:
            self.network_module.fail_json(
                msg='Error: Confirm must be set to true for this module to work.')

        xml_str = CE_NC_XML_EXECUTE_REBOOT % self.save_config
        self.netconf_set_action(xml_str)


def main():
    """ main """

    argument_spec = dict(
        confirm=dict(required=True, type='bool'),
        save_config=dict(required=False, default='false',
                         type='str', choices=['true', 'false'])
    )

    module = Reboot(argument_spec=argument_spec, supports_check_mode=True)

    changed = False
    rebooted = False

    module.work()

    changed = True
    rebooted = True

    results = dict()
    results['changed'] = changed
    results['rebooted'] = rebooted

    module.network_module.exit_json(**results)


if __name__ == '__main__':
    main()
