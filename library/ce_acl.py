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
module: ce_acl
version_added: "2.3"
short_description: Manages base ACL configuration.
description:
    - Manages base ACL configurations on CloudEngine switches.
author:
    - wangdezhuang (@CloudEngine-Ansible)
options:
    state:
        description:
            - Specify desired state of the resource.
        required: false
        default: present
        choices: ['present','absent','delete_acl']
    acl_name:
        description:
            - ACL number or name.
              For a numbered rule group, the value ranging from 2000 to 2999 indicates a basic ACL.
              For a named rule group, the value is a string of 1 to 32 case-sensitive characters starting
              with a letter, spaces not supported.
        required: true
    acl_num:
        description:
            - ACL number.
              The value is an integer ranging from 2000 to 2999.
        required: false
        default: null
    acl_step:
        description:
            - ACL step.
              The value is an integer ranging from 1 to 20. The default value is 5.
        required: false
        default: null
    acl_description:
        description:
            - ACL description.
              The value is a string of 1 to 127 characters.
        required: false
        default: null
    rule_name:
        description:
            - Name of a basic ACL rule.
              The value is a string of 1 to 32 characters.
              The value is case-insensitive, and cannot contain spaces or begin with an underscore (_).
        required: false
        default: null
    rule_id:
        description:
            - ID of a basic ACL rule in configuration mode.
              The value is an integer ranging from 0 to 4294967294.
        required: false
        default: null
    rule_action:
        description:
            - Matching mode of basic ACL rules.
        required: false
        default: null
        choices: ['permit','deny']
    source_ip:
        description:
            - Source IP address.
              The value is a string of 0 to 255 characters.The default value is 0.0.0.0.
              The value is in dotted decimal notation.
        required: false
        default: null
    src_mask:
        description:
            - Mask of a source IP address.
              The value is an integer ranging from 1 to 32.
        required: false
        default: null
    frag_type:
        description:
            - Type of packet fragmentation.
        required: false
        default: null
        choices: ['fragment', 'clear_fragment']
    vrf_name:
        description:
            - VPN instance name.
              The value is a string of 1 to 31 characters.The default value is _public_.
        required: false
        default: null
    time_range:
        description:
            - Name of a time range in which an ACL rule takes effect.
              The value is a string of 1 to 32 characters.
              The value is case-insensitive, and cannot contain spaces. The name must start with an uppercase
              or lowercase letter. In addition, the word "all" cannot be specified as a time range name.
        required: false
        default: null
    rule_description:
        description:
            - Description about an ACL rule.
              The value is a string of 1 to 127 characters.
        required: false
        default: null
    log_flag:
        description:
            - Flag of logging matched data packets.
        required: false
        default: false
        choices: ['true', 'false']
'''

EXAMPLES = '''

- name: CloudEngine command test
  vars:
    host: "{{ inventory_hostname }}"
    username: admin
    password: admin
    transport: cli

  tasks:

  - name: "Config ACL"
    ce_acl:
      state:  present
      acl_name:  2200
      provider: "{{ cli }}"

  - name: "Undo ACL"
    ce_acl:
      state:  delete_acl
      acl_name:  2200
      provider: "{{ cli }}"

  - name: "Config ACL base rule"
    ce_acl:
      state:  present
      acl_name:  2200
      rule_name:  test_rule
      rule_id:  111
      rule_action:  permit
      source_ip:  10.10.10.10
      src_mask:  24
      frag_type:  fragment
      time_range:  wdz_acl_time
      provider: "{{ cli }}"

  - name: "undo ACL base rule"
    ce_acl:
      state:  absent
      acl_name:  2200
      rule_name:  test_rule
      rule_id:  111
      rule_action:  permit
      source_ip:  10.10.10.10
      src_mask:  24
      frag_type:  fragment
      time_range:  wdz_acl_time
      provider: "{{ cli }}"
'''

RETURN = '''
changed:
    description: check to see if a change was made on the device
    returned: always
    type: boolean
    sample: true
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"acl_name": "test", "state": "delete_acl"}
existing:
    description:
        - k/v pairs of existing aaa server
    type: dict
    sample: {"aclNumOrName": "test", "aclType": "Basic"}
end_state:
    description: k/v pairs of aaa params after module execution
    returned: always
    type: dict
    sample: {}
updates:
    description: command sent to the device
    returned: always
    type: list
    sample: ["undo acl name test"]
'''

import socket
import sys
from xml.etree import ElementTree
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ce import get_netconf, ce_argument_spec

try:
    from ncclient.operations.rpc import RPCError
    HAS_NCCLIENT = True
except ImportError:
    HAS_NCCLIENT = False


# get acl
CE_GET_ACL_HEADER = """
    <filter type="subtree">
      <acl xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <aclGroups>
          <aclGroup>
            <aclNumOrName></aclNumOrName>
"""
CE_GET_ACL_TAIL = """
          </aclGroup>
        </aclGroups>
      </acl>
    </filter>
"""
# merge acl
CE_MERGE_ACL_HEADER = """
    <config>
      <acl xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <aclGroups>
          <aclGroup operation="merge">
            <aclNumOrName>%s</aclNumOrName>
"""
CE_MERGE_ACL_TAIL = """
          </aclGroup>
        </aclGroups>
      </acl>
    </config>
"""
# delete acl
CE_DELETE_ACL_HEADER = """
    <config>
      <acl xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <aclGroups>
          <aclGroup operation="delete">
            <aclNumOrName>%s</aclNumOrName>
"""
CE_DELETE_ACL_TAIL = """
          </aclGroup>
        </aclGroups>
      </acl>
    </config>
"""

# get acl base rule
CE_GET_ACL_BASE_RULE_HEADER = """
    <filter type="subtree">
      <acl xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <aclGroups>
          <aclGroup>
            <aclNumOrName>%s</aclNumOrName>
            <aclRuleBas4s>
              <aclRuleBas4>
                <aclRuleName></aclRuleName>
"""
CE_GET_ACL_BASE_RULE_TAIL = """
              </aclRuleBas4>
            </aclRuleBas4s>
          </aclGroup>
        </aclGroups>
      </acl>
    </filter>
"""
# merge acl base rule
CE_MERGE_ACL_BASE_RULE_HEADER = """
    <config>
      <acl xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <aclGroups>
          <aclGroup>
            <aclNumOrName>%s</aclNumOrName>
            <aclRuleBas4s>
              <aclRuleBas4 operation="merge">
                <aclRuleName>%s</aclRuleName>
"""
CE_MERGE_ACL_BASE_RULE_TAIL = """
              </aclRuleBas4>
            </aclRuleBas4s>
          </aclGroup>
        </aclGroups>
      </acl>
    </config>
"""
# delete acl base rule
CE_DELETE_ACL_BASE_RULE_HEADER = """
    <config>
      <acl xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <aclGroups>
          <aclGroup>
            <aclNumOrName>%s</aclNumOrName>
            <aclRuleBas4s>
              <aclRuleBas4 operation="delete">
                <aclRuleName>%s</aclRuleName>
"""
CE_DELETE_ACL_BASE_RULE_TAIL = """
              </aclRuleBas4>
            </aclRuleBas4s>
          </aclGroup>
        </aclGroups>
      </acl>
    </config>
"""


def check_ip_addr(ipaddr):
    """ check_ip_addr, Supports IPv4 and IPv6 """

    if not ipaddr or '\x00' in ipaddr:
        return False

    try:
        res = socket.getaddrinfo(ipaddr, 0, socket.AF_UNSPEC,
                                 socket.SOCK_STREAM,
                                 0, socket.AI_NUMERICHOST)
        return bool(res)
    except socket.gaierror:
        err = sys.exc_info()[1]
        if err.args[0] == socket.EAI_NONAME:
            return False
        raise
    return True


class BaseAcl(object):
    """ Manages base acl configuration """

    def __init__(self, **kwargs):
        """ Class init """

        # argument spec
        argument_spec = kwargs["argument_spec"]
        self.spec = argument_spec
        self.module = AnsibleModule(argument_spec=self.spec, supports_check_mode=True)

        # module args
        self.state = self.module.params['state']
        self.host = self.module.params['provider']['host']
        self.port = self.module.params['provider']['port']
        self.username = self.module.params['provider']['username']
        self.password = self.module.params['provider']['password']
        self.acl_name = self.module.params['acl_name'] or None
        self.acl_num = self.module.params['acl_num'] or None
        self.acl_type = None
        self.acl_step = self.module.params['acl_step'] or None
        self.acl_description = self.module.params['acl_description'] or None
        self.rule_name = self.module.params['rule_name'] or None
        self.rule_id = self.module.params['rule_id'] or None
        self.rule_action = self.module.params['rule_action'] or None
        self.source_ip = self.module.params['source_ip'] or None
        self.src_mask = self.module.params['src_mask'] or None
        self.src_wild = None
        self.frag_type = self.module.params['frag_type'] or None
        self.vrf_name = self.module.params['vrf_name'] or None
        self.time_range = self.module.params['time_range'] or None
        self.rule_description = self.module.params['rule_description'] or None
        self.log_flag = self.module.params['log_flag']

        # cur config
        self.cur_acl_cfg = dict()
        self.cur_base_rule_cfg = dict()

        # state
        self.changed = False
        self.updates_cmd = list()
        self.results = dict()
        self.proposed = dict()
        self.existing = dict()
        self.end_state = dict()

        # netconf
        if not HAS_NCCLIENT:
            raise Exception("Error: The ncclient library is required.")

        self.netconf = get_netconf(host=self.host,
                                   port=self.port,
                                   username=self.username,
                                   password=self.password)
        if not self.netconf:
            self.module.fail_json(msg='Error: netconf init failed.')

    def netconf_get_config(self, conf_str):
        """ Get configure by netconf """

        try:
            con_obj = self.netconf.get_config(filter=conf_str)
        except RPCError:
            err = sys.exc_info()[1]
            self.module.fail_json(msg='Error: %s.' %
                                  err.message.replace("\r\n", ""))

        return con_obj

    def netconf_set_config(self, conf_str):
        """ Set configure by netconf """

        try:
            con_obj = self.netconf.set_config(config=conf_str)
        except RPCError:
            err = sys.exc_info()[1]
            self.module.fail_json(msg='Error: %s.' %
                                  err.message.replace("\r\n", ""))

        return con_obj

    def get_wildcard_mask(self):
        """ convert mask length to ip address wildcard mask, i.e. 24 to 0.0.0.255 """

        mask_int = ["255"] * 4
        value = int(self.src_mask)

        if value > 32:
            self.module.fail_json(msg='Error: IPv4 ipaddress mask length is invalid.')
        if value < 8:
            mask_int[0] = str(int(~(0xFF << (8 - value % 8)) & 0xFF))
        if value >= 8:
            mask_int[0] = '0'
            mask_int[1] = str(int(~(0xFF << (16 - (value % 16))) & 0xFF))
        if value >= 16:
            mask_int[1] = '0'
            mask_int[2] = str(int(~(0xFF << (24 - (value % 24))) & 0xFF))
        if value >= 24:
            mask_int[2] = '0'
            mask_int[3] = str(int(~(0xFF << (32 - (value % 32))) & 0xFF))
        if value == 32:
            mask_int[3] = '0'

        return '.'.join(mask_int)

    def check_acl_args(self):
        """ Check acl invalid args """

        need_cfg = False
        find_flag = False
        self.cur_acl_cfg["acl_info"] = []

        if self.acl_name:

            if self.acl_name.isdigit():
                if int(self.acl_name) < 2000 or int(self.acl_name) > 2999:
                    self.module.fail_json(
                        msg='Error: The value of acl_name is out of [2000-2999] for base ACL.')

                if self.acl_num:
                    self.module.fail_json(
                        msg='Error: The acl_name is digit, so should not input acl_num at the same time.')
            else:

                self.acl_type = "Basic"

                if len(self.acl_name) < 1 or len(self.acl_name) > 32:
                    self.module.fail_json(
                        msg='Error: The len of acl_name is out of [1 - 32].')

                if self.state == "present":
                    if not self.acl_num and not self.acl_type and not self.rule_name:
                        self.module.fail_json(
                            msg='Error: Please input acl_num or acl_type when config ACL.')

            if self.acl_num:
                if self.acl_num.isdigit():
                    if int(self.acl_num) < 2000 or int(self.acl_num) > 2999:
                        self.module.fail_json(
                            msg='Error: The value of acl_name is out of [2000-2999] for base ACL.')
                else:
                    self.module.fail_json(
                        msg='Error: The acl_num is not digit.')

            if self.acl_step:
                if self.acl_step.isdigit():
                    if int(self.acl_step) < 1 or int(self.acl_step) > 20:
                        self.module.fail_json(
                            msg='Error: The value of acl_step is out of [1 - 20].')
                else:
                    self.module.fail_json(
                        msg='Error: The acl_step is not digit.')

            if self.acl_description:
                if len(self.acl_description) < 1 or len(self.acl_description) > 127:
                    self.module.fail_json(
                        msg='Error: The len of acl_description is out of [1 - 127].')

            conf_str = CE_GET_ACL_HEADER

            if self.acl_type:
                conf_str += "<aclType></aclType>"
            if self.acl_num:
                conf_str += "<aclNumber></aclNumber>"
            if self.acl_step:
                conf_str += "<aclStep></aclStep>"
            if self.acl_description:
                conf_str += "<aclDescription></aclDescription>"

            conf_str += CE_GET_ACL_TAIL
            con_obj = self.netconf_get_config(conf_str=conf_str)

            if "<data/>" in con_obj.xml:
                find_flag = False

            else:
                xml_str = con_obj.xml.replace('\r', '').replace('\n', '').\
                    replace('xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"', "").\
                    replace('xmlns="http://www.huawei.com/netconf/vrp"', "")

                root = ElementTree.fromstring(xml_str)

                # parse acl
                acl_info = root.findall(
                    "data/acl/aclGroups/aclGroup")
                if acl_info:
                    for tmp in acl_info:
                        tmp_dict = dict()
                        for site in tmp:
                            if site.tag in ["aclNumOrName", "aclType", "aclNumber", "aclStep", "aclDescription"]:
                                tmp_dict[site.tag] = site.text

                        self.cur_acl_cfg["acl_info"].append(tmp_dict)

                if self.cur_acl_cfg["acl_info"]:
                    for tmp in self.cur_acl_cfg["acl_info"]:
                        find_flag = True

                        if self.acl_name and tmp.get("aclNumOrName") != self.acl_name:
                            find_flag = False
                        if self.acl_type and tmp.get("aclType") != self.acl_type:
                            find_flag = False
                        if self.acl_num and tmp.get("aclNumber") != self.acl_num:
                            find_flag = False
                        if self.acl_step and tmp.get("aclStep") != self.acl_step:
                            find_flag = False
                        if self.acl_description and tmp.get("aclDescription") != self.acl_description:
                            find_flag = False

                        if find_flag:
                            break
                else:
                    find_flag = False

        if self.state == "present":
            need_cfg = bool(not find_flag)
        elif self.state == "delete_acl":
            need_cfg = bool(find_flag)
        else:
            need_cfg = False

        self.cur_acl_cfg["need_cfg"] = need_cfg

    def check_base_rule_args(self):
        """ Check base rule invalid args """

        need_cfg = False
        find_flag = False
        self.cur_base_rule_cfg["base_rule_info"] = []

        if self.acl_name:

            if self.state == "absent":
                if not self.rule_name:
                    self.module.fail_json(
                        msg='Error: Please input rule_name when state is absent.')

            # config rule
            if self.rule_name:
                if len(self.rule_name) < 1 or len(self.rule_name) > 32:
                    self.module.fail_json(
                        msg='Error: The len of rule_name is out of [1 - 32].')

                if self.state != "delete_acl" and not self.rule_id:
                    self.module.fail_json(
                        msg='Error: Please input rule_id.')

                if self.rule_id:
                    if self.rule_id.isdigit():
                        if int(self.rule_id) < 0 or int(self.rule_id) > 4294967294:
                            self.module.fail_json(
                                msg='Error: The value of rule_id is out of [0 - 4294967294].')
                    else:
                        self.module.fail_json(
                            msg='Error: The rule_id is not digit.')

                if self.source_ip:
                    if not check_ip_addr(self.source_ip):
                        self.module.fail_json(
                            msg='Error: The source_ip %s is invalid.' % self.source_ip)
                    if not self.src_mask:
                        self.module.fail_json(
                            msg='Error: Please input src_mask.')

                if self.src_mask:
                    if self.src_mask.isdigit():
                        if int(self.src_mask) < 1 or int(self.src_mask) > 32:
                            self.module.fail_json(
                                msg='Error: The src_mask is out of [1 - 32].')
                        self.src_wild = self.get_wildcard_mask()
                    else:
                        self.module.fail_json(
                            msg='Error: The src_mask is not digit.')

                if self.vrf_name:
                    if len(self.vrf_name) < 1 or len(self.vrf_name) > 31:
                        self.module.fail_json(
                            msg='Error: The len of vrf_name is out of [1 - 31].')

                if self.time_range:
                    if len(self.time_range) < 1 or len(self.time_range) > 32:
                        self.module.fail_json(
                            msg='Error: The len of time_range is out of [1 - 32].')

                if self.rule_description:
                    if len(self.rule_description) < 1 or len(self.rule_description) > 127:
                        self.module.fail_json(
                            msg='Error: The len of rule_description is out of [1 - 127].')

                    if self.state != "delete_acl" and not self.rule_id:
                        self.module.fail_json(
                            msg='Error: Please input rule_id.')

                conf_str = CE_GET_ACL_BASE_RULE_HEADER % self.acl_name

                if self.rule_id:
                    conf_str += "<aclRuleID></aclRuleID>"
                if self.rule_action:
                    conf_str += "<aclAction></aclAction>"
                if self.source_ip:
                    conf_str += "<aclSourceIp></aclSourceIp>"
                if self.src_wild:
                    conf_str += "<aclSrcWild></aclSrcWild>"
                if self.frag_type:
                    conf_str += "<aclFragType></aclFragType>"
                if self.vrf_name:
                    conf_str += "<vrfName></vrfName>"
                if self.time_range:
                    conf_str += "<aclTimeName></aclTimeName>"
                if self.rule_description:
                    conf_str += "<aclRuleDescription></aclRuleDescription>"
                conf_str += "<aclLogFlag></aclLogFlag>"

                conf_str += CE_GET_ACL_BASE_RULE_TAIL
                con_obj = self.netconf_get_config(conf_str=conf_str)

                if "<data/>" in con_obj.xml:
                    find_flag = False

                else:
                    xml_str = con_obj.xml.replace('\r', '').replace('\n', '').\
                        replace('xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"', "").\
                        replace('xmlns="http://www.huawei.com/netconf/vrp"', "")

                    root = ElementTree.fromstring(xml_str)

                    # parse base rule
                    base_rule_info = root.findall(
                        "data/acl/aclGroups/aclGroup/aclRuleBas4s/aclRuleBas4")
                    if base_rule_info:
                        for tmp in base_rule_info:
                            tmp_dict = dict()
                            for site in tmp:
                                if site.tag in ["aclRuleName", "aclRuleID", "aclAction", "aclSourceIp", "aclSrcWild",
                                                "aclFragType", "vrfName", "aclTimeName", "aclRuleDescription",
                                                "aclLogFlag"]:
                                    tmp_dict[site.tag] = site.text

                            self.cur_base_rule_cfg[
                                "base_rule_info"].append(tmp_dict)

                    if self.cur_base_rule_cfg["base_rule_info"]:
                        for tmp in self.cur_base_rule_cfg["base_rule_info"]:
                            find_flag = True

                            if self.rule_name and tmp.get("aclRuleName") != self.rule_name:
                                find_flag = False
                            if self.rule_id and tmp.get("aclRuleID") != self.rule_id:
                                find_flag = False
                            if self.rule_action and tmp.get("aclAction") != self.rule_action:
                                find_flag = False
                            if self.source_ip:
                                tmp_src_ip = self.source_ip.split(".")
                                tmp_src_wild = self.src_wild.split(".")
                                tmp_addr_item = []
                                for idx in range(4):
                                    item1 = 255 - int(tmp_src_wild[idx])
                                    item2 = item1 & int(tmp_src_ip[idx])
                                    tmp_addr_item.append(item2)
                                tmp_addr = "%s.%s.%s.%s" % (tmp_addr_item[0], tmp_addr_item[1],
                                                            tmp_addr_item[2], tmp_addr_item[3])
                                if tmp_addr != tmp.get("aclSourceIp"):
                                    find_flag = False
                            if self.src_wild and tmp.get("aclSrcWild") != self.src_wild:
                                find_flag = False
                            if self.frag_type and tmp.get("aclFragType") != self.frag_type:
                                find_flag = False
                            if self.vrf_name and tmp.get("vrfName") != self.vrf_name:
                                find_flag = False
                            if self.time_range and tmp.get("aclTimeName") != self.time_range:
                                find_flag = False
                            if self.rule_description and tmp.get("aclRuleDescription") != self.rule_description:
                                find_flag = False
                            if tmp.get("aclLogFlag") != str(self.log_flag).lower():
                                find_flag = False

                            if find_flag:
                                break
                    else:
                        find_flag = False

                if self.state == "present":
                    need_cfg = bool(not find_flag)
                elif self.state == "absent":
                    need_cfg = bool(find_flag)
                else:
                    need_cfg = False

        self.cur_base_rule_cfg["need_cfg"] = need_cfg

    def get_proposed(self):
        """ Get proposed state """

        self.proposed["state"] = self.state

        if self.acl_name:
            self.proposed["acl_name"] = self.acl_name
        if self.acl_num:
            self.proposed["acl_num"] = self.acl_num
        if self.acl_step:
            self.proposed["acl_step"] = self.acl_step
        if self.acl_description:
            self.proposed["acl_description"] = self.acl_description
        if self.rule_name:
            self.proposed["rule_name"] = self.rule_name
        if self.rule_id:
            self.proposed["rule_id"] = self.rule_id
        if self.rule_action:
            self.proposed["rule_action"] = self.rule_action
        if self.source_ip:
            self.proposed["source_ip"] = self.source_ip
        if self.src_mask:
            self.proposed["src_mask"] = self.src_mask
        if self.frag_type:
            self.proposed["frag_type"] = self.frag_type
        if self.vrf_name:
            self.proposed["vrf_name"] = self.vrf_name
        if self.time_range:
            self.proposed["time_range"] = self.time_range
        if self.rule_description:
            self.proposed["rule_description"] = self.rule_description
        if self.log_flag:
            self.proposed["log_flag"] = self.log_flag

    def get_existing(self):
        """ Get existing state """

        self.existing["acl_info"] = self.cur_acl_cfg["acl_info"]
        self.existing["base_rule_info"] = self.cur_base_rule_cfg[
            "base_rule_info"]

    def get_end_state(self):
        """ Get end state """

        self.check_acl_args()
        self.end_state["acl_info"] = self.cur_acl_cfg["acl_info"]

        self.check_base_rule_args()
        self.end_state["base_rule_info"] = self.cur_base_rule_cfg[
            "base_rule_info"]

    def merge_acl(self):
        """ Merge acl operation """

        conf_str = CE_MERGE_ACL_HEADER % self.acl_name

        if self.acl_type:
            conf_str += "<aclType>%s</aclType>" % self.acl_type
        if self.acl_num:
            conf_str += "<aclNumber>%s</aclNumber>" % self.acl_num
        if self.acl_step:
            conf_str += "<aclStep>%s</aclStep>" % self.acl_step
        if self.acl_description:
            conf_str += "<aclDescription>%s</aclDescription>" % self.acl_description

        conf_str += CE_MERGE_ACL_TAIL

        con_obj = self.netconf_set_config(conf_str=conf_str)

        if "<ok/>" not in con_obj.xml:
            self.module.fail_json(msg='Error: Merge acl failed.')

        if self.acl_name.isdigit():
            cmd = "acl number %s" % self.acl_name
        else:
            if self.acl_type and not self.acl_num:
                cmd = "acl name %s %s" % (self.acl_name, self.acl_type.lower())
            elif self.acl_type and self.acl_num:
                cmd = "acl name %s number %s" % (self.acl_name, self.acl_num)
            elif not self.acl_type and self.acl_num:
                cmd = "acl name %s number %s" % (self.acl_name, self.acl_num)
        self.updates_cmd.append(cmd)

        if self.acl_description:
            cmd = "description %s" % self.acl_description
            self.updates_cmd.append(cmd)

        if self.acl_step:
            cmd = "step %s" % self.acl_step
            self.updates_cmd.append(cmd)

        self.changed = True

    def delete_acl(self):
        """ Delete acl operation """

        conf_str = CE_DELETE_ACL_HEADER % self.acl_name

        if self.acl_type:
            conf_str += "<aclType>%s</aclType>" % self.acl_type
        if self.acl_num:
            conf_str += "<aclNumber>%s</aclNumber>" % self.acl_num
        if self.acl_step:
            conf_str += "<aclStep>%s</aclStep>" % self.acl_step
        if self.acl_description:
            conf_str += "<aclDescription>%s</aclDescription>" % self.acl_description

        conf_str += CE_DELETE_ACL_TAIL

        con_obj = self.netconf_set_config(conf_str=conf_str)

        if "<ok/>" not in con_obj.xml:
            self.module.fail_json(msg='Error: Delete acl failed.')

        if self.acl_description:
            cmd = "undo description"
            self.updates_cmd.append(cmd)

        if self.acl_step:
            cmd = "undo step"
            self.updates_cmd.append(cmd)

        if self.acl_name.isdigit():
            cmd = "undo acl number %s" % self.acl_name
        else:
            cmd = "undo acl name %s" % self.acl_name
        self.updates_cmd.append(cmd)

        self.changed = True

    def merge_base_rule(self):
        """ Merge base rule operation """

        conf_str = CE_MERGE_ACL_BASE_RULE_HEADER % (
            self.acl_name, self.rule_name)

        if self.rule_id:
            conf_str += "<aclRuleID>%s</aclRuleID>" % self.rule_id
        if self.rule_action:
            conf_str += "<aclAction>%s</aclAction>" % self.rule_action
        if self.source_ip:
            conf_str += "<aclSourceIp>%s</aclSourceIp>" % self.source_ip
        if self.src_wild:
            conf_str += "<aclSrcWild>%s</aclSrcWild>" % self.src_wild
        if self.frag_type:
            conf_str += "<aclFragType>%s</aclFragType>" % self.frag_type
        if self.vrf_name:
            conf_str += "<vrfName>%s</vrfName>" % self.vrf_name
        if self.time_range:
            conf_str += "<aclTimeName>%s</aclTimeName>" % self.time_range
        if self.rule_description:
            conf_str += "<aclRuleDescription>%s</aclRuleDescription>" % self.rule_description
        conf_str += "<aclLogFlag>%s</aclLogFlag>" % str(self.log_flag).lower()

        conf_str += CE_MERGE_ACL_BASE_RULE_TAIL

        con_obj = self.netconf_set_config(conf_str=conf_str)

        if "<ok/>" not in con_obj.xml:
            self.module.fail_json(msg='Error: Merge acl base rule failed.')

        if self.rule_action:
            cmd = "rule"
            if self.rule_id:
                cmd += " %s" % self.rule_id
            cmd += " %s" % self.rule_action
            if self.frag_type == "fragment":
                cmd += " fragment-type fragment"
            if self.source_ip and self.src_wild:
                cmd += " source %s %s" % (self.source_ip, self.src_wild)
            if self.time_range:
                cmd += " time-range %s" % self.time_range
            if self.vrf_name:
                cmd += " vpn-instance %s" % self.vrf_name
            if self.log_flag:
                cmd += " logging"
            self.updates_cmd.append(cmd)

        if self.rule_description:
            cmd = "rule %s description %s" % (
                self.rule_id, self.rule_description)
            self.updates_cmd.append(cmd)

        self.changed = True

    def delete_base_rule(self):
        """ Delete base rule operation """

        conf_str = CE_DELETE_ACL_BASE_RULE_HEADER % (
            self.acl_name, self.rule_name)

        if self.rule_id:
            conf_str += "<aclRuleID>%s</aclRuleID>" % self.rule_id
        if self.rule_action:
            conf_str += "<aclAction>%s</aclAction>" % self.rule_action
        if self.source_ip:
            conf_str += "<aclSourceIp>%s</aclSourceIp>" % self.source_ip
        if self.src_wild:
            conf_str += "<aclSrcWild>%s</aclSrcWild>" % self.src_wild
        if self.frag_type:
            conf_str += "<aclFragType>%s</aclFragType>" % self.frag_type
        if self.vrf_name:
            conf_str += "<vrfName>%s</vrfName>" % self.vrf_name
        if self.time_range:
            conf_str += "<aclTimeName>%s</aclTimeName>" % self.time_range
        if self.rule_description:
            conf_str += "<aclRuleDescription>%s</aclRuleDescription>" % self.rule_description
        conf_str += "<aclLogFlag>%s</aclLogFlag>" % str(self.log_flag).lower()

        conf_str += CE_DELETE_ACL_BASE_RULE_TAIL

        con_obj = self.netconf_set_config(conf_str=conf_str)

        if "<ok/>" not in con_obj.xml:
            self.module.fail_json(msg='Error: Delete acl base rule failed.')

        if self.rule_description:
            if self.acl_name.isdigit():
                cmd = "acl number %s" % self.acl_name
            else:
                cmd = "acl name %s" % self.acl_name
            self.updates_cmd.append(cmd)

            cmd = "undo rule %s description" % self.rule_id
            self.updates_cmd.append(cmd)

        if self.rule_id:
            if self.acl_name.isdigit():
                cmd = "acl number %s" % self.acl_name
            else:
                cmd = "acl name %s" % self.acl_name
            self.updates_cmd.append(cmd)

            cmd = "undo rule %s" % self.rule_id
            self.updates_cmd.append(cmd)
        elif self.rule_action:
            if self.acl_name.isdigit():
                cmd = "acl number %s" % self.acl_name
            else:
                cmd = "acl name %s" % self.acl_name
            self.updates_cmd.append(cmd)

            cmd = "undo rule"
            cmd += " %s" % self.rule_action
            if self.frag_type == "fragment":
                cmd += " fragment-type fragment"
            if self.source_ip and self.src_wild:
                cmd += " source %s %s" % (self.source_ip, self.src_wild)
            if self.time_range:
                cmd += " time-range %s" % self.time_range
            if self.vrf_name:
                cmd += " vpn-instance %s" % self.vrf_name
            if self.log_flag:
                cmd += " logging"
            self.updates_cmd.append(cmd)

        self.changed = True

    def work(self):
        """ Main work function """

        self.check_acl_args()
        self.check_base_rule_args()
        self.get_proposed()
        self.get_existing()

        if self.state == "present":
            if self.cur_acl_cfg["need_cfg"]:
                self.merge_acl()
            if self.cur_base_rule_cfg["need_cfg"]:
                self.merge_base_rule()

        elif self.state == "absent":
            if self.cur_base_rule_cfg["need_cfg"]:
                self.delete_base_rule()

        elif self.state == "delete_acl":
            if self.cur_acl_cfg["need_cfg"]:
                self.delete_acl()

        self.get_end_state()

        self.results['changed'] = self.changed
        self.results['proposed'] = self.proposed
        self.results['existing'] = self.existing
        self.results['end_state'] = self.end_state
        self.results['updates'] = self.updates_cmd

        self.module.exit_json(**self.results)


def main():
    """ Module main """

    argument_spec = dict(
        state=dict(choices=['present', 'absent',
                            'delete_acl'], default='present'),
        acl_name=dict(type='str', required=True),
        acl_num=dict(type='str'),
        acl_step=dict(type='str'),
        acl_description=dict(type='str'),
        rule_name=dict(type='str'),
        rule_id=dict(type='str'),
        rule_action=dict(choices=['permit', 'deny']),
        source_ip=dict(type='str'),
        src_mask=dict(type='str'),
        frag_type=dict(choices=['fragment', 'clear_fragment']),
        vrf_name=dict(type='str'),
        time_range=dict(type='str'),
        rule_description=dict(type='str'),
        log_flag=dict(required=False, default=False, type='bool')
    )

    argument_spec.update(ce_argument_spec)
    module = BaseAcl(argument_spec=argument_spec)
    module.work()


if __name__ == '__main__':
    main()
