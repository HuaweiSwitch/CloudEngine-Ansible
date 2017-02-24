#
# This code is part of Ansible, but is an independent component.
#
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2017 Red Hat, Inc.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import re
import collections

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.network_common import to_list, ComplexList
from ansible.module_utils.connection import exec_command
from ansible.module_utils.six import iteritems
from ansible.module_utils.urls import fetch_url


try:
    from ncclient import manager
    from ncclient import xml_
    HAS_NCCLIENT = True
except ImportError:
    HAS_NCCLIENT = False
    pass


_DEVICE_CONNECTION = None

ce_argument_spec = {
    'host': dict(),
    'port': dict(type='int'),
    'username': dict(fallback=(env_fallback, ['ANSIBLE_NET_USERNAME'])),
    'password': dict(fallback=(env_fallback, ['ANSIBLE_NET_PASSWORD']), no_log=True),
    'use_ssl': dict(type='bool'),
    'validate_certs': dict(type='bool'),
    'timeout': dict(type='int'),
    'provider': dict(type='dict', no_log=True),
    'transport': dict(choices=['cli'])
}

def check_args(module, warnings):
    provider = module.params['provider'] or {}
    for key in ce_argument_spec:
        if key not in ['provider', 'transport'] and module.params[key]:
            warnings.append('argument %s has been deprecated and will be '
                    'removed in a future version' % key)

def load_params(module):
    provider = module.params.get('provider') or dict()
    for key, value in iteritems(provider):
        if key in ce_argument_spec:
            if module.params.get(key) is None and value is not None:
                module.params[key] = value

def get_connection(module):
    global _DEVICE_CONNECTION
    if not _DEVICE_CONNECTION:
        load_params(module)
        conn = Cli(module)
        _DEVICE_CONNECTION = conn
    return _DEVICE_CONNECTION

def rm_config_prefix(cfg):
    if not cfg:
        return cfg

    cmds = cfg.split("\n")
    for i in range(len(cmds)):
        if not cmds[i]:
            continue
        if '~' in cmds[i]:
            index = cmds[i].index('~')
            if cmds[i][:index] == ' ' * index:
                cmds[i] = cmds[i].replace("~", "", 1)
    return '\n'.join(cmds)

class Cli:

    def __init__(self, module):
        self._module = module
        self._device_configs = {}

    def exec_command(self, command):
        if isinstance(command, dict):
            command = self._module.jsonify(command)

        return exec_command(self._module, command)

    def get_config(self, flags=[]):
        """Retrieves the current config from the device or cache
        """
        cmd = 'display current-configuration '
        cmd += ' '.join(flags)
        cmd = cmd.strip()

        try:
            return self._device_configs[cmd]
        except KeyError:
            rc, out, err = self.exec_command(cmd)
            if rc != 0:
                self._module.fail_json(msg=err)
            cfg = str(out).strip()
            # remove default configuration prefix '~'
            for flag in flags:
                if "include-default" in flag:
                    cfg = rm_config_prefix(cfg)
                    break

            self._device_configs[cmd] = cfg
            return cfg

    def run_commands(self, commands, check_rc=True):
        """Run list of commands on remote device and return results
        """
        responses = list()

        for item in to_list(commands):
            cmd = item['command']

            rc, out, err = self.exec_command(cmd)

            if check_rc and rc != 0:
                self._module.fail_json(msg=cli_err_msg(cmd.strip(), err))

            try:
                out = self._module.from_json(out)
            except ValueError:
                out = str(out).strip()

            responses.append(out)
        return responses

    def load_config(self, config):
        """Sends configuration commands to the remote device
        """
        rc, out, err = self.exec_command('mmi-mode enable')
        if rc != 0:
            self._module.fail_json(msg='unable to set mmi-mode enable', output=err)
        rc, out, err = self.exec_command('system-view immediately')
        if rc != 0:
            self._module.fail_json(msg='unable to enter system-view', output=err)

        for cmd in config:
            rc, out, err = self.exec_command(cmd)
            if rc != 0:
                self._module.fail_json(msg=cli_err_msg(cmd.strip(), err))

        self.exec_command('return')


def cli_err_msg(cmd, err):
    """ get cli exception message"""

    if not err:
        return "Error: Fail to get cli exception message."

    msg = list()
    err_list = str(err).split("\r\n")
    for err in err_list:
        err = err.strip('.,\r\n\t ')
        if not err:
            continue
        if cmd and cmd == err:
            continue
        if " at '^' position" in err:
            err = err.replace(" at '^' position", "").strip()
        err = err.strip('.,\r\n\t ')
        if err == "^":
            continue
        if len(err) > 2 and err[0] in ["<", "["] and err[-1] in [">", "]"]:
            continue
        err.strip('.,\r\n\t ')
        if err:
            msg.append(err)

    if cmd:
        msg.insert(0, "Command: %s" % cmd)

    return ", ".join(msg).capitalize() + "."


def to_command(module, commands):
    default_output = 'text'
    transform = ComplexList(dict(
        command=dict(key=True),
        output=dict(default=default_output),
        prompt=dict(),
        response=dict()
    ), module)

    commands = transform(to_list(commands))

    return commands

def get_config(module, flags=[]):
    conn = get_connection(module)
    return conn.get_config(flags)

def run_commands(module, commands, check_rc=True):
    conn = get_connection(module)
    return conn.run_commands(to_command(module, commands), check_rc)

def load_config(module, config):
    conn = get_connection(module)
    return conn.load_config(config)


def ce_unknown_host_cb(host, fingerprint):
    """ ce_unknown_host_cb """

    return True

def get_nc_set_id(xml_str):
    """get netconf set-id value"""

    result = re.findall(r'<rpc-reply.+?set-id=\"(\d+)\"', xml_str)
    if not result:
        return None
    return result[0]


def get_xml_line(xml_list, index):
    """get xml specified line valid string data"""

    ele = None
    while xml_list and not ele:
        if index >= 0 and index >= len(xml_list):
            return None
        if index < 0 and abs(index) > len(xml_list):
            return None

        ele = xml_list[index]
        if not ele.replace(" ", ""):
            xml_list.pop(index)
            ele = None
    return ele


def merge_xml(xml1, xml2):
    """merge xml1 and xml2"""

    xml1_list = xml1.split("</data>")[0].split("\n")
    xml2_list = xml2.split("<data>")[1].split("\n")

    while True:
        xml1_ele1 = get_xml_line(xml1_list, -1)
        xml1_ele2 = get_xml_line(xml1_list, -2)
        xml2_ele1 = get_xml_line(xml2_list, 0)
        xml2_ele2 = get_xml_line(xml2_list, 1)
        if not xml1_ele1 or not xml1_ele2 or not xml2_ele1 or not xml2_ele2:
            return xml1

        if "xmlns" in xml2_ele1:
            xml2_ele1 = xml2_ele1.lstrip().split(" ")[0] + ">"
        if "xmlns" in xml2_ele2:
            xml2_ele2 = xml2_ele2.lstrip().split(" ")[0] + ">"
        if xml1_ele1.replace(" ", "").replace("/", "") == xml2_ele1.replace(" ", "").replace("/", ""):
            if xml1_ele2.replace(" ", "").replace("/", "") == xml2_ele2.replace(" ", "").replace("/", ""):
                xml1_list.pop()
                xml2_list.pop(0)
            else:
                break
        else:
            break

    return "\n".join(xml1_list + xml2_list)


class Netconf(object):
    """ Netconf """

    def __init__(self, **kwargs):

        if not HAS_NCCLIENT:
            raise Exception("the ncclient library is required")

        self.mc = None

        host = kwargs["host"]
        port = kwargs["port"]
        username = kwargs["username"]
        password = kwargs["password"]

        self.mc = manager.connect(host=host, port=port,
                                  username=username,
                                  password=password,
                                  unknown_host_cb=ce_unknown_host_cb,
                                  allow_agent=False,
                                  look_for_keys=False,
                                  hostkey_verify=False,
                                  device_params={'name': 'huawei'},
                                  timeout=30)

    def __del__(self):

        self.mc.close_session()

    def set_config(self, **kwargs):
        """ set_config """

        confstr = kwargs["config"]
        con_obj = self.mc.edit_config(target='running', config=confstr)

        return con_obj

    def get_config(self, **kwargs):
        """ get_config """

        filterstr = kwargs["filter"]
        con_obj = self.mc.get(filter=filterstr)
        set_id = get_nc_set_id(con_obj.xml)
        if not set_id:
            return con_obj

        # continue to get next
        xml_str = con_obj.xml
        while set_id:
            set_attr = dict()
            set_attr["set-id"] = str(set_id)
            xsd_fetch = xml_.new_ele_ns('get-next', "http://www.huawei.com/netconf/capability/base/1.0", set_attr)
            # get next data
            con_obj_next = self.mc.dispatch(xsd_fetch)
            if "<data/>" in con_obj_next.xml:
                break
            # merge two xml data
            xml_str = merge_xml(xml_str, con_obj_next.xml)
            set_id = get_nc_set_id(con_obj_next.xml)

        con_obj._raw = xml_str
        return con_obj

    def execute_action(self, **kwargs):
        """huawei execute-action"""

        confstr = kwargs["action"]
        con_obj = self.mc.action(action=confstr)

        return con_obj

    def execute_cli(self, **kwargs):
        """huawei execute-cli"""

        confstr = kwargs["command"]
        con_obj = self.mc.cli(command=confstr)

        return con_obj


def get_netconf(**kwargs):
    """ get_netconf """

    return Netconf(**kwargs)
