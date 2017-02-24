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

ANSIBLE_METADATA = {
    'status': ['preview'],
    'supported_by': 'community',
    'version': '1.0'
}

DOCUMENTATION = """
---
module: ce_config
version_added: "2.3"
author: "QijunPan (@CloudEngine-Ansible)"
short_description: Manage Huawei CloudEngine configuration sections
description:
  - Huawei CloudEngine configurations use a simple block indent file syntax
    for segmenting configuration into sections.  This module provides
    an implementation for working with CloudEngine configuration sections in
    a deterministic way.  This module works with CLI transports.
options:
  lines:
    description:
      - The ordered set of commands that should be configured in the
        section.  The commands must be the exact same commands as found
        in the device current-configuration.  Be sure to note the configuration
        command syntax as some commands are automatically modified by the
        device config parser.
    required: false
    default: null
  parents:
    description:
      - The ordered set of parents that uniquely identify the section
        the commands should be checked against.  If the parents argument
        is omitted, the commands are checked against the set of top
        level or global commands.
    required: false
    default: null
  src:
    description:
      - The I(src) argument provides a path to the configuration file
        to load into the remote system.  The path can either be a full
        system path to the configuration file if the value starts with /
        or relative to the root of the implemented role or playbook.
        This argument is mutually exclusive with the I(lines) and
        I(parents) arguments.
    required: false
    default: null
  before:
    description:
      - The ordered set of commands to push on to the command stack if
        a change needs to be made.  This allows the playbook designer
        the opportunity to perform configuration commands prior to pushing
        any changes without affecting how the set of commands are matched
        against the system.
    required: false
    default: null
  after:
    description:
      - The ordered set of commands to append to the end of the command
        stack if a change needs to be made.  Just like with I(before) this
        allows the playbook designer to append a set of commands to be
        executed after the command set.
    required: false
    default: null
  match:
    description:
      - Instructs the module on the way to perform the matching of
        the set of commands against the current device config.  If
        match is set to I(line), commands are matched line by line.  If
        match is set to I(strict), command lines are matched with respect
        to position.  If match is set to I(exact), command lines
        must be an equal match.  Finally, if match is set to I(none), the
        module will not attempt to compare the source configuration with
        the current-configuration on the remote device.
    required: false
    default: line
    choices: ['line', 'strict', 'exact', 'none']
  replace:
    description:
      - Instructs the module on the way to perform the configuration
        on the device.  If the replace argument is set to I(line) then
        the modified lines are pushed to the device in configuration
        mode.  If the replace argument is set to I(block) then the entire
        command block is pushed to the device in configuration mode if any
        line is not correct.
    required: false
    default: line
    choices: ['line', 'block']
  force:
    description:
      - The force argument instructs the module to not consider the
        current devices current-configuration.  When set to true, this will
        cause the module to push the contents of I(src) into the device
        without first checking if already configured.
      - Note this argument should be considered deprecated.  To achieve
        the equivalent, set the C(match=none) which is idempotent.  This argument
        will be removed in a future release.
    required: false
    default: false
    choices: [ "true", "false" ]
  backup:
    description:
      - This argument will cause the module to create a full backup of
        the current C(current-configuration) from the remote device before any
        changes are made.  The backup file is written to the C(backup)
        folder in the playbook root directory.  If the directory does not
        exist, it is created.
    required: false
    default: no
    choices: ['yes', 'no']
  config:
    description:
      - The module, by default, will connect to the remote device and
        retrieve the current current-configuration to use as a base for comparing
        against the contents of source.  There are times when it is not
        desirable to have the task get the current-configuration for
        every task in a playbook.  The I(config) argument allows the
        implementer to pass in the configuration to use as the base
        config for comparison.
    required: false
    default: null
  defaults:
    description:
      - The I(defaults) argument will influence how the current-configuration
        is collected from the device.  When the value is set to true,
        the command used to collect the current-configuration is append with
        the all keyword.  When the value is set to false, the command
        is issued without the all keyword
    required: false
    default: false
  save:
    description:
      - The C(save) argument instructs the module to save the
        current-configuration to saved-configuration.  This operation is performed
        after any changes are made to the current running config.  If
        no changes are made, the configuration is still saved to the
        startup config.  This option will always cause the module to
        return changed.
    required: false
    default: false
"""

EXAMPLES = """
# Note: examples below use the following provider dict to handle
#       transport and authentication to the node.

- name: CloudEngine config test
  vars:
    cli:
      host: "{{ inventory_hostname }}"
      username: admin
      password: admin
      transport: cli

  tasks:
  - name: "Configure top level configuration and save it"
    ce_config:
      lines: sysname {{ inventory_hostname }}
      save: yes
      provider: "{{ cli }}"

  - name: "Configure acl configuration and save it"
    ce_config:
      lines:
        - rule 10 permit source 1.1.1.1 32
        - rule 20 permit source 2.2.2.2 32
        - rule 30 permit source 3.3.3.3 32
        - rule 40 permit source 4.4.4.4 32
        - rule 50 permit source 5.5.5.5 32
      parents: acl 2000
      before: undo acl 2000
      match: exact
      provider: "{{ cli }}"

  - name: "Configure acl configuration and save it"
    ce_config:
      lines:
        - rule 10 permit source 1.1.1.1 32
        - rule 20 permit source 2.2.2.2 32
        - rule 30 permit source 3.3.3.3 32
        - rule 40 permit source 4.4.4.4 32
      parents: acl 2000
      before: undo acl 2000
      replace: block
      provider: "{{ cli }}"
"""

RETURN = """
updates:
  description: The set of commands that will be pushed to the remote device
  returned: Only when lines is specified.
  type: list
  sample: ['...', '...']
backup_path:
  description: The full path to the backup file
  returned: when backup is yes
  type: path
  sample: /playbooks/ansible/backup/ce_config.2016-07-16@22:28:34
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.netcfg import NetworkConfig, dumps
from ansible.module_utils.ce import get_config, load_config, run_commands
from ansible.module_utils.ce import ce_argument_spec
from ansible.module_utils.ce import check_args as ce_check_args

def check_args(module, warnings):
    ce_check_args(module, warnings)
    if module.params['force']:
        warnings.append('The force argument is deprecated, please use '
                        'match=none instead.  This argument will be '
                        'removed in the future')

def get_running_config(module):
    contents = module.params['config']
    if not contents:
        flags = []
        if module.params['defaults']:
            flags.append('include-default')
        contents = get_config(module, flags=flags)
    return NetworkConfig(indent=1, contents=contents)

def get_candidate(module):
    candidate = NetworkConfig(indent=1)
    if module.params['src']:
        candidate.load(module.params['src'])
    elif module.params['lines']:
        parents = module.params['parents'] or list()
        candidate.add(module.params['lines'], parents=parents)
    return candidate

def run(module, result):
    match = module.params['match']
    replace = module.params['replace']

    candidate = get_candidate(module)

    if match != 'none':
        config = get_running_config(module)
        path = module.params['parents']
        configobjs = candidate.difference(config, match=match, replace=replace, path=path)
    else:
        configobjs = candidate.items

    if configobjs:
        commands = dumps(configobjs, 'commands').split('\n')

        if module.params['lines']:
            if module.params['before']:
                commands[:0] = module.params['before']

            if module.params['after']:
                commands.extend(module.params['after'])

        result['commands'] = commands
        result['updates'] = commands

        if not module.check_mode:
            load_config(module, commands)

        result['changed'] = True

def main():
    """ main entry point for module execution
    """
    argument_spec = dict(
        src=dict(type='path'),

        lines=dict(aliases=['commands'], type='list'),
        parents=dict(type='list'),

        before=dict(type='list'),
        after=dict(type='list'),

        match=dict(default='line', choices=['line', 'strict', 'exact', 'none']),
        replace=dict(default='line', choices=['line', 'block']),

        # this argument is deprecated in favor of setting match: none
        # it will be removed in a future version
        force=dict(default=False, type='bool'),

        config=dict(),
        defaults=dict(type='bool', default=False),

        backup=dict(type='bool', default=False),
        save=dict(type='bool', default=False),
    )

    argument_spec.update(ce_argument_spec)

    mutually_exclusive = [('lines', 'src')]

    required_if = [('match', 'strict', ['lines']),
                   ('match', 'exact', ['lines']),
                   ('replace', 'block', ['lines'])]

    module = AnsibleModule(argument_spec=argument_spec,
                           mutually_exclusive=mutually_exclusive,
                           required_if=required_if,
                           supports_check_mode=True)

    if module.params['force'] is True:
        module.params['match'] = 'none'

    warnings = list()
    check_args(module, warnings)

    result = dict(changed=False, warnings=warnings)

    if module.params['backup']:
        result['__backup__'] = get_config(module)

    if any((module.params['src'], module.params['lines'])):
        run(module, result)

    if module.params['save']:
        if not module.check_mode:
            run_commands(module, ['save'])
        result['changed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
