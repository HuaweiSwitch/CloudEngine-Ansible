
# CloudEngine Ansible Module Docs
### *Network Automation with CloudEngine and Ansible*

---
### Requirements
* Check

---
### Modules
        
  * [ce_aaa_server - Manages AAA server global configuration.](#ce_aaa_server)
  * [ce_aaa_server_host - Manages AAA server host configuration.](#ce_aaa_server_host)
  * [ce_acl - Manages base ACL configuration.](#ce_acl)
  * [ce_acl_advance - Manages advanced ACL configuration.](#ce_acl_advance)
  * [ce_acl_interface - Manages applying ACLs to interfaces.](#ce_acl_interface)
  * [ce_bgp - Manages BGP configuration.](#ce_bgp)
  * [ce_bgp_af - Manages BGP Address-family configuration.](#ce_bgp_af)
  * [ce_bgp_neighbor - Manages BGP peer configuration.](#ce_bgp_neighbor)
  * [ce_bgp_neighbor_af - Manages BGP neighbor Address-family configuration.](#ce_bgp_neighbor_af)
  * [ce_command - Run arbitrary command on HUAWEI CloudEngine devices.](#ce_command)
  * [ce_config - Manage Huawei CloudEngine configuration sections.](#ce_config)
  * [ce_dldp - Manages global DLDP configuration.](#ce_dldp)
  * [ce_dldp_interface - Manages interface DLDP configuration.](#ce_dldp_interface)
  * [ce_eth_trunk - Manages Eth-Trunk interfaces.](#ce_eth_trunk)
  * [ce_evpn_bd_vni - Manages Huawei EVPN VXLAN Network Identifier (VNI).](#ce_evpn_bd_vni)
  * [ce_evpn_bgp - Manages BGP EVPN configuration.](#ce_evpn_bgp)
  * [ce_evpn_bgp_rr - Manages RR for the VXLAN Network.](#ce_evpn_bgp_rr)
  * [ce_evpn_global - Manages global configuration of EVPN.](#ce_evpn_global)
  * [ce_facts - Gets facts about HUAWEI CloudEngine switches.](#ce_facts)
  * [ce_file_copy - Copy a file to a remote cloudengine device over SCP.](#ce_file_copy)
  * [ce_info_center_debug - Manages information center debug configuration.](#ce_info_center_debug)
  * [ce_info_center_global - Manages outputting logs.](#ce_info_center_global)
  * [ce_info_center_log - Manages information center log configuration.](#ce_info_center_log)
  * [ce_info_center_trap - Manages information center trap configuration.](#ce_info_center_trap)
  * [ce_interface - Manages physical attributes of interfaces.](#ce_interface)
  * [ce_interface_ospf - Manages configuration of an OSPF interface instance.](#ce_interface_ospf)
  * [ce_ip_interface - Manages L3 attributes for IPv4 and IPv6 interfaces.](#ce_ip_interface)
  * [ce_link_status - Get interface link status.](#ce_link_status)
  * [ce_mlag_config - Manages MLAG configuration.](#ce_mlag_config)
  * [ce_mlag_interface - Manages MLAG interfaces.](#ce_mlag_interface)
  * [ce_mtu - Manages MTU settings on CloudEngine switch.](#ce_mtu)
  * [ce_netconf - Run arbitrary netconf command on cloudengine devices.](#ce_netconf)
  * [ce_netstream_aging - Manages timeout mode of NetStream.](#ce_netstream_aging)
  * [ce_netstream_export - Manages netstream export.](#ce_netstream_export)
  * [ce_netstream_global - Manages global parameters of NetStream.](#ce_netstream_global)
  * [ce_netstream_template - Manages NetStream template configuration.](#ce_netstream_template)
  * [ce_ntp - Manages core NTP configuration.](#ce_ntp)
  * [ce_ntp_auth - Manages NTP authentication configuration.](#ce_ntp_auth)
  * [ce_ospf - Manages configuration of an OSPF instance.](#ce_ospf)
  * [ce_ospf_vrf - Manages configuration of an OSPF VPN instance.](#ce_ospf_vrf)
  * [ce_reboot - Reboot a network device.](#ce_reboot)
  * [ce_rollback - Set a checkpoint or rollback to a checkpoint.](#ce_rollback)
  * [ce_sflow - Manages sFlow configuration.](#ce_sflow)
  * [ce_snmp_community - Manages SNMP community configuration.](#ce_snmp_community)
  * [ce_snmp_contact - Manages SNMP contact configuration.](#ce_snmp_contact)
  * [ce_snmp_location - Manages SNMP location configuration.](#ce_snmp_location)
  * [ce_snmp_target_host - Manages SNMP target host configuration.](#ce_snmp_target_host)
  * [ce_snmp_traps - Manages SNMP traps configuration.](#ce_snmp_traps)
  * [ce_snmp_user - Manages SNMP user configuration.](#ce_snmp_user)
  * [ce_startup - Manages a system startup information.](#ce_startup)
  * [ce_static_route - Manages static route configuration.](#ce_static_route)
  * [ce_stp - Manages STP configuration.](#ce_stp)
  * [ce_switchport - Manages Layer 2 switchport interfaces.](#ce_switchport)
  * [ce_vlan - Manages VLAN resources and attributes.](#ce_vlan)
  * [ce_vrf - Manages VPN instance.](#ce_vrf)
  * [ce_vrf_af - Manages VPN instance address family.](#ce_vrf_af)
  * [ce_vrf_interface - Manages interface specific VPN configuration.](#ce_vrf_interface)
  * [ce_vrrp - Manages VRRP interfaces.](#ce_vrrp)
  * [ce_vxlan_arp - Manages ARP attributes of VXLAN.](#ce_vxlan_arp)
  * [ce_vxlan_gateway - Manages gateway for the VXLAN network.](#ce_vxlan_gateway)
  * [ce_vxlan_global - Manages global attributes of VXLAN and bridge domain.](#ce_vxlan_global)
  * [ce_vxlan_tunnel - Manages VXLAN tunnel configuration.](#ce_vxlan_tunnel)
  * [ce_vxlan_vap - Manages VXLAN virtual access point.](#ce_vxlan_vap)

---

## ce_aaa_server

Manages AAA server global configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages AAA server global configuration.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| accounting_mode | no |  | <ul><li>invalid</li><li>hwtacacs</li><li>radius</li><li>none</li></ul> | Accounting Mode. |
| acct_scheme_name | no |  |  | Accounting scheme name. The value is a string of 1 to 32 characters. |
| authen_scheme_name | no |  |  | Name of an authentication scheme. The value is a string of 1 to 32 characters. |
| author_scheme_name | no |  |  | Name of an authorization scheme. The value is a string of 1 to 32 characters. |
| domain_name | no |  |  | Name of a domain. The value is a string of 1 to 64 characters. |
| first_authen_mode | no |  | <ul><li>invalid</li><li>local</li><li>hwtacacs</li><li>radius</li><li>none</li></ul> | Preferred authentication mode. |
| first_author_mode | no |  | <ul><li>invalid</li><li>local</li><li>hwtacacs</li><li>if-authenticated</li><li>none</li></ul> | Preferred authorization mode. |
| hwtacas_template | no |  |  | Name of a HWTACACS template. The value is a string of 1 to 32 case-insensitive characters. |
| local_user_group | no |  |  | Name of the user group where the user belongs. The user inherits all the rights of the user group. The value is a string of 1 to 32 characters. |
| radius_server_group | no |  |  | RADIUS server group's name. The value is a string of 1 to 32 case-insensitive characters. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
#### Examples

```

- name: AAA server test
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

  - name: "Radius authentication Server Basic settings"
    ce_aaa_server:
      state:  present
      authen_scheme_name:  test1
      first_authen_mode:  radius
      radius_server_group:  test2
      provider: "{{ cli }}"

  - name: "Undo radius authentication Server Basic settings"
    ce_aaa_server:
      state:  absent
      authen_scheme_name:  test1
      first_authen_mode:  radius
      radius_server_group:  test2
      provider: "{{ cli }}"

  - name: "Hwtacacs accounting Server Basic settings"
    ce_aaa_server:
      state:  present
      acct_scheme_name:  test1
      accounting_mode:  hwtacacs
      hwtacas_template:  test2
      provider: "{{ cli }}"

  - name: "Undo hwtacacs accounting Server Basic settings"
    ce_aaa_server:
      state:  absent
      acct_scheme_name:  test1
      accounting_mode:  hwtacacs
      hwtacas_template:  test2
      provider: "{{ cli }}"

```

---

## ce_aaa_server_host

Manages AAA server host configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages AAA server host configuration.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| hwtacacs_is_public_net | no |  | <ul><li>true</li><li>false</li></ul> | Set the public-net. |
| hwtacacs_is_secondary_server | no |  | <ul><li>true</li><li>false</li></ul> | Whether the server is secondary. |
| hwtacacs_server_host_name | no |  |  | Hwtacacs server host name. |
| hwtacacs_server_ip | no |  |  | Server IPv4 address. Must be a valid unicast IP address. The value is a string of 0 to 255 characters, in dotted decimal notation. |
| hwtacacs_server_ipv6 | no |  |  | Server IPv6 address. Must be a valid unicast IP address. The total length is 128 bits. |
| hwtacacs_server_type | no |  | <ul><li>Authentication</li><li>Authorization</li><li>Accounting</li><li>Common</li></ul> | Hwtacacs server type. |
| hwtacacs_template | no |  |  | Name of a HWTACACS template. The value is a string of 1 to 32 case-insensitive characters. |
| hwtacacs_vpn_name | no |  |  | VPN instance name. |
| local_ftp_dir | no |  |  | FTP user directory. The value is a string of 1 to 255 characters. |
| local_password | no |  |  | Login password of a user. The password can contain letters, numbers, and special characters. The value is a string of 1 to 255 characters. |
| local_service_type | no |  |  | The type of local user login through, such as ftp ssh snmp telnet. |
| local_user_group | no |  |  | Name of the user group where the user belongs. The user inherits all the rights of the user group. The value is a string of 1 to 32 characters. |
| local_user_level | no |  |  | Login level of a local user. The value is an integer ranging from 0 to 15. |
| local_user_name | no |  |  | Name of a local user. The value is a string of 1 to 253 characters. |
| radius_group_name | no |  |  | RADIUS server group's name. The value is a string of 1 to 32 case-insensitive characters. |
| radius_server_ip | no |  |  | IPv4 address of configured server. The value is a string of 0 to 255 characters, in dotted decimal notation. |
| radius_server_ipv6 | no |  |  | IPv6 address of configured server. The total length is 128 bits. |
| radius_server_mode | no |  | <ul><li>Secondary-server</li><li>Primary-server</li></ul> | Configured primary or secondary server for a particular server. |
| radius_server_name | no |  |  | Hostname of configured server. The value is a string of 0 to 255 case-sensitive characters. |
| radius_server_port | no |  |  | Configured server port for a particular server. The value is an integer ranging from 1 to 65535. |
| radius_server_type | no |  | <ul><li>Authentication</li><li>Accounting</li></ul> | Type of Radius Server. |
| radius_vpn_name | no |  |  | Set VPN instance. The value is a string of 1 to 31 case-sensitive characters. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
#### Examples

```

- name: AAA server host test
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

  - name: "Config local user when use local scheme"
    ce_aaa_server_host:
      state:  present
      local_user_name:  user1
      local_password:  123456
      provider: "{{ cli }}"

  - name: "Undo local user when use local scheme"
    ce_aaa_server_host:
      state:  absent
      local_user_name:  user1
      local_password:  123456
      provider: "{{ cli }}"

  - name: "Config radius server ip"
    ce_aaa_server_host:
      state:  present
      radius_group_name:  group1
      raduis_server_type:  Authentication
      radius_server_ip:  10.1.10.1
      radius_server_port:  2000
      radius_server_mode:  Primary-server
      radius_vpn_name:  _public_
      provider: "{{ cli }}"

  - name: "Undo radius server ip"
    ce_aaa_server_host:
      state:  absent
      radius_group_name:  group1
      raduis_server_type:  Authentication
      radius_server_ip:  10.1.10.1
      radius_server_port:  2000
      radius_server_mode:  Primary-server
      radius_vpn_name:  _public_
      provider: "{{ cli }}"

  - name: "Config hwtacacs server ip"
    ce_aaa_server_host:
      state:  present
      hwtacacs_template:  template
      hwtacacs_server_ip:  10.10.10.10
      hwtacacs_server_type:  Authorization
      hwtacacs_vpn_name:  _public_
      provider: "{{ cli }}"

  - name: "Undo hwtacacs server ip"
    ce_aaa_server_host:
      state:  absent
      hwtacacs_template:  template
      hwtacacs_server_ip:  10.10.10.10
      hwtacacs_server_type:  Authorization
      hwtacacs_vpn_name:  _public_
      provider: "{{ cli }}"

```

---

## ce_acl

Manages base ACL configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages base ACL configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| acl_description | no |  |  | ACL description. The value is a string of 1 to 127 characters. |
| acl_name | yes |  |  | ACL number or name. For a numbered rule group, the value ranging from 2000 to 2999 indicates a basic ACL. For a named rule group, the value is a string of 1 to 32 case-sensitive characters starting with a letter, spaces not supported. |
| acl_num | no |  |  | ACL number. The value is an integer ranging from 2000 to 2999. |
| acl_step | no |  |  | ACL step. The value is an integer ranging from 1 to 20. The default value is 5. |
| frag_type | no |  | <ul><li>fragment</li><li>clear_fragment</li></ul> | Type of packet fragmentation. |
| log_flag | no |  | <ul><li>true</li><li>false</li></ul> | Flag of logging matched data packets. |
| rule_action | no |  | <ul><li>permit</li><li>deny</li></ul> | Matching mode of basic ACL rules. |
| rule_description | no |  |  | Description about an ACL rule. The value is a string of 1 to 127 characters. |
| rule_id | no |  |  | ID of a basic ACL rule in configuration mode. The value is an integer ranging from 0 to 4294967294. |
| rule_name | no |  |  | Name of a basic ACL rule. The value is a string of 1 to 32 characters. The value is case-insensitive, and cannot contain spaces or begin with an underscore (_). |
| source_ip | no |  |  | Source IP address. The value is a string of 0 to 255 characters.The default value is 0.0.0.0. The value is in dotted decimal notation. |
| src_mask | no |  |  | Mask of a source IP address. The value is an integer ranging from 1 to 32. |
| state | no | present | <ul><li>present</li><li>absent</li><li>delete_acl</li></ul> | Specify desired state of the resource. |
| time_range | no |  |  | Name of a time range in which an ACL rule takes effect. The value is a string of 1 to 32 characters. The value is case-insensitive, and cannot contain spaces. The name must start with an uppercase or lowercase letter. In addition, the word "all" cannot be specified as a time range name. |
| vrf_name | no |  |  | VPN instance name. The value is a string of 1 to 31 characters.The default value is _public_. |
#### Examples

```

- name: CloudEngine acl test
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

```

---

## ce_acl_advance

Manages advanced ACL configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages advanced ACL configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| acl_description | no |  |  | ACL description. The value is a string of 1 to 127 characters. |
| acl_name | yes |  |  | ACL number or name. For a numbered rule group, the value ranging from 3000 to 3999 indicates a advance ACL. For a named rule group, the value is a string of 1 to 32 case-sensitive characters starting with a letter, spaces not supported. |
| acl_num | no |  |  | ACL number. The value is an integer ranging from 3000 to 3999. |
| acl_step | no |  |  | ACL step. The value is an integer ranging from 1 to 20. The default value is 5. |
| dest_ip | no |  |  | Destination IP address. The value is a string of 0 to 255 characters.The default value is 0.0.0.0. The value is in dotted decimal notation. |
| dest_mask | no |  |  | Destination IP address mask. The value is an integer ranging from 1 to 32. |
| dest_pool_name | no |  |  | Name of a destination pool. The value is a string of 1 to 32 characters. |
| dest_port_begin | no |  |  | Start port number of the destination port. The value is an integer ranging from 0 to 65535. |
| dest_port_end | no |  |  | End port number of the destination port. The value is an integer ranging from 0 to 65535. |
| dest_port_op | no |  | <ul><li>lt</li><li>eq</li><li>gt</li><li>range</li></ul> | Range type of the destination port. |
| dest_port_pool_name | no |  |  | Name of a destination port pool. The value is a string of 1 to 32 characters. |
| dscp | no |  |  | Differentiated Services Code Point. The value is an integer ranging from 0 to 63. |
| established | no |  | <ul><li>true</li><li>false</li></ul> | Match established connections. |
| frag_type | no |  | <ul><li>fragment</li><li>clear_fragment</li></ul> | Type of packet fragmentation. |
| icmp_code | no |  |  | ICMP message code. Data packets can be filtered based on the ICMP message code. The value is an integer ranging from 0 to 255. |
| icmp_name | no |  | <ul><li>unconfiged</li><li>echo</li><li>echo-reply</li><li>fragmentneed-DFset</li><li>host-redirect</li><li>host-tos-redirect</li><li>host-unreachable</li><li>information-reply</li><li>information-request</li><li>net-redirect</li><li>net-tos-redirect</li><li>net-unreachable</li><li>parameter-problem</li><li>port-unreachable</li><li>protocol-unreachable</li><li>reassembly-timeout</li><li>source-quench</li><li>source-route-failed</li><li>timestamp-reply</li><li>timestamp-request</li><li>ttl-exceeded</li><li>address-mask-reply</li><li>address-mask-request</li><li>custom</li></ul> | ICMP name. |
| icmp_type | no |  |  | ICMP type. This parameter is available only when the packet protocol is ICMP. The value is an integer ranging from 0 to 255. |
| igmp_type | no |  | <ul><li>host-query</li><li>mrouter-adver</li><li>mrouter-solic</li><li>mrouter-termi</li><li>mtrace-resp</li><li>mtrace-route</li><li>v1host-report</li><li>v2host-report</li><li>v2leave-group</li><li>v3host-report</li></ul> | Internet Group Management Protocol. |
| log_flag | no |  | <ul><li>true</li><li>false</li></ul> | Flag of logging matched data packets. |
| precedence | no |  |  | Data packets can be filtered based on the priority field. The value is an integer ranging from 0 to 7. |
| protocol | no |  | <ul><li>ip</li><li>icmp</li><li>igmp</li><li>ipinip</li><li>tcp</li><li>udp</li><li>gre</li><li>ospf</li></ul> | Protocol type. |
| rule_action | no |  | <ul><li>permit</li><li>deny</li></ul> | Matching mode of basic ACL rules. |
| rule_description | no |  |  | Description about an ACL rule. |
| rule_id | no |  |  | ID of a basic ACL rule in configuration mode. The value is an integer ranging from 0 to 4294967294. |
| rule_name | no |  |  | Name of a basic ACL rule. The value is a string of 1 to 32 characters. |
| source_ip | no |  |  | Source IP address. The value is a string of 0 to 255 characters.The default value is 0.0.0.0. The value is in dotted decimal notation. |
| src_mask | no |  |  | Source IP address mask. The value is an integer ranging from 1 to 32. |
| src_pool_name | no |  |  | Name of a source pool. The value is a string of 1 to 32 characters. |
| src_port_begin | no |  |  | Start port number of the source port. The value is an integer ranging from 0 to 65535. |
| src_port_end | no |  |  | End port number of the source port. The value is an integer ranging from 0 to 65535. |
| src_port_op | no |  | <ul><li>lt</li><li>eq</li><li>gt</li><li>range</li></ul> | Range type of the source port. |
| src_port_pool_name | no |  |  | Name of a source port pool. The value is a string of 1 to 32 characters. |
| state | no | present | <ul><li>present</li><li>absent</li><li>delete_acl</li></ul> | Specify desired state of the resource. |
| syn_flag | no |  |  | TCP flag value. The value is an integer ranging from 0 to 63. |
| tcp_flag_mask | no |  |  | TCP flag mask value. The value is an integer ranging from 0 to 63. |
| time_range | no |  |  | Name of a time range in which an ACL rule takes effect. |
| tos | no |  |  | ToS value on which data packet filtering is based. The value is an integer ranging from 0 to 15. |
| ttl_expired | no |  | <ul><li>true</li><li>false</li></ul> | Whether TTL Expired is matched, with the TTL value of 1. |
| vrf_name | no |  |  | VPN instance name. The value is a string of 1 to 31 characters.The default value is _public_. |
#### Examples

```

- name: CloudEngine advance acl test
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

  - name: "Config ACL"
    ce_acl_advance:
      state:  present
      acl_name:  3200
      provider: "{{ cli }}"

  - name: "Undo ACL"
    ce_acl_advance:
      state:  delete_acl
      acl_name:  3200
      provider: "{{ cli }}"

  - name: "Config ACL advance rule"
    ce_acl_advance:
      state:  present
      acl_name:  test
      rule_name:  test_rule
      rule_id:  111
      rule_action:  permit
      protocol:  tcp
      source_ip:  10.10.10.10
      src_mask:  24
      frag_type:  fragment
      provider: "{{ cli }}"

  - name: "Undo ACL advance rule"
    ce_acl_advance:
      state:  absent
      acl_name:  test
      rule_name:  test_rule
      rule_id:  111
      rule_action:  permit
      protocol:  tcp
      source_ip:  10.10.10.10
      src_mask:  24
      frag_type:  fragment
      provider: "{{ cli }}"

```

---

## ce_acl_interface

Manages applying ACLs to interfaces.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages applying ACLs to interfaces on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| acl_name | yes |  |  | ACL number or name. For a numbered rule group, the value ranging from 2000 to 4999. For a named rule group, the value is a string of 1 to 32 case-sensitive characters starting with a letter, spaces not supported. |
| direction | yes |  | <ul><li>inbound</li><li>outbound</li></ul> | Direction ACL to be applied in on the interface. |
| interface | yes |  |  | Interface name. Only support interface full name, such as "40GE2/0/1". |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Determines whether the config should be present or not on the device. |
#### Examples

```

- name: CloudEngine acl interface test
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

  - name: "Apply acl to interface"
    ce_acl_interface:
      state:  present
      acl_name:  2000
      interface:  40GE1/0/1
      direction:  outbound
      provider: "{{ cli }}"

  - name: "Undo acl from interface"
    ce_acl_interface:
      state:  absent
      acl_name:  2000
      interface:  40GE1/0/1
      direction:  outbound
      provider: "{{ cli }}"

```

---

## ce_bgp

Manages BGP configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages BGP configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| as_number | no |  |  | Local AS number. The value is a string of 1 to 11 characters. |
| as_path_limit | no |  |  | Maximum number of AS numbers in the AS_Path attribute. The default value is 255. |
| bgp_rid_auto_sel | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | The function to automatically select router IDs for all VPN BGP instances is enabled. |
| check_first_as | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Check the first AS in the AS_Path of the update messages from EBGP peers. |
| clear_interval | no |  |  | Clear interval. |
| confed_id_number | no |  |  | Confederation ID. The value is a string of 1 to 11 characters. |
| confed_nonstanded | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Configure the device to be compatible with devices in a nonstandard confederation. |
| confed_peer_as_num | no |  |  | Confederation AS number, in two-byte or four-byte format. The value is a string of 1 to 11 characters. |
| conn_retry_time | no |  |  | ConnectRetry interval. The value is an integer, in seconds. The default value is 32s. |
| default_af_type | no |  | <ul><li>ipv4uni</li><li>ipv6uni</li></ul> | Type of a created address family, which can be IPv4 unicast or IPv6 unicast. The default type is IPv4 unicast. |
| ebgp_if_sensitive | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, After the fast EBGP interface awareness function is enabled, EBGP sessions on an interface are deleted immediately when the interface goes Down. If the value is  false, After the fast EBGP interface awareness function is enabled, EBGP sessions on an interface are not deleted immediately when the interface goes Down. |
| gr_peer_reset | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Peer disconnection through GR. |
| graceful_restart | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Enable GR of the BGP speaker in the specified address family, peer address, or peer group. |
| hold_interval | no |  |  | Hold interval. |
| hold_time | no |  |  | Hold time, in seconds. The value of the hold time can be 0 or range from 3 to 65535. |
| is_shutdown | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Interrupt BGP all neighbor. |
| keep_all_routes | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the system stores all route update messages received from all peers (groups) after BGP connection setup. If the value is false, the system stores only BGP update messages that are received from peers and pass the configured import policy. |
| keepalive_time | no |  |  | If the value of a timer changes, the BGP peer relationship between the routers is disconnected. The value is an integer ranging from 0 to 21845. The default value is 60. |
| memory_limit | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Support BGP RIB memory protection. |
| min_hold_time | no |  |  | Min hold time, in seconds. The value of the hold time can be 0 or range from 20 to 65535. |
| router_id | no |  |  | ID of a router that is in IPv4 address format. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| suppress_interval | no |  |  | Suppress interval. |
| time_wait_for_rib | no |  |  | Period of waiting for the End-Of-RIB flag. The value is an integer ranging from 3 to 3000. The default value is 600. |
| vrf_name | no |  |  | Name of a BGP instance. The name is a case-sensitive string of characters. |
| vrf_rid_auto_sel | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, VPN BGP instances are enabled to automatically select router IDs. If the value is false, VPN BGP instances are disabled from automatically selecting router IDs. |
#### Examples

```

- name: CloudEngine BGP test
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

  - name: "Enable BGP"
    ce_bgp:
      state:  present
      as_number:  100
      confed_id_number:  250
      provider: "{{ cli }}"

  - name: "Disable BGP"
    ce_bgp:
      state:  absent
      as_number:  100
      confed_id_number:  250
      provider: "{{ cli }}"

  - name: "Create confederation peer AS num"
    ce_bgp:
      state:  present
      confed_peer_as_num:  260
      provider: "{{ cli }}"

```

---

## ce_bgp_af

Manages BGP Address-family configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages BGP Address-family configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| active_route_advertise | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, BGP is enabled to advertise only optimal routes in the RM to peers. If the value is false, BGP is not enabled to advertise only optimal routes in the RM to peers. |
| add_path_sel_num | no |  |  | Number of Add-Path routes. The value is an integer ranging from 2 to 64. |
| af_type | yes |  | <ul><li>ipv4uni</li><li>ipv4multi</li><li>ipv4vpn</li><li>ipv6uni</li><li>ipv6vpn</li><li>evpn</li></ul> | Address family type of a BGP instance. |
| allow_invalid_as | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Allow routes with BGP origin AS validation result Invalid to be selected. If the value is true, invalid routes can participate in route selection. If the value is false, invalid routes cannot participate in route selection. |
| always_compare_med | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the MEDs of routes learned from peers in different autonomous systems are compared when BGP selects an optimal route. If the value is false, the MEDs of routes learned from peers in different autonomous systems are not compared when BGP selects an optimal route. |
| as_path_neglect | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the AS path attribute is ignored when BGP selects an optimal route. If the value is false, the AS path attribute is not ignored when BGP selects an optimal route. An AS path with a smaller length has a higher priority. |
| auto_frr_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, BGP auto FRR is enabled. If the value is false, BGP auto FRR is disabled. |
| default_local_pref | no |  |  | Set the Local-Preference attribute. The value is an integer. The value is an integer ranging from 0 to 4294967295. |
| default_med | no |  |  | Specify the Multi-Exit-Discriminator (MED) of BGP routes. The value is an integer ranging from 0 to 4294967295. |
| default_rt_import_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, importing default routes to the BGP routing table is allowed. If the value is false, importing default routes to the BGP routing table is not allowed. |
| determin_med | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, BGP deterministic-MED is enabled. If the value is false, BGP deterministic-MED is disabled. |
| ebgp_ecmp_nexthop_changed | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the next hop of an advertised route is changed to the advertiser itself in EBGP load-balancing scenarios. If the value is false, the next hop of an advertised route is not changed to the advertiser itself in EBGP load-balancing scenarios. |
| ebgp_if_sensitive | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, after the fast EBGP interface awareness function is enabled, EBGP sessions on an interface are deleted immediately when the interface goes Down. If the value is false, after the fast EBGP interface awareness function is enabled, EBGP sessions on an interface are not deleted immediately when the interface goes Down. |
| ecmp_nexthop_changed | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the next hop of an advertised route is changed to the advertiser itself in BGP load-balancing scenarios. If the value is false, the next hop of an advertised route is not changed to the advertiser itself in BGP load-balancing scenarios. |
| ibgp_ecmp_nexthop_changed | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the next hop of an advertised route is changed to the advertiser itself in IBGP load-balancing scenarios. If the value is false, the next hop of an advertised route is not changed to the advertiser itself in IBGP load-balancing scenarios. |
| igp_metric_ignore | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the metrics of next-hop IGP routes are not compared when BGP selects an optimal route. If the value is false, the metrics of next-hop IGP routes are not compared when BGP selects an optimal route. A route with a smaller metric has a higher priority. |
| import_process_id | no |  |  | Process ID of an imported routing protocol. The value is an integer ranging from 0 to 4294967295. |
| import_protocol | no |  | <ul><li>direct</li><li>ospf</li><li>isis</li><li>static</li><li>rip</li><li>ospfv3</li><li>ripng</li></ul> | Routing protocol from which routes can be imported. |
| ingress_lsp_policy_name | no |  |  | Ingress lsp policy name. |
| load_balancing_as_path_ignore | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Load balancing as path ignore. |
| lowest_priority | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, enable reduce priority to advertise route. If the value is false, disable reduce priority to advertise route. |
| mask_len | no |  |  | Specify the mask length of an IP address. The value is an integer ranging from 0 to 128. |
| max_load_ebgp_num | no |  |  | Specify the maximum number of equal-cost EBGP routes. The value is an integer ranging from 1 to 65535. |
| max_load_ibgp_num | no |  |  | Specify the maximum number of equal-cost IBGP routes. The value is an integer ranging from 1 to 65535. |
| maximum_load_balance | no |  |  | Specify the maximum number of equal-cost routes in the BGP routing table. The value is an integer ranging from 1 to 65535. |
| med_none_as_maximum | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, when BGP selects an optimal route, the system uses 4294967295 as the MED value of a route if the route's attribute does not carry a MED value. If the value is false, the system uses 0 as the MED value of a route if the route's attribute does not carry a MED value. |
| network_address | no |  |  | Specify the IP address advertised by BGP. The value is a string of 0 to 255 characters. |
| next_hop_sel_depend_type | no | default | <ul><li>default</li><li>dependTunnel</li><li>dependIp</li></ul> | Next hop select depend type. |
| nexthop_third_party | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the third-party next hop function is enabled. If the value is false, the third-party next hop function is disabled. |
| nhp_relay_route_policy_name | no |  |  | Specify the name of a route-policy for route iteration. The value is a string of 1 to 40 characters. |
| originator_prior | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Originator prior. |
| policy_ext_comm_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, modifying extended community attributes is allowed. If the value is false, modifying extended community attributes is not allowed. |
| policy_vpn_target | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, VPN-Target filtering function is performed for received VPN routes. If the value is false, VPN-Target filtering function is not performed for received VPN routes. |
| preference_external | no |  |  | Set the protocol priority of EBGP routes. The value is an integer ranging from 1 to 255. |
| preference_internal | no |  |  | Set the protocol priority of IBGP routes. The value is an integer ranging from 1 to 255. |
| preference_local | no |  |  | Set the protocol priority of a local BGP route. The value is an integer ranging from 1 to 255. |
| prefrence_policy_name | no |  |  | Set a routing policy to filter routes so that a configured priority is applied to the routes that match the specified policy. The value is a string of 1 to 40 characters. |
| reflect_between_client | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, route reflection is enabled between clients. If the value is false, route reflection is disabled between clients. |
| reflect_chg_path | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the route reflector is enabled to modify route path attributes based on an export policy. If the value is false, the route reflector is disabled from modifying route path attributes based on an export policy. |
| reflector_cluster_id | no |  |  | Set a cluster ID. Configuring multiple RRs in a cluster can enhance the stability of the network. The value is an integer ranging from 1 to 4294967295. |
| reflector_cluster_ipv4 | no |  |  | Set a cluster ipv4 address. The value is expressed in the format of an IPv4 address. |
| relay_delay_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, relay delay enable. If the value is false, relay delay disable. |
| rib_only_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, BGP routes cannot be advertised to the IP routing table. If the value is false, Routes preferred by BGP are advertised to the IP routing table. |
| rib_only_policy_name | no |  |  | Specify the name of a routing policy. The value is a string of 1 to 40 characters. |
| route_sel_delay | no |  |  | Route selection delay. The value is an integer ranging from 0 to 3600. |
| router_id | no |  |  | ID of a router that is in IPv4 address format. The value is a string of 0 to 255 characters. The value is in dotted decimal notation. |
| router_id_neglect | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the router ID attribute is ignored when BGP selects the optimal route. If the value is false, the router ID attribute is not ignored when BGP selects the optimal route. |
| rr_filter_number | no |  |  | Set the number of the extended community filter supported by an RR group. The value is a string of 1 to 51 characters. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| summary_automatic | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, automatic aggregation is enabled for locally imported routes. If the value is false, automatic aggregation is disabled for locally imported routes. |
| supernet_label_adv | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the function to advertise supernetwork label is enabled. If the value is false, the function to advertise supernetwork label is disabled. |
| supernet_uni_adv | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the function to advertise supernetwork unicast routes is enabled. If the value is false, the function to advertise supernetwork unicast routes is disabled. |
| vrf_name | yes |  |  | Name of a BGP instance. The name is a case-sensitive string of characters. The BGP instance can be used only after the corresponding VPN instance is created. The value is a string of 1 to 31 case-sensitive characters. |
| vrf_rid_auto_sel | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, VPN BGP instances are enabled to automatically select router IDs. If the value is false, VPN BGP instances are disabled from automatically selecting router IDs. |
#### Examples

```

- name: CloudEngine BGP address family test
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

  - name: "Config BGP Address_Family"
    ce_bgp_af:
      state:  present
      vrf_name:  js
      af_type:  ipv4uni
      provider: "{{ cli }}"

  - name: "Undo BGP Address_Family"
    ce_bgp_af:
      state:  absent
      vrf_name:  js
      af_type:  ipv4uni
      provider: "{{ cli }}"

  - name: "Config import route"
    ce_bgp_af:
      state:  present
      vrf_name:  js
      af_type:  ipv4uni
      import_protocol:  ospf
      import_process_id:  123
      provider: "{{ cli }}"

  - name: "Undo import route"
    ce_bgp_af:
      state:  absent
      vrf_name:  js
      af_type:  ipv4uni
      import_protocol:  ospf
      import_process_id:  123
      provider: "{{ cli }}"

  - name: "Config network route"
    ce_bgp_af:
      state:  present
      vrf_name:  js
      af_type:  ipv4uni
      network_address:  1.1.1.1
      mask_len:  24
      provider: "{{ cli }}"

  - name: "Undo network route"
    ce_bgp_af:
      state:  absent
      vrf_name:  js
      af_type:  ipv4uni
      network_address:  1.1.1.1
      mask_len:  24
      provider: "{{ cli }}"

```

---

## ce_bgp_neighbor

Manages BGP peer configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages BGP peer configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| conn_retry_time | no |  |  | ConnectRetry interval. The value is an integer ranging from 1 to 65535. |
| connect_mode | no |  |  | The value can be Connect-only, Listen-only, or Both. |
| conventional | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the router has all extended capabilities. If the value is false, the router does not have all extended capabilities. |
| description | no |  |  | Description of a peer, which can be letters or digits. The value is a string of 1 to 80 characters. |
| dual_as | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the EBGP peer can use either a fake AS number or the actual AS number. If the value is false, the EBGP peer can only use a fake AS number. |
| ebgp_max_hop | no |  |  | Maximum number of hops in an indirect EBGP connection. The value is an ranging from 1 to 255. |
| fake_as | no |  |  | Fake AS number that is specified for a local peer. The value is a string of 1 to 11 characters. |
| hold_time | no |  |  | Specify the Hold time of a peer or peer group. The value is 0 or an integer ranging from 3 to 65535. |
| is_bfd_block | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, peers are enabled to inherit the BFD function from the peer group. If the value is false, peers are disabled to inherit the BFD function from the peer group. |
| is_bfd_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, BFD is enabled. If the value is false, BFD is disabled. |
| is_ignore | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the session with a specified peer is torn down and all related routing entries are cleared. If the value is false, the session with a specified peer is retained. |
| is_log_change | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, BGP is enabled to record peer session status and event information. If the value is false, BGP is disabled from recording peer session status and event information. |
| is_single_hop | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the system is enabled to preferentially use the single-hop mode for BFD session setup between IBGP peers. If the value is false, the system is disabled from preferentially using the single-hop mode for BFD session setup between IBGP peers. |
| keep_alive_time | no |  |  | Specify the Keepalive time of a peer or peer group. The value is an integer ranging from 0 to 21845. The default value is 60. |
| key_chain_name | no |  |  | Specify the Keychain authentication name used when BGP peers establish a TCP connection. The value is a string of 1 to 47 case-insensitive characters. |
| local_if_name | no |  |  | Name of a source interface that sends BGP packets. The value is a string of 1 to 63 characters. |
| min_hold_time | no |  |  | Specify the Min hold time of a peer or peer group. |
| mpls_local_ifnet_disable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, peer create MPLS Local IFNET disable. If the value is false, peer create MPLS Local IFNET enable. |
| multiplier | no |  |  | Specify the detection multiplier. The default value is 3. The value is an integer ranging from 3 to 50. |
| peer_addr | yes |  |  | Connection address of a peer, which can be an IPv4 or IPv6 address. |
| prepend_fake_as | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Add the Fake AS number to received Update packets. |
| prepend_global_as | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Add the global AS number to the Update packets to be advertised. |
| pswd_cipher_text | no |  |  | The character string in a password identifies the contents of the password, spaces not supported. The value is a string of 1 to 255 characters. |
| pswd_type | no |  | <ul><li>null</li><li>cipher</li><li>simple</li></ul> | Enable BGP peers to establish a TCP connection and perform the Message Digest 5 (MD5) authentication for BGP messages. |
| remote_as | yes |  |  | AS number of a peer. The value is a string of 1 to 11 characters. |
| route_refresh | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, BGP is enabled to advertise REFRESH packets. If the value is false, the route refresh function is enabled. |
| rx_interval | no |  |  | Specify the minimum interval at which BFD packets are received. The value is an integer ranging from 50 to 1000, in milliseconds. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| tcp_MSS | no |  |  | Maximum TCP MSS value used for TCP connection establishment for a peer. The value is an integer ranging from 176 to 4096. |
| tx_interval | no |  |  | Specify the minimum interval at which BFD packets are sent. The value is an integer ranging from 50 to 1000, in milliseconds. |
| valid_ttl_hops | no |  |  | Enable GTSM on a peer or peer group. The valid-TTL-Value parameter is used to specify the number of TTL hops to be detected. The value is an integer ranging from 1 to 255. |
| vrf_name | yes |  |  | Name of a BGP instance. The name is a case-sensitive string of characters. The BGP instance can be used only after the corresponding VPN instance is created. |
#### Examples

```

- name: CloudEngine BGP neighbor test
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

  - name: "Config bgp peer"
    ce_bgp_neighbor:
      state:  present
      vrf_name:  js
      peer_addr:  192.168.10.10
      remote_as:  500
      provider: "{{ cli }}"

  - name: "Config bgp route id"
    ce_bgp_neighbor:
      state:  absent
      vrf_name:  js
      peer_addr:  192.168.10.10
      provider: "{{ cli }}"

```

---

## ce_bgp_neighbor_af

Manages BGP neighbor Address-family configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages BGP neighbor Address-family configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| add_path_mode | no |  | <ul><li>null</li><li>receive</li><li>send</li><li>both</li></ul> | null, Null. receive, Support receiving Add-Path routes. send, Support sending Add-Path routes. both, Support receiving and sending Add-Path routes. |
| adv_add_path_num | no |  |  | The number of addPath advertise route. The value is an integer ranging from 2 to 64. |
| advertise_arp | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, advertised ARP routes are distinguished. If the value is false, advertised ARP routes are not distinguished. |
| advertise_community | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the community attribute is advertised to peers. If the value is false, the community attribute is not advertised to peers. |
| advertise_ext_community | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the extended community attribute is advertised to peers. If the value is false, the extended community attribute is not advertised to peers. |
| advertise_irb | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, advertised IRB routes are distinguished. If the value is false, advertised IRB routes are not distinguished. |
| advertise_remote_nexthop | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the remote next-hop attribute is advertised to peers. If the value is false, the remote next-hop attribute is not advertised to any peers. |
| af_type | yes |  | <ul><li>ipv4uni</li><li>ipv4multi</li><li>ipv4vpn</li><li>ipv6uni</li><li>ipv6vpn</li><li>evpn</li></ul> | Address family type of a BGP instance. |
| allow_as_loop_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, repetitive local AS numbers are allowed. If the value is false, repetitive local AS numbers are not allowed. |
| allow_as_loop_limit | no |  |  | Set the maximum number of repetitive local AS number. The value is an integer ranging from 1 to 10. |
| default_rt_adv_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the function to advertise default routes to peers is enabled. If the value is false, the function to advertise default routes to peers is disabled. |
| default_rt_adv_policy | no |  |  | Specify the name of a used policy. The value is a string. The value is a string of 1 to 40 characters. |
| default_rt_match_mode | no |  | <ul><li>null</li><li>matchall</li><li>matchany</li></ul> | null, Null. matchall, Advertise the default route if all matching conditions are met. matchany, Advertise the default route if any matching condition is met. |
| discard_ext_community | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the extended community attribute in the peer route information is discarded. If the value is false, the extended community attribute in the peer route information is not discarded. |
| export_acl_name_or_num | no |  |  | Apply an IPv4 ACL-based filtering policy to the routes to be advertised to a specified peer. The value is a string of 1 to 32 characters. |
| export_as_path_filter | no |  |  | Apply an AS_Path-based filtering policy to the routes to be advertised to a specified peer. The value is an integer ranging from 1 to 256. |
| export_as_path_name_or_num | no |  |  | Application of a AS path list based filtering policy to the routing of a specified peer. |
| export_pref_filt_name | no |  |  | Specify the IPv4 filtering policy applied to the routes to be advertised to a specified peer. The value is a string of 1 to 169 characters. |
| export_rt_policy_name | no |  |  | Specify the filtering policy applied to the routes to be advertised to a peer. The value is a string of 1 to 40 characters. |
| import_acl_name_or_num | no |  |  | Apply an IPv4 ACL-based filtering policy to the routes received from a specified peer. The value is a string of 1 to 32 characters. |
| import_as_path_filter | no |  |  | Apply an AS_Path-based filtering policy to the routes received from a specified peer. The value is an integer ranging from 1 to 256. |
| import_as_path_name_or_num | no |  |  | A routing strategy based on the AS path list for routing received by a designated peer. |
| import_pref_filt_name | no |  |  | Specify the IPv4 filtering policy applied to the routes received from a specified peer. The value is a string of 1 to 169 characters. |
| import_rt_policy_name | no |  |  | Specify the filtering policy applied to the routes learned from a peer. The value is a string of 1 to 40 characters. |
| ipprefix_orf_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the address prefix-based Outbound Route Filter (ORF) capability is enabled for peers. If the value is false, the address prefix-based Outbound Route Filter (ORF) capability is disabled for peers. |
| is_nonstd_ipprefix_mod | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, Non-standard capability codes are used during capability negotiation. If the value is false, RFC-defined standard ORF capability codes are used during capability negotiation. |
| keep_all_routes | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the system stores all route update messages received from all peers (groups) after BGP connection setup. If the value is false, the system stores only BGP update messages that are received from peers and pass the configured import policy. |
| nexthop_configure | no |  | <ul><li>null</li><li>local</li><li>invariable</li></ul> | null, The next hop is not changed. local, The next hop is changed to the local IP address. invariable, Prevent the device from changing the next hop of each imported IGP route when advertising it to its BGP peers. |
| orf_mode | no |  | <ul><li>null</li><li>receive</li><li>send</li><li>both</li></ul> | ORF mode. null, Default value. receive, ORF for incoming packets. send, ORF for outgoing packets. both, ORF for incoming and outgoing packets. |
| orftype | no |  |  | ORF Type. The value is an integer ranging from 0 to 65535. |
| origin_as_valid | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, Application results of route announcement. If the value is false, Routing application results are not notified. |
| preferred_value | no |  |  | Assign a preferred value for the routes learned from a specified peer. The value is an integer ranging from 0 to 65535. |
| public_as_only | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, sent BGP update messages carry only the public AS number but do not carry private AS numbers. If the value is false, sent BGP update messages can carry private AS numbers. |
| public_as_only_force | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, sent BGP update messages carry only the public AS number but do not carry private AS numbers. If the value is false, sent BGP update messages can carry private AS numbers. |
| public_as_only_limited | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Limited use public as number. |
| public_as_only_replace | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Private as replaced by public as number. |
| public_as_only_skip_peer_as | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Public as only skip peer as. |
| redirect_ip | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Redirect ip. |
| redirect_ip_vaildation | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Redirect ip vaildation. |
| reflect_client | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the local device functions as the route reflector and a peer functions as a client of the route reflector. If the value is false, the route reflector and client functions are not configured. |
| remote_address | yes |  |  | IPv4 or IPv6 peer connection address. |
| route_limit | no |  |  | Configure the maximum number of routes that can be accepted from a peer. The value is an integer ranging from 1 to 4294967295. |
| route_limit_idle_timeout | no |  |  | Specify the value of the idle-timeout timer to automatically reestablish the connections after they are cut off when the number of routes exceeds the set threshold. The value is an integer ranging from 1 to 1200. |
| route_limit_percent | no |  |  | Specify the percentage of routes when a router starts to generate an alarm. The value is an integer ranging from 1 to 100. |
| route_limit_type | no |  | <ul><li>noparameter</li><li>alertOnly</li><li>idleForever</li><li>idleTimeout</li></ul> | Noparameter, After the number of received routes exceeds the threshold and the timeout timer expires,no action. AlertOnly, An alarm is generated and no additional routes will be accepted if the maximum number of routes allowed have been received. IdleForever, The connection that is interrupted is not automatically re-established if the maximum number of routes allowed have been received. IdleTimeout, After the number of received routes exceeds the threshold and the timeout timer expires, the connection that is interrupted is automatically re-established. |
| rt_updt_interval | no |  |  | Specify the minimum interval at which Update packets are sent. The value is an integer, in seconds. The value is an integer ranging from 0 to 600. |
| soostring | no |  |  | Configure the Site-of-Origin (SoO) extended community attribute. The value is a string of 3 to 21 characters. |
| substitute_as_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, the function to replace a specified peer's AS number in the AS-Path attribute with the local AS number is enabled. If the value is false, the function to replace a specified peer's AS number in the AS-Path attribute with the local AS number is disabled. |
| update_pkt_standard_compatible | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, When the vpnv4 multicast neighbor receives and updates the message, the message has no label. If the value is false, When the vpnv4 multicast neighbor receives and updates the message, the message has label. |
| vpls_ad_disable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, enable vpls-ad. If the value is false, disable vpls-ad. |
| vpls_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | If the value is true, vpls enable. If the value is false, vpls disable. |
| vrf_name | yes |  |  | Name of a BGP instance. The name is a case-sensitive string of characters. The BGP instance can be used only after the corresponding VPN instance is created. |
#### Examples

```

- name: CloudEngine BGP neighbor address family test
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

  - name: "Config BGP peer Address_Family"
    ce_bgp_neighbor_af:
      state:  present
      vrf_name:  js
      af_type:  ipv4uni
      remote_address:  192.168.10.10
      nexthop_configure:  local
      provider: "{{ cli }}"

  - name: "Undo BGP peer Address_Family"
    ce_bgp_neighbor_af:
      state:  absent
      vrf_name:  js
      af_type:  ipv4uni
      remote_address:  192.168.10.10
      nexthop_configure:  local
      provider: "{{ cli }}"

```

---

## ce_command

Run arbitrary command on HUAWEI CloudEngine devices.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Sends an arbitrary command to an HUAWEI CloudEngine node and returns the results read from the device.  The ce_command module includes an argument that will cause the module to wait for a specific condition before returning or timing out if the condition is not met.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| commands | yes |  |  | The commands to send to the remote HUAWEI CloudEngine device over the configured provider.  The resulting output from the command is returned. If the I(wait_for) argument is provided, the module is not returned until the condition is satisfied or the number of I(retries) has been exceeded. |
| interval | no | 1 |  | Configures the interval in seconds to wait between retries of the command.  If the command does not pass the specified conditional, the interval indicates how to long to wait before trying the command again. |
| match | no | all |  | The I(match) argument is used in conjunction with the I(wait_for) argument to specify the match policy.  Valid values are C(all) or C(any).  If the value is set to C(all) then all conditionals in the I(wait_for) must be satisfied.  If the value is set to C(any) then only one of the values must be satisfied. |
| retries | no | 10 |  | Specifies the number of retries a command should by tried before it is considered failed.  The command is run on the target device every retry and evaluated against the I(wait_for) conditionals. |
| wait_for | no |  |  | Specifies what to evaluate from the output of the command and what conditionals to apply.  This argument will cause the task to wait for a particular conditional to be true before moving forward.   If the conditional is not true by the configured retries, the task fails.  See examples. |
#### Examples

```
# Note: examples below use the following provider dict to handle
#       transport and authentication to the node.

- name: CloudEngine command test
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

  tasks:
  - name: "Run display version on remote devices"
    ce_command:
      commands: display version
      provider: "{{ cli }}"

  - name: "Run display version and check to see if output contains HUAWEI"
    ce_command:
      commands: display version
      wait_for: result[0] contains HUAWEI
      provider: "{{ cli }}"

  - name: "Run multiple commands on remote nodes"
    ce_command:
      commands:
        - display version
        - display device
      provider: "{{ cli }}"

  - name: "Run multiple commands and evaluate the output"
    ce_command:
      commands:
        - display version
        - display device
      wait_for:
        - result[0] contains HUAWEI
        - result[1] contains Device
      provider: "{{ cli }}"

```

---

## ce_config

Manage Huawei CloudEngine configuration sections.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Huawei CloudEngine configurations use a simple block indent file syntax for segmenting configuration into sections.  This module provides an implementation for working with CloudEngine configuration sections in a deterministic way.  This module works with CLI transports.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| after | no |  |  | The ordered set of commands to append to the end of the command stack if a change needs to be made.  Just like with I(before) this allows the playbook designer to append a set of commands to be executed after the command set. |
| backup | no |  | <ul><li>yes</li><li>no</li></ul> | This argument will cause the module to create a full backup of the current C(current-configuration) from the remote device before any changes are made.  The backup file is written to the C(backup) folder in the playbook root directory.  If the directory does not exist, it is created. |
| before | no |  |  | The ordered set of commands to push on to the command stack if a change needs to be made.  This allows the playbook designer the opportunity to perform configuration commands prior to pushing any changes without affecting how the set of commands are matched against the system. |
| config | no |  |  | The module, by default, will connect to the remote device and retrieve the current current-configuration to use as a base for comparing against the contents of source.  There are times when it is not desirable to have the task get the current-configuration for every task in a playbook.  The I(config) argument allows the implementer to pass in the configuration to use as the base config for comparison. |
| defaults | no |  |  | The I(defaults) argument will influence how the current-configuration is collected from the device.  When the value is set to true, the command used to collect the current-configuration is append with the all keyword.  When the value is set to false, the command is issued without the all keyword. |
| force | no |  | <ul><li>true</li><li>false</li></ul> | The force argument instructs the module to not consider the current devices current-configuration.  When set to true, this will cause the module to push the contents of I(src) into the device without first checking if already configured.<br>Note this argument should be considered deprecated.  To achieve the equivalent, set the C(match=none) which is idempotent.  This argument will be removed in a future release. |
| lines | no |  |  | The ordered set of commands that should be configured in the section.  The commands must be the exact same commands as found in the device current-configuration.  Be sure to note the configuration command syntax as some commands are automatically modified by the device config parser. |
| match | no | line | <ul><li>line</li><li>strict</li><li>exact</li><li>none</li></ul> | Instructs the module on the way to perform the matching of the set of commands against the current device config.  If match is set to I(line), commands are matched line by line.  If match is set to I(strict), command lines are matched with respect to position.  If match is set to I(exact), command lines must be an equal match.  Finally, if match is set to I(none), the module will not attempt to compare the source configuration with the current-configuration on the remote device. |
| parents | no |  |  | The ordered set of parents that uniquely identify the section the commands should be checked against.  If the parents argument is omitted, the commands are checked against the set of top level or global commands. |
| replace | no | line | <ul><li>line</li><li>block</li></ul> | Instructs the module on the way to perform the configuration on the device.  If the replace argument is set to I(line) then the modified lines are pushed to the device in configuration mode.  If the replace argument is set to I(block) then the entire command block is pushed to the device in configuration mode if any line is not correct. |
| save | no |  |  | The C(save) argument instructs the module to save the current-configuration to saved-configuration.  This operation is performed after any changes are made to the current running config.  If no changes are made, the configuration is still saved to the startup config.  This option will always cause the module to return changed. |
| src | no |  |  | The I(src) argument provides a path to the configuration file to load into the remote system.  The path can either be a full system path to the configuration file if the value starts with / or relative to the root of the implemented role or playbook. This argument is mutually exclusive with the I(lines) and I(parents) arguments. |
#### Examples

```
# Note: examples below use the following provider dict to handle
#       transport and authentication to the node.

- name: CloudEngine config test
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

```

---

## ce_dldp

Manages global DLDP configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages global DLDP configuration.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| auth_mode | no |  | <ul><li>md5</li><li>simple</li><li>sha</li><li>hmac-sha256</li><li>none</li></ul> | Specifies authentication algorithm of DLDP. |
| auth_pwd | no |  |  | Specifies authentication password. The value is a string of 1 to 16 case-sensitive plaintexts or 24/32/48/108/128 case-sensitive encrypted characters. The string excludes a question mark (?). |
| enable | no |  | <ul><li>enable</li><li>disable</li></ul> | Set global DLDP enable state. |
| reset | no |  | <ul><li>enable</li><li>disable</li></ul> | Specify whether reset DLDP state of disabled interfaces. |
| time_internal | no |  |  | Specifies the interval for sending Advertisement packets. The value is an integer ranging from 1 to 100, in seconds. The default interval for sending Advertisement packets is 5 seconds. |
| work_mode | no |  | <ul><li>enhance</li><li>normal</li></ul> | Set global DLDP work-mode. |
#### Examples

```
- name: DLDP test
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

  - name: "Configure global DLDP enable state"
    ce_dldp:
      enable: enable
      provider: "{{ cli }}"

  - name: "Configure DLDP work-mode and ensure global DLDP state is already enabled"
    ce_dldp:
      enable: enable
      work_mode: normal
      provider: "{{ cli }}"

  - name: "Configure advertisement message time interval in seconds and ensure global DLDP state is already enabled"
    ce_dldp:
      enable: enable
      time_interval: 6
      provider: "{{ cli }}"

  - name: "Configure a DLDP authentication mode and ensure global DLDP state is already enabled"
    ce_dldp:
      enable: enable
      auth_mode: md5
      auth_pwd: abc
      provider: "{{ cli }}"

  - name: "Reset DLDP state of disabled interfaces and ensure global DLDP state is already enabled"
    ce_dldp:
      enable: enable
      reset: enable
      provider: "{{ cli }}"

```

#### Notes

- The relevant configurations will be deleted if DLDP is disabled using enable=disable.
- When using auth_mode=none, it will restore the default DLDP authentication mode(By default, DLDP packets are not authenticated.).
- By default, the working mode of DLDP is enhance, so you are advised to use work_mode=enhance to restore defualt DLDP working mode.
- The default interval for sending Advertisement packets is 5 seconds, so you are advised to use time_interval=5 to restore defualt DLDP interval.
 

---

## ce_dldp_interface

Manages interface DLDP configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages interface DLDP configuration.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| enable | no |  | <ul><li>enable</li><li>disable</li></ul> | Set interface DLDP enable state. |
| interface | yes |  |  | Must be fully qualified interface name, i.e. GE1/0/1, 10GE1/0/1, 40GE1/0/22, 100GE1/0/1. |
| local_mac | no |  |  | Set the source MAC address for DLDP packets sent in the DLDP-compatible mode. The value of MAC address is in H-H-H format. H contains 1 to 4 hexadecimal digits. |
| mode_enable | no |  | <ul><li>enable</li><li>disable</li></ul> | Set DLDP compatible-mode enable state. |
| reset | no |  | <ul><li>enable</li><li>disable</li></ul> | Specify whether reseting interface DLDP state. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
#### Examples

```
- name: DLDP interface test
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

  - name: "Configure interface DLDP enable state and ensure global dldp enable is turned on"
    ce_dldp_interface:
      interface: 40GE2/0/1
      enable: enable
      provider: "{{ cli }}"

  - name: "Configuire interface DLDP compatible-mode enable state  and ensure interface DLDP state is already enabled"
    ce_dldp_interface:
      interface: 40GE2/0/1
      enable: enable
      mode_enable: enable
      provider: "{{ cli }}"

  - name: "Configuire the source MAC address for DLDP packets sent in the DLDP-compatible mode  and
           ensure interface DLDP state and compatible-mode enable state  is already enabled"
    ce_dldp_interface:
      interface: 40GE2/0/1
      enable: enable
      mode_enable: enable
      local_mac: aa-aa-aa
      provider: "{{ cli }}"

  - name: "Reset DLDP state of specified interface and ensure interface DLDP state is already enabled"
    ce_dldp_interface:
      interface: 40GE2/0/1
      enable: enable
      reset: enable
      provider: "{{ cli }}"

  - name: "Unconfigure interface DLDP local mac addreess when C(state=absent)"
    ce_dldp_interface:
      interface: 40GE2/0/1
      state: absent
      local_mac: aa-aa-aa
      provider: "{{ cli }}"

```

#### Notes

- If C(state=present, enable=disable), interface DLDP enable will be turned off and related interface DLDP confuration will be cleared.
- If C(state=absent), only local_mac is supported to configure.
 

---

## ce_eth_trunk

Manages Eth-Trunk interfaces.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages Eth-Trunk specific configuration parameters.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| force | no |  |  | When true it forces Eth-Trunk members to match what is declared in the members param. This can be used to remove members. |
| hash_type | no |  | <ul><li>src-dst-ip</li><li>src-dst-mac</li><li>enhanced</li><li>dst-ip</li><li>dst-mac</li><li>src-ip</li><li>src-mac</li></ul> | Hash algorithm used for load balancing among Eth-Trunk member interfaces. |
| members | no |  |  | List of interfaces that will be managed in a given Eth-Trunk. The interface name must be full name. |
| min_links | no |  |  | Specifies the minimum number of Eth-Trunk member links in the Up state. The value is an integer ranging from 1 to the maximum number of interfaces that can be added to a Eth-Trunk interface. |
| mode | no |  | <ul><li>manual</li><li>lacp-dynamic</li><li>lacp-static</li></ul> | Specifies the working mode of an Eth-Trunk interface. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
| trunk_id | yes |  |  | Eth-Trunk interface number. The value is an integer. The value range depends on the assign forward eth-trunk mode command. When 256 is specified, the value ranges from 0 to 255. When 512 is specified, the value ranges from 0 to 511. When 1024 is specified, the value ranges from 0 to 1023. |
#### Examples

```
- name: eth_trunk module test
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
  - name: Ensure Eth-Trunk100 is created, add two members, and set to mode lacp-static
    ce_eth_trunk:
      trunk_id: 100
      members: ['10GE1/0/24','10GE1/0/25']
      mode: 'lacp-static'
      state: present
      provider: '{{ cli }}'

```

#### Notes

- C(state=absent) removes the Eth-Trunk config and interface if it already exists. If members to be removed are not explicitly passed, all existing members (if any), are removed, and Eth-Trunk removed.
- Members must be a list.
 

---

## ce_evpn_bd_vni

Manages Huawei EVPN VXLAN Network Identifier (VNI).

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages Huawei Ethernet Virtual Private Network (EVPN) VXLAN Network Identifier (VNI) configurations.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| bridge_domain_id | yes |  |  | Specify an existed bridge domain (BD).The value is an integer ranging from 1 to 16777215. |
| evpn | no | enable | <ul><li>enable</li><li>disable</li></ul> | Create or delete an EVPN instance for a VXLAN in BD view. |
| route_distinguisher | no |  |  | Configures a route distinguisher (RD) for a BD EVPN instance. The format of an RD can be as follows 1) 2-byte AS number:4-byte user-defined number, for example, 1:3. An AS number is an integer ranging from 0 to 65535, and a user-defined number is an integer ranging from 0 to 4294967295. The AS and user-defined numbers cannot be both 0s. This means that an RD cannot be 0:0. 2) Integral 4-byte AS number:2-byte user-defined number, for example, 65537:3. An AS number is an integer ranging from 65536 to 4294967295, and a user-defined number is an integer ranging from 0 to 65535. 3) 4-byte AS number in dotted notation:2-byte user-defined number, for example, 0.0:3 or 0.1:0. A 4-byte AS number in dotted notation is in the format of x.y, where x and y are integers ranging from 0 to 65535. 4) A user-defined number is an integer ranging from 0 to 65535. The AS and user-defined numbers cannot be both 0s. This means that an RD cannot be 0.0:0. 5) 32-bit IP address:2-byte user-defined number. For example, 192.168.122.15:1. An IP address ranges from 0.0.0.0 to 255.255.255.255, and a user-defined number is an integer ranging from 0 to 65535. 6) 'auto' specifies the RD that is automatically generated. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
| vpn_target_both | no |  |  | Add VPN targets to both the import and export VPN target lists of a BD EVPN instance. The format is the same as route_distinguisher. |
| vpn_target_export | no |  |  | Add VPN targets to the export VPN target list of a BD EVPN instance. The format is the same as route_distinguisher. |
| vpn_target_import | yes |  |  | Add VPN targets to the import VPN target list of a BD EVPN instance. The format is the same as route_distinguisher. |
#### Examples

```
- name: EVPN BD VNI test
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

  - name: "Configure an EVPN instance for a VXLAN in BD view"
    ce_evpn_bd_vni:
      bridge_domain_id: 20
      evpn: enable
      provider: "{{ cli }}"

  - name: "Configure a route distinguisher (RD) for a BD EVPN instance"
    ce_evpn_bd_vni:
      bridge_domain_id: 20
      route_distinguisher: '22:22'
      provider: "{{ cli }}"

  - name: "Configure VPN targets to both the import and export VPN target lists of a BD EVPN instance"
    ce_evpn_bd_vni:
      bridge_domain_id: 20
      vpn_target_both: 22:100,22:101
      provider: "{{ cli }}"

  - name: "Configure VPN targets to the import VPN target list of a BD EVPN instance"
    ce_evpn_bd_vni:
      bridge_domain_id: 20
      vpn_target_import: 22:22,22:23
      provider: "{{ cli }}"

  - name: "Configure VPN targets to the export VPN target list of a BD EVPN instance"
    ce_evpn_bd_vni:
      bridge_domain_id: 20
      vpn_target_export: 22:38,22:39
      provider: "{{ cli }}"

  - name: "Unconfigure VPN targets to both the import and export VPN target lists of a BD EVPN instance"
    ce_evpn_bd_vni:
      bridge_domain_id: 20
      vpn_target_both: '22:100'
      state: absent
      provider: "{{ cli }}"

  - name: "Unconfigure VPN targets to the import VPN target list of a BD EVPN instance"
    ce_evpn_bd_vni:
      bridge_domain_id: 20
      vpn_target_import: '22:22'
      state: absent
      provider: "{{ cli }}"

  - name: "Unconfigure VPN targets to the export VPN target list of a BD EVPN instance"
    ce_evpn_bd_vni:
      bridge_domain_id: 20
      vpn_target_export: '22:38'
      state: absent
      provider: "{{ cli }}"

  - name: "Unconfigure a route distinguisher (RD) of a BD EVPN instance"
    ce_evpn_bd_vni:
      bridge_domain_id: 20
      route_distinguisher: '22:22'
      state: absent
      provider: "{{ cli }}"

  - name: "Unconfigure an EVPN instance for a VXLAN in BD view"
    ce_evpn_bd_vni:
      bridge_domain_id: 20
      evpn: disable
      provider: "{{ cli }}"

```

#### Notes

- Ensure that EVPN has been configured to serve as the VXLAN control plane when state is present.
- Ensure that a bridge domain (BD) has existed when state is present.
- Ensure that a VNI has been created and associated with a broadcast domain (BD) when state is present.
- If you configure evpn:false to delete an EVPN instance, all configurations in the EVPN instance are deleted.
- After an EVPN instance has been created in the BD view, you can configure an RD using route_distinguisher parameter in BD-EVPN instance view.
- Before configuring VPN targets for a BD EVPN instance, ensure that an RD has been configured for the BD EVPN instance
- If you unconfigure route_distinguisher, all VPN target attributes for the BD EVPN instance will be removed at the same time.
- When using state:absent, evpn is not supported and it will be ignored.
- When using state:absent to delete VPN target attributes, ensure the configuration of VPN target attributes has existed and otherwise it will report an error.
 

---

## ce_evpn_bgp

Manages BGP EVPN configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

This module offers the ability to configure a BGP EVPN peer relationship on CloudEngine switch.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| advertise_l2vpn_evpn | no |  | <ul><li>enable</li><li>disable</li></ul> | Enable or disable a device to advertise IP routes imported to a VPN instance to its EVPN instance. |
| advertise_router_type | no |  | <ul><li>arp</li><li>irb</li></ul> | Configures a device to advertise routes to its BGP EVPN peers. |
| as_number | no |  |  | Specifies integral AS number. The value is an integer ranging from 1 to 4294967295. |
| bgp_instance | yes |  |  | Name of a BGP instance. The value is a string of 1 to 31 case-sensitive characters, spaces not supported. |
| peer_address | no |  |  | Specifies the IPv4 address of a BGP EVPN peer. The value is in dotted decimal notation. |
| peer_enable | no |  | <ul><li>true</li><li>false</li></ul> | Enable or disable a BGP device to exchange routes with a specified peer or peer group in the address family view. |
| peer_group_name | no |  |  | Specify the name of a peer group that BGP peers need to join. The value is a string of 1 to 47 case-sensitive characters, spaces not supported. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
| vpn_name | no |  |  | Associates a specified VPN instance with the IPv4 address family. The value is a string of 1 to 31 case-sensitive characters, spaces not supported. |
#### Examples

```
- name: evpn bgp module test
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

  - name: Enable peer address.
    ce_evpn_bgp:
      bgp_instance: 100
      peer_address: 1.1.1.1
      as_number: 100
      peer_enable: true
      provider: "{{ cli }}"

  - name: Enable peer group arp.
    ce_evpn_bgp:
      bgp_instance: 100
      peer_group_name: aaa
      advertise_router_type: arp
      provider: "{{ cli }}"

  - name: Enable advertise l2vpn evpn.
    ce_evpn_bgp:
      bgp_instance: 100
      vpn_name: aaa
      advertise_l2vpn_evpn: enable
      provider: "{{ cli }}"

```

---

## ce_evpn_bgp_rr

Manages RR for the VXLAN Network.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Configure an RR in BGP-EVPN address family view.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| as_number | yes |  |  | Specifies the number of the AS, in integer format. The value is an integer that ranges from 1 to 4294967295. |
| bgp_evpn_enable | no | enable | <ul><li>enable</li><li>disable</li></ul> | Enable or disable the BGP-EVPN address family. |
| bgp_instance | no |  |  | Specifies the name of a BGP instance. The value of instance-name can be an integer 1 or a string of 1 to 31. |
| peer | no |  |  | Specifies the IPv4 address or the group name of a peer. |
| peer_type | no |  | <ul><li>group_name</li><li>ipv4_address</li></ul> | Specify the peer type. |
| policy_vpn_target | no |  | <ul><li>enable</li><li>disable</li></ul> | Enable or disable the VPN-Target filtering. |
| reflect_client | no |  | <ul><li>enable</li><li>disable</li></ul> | Configure the local device as the route reflector and the peer or peer group as the client of the route reflector. |
#### Examples

```
- name: BGP RR test
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

  - name: "Configure BGP-EVPN address family view and ensure that BGP view has existed."
    ce_evpn_bgp_rr:
      as_number: 20
      bgp_evpn_enable: enable
      provider: "{{ cli }}"

  - name: "Configure reflect client and ensure peer has existed."
    ce_evpn_bgp_rr:
      as_number: 20
      peer_type: ipv4_address
      peer: 192.8.3.3
      reflect_client: enable
      provider: "{{ cli }}"

  - name: "Configure the VPN-Target filtering."
    ce_evpn_bgp_rr:
      as_number: 20
      policy_vpn_target: enable
      provider: "{{ cli }}"

  - name: "Configure an RR in BGP-EVPN address family view."
    ce_evpn_bgp_rr:
      as_number: 20
      bgp_evpn_enable: enable
      peer_type: ipv4_address
      peer: 192.8.3.3
      reflect_client: enable
      policy_vpn_target: disable
      provider: "{{ cli }}"

```

#### Notes

- Ensure that BGP view is existed.
- The peer, peer_type, and reflect_client arguments must all exist or not exist.
 

---

## ce_evpn_global

Manages global configuration of EVPN.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages global configuration of EVPN.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| evpn_overlay_enable | yes |  | <ul><li>enable</li><li>disable</li></ul> | Configure EVPN as the VXLAN control plane. |
#### Examples

```
- name: evpn global module test
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

  - name: Configure EVPN as the VXLAN control plan
    ce_evpn_global:
      evpn_overlay_enable: enable
      provider: "{{ cli }}"

  - name: Undo EVPN as the VXLAN control plan
    ce_evpn_global:
      evpn_overlay_enable: disable
      provider: "{{ cli }}"

```

#### Notes

- Before configuring evpn_overlay_enable=disable, delete other EVPN configurations.
 

---

## ce_facts

Gets facts about HUAWEI CloudEngine switches.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Collects facts from CloudEngine devices running the CloudEngine operating system.  Fact collection is supported over Cli transport.  This module prepends all of the base network fact keys with C(ansible_net_<fact>).  The facts module will always collect a base set of facts from the device and can enable or disable collection of additional facts.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| gather_subset | no | !config |  | When supplied, this argument will restrict the facts collected to a given subset.  Possible values for this argument include all, hardware, config, and interfaces.  Can specify a list of values to include a larger subset.  Values can also be used with an initial C(M(!)) to specify that a specific subset should not be collected. |
#### Examples

```
# Note: examples below use the following provider dict to handle
#       transport and authentication to the node.

- name: CloudEngine facts test
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

  - name: "Gather_subset is all"
    ce_facts:
      gather_subset: all
      provider: "{{ cli }}"

  - name: "Collect only the config facts"
    ce_facts:
      gather_subset:  config
      provider: "{{ cli }}"

  - name: "Do not collect hardware facts"
    ce_facts:
      gather_subset:  "!hardware"
      provider: "{{ cli }}"

```

---

## ce_file_copy

Copy a file to a remote cloudengine device over SCP.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Copy a file to a remote cloudengine device over SCP.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| file_system | no | flash: |  | The remote file system of the device. If omitted, devices that support a file_system parameter will use their default values. File system indicates the storage medium and can be set to as follows, 1) 'flash:' is root directory of the flash memory on the master MPU. 2) 'slave#flash:' is root directory of the flash memory on the slave MPU. If no slave MPU exists, this drive is unavailable. 3) 'chassis ID/slot number#flash:' is root directory of the flash memory on a device in a stack. For example, 1/5#flash indicates the flash memory whose chassis ID is 1 and slot number is 5. |
| local_file | yes |  |  | Path to local file. Local directory must exist. The maximum length of local_file is 4096. |
| remote_file | no |  |  | Remote file path of the copy. Remote directories must exist. If omitted, the name of the local file will be used. The maximum length of remote_file is 4096. |
#### Examples

```
- name: File copy test
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

  - name: "Copy a local file to remote device"
    ce_file_copy:
      local_file: /usr/vrpcfg.cfg
      remote_file: /vrpcfg.cfg
      file_system: 'flash:'
      provider: "{{ cli }}"

```

#### Notes

- The feature must be enabled with feature scp-server.
- If the file is already present, no transfer will take place.
 

---

## ce_info_center_debug

Manages information center debug configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages information center debug configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| channel_id | no |  |  | Number of a channel. The value is an integer ranging from 0 to 9. The default value is 0. |
| debug_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Whether a device is enabled to output debugging information. |
| debug_level | no |  | <ul><li>emergencies</li><li>alert</li><li>critical</li><li>error</li><li>warning</li><li>notification</li><li>informational</li><li>debugging</li></ul> | Debug level permitted to output. |
| debug_time_stamp | no |  | <ul><li>date_boot</li><li>date_second</li><li>date_tenthsecond</li><li>date_millisecond</li><li>shortdate_second</li><li>shortdate_tenthsecond</li><li>shortdate_millisecond</li><li>formatdate_second</li><li>formatdate_tenthsecond</li><li>formatdate_millisecond</li></ul> | Timestamp type of debugging information. |
| module_name | no |  |  | Module name of the rule. The value is a string of 1 to 31 case-insensitive characters. The default value is default. Please use lower-case letter, such as [aaa, acl, arp, bfd]. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
#### Examples

```

- name: CloudEngine info center debug test
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

  - name: "Config debug time stamp"
    ce_info_center_debug:
      state:  present
      debug_time_stamp:  date_boot
      provider: "{{ cli }}"

  - name: "Undo debug time stamp"
    ce_info_center_debug:
      state:  absent
      debug_time_stamp:  date_boot
      provider: "{{ cli }}"

  - name: "Config debug module log level"
    ce_info_center_debug:
      state:  present
      module_name:  aaa
      channel_id:  1
      debug_enable:  true
      debug_level:  error
      provider: "{{ cli }}"

  - name: "Undo debug module log level"
    ce_info_center_debug:
      state:  absent
      module_name:  aaa
      channel_id:  1
      debug_enable:  true
      debug_level:  error
      provider: "{{ cli }}"

```

---

## ce_info_center_global

Manages outputting logs.

  * Synopsis
  * Options
  * Examples

#### Synopsis

This module offers the ability to be output to the log buffer, log file, console, terminal, or log host on CloudEngine switch.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| channel_cfg_name | no | console |  | Channel name.The value is a string of 1 to 30 case-sensitive characters. The default value is console. |
| channel_id | no |  |  | Number for channel. The value is an integer ranging from 0 to 9. The default value is 0. |
| channel_name | no |  |  | Channel name. The value is a string of 1 to 30 case-sensitive characters. |
| channel_out_direct | no |  | <ul><li>console</li><li>monitor</li><li>trapbuffer</li><li>logbuffer</li><li>snmp</li><li>logfile</li></ul> | Direction of information output. |
| facility | no |  | <ul><li>local0</li><li>local1</li><li>local2</li><li>local3</li><li>local4</li><li>local5</li><li>local6</li><li>local7</li></ul> | Log record tool. |
| filter_feature_name | no |  |  | Feature name of the filtered log. The value is a string of 1 to 31 case-insensitive characters. |
| filter_log_name | no |  |  | Name of the filtered log. The value is a string of 1 to 63 case-sensitive characters. |
| info_center_enable | no |  | <ul><li>true</li><li>false</li></ul> | Whether the info-center function is enabled. The value is of the Boolean type. |
| ip_type | no |  | <ul><li>ipv4</li><li>ipv6</li></ul> | Log server address type, IPv4 or IPv6. |
| is_default_vpn | no |  |  | Use the default VPN or not. |
| level | no |  | <ul><li>emergencies</li><li>alert</li><li>critical</li><li>error</li><li>warning</li><li>notification</li><li>informational</li><li>debugging</li></ul> | Level of logs saved on a log server. |
| logfile_max_num | no |  |  | Maximum number of log files of the same type. The default value is 200.<br>The value range for log files is[3, 500], for security files is [1, 3],and for operation files is [1, 7]. |
| logfile_max_size | no | 32 | <ul><li>4</li><li>8</li><li>16</li><li>32</li></ul> | Maximum size (in MB) of a log file. The default value is 32.<br>The value range for log files is [4, 8, 16, 32], for security files is [1, 4],<br>and for operation files is [1, 4]. |
| packet_priority | no |  |  | Set the priority of the syslog packet.The value is an integer ranging from 0 to 7. The default value is 0. |
| server_domain | no |  |  | Server name. The value is a string of 1 to 255 case-sensitive characters. |
| server_ip | no |  |  | Log server address, IPv4 or IPv6 type. The value is a string of 0 to 255 characters. The value can be an valid IPv4 or IPv6 address. |
| server_port | no |  |  | Number of a port sending logs.The value is an integer ranging from 1 to 65535. For UDP, the default value is 514. For TCP, the default value is 601. For TSL, the default value is 6514. |
| source_ip | no |  |  | Log source ip address, IPv4 or IPv6 type. The value is a string of 0 to 255. The value can be an valid IPv4 or IPv6 address. |
| ssl_policy_name | no |  |  | SSL policy name. The value is a string of 1 to 23 case-sensitive characters. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| suppress_enable | no |  | <ul><li>true</li><li>false</li></ul> | Whether a device is enabled to suppress duplicate statistics. The value is of the Boolean type. |
| timestamp | no |  | <ul><li>UTC</li><li>localtime</li></ul> | Log server timestamp. The value is of the enumerated type and case-sensitive. |
| transport_mode | no |  | <ul><li>tcp</li><li>udp</li></ul> | Transport mode. The value is of the enumerated type and case-sensitive. |
| vrf_name | no |  |  | VPN name on a log server. The value is a string of 1 to 31 case-sensitive characters. The default value is _public_. |
#### Examples

```
- name: info center global module test
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

  - name: Config info-center enable
    ce_info_center_global:
      info_center_enable: true
      state: present
      provider: "{{ cli }}"

  - name: Config statistic-suppress enable
    ce_info_center_global:
      suppress_enable: true
      state: present
      provider: "{{ cli }}"

  - name: Config info-center syslog packet-priority 1
    ce_info_center_global:
      packet_priority: 2
      state: present
      provider: "{{ cli }}"

  - name: Config info-center channel 1 name aaa
    ce_info_center_global:
      channel_id: 1
      channel_cfg_name: aaa
      state: present
      provider: "{{ cli }}"

  - name: Config info-center logfile size 10
    ce_info_center_global:
      logfile_max_num: 10
      state: present
      provider: "{{ cli }}"

  - name: Config info-center console channel 1
    ce_info_center_global:
      channel_out_direct: console
      channel_id: 1
      state: present
      provider: "{{ cli }}"

  - name: Config info-center filter-id bymodule-alias snmp snmp_ipunlock
    ce_info_center_global:
      filter_feature_name: SNMP
      filter_log_name: SNMP_IPLOCK
      state: present
      provider: "{{ cli }}"


  - name: Config info-center max-logfile-number 16
    ce_info_center_global:
      logfile_max_size: 16
      state: present
      provider: "{{ cli }}"

  - name: Config syslog loghost domain.
    ce_info_center_global:
      server_domain: aaa
      vrf_name: aaa
      channel_id: 1
      transport_mode: tcp
      facility: local4
      server_port: 100
      level: alert
      timestamp: UTC
      state: present
      provider: "{{ cli }}"

```

---

## ce_info_center_log

Manages information center log configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Setting the Timestamp Format of Logs. Configuring the Device to Output Logs to the Log Buffer.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| channel_id | no |  |  | Specifies a channel ID. The value is an integer ranging from 0 to 9. |
| log_buff_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Enables the Switch to send logs to the log buffer. |
| log_buff_size | no |  |  | Specifies the maximum number of logs in the log buffer. The value is an integer that ranges from 0 to 10240. If logbuffer-size is 0, logs are not displayed. |
| log_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Indicates whether log filtering is enabled. |
| log_level | no |  | <ul><li>emergencies</li><li>alert</li><li>critical</li><li>error</li><li>warning</li><li>notification</li><li>informational</li><li>debugging</li></ul> | Specifies a log severity. |
| log_time_stamp | no |  | <ul><li>date_boot</li><li>date_second</li><li>date_tenthsecond</li><li>date_millisecond</li><li>shortdate_second</li><li>shortdate_tenthsecond</li><li>shortdate_millisecond</li><li>formatdate_second</li><li>formatdate_tenthsecond</li><li>formatdate_millisecond</li></ul> | Sets the timestamp format of logs. |
| module_name | no |  |  | Specifies the name of a module. The value is a module name in registration logs. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Determines whether the config should be present or not on the device. |
#### Examples

```

- name: CloudEngine info center log test
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

  - name: "Setting the timestamp format of logs"
    ce_info_center_log:
      log_time_stamp: date_tenthsecond
      provider: "{{ cli }}"

  - name: "Enabled to output information to the log buffer"
    ce_info_center_log:
      log_buff_enable: true
      provider: "{{ cli }}"

  - name: "Set the maximum number of logs in the log buffer"
    ce_info_center_log:
      log_buff_size: 100
      provider: "{{ cli }}"

  - name: "Set a rule for outputting logs to a channel"
    ce_info_center_log:
      module_name: aaa
      channel_id: 1
      log_enable: true
      log_level: critical
      provider: "{{ cli }}"

```

---

## ce_info_center_trap

Manages information center trap configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages information center trap configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| channel_id | no |  |  | Number of a channel. The value is an integer ranging from 0 to 9. The default value is 0. |
| module_name | no |  |  | Module name of the rule. The value is a string of 1 to 31 case-insensitive characters. The default value is default. Please use lower-case letter, such as [aaa, acl, arp, bfd]. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| trap_buff_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Whether a trap buffer is enabled to output information. |
| trap_buff_size | no |  |  | Size of a trap buffer. The value is an integer ranging from 0 to 1024. The default value is 256. |
| trap_enable | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | Whether a device is enabled to output alarms. |
| trap_level | no |  | <ul><li>emergencies</li><li>alert</li><li>critical</li><li>error</li><li>warning</li><li>notification</li><li>informational</li><li>debugging</li></ul> | Trap level permitted to output. |
| trap_time_stamp | no |  | <ul><li>date_boot</li><li>date_second</li><li>date_tenthsecond</li><li>date_millisecond</li><li>shortdate_second</li><li>shortdate_tenthsecond</li><li>shortdate_millisecond</li><li>formatdate_second</li><li>formatdate_tenthsecond</li><li>formatdate_millisecond</li></ul> | Timestamp format of alarm information. |
#### Examples

```

- name: CloudEngine info center trap test
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

  - name: "Config trap buffer"
    ce_info_center_trap:
      state:  present
      trap_buff_enable:  true
      trap_buff_size:  768
      provider: "{{ cli }}"

  - name: "Undo trap buffer"
    ce_info_center_trap:
      state:  absent
      trap_buff_enable:  true
      trap_buff_size:  768
      provider: "{{ cli }}"

  - name: "Config trap module log level"
    ce_info_center_trap:
      state:  present
      module_name:  aaa
      channel_id:  1
      trap_enable:  true
      trap_level:  error
      provider: "{{ cli }}"

  - name: "Undo trap module log level"
    ce_info_center_trap:
      state:  absent
      module_name:  aaa
      channel_id:  1
      trap_enable:  true
      trap_level:  error
      provider: "{{ cli }}"

```

---

## ce_interface

Manages physical attributes of interfaces.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages physical attributes of interfaces of Huawei CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| admin_state | no |  | <ul><li>up</li><li>down</li></ul> | Specifies the interface management status. The value is an enumerated type. up, An interface is in the administrative Up state. down, An interface is in the administrative Down state. |
| description | no |  |  | Specifies an interface description. The value is a string of 1 to 242 case-sensitive characters, spaces supported but question marks (?) not supported. |
| interface | no |  |  | Full name of interface, i.e. 40GE1/0/10, Tunnel1. |
| interface_type | no |  | <ul><li>ge</li><li>10ge</li><li>25ge</li><li>4x10ge</li><li>40ge</li><li>100ge</li><li>vlanif</li><li>loopback</li><li>meth</li><li>eth-trunk</li><li>nve</li><li>tunnel</li><li>ethernet</li><li>fcoe-port</li><li>fabric-port</li><li>stack-port</li><li>null</li></ul> | Interface type to be configured from the device. |
| l2sub | no |  |  | Specifies whether the interface is a Layer 2 sub-interface. |
| mode | no |  | <ul><li>layer2</li><li>layer3</li></ul> | Manage Layer 2 or Layer 3 state of the interface. |
| state | yes | present | <ul><li>present</li><li>absent</li><li>default</li></ul> | Specify desired state of the resource. |
#### Examples

```
- name: interface module test
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
  - name: Ensure an interface is a Layer 3 port and that it has the proper description
    ce_interface:
      interface: 10GE1/0/22
      description: 'Configured by Ansible'
      mode: layer3
      provider: '{{ cli }}'

  - name: Admin down an interface
    ce_interface:
      interface: 10GE1/0/22
      admin_state: down
      provider: '{{ cli }}'

  - name: Remove all tunnel interfaces
    ce_interface:
      interface_type: tunnel
      state: absent
      provider: '{{ cli }}'

  - name: Remove all logical interfaces
    ce_interface:
      interface_type: '{{ item }}'
      state: absent
      provider: '{{ cli }}'
    with_items:
      - loopback
      - eth-trunk
      - nve

  - name: Admin up all 10GE interfaces
    ce_interface:
      interface_type: 10GE
      admin_state: up
      provider: '{{ cli }}'

```

#### Notes

- This module is also used to create logical interfaces such as vlanif and loopbacks.
 

---

## ce_interface_ospf

Manages configuration of an OSPF interface instance.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages configuration of an OSPF interface instance.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| area | yes |  |  | Ospf area associated with this ospf process. Valid values are a string, formatted as an IP address (i.e. "0.0.0.0") or as an integer between 1 and 4294967295. |
| auth_key_id | no |  |  | Authentication key id when C(auth_mode) is 'hmac-sha256', 'md5' or 'hmac-md5. Valid value is an integer is in the range from 1 to 255. |
| auth_mode | no |  | <ul><li>none</li><li>null</li><li>hmac-sha256</li><li>md5</li><li>hmac-md5</li><li>simple</li></ul> | Specifies the authentication type. |
| auth_text_md5 | no |  |  | Specifies a password for MD5, HMAC-MD5, or HMAC-SHA256 authentication. The value is a string of 1 to 255 case-sensitive characters, spaces not supported. |
| auth_text_simple | no |  |  | Specifies a password for simple authentication. The value is a string of 1 to 8 characters. |
| cost | no |  |  | The cost associated with this interface. Valid values are an integer in the range from 1 to 65535. |
| dead_interval | no |  |  | Time interval an ospf neighbor waits for a hello packet before tearing down adjacencies. Valid values are an integer in the range from 1 to 235926000. |
| hello_interval | no |  |  | Time between sending successive hello packets. Valid values are an integer in the range from 1 to 65535. |
| interface | yes |  |  | Full name of interface, i.e. 40GE1/0/10. |
| process_id | yes |  |  | Specifies a process ID. The value is an integer ranging from 1 to 4294967295. |
| silent_interface | no |  |  | Setting to true will prevent this interface from receiving HELLO packets. Valid values are 'true' and 'false'. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Determines whether the config should be present or not on the device. |
#### Examples

```
- name: eth_trunk module test
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
  - name: Enables OSPF and sets the cost on an interface
    ce_interface_ospf:
      interface: 10GE1/0/30
      process_id: 1
      area: 100
      cost: 100
      provider: '{{ cli }}'

  - name: Sets the dead interval of the OSPF neighbor
    ce_interface_ospf:
      interface: 10GE1/0/30
      process_id: 1
      area: 100
      dead_interval: 100
      provider: '{{ cli }}'

  - name: Sets the interval for sending Hello packets on an interface
    ce_interface_ospf:
      interface: 10GE1/0/30
      process_id: 1
      area: 100
      hello_interval: 2
      provider: '{{ cli }}'

  - name: Disables an interface from receiving and sending OSPF packets
    ce_interface_ospf:
      interface: 10GE1/0/30
      process_id: 1
      area: 100
      silent_interface: true
      provider: '{{ cli }}'

```

---

## ce_ip_interface

Manages L3 attributes for IPv4 and IPv6 interfaces.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages Layer 3 attributes for IPv4 and IPv6 interfaces.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| addr | no |  |  | IPv4 or IPv6 Address. |
| interface | yes |  |  | Full name of interface, i.e. 40GE1/0/22, vlanif10. |
| ipv4_type | no | main | <ul><li>main</li><li>sub</li></ul> | Specifies an address type. The value is an enumerated type. main, primary IP address. sub, secondary IP address. |
| mask | no |  |  | Subnet mask for IPv4 or IPv6 Address in decimal format. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| version | no | v4 | <ul><li>v4</li><li>v6</li></ul> | IP address version. |
#### Examples

```
- name: ip_interface module test
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
  - name: Ensure ipv4 address is configured on 10GE1/0/22
    ce_ip_interface:
      interface: 10GE1/0/22
      version: v4
      state: present
      addr: 20.20.20.20
      mask: 24
      provider: '{{ cli }}'

  - name: Ensure ipv4 secondary address is configured on 10GE1/0/22
    ce_ip_interface:
      interface: 10GE1/0/22
      version: v4
      state: present
      addr: 30.30.30.30
      mask: 24
      ipv4_type: sub
      provider: '{{ cli }}'

  - name: Ensure ipv6 is enabled on 10GE1/0/22
    ce_ip_interface:
      interface: 10GE1/0/22
      version: v6
      state: present
      provider: '{{ cli }}'

  - name: Ensure ipv6 address is configured on 10GE1/0/22
    ce_ip_interface:
      interface: 10GE1/0/22
      version: v6
      state: present
      addr: 2001::db8:800:200c:cccb
      mask: 64
      provider: '{{ cli }}'

```

#### Notes

- Interface must already be a L3 port when using this module.
- Logical interfaces (loopback, vlanif) must be created first.
- C(mask) must be inserted in decimal format (i.e. 24) for both IPv6 and IPv4.
- A single interface can have multiple IPv6 configured.
 

---

## ce_link_status

Get interface link status.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Get interface link status.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| interface | yes |  |  | For the interface parameter, you can enter "all" to display information about all interface, an interface type such as 40GE to display information about interfaces of the specified type, or full name of an interface such as 40GE1/0/22 or vlanif10 to display information about the specific interface. |
#### Examples

```

- name: Link status test
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

  - name: Get specified interface link status information
    ce_link_status:
      interface: 40GE1/0/1
      provider: "{{ cli }}"

  - name: Get specified interface type link status information
    ce_link_status:
      interface: 40GE
      provider: "{{ cli }}"

  - name: Get all interface link status information
    ce_link_status:
      interface: all
      provider: "{{ cli }}"

```

#### Notes

- Current physical state shows an interface's physical status.
- Current link state shows an interface's link layer protocol status.
- Current IPv4 state shows an interface's IPv4 protocol status.
- Current IPv6 state shows an interface's  IPv6 protocol status.
- Inbound octets(bytes) shows the number of bytes that an interface received.
- Inbound unicast(pkts) shows the number of unicast packets that an interface received.
- Inbound multicast(pkts) shows the number of multicast packets that an interface received.
- Inbound broadcast(pkts) shows  the number of broadcast packets that an interface received.
- Inbound error(pkts) shows the number of error packets that an interface received.
- Inbound drop(pkts) shows the total number of packets that were sent to the interface but dropped by an interface.
- Inbound rate(byte/sec) shows the rate at which an interface receives bytes within an interval.
- Inbound rate(pkts/sec) shows the rate at which an interface receives packets within an interval.
- Outbound octets(bytes) shows the number of the bytes that an interface sent.
- Outbound unicast(pkts) shows  the number of unicast packets that an interface sent.
- Outbound multicast(pkts) shows the number of multicast packets that an interface sent.
- Outbound broadcast(pkts) shows the number of broadcast packets that an interface sent.
- Outbound error(pkts) shows the total number of packets that an interface sent but dropped by the remote interface.
- Outbound drop(pkts) shows the number of dropped packets that an interface sent.
- Outbound rate(byte/sec) shows the rate at which an interface sends bytes within an interval.
- Outbound rate(pkts/sec) shows the rate at which an interface sends packets within an interval.
- Speed shows the rate for an Ethernet interface.
 

---

## ce_mlag_config

Manages MLAG configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages MLAG configuration on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| dfs_group_id | no | present |  | ID of a DFS group. The value is 1. |
| eth_trunk_id | no |  |  | Name of the peer-link interface. The value is in the range from 0 to 511. |
| ip_address | no |  |  | IP address bound to the DFS group. The value is in dotted decimal notation. |
| nickname | no |  |  | The nickname bound to a DFS group. The value is an integer that ranges from 1 to 65471. |
| peer_link_id | no |  |  | Number of the peer-link interface.The value is 1. |
| priority_id | no |  |  | Priority of a DFS group. The value is an integer that ranges from 1 to 254. The default value is 100. |
| pseudo_nickname | no |  |  | A pseudo nickname of a DFS group. The value is an integer that ranges from 1 to 65471. |
| pseudo_priority | no |  |  | The priority of a pseudo nickname. The value is an integer that ranges from 128 to 255. The default value is 192. A larger value indicates a higher priority. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| vpn_instance_name | no |  |  | Name of the VPN instance bound to the DFS group. The value is a string of 1 to 31 case-sensitive characters without spaces. If the character string is quoted by double quotation marks, the character string can contain spaces. The value _public_ is reserved and cannot be used as the VPN instance name. |
#### Examples

```
- name: mlag config module test
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

  - name: Create DFS Group id
    ce_mlag_config:
      dfs_group_id: 1
      provider: "{{ cli }}"
  - name: Set dfs-group priority
    ce_mlag_config:
      dfs_group_id: 1
      priority_id: 3
      state: present
      provider: "{{ cli }}"
  - name: Set pseudo nickname
    ce_mlag_config:
      dfs_group_id: 1
      pseudo_nickname: 3
      pseudo_priority: 130
      state: present
      provider: "{{ cli }}"
  - name: Set ip
    ce_mlag_config:
      dfs_group_id: 1
      ip_address: 11.1.1.2
      vpn_instance_name: 6
      provider: "{{ cli }}"
  - name: Set peer link
    ce_mlag_config:
      eth_trunk_id: 3
      peer_link_id: 2
      state: present
      provider: "{{ cli }}"

```

---

## ce_mlag_interface

Manages MLAG interfaces.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages MLAG interface attributes on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| dfs_group_id | no | present |  | ID of a DFS group.The value is 1. |
| eth_trunk_id | no |  |  | Name of the local M-LAG interface. The value is ranging from 0 to 511. |
| interface | no |  |  | Name of the interface that enters the Error-Down state when the peer-link fails. The value is a string of 1 to 63 characters. |
| mlag_error_down | no |  | <ul><li>enable</li><li>disable</li></ul> | Configure the interface on the slave device to enter the Error-Down state. |
| mlag_id | no |  |  | ID of the M-LAG. The value is an integer that ranges from 1 to 2048. |
| mlag_priority_id | no |  |  | M-LAG global LACP system priority. The value is an integer ranging from 0 to 65535. The default value is 32768. |
| mlag_system_id | no |  |  | M-LAG global LACP system MAC address. The value is a string of 0 to 255 characters. The default value is the MAC address of the Ethernet port of MPU. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
#### Examples

```
- name: mlag interface module test
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

  - name: Set interface mlag error down
    ce_mlag_interface:
      interface: 10GE2/0/1
      mlag_error_down: enable
      provider: "{{ cli }}"
  - name: Create mlag
    ce_mlag_interface:
      eth_trunk_id: 1
      dfs_group_id: 1
      mlag_id: 4
      provider: "{{ cli }}"
  - name: Set mlag global attribute
    ce_mlag_interface:
      mlag_system_id: 0020-1409-0407
      mlag_priority_id: 5
      provider: "{{ cli }}"
  - name: Set mlag interface attribute
    ce_mlag_interface:
      eth_trunk_id: 1
      mlag_system_id: 0020-1409-0400
      mlag_priority_id: 3
      provider: "{{ cli }}"

```

---

## ce_mtu

Manages MTU settings on CloudEngine switch.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages MTU settings on CloudEngine switch.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| interface | no |  |  | Full name of interface, i.e. 40GE1/0/22. |
| jumbo_max | no |  |  | Maximum frame size. The default value is 9216. The value is an integer and expressed in bytes. The value range is 1536 to 12224 for the CE12800 and 1536 to 12288 for ToR switches. |
| jumbo_min | no |  |  | Non-jumbo frame size threshod. The default value is 1518. The value is an integer that ranges from 1518 to jumbo_max, in bytes. |
| mtu | no |  |  | MTU for a specific interface. The value is an integer ranging from 46 to 9600, in bytes. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
#### Examples

```
- name: Mtu test
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

  - name: "Config jumboframe on 40GE1/0/22"
    ce_mtu:
      interface: 40GE1/0/22
      jumbo_max: 9000
      jumbo_min: 8000
      provider: "{{ cli }}"

  - name: "Config mtu on 40GE1/0/22 (routed interface)"
    ce_mtu:
      interface: 40GE1/0/22
      mtu: 1600
      provider: "{{ cli }}"

  - name: "Config mtu on 40GE1/0/23 (switched interface)"
    ce_mtu:
      interface: 40GE1/0/22
      mtu: 9216
      provider: "{{ cli }}"

  - name: "Config mtu and jumboframe on 40GE1/0/22 (routed interface)"
    ce_mtu:
      interface: 40GE1/0/22
      mtu: 1601
      jumbo_max: 9001
      jumbo_min: 8001
      provider: "{{ cli }}"

  - name: "Unconfigure mtu and jumboframe on a given interface"
    ce_mtu:
      state: absent
      interface: 40GE1/0/22
      provider: "{{ cli }}"

```

#### Notes

- Either C(sysmtu) param is required or C(interface) AND C(mtu) params are req'd.
- C(state=absent) unconfigures a given MTU if that value is currently present.
 

---

## ce_netconf

Run arbitrary netconf command on cloudengine devices.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Sends an arbitrary netconf command to a cloudengine node and returns the results read from the device.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| cfg_xml | yes |  |  | The config xml string. |
| rpc | no |  | <ul><li>get</li><li>edit-config</li><li>execute-action</li><li>execute-cli</li></ul> | The type of rpc. |
#### Examples

```

- name: CloudEngine netconf test
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

  - name: "Netconf get operation"
    ce_netconf:
      rpc: get
      cfg_xml: '<filter type="subtree">
                  <vlan xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
                    <vlans>
                      <vlan>
                        <vlanId>10</vlanId>
                        <vlanif>
                          <ifName></ifName>
                          <cfgBand></cfgBand>
                          <dampTime></dampTime>
                        </vlanif>
                      </vlan>
                    </vlans>
                  </vlan>
                </filter>'
      provider: "{{ cli }}"

  - name: "Netconf edit-config operation"
    ce_netconf:
      rpc: edit-config
      cfg_xml: '<config>
                    <aaa xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
                      <authenticationSchemes>
                        <authenticationScheme operation="create">
                          <authenSchemeName>default_wdz</authenSchemeName>
                          <firstAuthenMode>local</firstAuthenMode>
                          <secondAuthenMode>invalid</secondAuthenMode>
                        </authenticationScheme>
                      </authenticationSchemes>
                    </aaa>
                   </config>'
      provider: "{{ cli }}"

  - name: "Netconf execute-action operation"
    ce_netconf:
      rpc: execute-action
      cfg_xml: '<action>
                     <l2mc xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
                       <l2McResetAllVlanStatis>
                         <addrFamily>ipv4unicast</addrFamily>
                       </l2McResetAllVlanStatis>
                     </l2mc>
                   </action>'
      provider: "{{ cli }}"

```

#### Notes

- The rpc parameter is always required.
 

---

## ce_netstream_aging

Manages timeout mode of NetStream.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages timeout mode of NetStream.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| manual_slot | no |  |  | Specifies the slot number of netstream manual timeout. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| timeout_interval | no | 30 |  | Netstream timeout interval. If is active type the interval is 1-60. If is inactive ,the interval is 5-600. |
| timeout_type | no |  | <ul><li>active</li><li>inactive</li><li>tcp-session</li><li>manual</li></ul> | Netstream timeout type. |
| type | no |  | <ul><li>ip</li><li>vxlan</li></ul> | Specifies the packet type of netstream timeout active interval. |
#### Examples

```
- name: netstream aging module test
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

  - name: Configure netstream ip timeout active interval , the interval is 40 minutes.
    ce_netstream_aging:
      timeout_interval: 40
      type: ip
      timeout_type: active
      state: present
      provider: "{{ cli }}"

  - name: Configure netstream vxlan timeout active interval , the interval is 40 minutes.
    ce_netstream_aging:
      timeout_interval: 40
      type: vxlan
      timeout_type: active
      active_state: present
      provider: "{{ cli }}"

  - name: Delete netstream ip timeout active interval , set the ip timeout interval to 30 minutes.
    ce_netstream_aging:
      type: ip
      timeout_type: active
      state: absent
      provider: "{{ cli }}"

  - name: Delete netstream vxlan timeout active interval , set the vxlan timeout interval to 30 minutes.
    ce_netstream_aging:
      type: vxlan
      timeout_type: active
      state: absent
      provider: "{{ cli }}"

  - name: Enable netstream ip tcp session timeout.
    ce_netstream_aging:
      type: ip
      timeout_type: tcp-session
      state: present
      provider: "{{ cli }}"

  - name: Enable netstream vxlan tcp session timeout.
    ce_netstream_aging:
      type: vxlan
      timeout_type: tcp-session
      state: present
      provider: "{{ cli }}"

  - name: Disable netstream ip tcp session timeout.
    ce_netstream_aging:
      type: ip
      timeout_type: tcp-session
      state: absent
      provider: "{{ cli }}"

  - name: Disable netstream vxlan tcp session timeout.
    ce_netstream_aging:
      type: vxlan
      timeout_type: tcp-session
      state: absent
      provider: "{{ cli }}"

```

---

## ce_netstream_export

Manages netstream export.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Configure NetStream flow statistics exporting and versions for exported packets.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| as_option | no |  | <ul><li>origin</li><li>peer</li></ul> | Specifies the AS number recorded in the statistics as the original or the peer AS number. |
| bgp_nexthop | no | disable | <ul><li>enable</li><li>disable</li></ul> | Configures the statistics to carry BGP next hop information. Currently, only V9 supports the exported packets carrying BGP next hop information. |
| host_ip | no |  |  | Specifies destination address which can be IPv6 or IPv4 of the exported NetStream packet. |
| host_port | no |  |  | Specifies the destination UDP port number of the exported packets. The value is an integer that ranges from 1 to 65535. |
| host_vpn | no |  |  | Specifies the VPN instance of the exported packets carrying flow statistics. Ensure the VPN instance has been created on the device. |
| source_ip | no |  |  | Specifies source address which can be IPv6 or IPv4 of the exported NetStream packet. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
| type | yes |  | <ul><li>ip</li><li>vxlan</li></ul> | Specifies NetStream feature. |
| version | no |  | <ul><li>5</li><li>9</li></ul> | Sets the version of exported packets. |
#### Examples

```
- name: netstream export module test
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

  - name: Configures the source address for the exported packets carrying IPv4 flow statistics.
    ce_netstream_export:
      type: ip
      source_ip: 192.8.2.2
      provider: "{{ cli }}"

  - name: Configures the source IP address for the exported packets carrying VXLAN flexible flow statistics.
    ce_netstream_export:
      type: vxlan
      source_ip: 192.8.2.3
      provider: "{{ cli }}"

  - name: Configures the destination IP address and destination UDP port number for the exported packets carrying IPv4 flow statistics.
    ce_netstream_export:
      type: ip
      host_ip: 192.8.2.4
      host_port: 25
      host_vpn: test
      provider: "{{ cli }}"

  - name: Configures the destination IP address and destination UDP port number for the exported packets carrying VXLAN flexible flow statistics.
    ce_netstream_export:
      type: vxlan
      host_ip: 192.8.2.5
      host_port: 26
      host_vpn: test
      provider: "{{ cli }}"

  - name: Configures the version number of the exported packets carrying IPv4 flow statistics.
    ce_netstream_export:
      type: ip
      version: 9
      as_option: origin
      bgp_nexthop: enable
      provider: "{{ cli }}"

  - name: Configures the version for the exported packets carrying VXLAN flexible flow statistics.
    ce_netstream_export:
      type: vxlan
      version: 9
      provider: "{{ cli }}"

```

---

## ce_netstream_global

Manages global parameters of NetStream.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages global parameters of NetStream.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| index_switch | no | 16 | <ul><li>16</li><li>32</li></ul> | Specifies the netstream index-switch. |
| interface | yes |  |  | Netstream global interface. |
| sampler_direction | no |  | <ul><li>inbound</li><li>outbound</li></ul> | Specifies the netstream sampler direction. |
| sampler_interval | no |  |  | Specifies the netstream sampler interval, length is 1 - 65535. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| statistics_direction | no |  | <ul><li>inbound</li><li>outbound</li></ul> | Specifies the netstream statistic direction. |
| statistics_record | no |  |  | Specifies the flexible netstream statistic record, length is 1 - 32. |
| type | no | ip | <ul><li>ip</li><li>vxlan</li></ul> | Specifies the type of netstream global. |
#### Examples

```
- name: netstream global module test
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

  - name: Configure a netstream sampler at interface 10ge1/0/2, direction is outbound,interval is 30.
    ce_netstream_global:
      interface: 10ge1/0/2
      type: ip
      sampler_interval: 30
      sampler_direction: outbound
      state: present
      provider: "{{ cli }}"
  - name: Configure a netstream flexible statistic at interface 10ge1/0/2, record is test1, type is ip.
    ce_netstream_global:
      type: ip
      interface: 10ge1/0/2
      statistics_record: test1
      provider: "{{ cli }}"
  - name: Set the vxlan index-switch to 32.
    ce_netstream_global:
      type: vxlan
      interface: all
      index_switch: 32
      provider: "{{ cli }}"

```

---

## ce_netstream_template

Manages NetStream template configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages NetStream template configuration on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| collect_counter | no |  | <ul><li>bytes</li><li>packets</li></ul> | Configure the number of packets and bytes that are included in the flexible flow statistics sent to NSC. |
| collect_interface | no |  | <ul><li>input</li><li>output</li></ul> | Configure the input or output interface that are included in the flexible flow statistics sent to NSC. |
| description | no |  |  | Configure the description of netstream record. The value is a string of 1 to 80 case-insensitive characters. |
| match | no |  | <ul><li>destination-address</li><li>destination-port</li><li>tos</li><li>protocol</li><li>source-address</li><li>source-port</li></ul> | Configure flexible flow statistics template keywords. |
| record_name | no |  |  | Configure the name of netstream record. The value is a string of 1 to 32 case-insensitive characters. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| type | yes |  | <ul><li>ip</li><li>vxlan</li></ul> | Configure the type of netstream record. |
#### Examples

```
- name: netstream template module test
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

  - name: Config ipv4 netstream record
    ce_netstream_template:
      state:  present
      type:  ip
      record_name:  test
      provider: "{{ cli }}"
  - name: Undo ipv4 netstream record
    ce_netstream_template:
      state:  absent
      type:  ip
      record_name:  test
      provider: "{{ cli }}"
  - name: Config ipv4 netstream record collect_counter
    ce_netstream_template:
      state:  present
      type:  ip
      record_name:  test
      collect_counter:  bytes
      provider: "{{ cli }}"
  - name: Undo ipv4 netstream record collect_counter
    ce_netstream_template:
      state:  absent
      type:  ip
      record_name:  test
      collect_counter:  bytes
      provider: "{{ cli }}"

```

---

## ce_ntp

Manages core NTP configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages core NTP configuration.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| is_preferred | no |  | <ul><li>enable</li><li>disable</li></ul> | Makes given NTP server or peer the preferred NTP server or peer for the device. |
| key_id | no |  |  | Authentication key identifier to use with given NTP server or peer. |
| peer | no |  |  | Network address of NTP peer. |
| server | no |  |  | Network address of NTP server. |
| source_int | no |  |  | Local source interface from which NTP messages are sent. Must be fully qualified interface name, i.e. 40GE1/0/22, vlanif10. Interface types, such as 10GE, 40GE, 100GE, Eth-Trunk, LoopBack, MEth, NULL, Tunnel, Vlanif... |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
| vpn_name | no | _public_ |  | Makes the device communicate with the given NTP server or peer over a specific vpn. |
#### Examples

```
- name: NTP test
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

  - name: "Set NTP Server with parameters"
    ce_ntp:
      server: 192.8.2.6
      vpn_name: js
      source_int: vlanif4001
      is_preferred: enable
      key_id: 32
      provider: "{{ cli }}"

  - name: "Set NTP Peer with parameters"
    ce_ntp:
      peer: 192.8.2.6
      vpn_name: js
      source_int: vlanif4001
      is_preferred: enable
      key_id: 32
      provider: "{{ cli }}"

```

---

## ce_ntp_auth

Manages NTP authentication configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages NTP authentication configuration.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| auth_mode | no |  | <ul><li>hmac-sha256</li><li>md5</li></ul> | Specify authentication algorithm md5 or hmac-sha256. |
| auth_pwd | no |  |  | Plain text with length of 1 to 255, encrypted text with length of 20 to 392. |
| auth_type | no | encrypt | <ul><li>text</li><li>encrypt</li></ul> | Whether the given password is in cleartext or has been encrypted. If in cleartext, the device will encrypt it before storing it. |
| authentication | no |  | <ul><li>enable</li><li>disable</li></ul> | Configure ntp authentication enable or unconfigure ntp authentication enable. |
| key_id | yes |  |  | Authentication key identifier (numeric). |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
| trusted_key | no | disable | <ul><li>enable</li><li>disable</li></ul> | Whether the given key is required to be supplied by a time source for the device to synchronize to the time source. |
#### Examples

```
- name: NTP AUTH test
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

  - name: "Configure ntp authentication key-id"
    ce_ntp_auth:
      key_id: 32
      auth_mode: md5
      auth_pwd: 11111111111111111111111
      provider: "{{ cli }}"

  - name: "Configure ntp authentication key-id and trusted authentication keyid"
    ce_ntp_auth:
      key_id: 32
      auth_mode: md5
      auth_pwd: 11111111111111111111111
      trusted_key: enable
      provider: "{{ cli }}"

  - name: "Configure ntp authentication key-id and authentication enable"
    ce_ntp_auth:
      key_id: 32
      auth_mode: md5
      auth_pwd: 11111111111111111111111
      authentication: enable
      provider: "{{ cli }}"

  - name: "Unconfigure ntp authentication key-id and trusted authentication keyid"
    ce_ntp_auth:
      key_id: 32
      state: absent
      provider: "{{ cli }}"

  - name: "Unconfigure ntp authentication key-id and authentication enable"
    ce_ntp_auth:
      key_id: 32
      authentication: enable
      state: absent
      provider: "{{ cli }}"

```

#### Notes

- If C(state=absent), the module will attempt to remove the given key configuration. If a matching key configuration isn't found on the device, the module will fail.
- If C(state=absent) and C(authentication=on), authentication will be turned on.
- If C(state=absent) and C(authentication=off), authentication will be turned off.
 

---

## ce_ospf

Manages configuration of an OSPF instance.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages configuration of an OSPF instance.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| addr | no |  |  | Specifies the address of the network segment where the interface resides. The value is in dotted decimal notation. |
| area | no |  |  | Specifies the area ID. The area with the area-id being 0 is a backbone area. Valid values are a string, formatted as an IP address (i.e. "0.0.0.0") or as an integer between 1 and 4294967295. |
| auth_key_id | no |  |  | Authentication key id when C(auth_mode) is 'hmac-sha256', 'md5' or 'hmac-md5. Valid value is an integer is in the range from 1 to 255. |
| auth_mode | no |  | <ul><li>none</li><li>hmac-sha256</li><li>md5</li><li>hmac-md5</li><li>simple</li></ul> | Specifies the authentication type. |
| auth_text_md5 | no |  |  | Specifies a password for MD5, HMAC-MD5, or HMAC-SHA256 authentication. The value is a string of 1 to 255 case-sensitive characters, spaces not supported. |
| auth_text_simple | no |  |  | Specifies a password for simple authentication. The value is a string of 1 to 8 characters. |
| mask | no |  |  | IP network wildcard bits in decimal format between 0 and 32. |
| max_load_balance | no |  |  | The maximum number of paths for forward packets over multiple paths. Valid value is an integer in the range from 1 to 64. |
| nexthop_addr | no |  |  | IPv4 address for configure next-hop address's weight. Valid values are a string, formatted as an IP address. |
| nexthop_weight | no |  |  | Indicates the weight of the next hop. The smaller the value is, the higher the preference of the route is. It is an integer that ranges from 1 to 254. |
| process_id | yes |  |  | Specifies a process ID. The value is an integer ranging from 1 to 4294967295. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Determines whether the config should be present or not on the device. |
#### Examples

```
- name: ospf module test
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

  - name: Configure ospf
    ce_ospf:
      process_id: 1
      area: 100
      state: present
      provider: "{{ cli }}"

```

---

## ce_ospf_vrf

Manages configuration of an OSPF VPN instance.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages configuration of an OSPF VPN instance.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| bandwidth | no |  |  | Specifies the reference bandwidth used to assign ospf cost. Valid values are an integer, in Mbps, 1 - 2147483648, the default value is 100. |
| description | no |  |  | Specifies the description information of ospf process. |
| lsaaholdinterval | no |  |  | Specifies the hold interval of arrive LSA when use the intelligent timer. Valid value is an integer, in millisecond, from 0 to 10000, the default value is 500. |
| lsaainterval | no |  |  | Specifies the interval of arrive LSA when use the general timer. Valid value is an integer, in millisecond, from 0 to 10000. |
| lsaalflag | no |  |  | Specifies the mode of timer to calculate interval of arrive LSA. If set the parameter but not specifies value,the default will be used. If true use general timer. If false use intelligent timer. |
| lsaamaxinterval | no |  |  | Specifies the max interval of arrive LSA when use the intelligent timer. Valid value is an integer, in millisecond, from 0 to 10000, the default value is 1000. |
| lsaastartinterval | no |  |  | Specifies the start interval of arrive LSA when use the intelligent timer. Valid value is an integer, in millisecond, from 0 to 10000, the default value is 500. |
| lsaoholdinterval | no |  |  | Specifies the hold interval of originate LSA . Valid value is an integer, in millisecond, from 0 to 5000, the default value is 1000. |
| lsaointerval | no |  |  | Specifies the interval of originate LSA . Valid value is an integer, in second, from 0 to 10, the default value is 5. |
| lsaointervalflag | no |  |  | Specifies whether cancel the interval of LSA originate or not. If set the parameter but noe specifies value ,the default will be used. true:cancel the interval of LSA originate,the interval is 0. false:do not cancel the interval of LSA originate. |
| lsaomaxinterval | no |  |  | Specifies the max interval of originate LSA . Valid value is an integer, in millisecond, from 1 to 10000, the default value is 5000. |
| lsaostartinterval | no |  |  | Specifies the start interval of originate LSA . Valid value is an integer, in millisecond, from 0 to 1000, the default value is 500. |
| ospf | yes |  |  | The ID of the ospf process. Valid values are an integer, 1 - 4294967295, the default value is 1. |
| route_id | no |  |  | Specifies the ospf private route id,. Valid values are a string, formatted as an IP address (i.e. "10.1.1.1") the length is 0 - 20. |
| spfholdinterval | no |  |  | Specifies the hold interval to calculate SPF when use intelligent timer. Valid value is an integer, in millisecond, from 1 to 5000, the default value is 200. |
| spfinterval | no |  |  | Specifies the interval to calculate SPF when use second level  timer. Valid value is an integer, in second, from 1 to 10. |
| spfintervalmi | no |  |  | Specifies the interval to calculate SPF when use millisecond level  timer. Valid value is an integer, in millisecond, from 1 to 10000. |
| spfintervaltype | no | intelligent-timer | <ul><li>intelligent-timer</li><li>timer</li><li>millisecond</li></ul> | Specifies the mode of timer which used to calculate SPF. If set the parameter but noe specifies value, the default will be used. If is intelligent-timer, then use intelligent timer. If is timer, then use second level timer. If is millisecond, then use millisecond level timer. |
| spfmaxinterval | no |  |  | Specifies the max interval to calculate SPF when use intelligent timer. Valid value is an integer, in millisecond, from 1 to 20000, the default value is 5000. |
| spfstartinterval | no |  |  | Specifies the start interval to calculate SPF when use intelligent timer. Valid value is an integer, in millisecond, from 1 to 1000, the default value is 50. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| vrf | no | _public_ |  | Specifies the vpn instance which use ospf,length is 1 - 31. Valid values are a string. |
#### Examples

```
- name: ospf vrf module test
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

  - name: Configure ospf route id
    ce_ospf_vrf:
      ospf: 2
      route_id: 2.2.2.2
      lsaointervalflag: False
      lsaointerval: 2
      provider: "{{ cli }}"

```

---

## ce_reboot

Reboot a network device.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Reboot a network device.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| confirm | yes |  |  | Safeguard boolean. Set to true if you're sure you want to reboot. |
| save_config | no |  |  | Flag indicating whether to save the configuration. |
#### Examples

```
- name: reboot module test
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
  - name: Reboot the device
    ce_reboot:
      confirm: true
      save_config: true
      provider: "{{ cli }}"

```

---

## ce_rollback

Set a checkpoint or rollback to a checkpoint.

  * Synopsis
  * Options
  * Examples

#### Synopsis

This module offers the ability to set a configuration checkpoint file or rollback to a configuration checkpoint file on CloudEngine switch.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| action | yes |  | <ul><li>rollback</li><li>clear</li><li>set</li><li>display</li><li>commit</li></ul> | The operation of configuration rollback. |
| commit_id | no |  |  | Specifies the label of the configuration rollback point to which system configurations are expected to roll back. The value is an integer that the system generates automatically. |
| filename | no |  |  | Specifies a configuration file for configuration rollback. The value is a string of 5 to 64 case-sensitive characters in the format of *.zip, *.cfg, or *.dat, spaces not supported. |
| label | no |  |  | Specifies a user label for a configuration rollback point. The value is a string of 1 to 256 case-sensitive ASCII characters, spaces not supported. The value must start with a letter and cannot be presented in a single hyphen (-). |
| last | no |  |  | Specifies the number of configuration rollback points. The value is an integer that ranges from 1 to 80. |
| oldest | no |  |  | Specifies the number of configuration rollback points. The value is an integer that ranges from 1 to 80. |
#### Examples

```
- name: rollback module test
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

- name: Ensure commit_id is exist, and specifies the label of the configuration rollback point to
        which system configurations are expected to roll back.
  ce_rollback:
    commit_id: 1000000748
    action: rollback
    provider: "{{ cli }}"

```

---

## ce_sflow

Manages sFlow configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Configure Sampled Flow (sFlow) to monitor traffic on an interface in real time, detect abnormal traffic, and locate the source of attack traffic, ensuring stable running of the network.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| agent_ip | no |  |  | Specifies the IPv4/IPv6 address of an sFlow agent. |
| collector_datagram_size | no |  |  | Specifies the maximum length of sFlow packets sent from an sFlow agent to an sFlow collector. The value is an integer, in bytes. It ranges from 1024 to 8100. The default value is 1400. |
| collector_description | no |  |  | Specifies the description of an sFlow collector. The value is a string of 1 to 255 case-sensitive characters without spaces. |
| collector_id | no |  | <ul><li>1</li><li>2</li></ul> | Specifies the ID of an sFlow collector. This ID is used when you specify the collector in subsequent sFlow configuration. The value is an integer that can be 1 or 2. |
| collector_ip | no |  |  | Specifies the IPv4/IPv6 address of the sFlow collector. |
| collector_ip_vpn | no |  |  | Specifies the name of a VPN instance. The value is a string of 1 to 31 case-sensitive characters, spaces not supported. When double quotation marks are used around the string, spaces are allowed in the string. The value _public_ is reserved and cannot be used as the VPN instance name. |
| collector_meth | no |  | <ul><li>meth</li><li>enhanced</li></ul> | Configures the device to send sFlow packets through service interfaces, enhancing the sFlow packet forwarding capability. The enhanced parameter is optional. No matter whether you configure the enhanced mode, the switch determines to send sFlow packets through service cards or management port based on the routing information on the collector. When the value is meth, the device forwards sFlow packets at the control plane. When the value is enhanced, the device forwards sFlow packets at the forwarding plane to enhance the sFlow packet forwarding capacity. |
| collector_udp_port | no |  |  | Specifies the UDP destination port number of sFlow packets. The value is an integer that ranges from 1 to 65535. The default value is 6343. |
| counter_collector | no |  |  | Indicates the ID list of the counter collector. |
| counter_interval | no |  |  | Indicates the the counter sampling interval. The value is an integer that ranges from 10 to 4294967295, in seconds. The default value is 20. |
| export_route | no |  | <ul><li>enable</li><li>disable</li></ul> | Configures the sFlow packets sent by the switch not to carry routing information. |
| forward_enp_slot | no |  |  | Enable the Embedded Network Processor (ENP) chip function. The switch uses the ENP chip to perform sFlow sampling, and the maximum sFlow sampling interval is 65535. If you set the sampling interval to be larger than 65535, the switch automatically restores it to 65535. The value is an integer or 'all'. |
| rate_limit | no |  |  | Specifies the rate of sFlow packets sent from a card to the control plane. The value is an integer that ranges from 100 to 1500, in pps. |
| rate_limit_slot | no |  |  | Specifies the slot where the rate of output sFlow packets is limited. If this parameter is not specified, the rate of sFlow packets sent from all cards to the control plane is limited. The value is an integer or a string of characters. |
| sample_collector | no |  |  | Indicates the ID list of the collector. |
| sample_direction | no |  | <ul><li>inbound</li><li>outbound</li><li>both</li></ul> | Enables flow sampling in the inbound or outbound direction. |
| sample_length | no |  |  | Specifies the maximum length of sampled packets. The value is an integer and ranges from 18 to 512, in bytes. The default value is 128. |
| sample_rate | no |  |  | Specifies the flow sampling rate in the format 1/rate. The value is an integer and ranges from 1 to 4294967295. The default value is 8192. |
| sflow_interface | no |  |  | Full name of interface for Flow Sampling or Counter. It must be a physical interface, Eth-Trunk, or Layer 2 subinterface. |
| source_ip | no |  |  | Specifies the source IPv4/IPv6 address of sFlow packets. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Determines whether the config should be present or not on the device. |
#### Examples

```
---

- name: sflow module test
  hosts: ce128
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
  - name: Configuring sFlow Agent
    ce_sflow:
      agent_ip: 6.6.6.6
      provider: '{{ cli }}'

  - name: Configuring sFlow Collector
    ce_sflow:
      collector_id: 1
      collector_ip: 7.7.7.7
      collector_ip_vpn: vpn1
      collector_description: Collector1
      provider: '{{ cli }}'

  - name: Configure flow sampling.
    ce_sflow:
      sflow_interface: 10GE2/0/2
      sample_collector: 1
      sample_direction: inbound
      provider: '{{ cli }}'

  - name: Configure counter sampling.
    ce_sflow:
      sflow_interface: 10GE2/0/2
      counter_collector: 1
      counter_interval: 1000
      provider: '{{ cli }}'

```

---

## ce_snmp_community

Manages SNMP community configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages SNMP community configuration on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| access_right | no |  | <ul><li>read</li><li>write</li></ul> | Access right read or write. |
| acl_number | no |  |  | Access control list number. |
| community_mib_view | no |  |  | Mib view name. |
| community_name | no |  |  | Unique name to identify the community. |
| group_name | no |  |  | Unique name to identify the SNMPv3 group. |
| notify_view | no |  |  | Mib view name for notification. |
| read_view | no |  |  | Mib view name for read. |
| security_level | no |  | <ul><li>noAuthNoPriv</li><li>authentication</li><li>privacy</li></ul> | Security level indicating whether to use authentication and encryption. |
| write_view | no |  |  | Mib view name for write. |
#### Examples

```

- name: CloudEngine snmp community test
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

  - name: "Config SNMP community"
    ce_snmp_community:
      state:  present
      community_name:  Wdz123456789
      access_right:  write
      provider: "{{ cli }}"

  - name: "Undo SNMP community"
    ce_snmp_community:
      state:  absent
      community_name:  Wdz123456789
      access_right:  write
      provider: "{{ cli }}"

  - name: "Config SNMP group"
    ce_snmp_community:
      state:  present
      group_name:  wdz_group
      security_level:  noAuthNoPriv
      acl_number:  2000
      provider: "{{ cli }}"

  - name: "Undo SNMP group"
    ce_snmp_community:
      state:  absent
      group_name:  wdz_group
      security_level:  noAuthNoPriv
      acl_number:  2000
      provider: "{{ cli }}"

```

---

## ce_snmp_contact

Manages SNMP contact configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages SNMP contact configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| contact | yes |  |  | Contact information. |
#### Examples

```

- name: CloudEngine snmp contact test
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

  - name: "Config SNMP contact"
    ce_snmp_contact:
      state:  present
      contact:  call Operator at 010-99999999
      provider: "{{ cli }}"

  - name: "Undo SNMP contact"
    ce_snmp_contact:
      state:  absent
      contact:  call Operator at 010-99999999
      provider: "{{ cli }}"

```

---

## ce_snmp_location

Manages SNMP location configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages SNMP location configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| location | yes |  |  | Location information. |
#### Examples

```

- name: CloudEngine snmp location test
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

  - name: "Config SNMP location"
    ce_snmp_location:
      state:  present
      location:  nanjing China
      provider: "{{ cli }}"

  - name: "Undo SNMP location"
    ce_snmp_location:
      state:  absent
      location:  nanjing China
      provider: "{{ cli }}"

```

---

## ce_snmp_target_host

Manages SNMP target host configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages SNMP target host configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| address | no |  |  | Network Address. |
| connect_port | no |  |  | Udp port used by SNMP agent to connect the Network management. |
| host_name | no |  |  | Unique name to identify target host entry. |
| interface_name | no |  |  | Name of the interface to send the trap message. |
| is_public_net | no | no_use | <ul><li>no_use</li><li>true</li><li>false</li></ul> | To enable or disable Public Net-manager for target Host. |
| notify_type | no |  | <ul><li>trap</li><li>inform</li></ul> | To configure notify type as trap or inform. |
| recv_port | no |  |  | UDP Port number used by network management to receive alarm messages. |
| security_level | no |  | <ul><li>noAuthNoPriv</li><li>authentication</li><li>privacy</li></ul> | Security level indicating whether to use authentication and encryption. |
| security_model | no |  | <ul><li>v1</li><li>v2c</li><li>v3</li></ul> | Security Model. |
| security_name | no |  |  | Security Name. |
| security_name_v3 | no |  |  | Security Name V3. |
| version | no |  | <ul><li>none</li><li>v1</li><li>v2c</li><li>v3</li><li>v1v2c</li><li>v1v3</li><li>v2cv3</li><li>all</li></ul> | Version(s) Supported by SNMP Engine. |
| vpn_name | no |  |  | VPN instance Name. |
#### Examples

```

- name: CloudEngine snmp target host test
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

  - name: "Config SNMP version"
    ce_snmp_target_host:
      state:  present
      version:  v2cv3
      provider: "{{ cli }}"

  - name: "Config SNMP target host"
    ce_snmp_target_host:
      state:  present
      host_name:  test1
      address:  1.1.1.1
      notify_type:  trap
      vpn_name:  js
      security_model:  v2c
      security_name:  wdz
      provider: "{{ cli }}"

```

---

## ce_snmp_traps

Manages SNMP traps configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages SNMP traps configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| feature_name | no |  | <ul><li>aaa</li><li>arp</li><li>bfd</li><li>bgp</li><li>cfg</li><li>configuration</li><li>dad</li><li>devm</li><li>dhcpsnp</li><li>dldp</li><li>driver</li><li>efm</li><li>erps</li><li>error-down</li><li>fcoe</li><li>fei</li><li>fei_comm</li><li>fm</li><li>ifnet</li><li>info</li><li>ipsg</li><li>ipv6</li><li>isis</li><li>l3vpn</li><li>lacp</li><li>lcs</li><li>ldm</li><li>ldp</li><li>ldt</li><li>lldp</li><li>mpls_lspm</li><li>msdp</li><li>mstp</li><li>nd</li><li>netconf</li><li>nqa</li><li>nvo3</li><li>openflow</li><li>ospf</li><li>ospfv3</li><li>pim</li><li>pim-std</li><li>qos</li><li>radius</li><li>rm</li><li>rmon</li><li>securitytrap</li><li>smlktrap</li><li>snmp</li><li>ssh</li><li>stackmng</li><li>sysclock</li><li>sysom</li><li>system</li><li>tcp</li><li>telnet</li><li>trill</li><li>trunk</li><li>tty</li><li>vbst</li><li>vfs</li><li>virtual-perception</li><li>vrrp</li><li>vstm</li><li>all</li></ul> | Alarm feature name. |
| interface_number | no |  |  | Interface number. |
| interface_type | no |  | <ul><li>Ethernet</li><li>Eth-Trunk</li><li>Tunnel</li><li>NULL</li><li>LoopBack</li><li>Vlanif</li><li>100GE</li><li>40GE</li><li>MTunnel</li><li>10GE</li><li>GE</li><li>MEth</li><li>Vbdif</li><li>Nve</li></ul> | Interface type. |
| port_number | no |  |  | Source port number. |
| trap_name | no |  |  | Alarm trap name. |
#### Examples

```

- name: CloudEngine snmp traps test
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

  - name: "Config SNMP trap all enable"
    ce_snmp_traps:
      state:  present
      feature_name:  all
      provider: "{{ cli }}"

  - name: "Config SNMP trap interface"
    ce_snmp_traps:
      state:  present
      interface_type:  40GE
      interface_number:  2/0/1
      provider: "{{ cli }}"

  - name: "Config SNMP trap port"
    ce_snmp_traps:
      state:  present
      port_number:  2222
      provider: "{{ cli }}"

```

---

## ce_snmp_user

Manages SNMP user configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages SNMP user configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| aaa_local_user | no |  |  | Unique name to identify the local user. |
| acl_number | no |  |  | Access control list number. |
| auth_key | no |  |  | The authentication password. Simple password length <8-255>. Field max. |
| auth_protocol | no |  | <ul><li>noAuth</li><li>md5</li><li>sha</li></ul> | Authentication protocol ( md5 | sha ). |
| priv_key | no |  |  | The encryption password. Simple password length <8-255>. Field max. |
| priv_protocol | no |  | <ul><li>noPriv</li><li>des56</li><li>3des168</li><li>aes128</li><li>aes192</li><li>aes256</li></ul> | Encryption protocol. |
| remote_engine_id | no |  |  | Remote engine id of the USM user. |
| user_group | no |  |  | Name of the group where user belongs to. |
| usm_user_name | no |  |  | Unique name to identify the USM user. |
#### Examples

```

- name: CloudEngine snmp user test
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

  - name: "Config SNMP usm user"
    ce_snmp_user:
      state:  present
      usm_user_name:  wdz_snmp
      remote_engine_id:  800007DB03389222111200
      acl_number:  2000
      user_group:  wdz_group
      provider: "{{ cli }}"

  - name: "Undo SNMP usm user"
    ce_snmp_user:
      state:  absent
      usm_user_name:  wdz_snmp
      remote_engine_id:  800007DB03389222111200
      acl_number:  2000
      user_group:  wdz_group
      provider: "{{ cli }}"

  - name: "Config SNMP local user"
    ce_snmp_user:
      state:  present
      aaa_local_user:  wdz_user
      auth_protocol:  md5
      auth_key:  huawei123
      priv_protocol:  des56
      priv_key:  huawei123
      provider: "{{ cli }}"

  - name: "Config SNMP local user"
    ce_snmp_user:
      state:  absent
      aaa_local_user:  wdz_user
      auth_protocol:  md5
      auth_key:  huawei123
      priv_protocol:  des56
      priv_key:  huawei123
      provider: "{{ cli }}"

```

---

## ce_startup

Manages a system startup information.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages a system startup information on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| action | no |  | <ul><li>display</li></ul> | Display the startup information. |
| cfg_file | no | present |  | Name of the configuration file that is applied for the next startup. The value is a string of 5 to 255 characters. |
| patch_file | no |  |  | Name of the patch file that is applied for the next startup. |
| slot | no |  |  | Position of the device.The value is a string of 1 to 32 characters. The possible value of slot is all, slave-board, or the specific slotID. |
| software_file | no |  |  | File name of the system software that is applied for the next startup. The value is a string of 5 to 255 characters. |
#### Examples

```
- name: startup module test
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

  - name: Display startup information
    ce_startup:
      action: display
      provider: "{{ cli }}"

  - name: Set startup patch file
    ce_startup:
      patch_file: 2.PAT
      slot: all
      provider: "{{ cli }}"

  - name: Set startup software file
    ce_startup:
      software_file: aa.cc
      slot: 1
      provider: "{{ cli }}"

  - name: Set startup cfg file
    ce_startup:
      cfg_file: 2.cfg
      slot: 1
      provider: "{{ cli }}"

```

---

## ce_static_route

Manages static route configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages the static routes of Huawei CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| aftype | yes |  | <ul><li>v4</li><li>v6</li></ul> | Destination ip address family type of static route. |
| description | no |  |  | Name of the route. Used with the name parameter on the CLI. |
| destvrf | no |  |  | VPN instance of next hop ip address. |
| mask | yes |  |  | Destination ip mask of static route. |
| next_hop | no |  |  | Next hop address of static route. |
| nhp_interface | no |  |  | Next hop interface full name of static route. |
| pref | no |  |  | Preference or administrative difference of route (range 1-255). |
| prefix | yes |  |  | Destination ip address of static route. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| tag | no |  |  | Route tag value (numeric). |
| vrf | no |  |  | VPN instance of destination ip address. |
#### Examples

```
- name: static route module test
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

  - name: Config a ipv4 static route, next hop is an address and that it has the proper description
    ce_static_route:
      prefix: 2.1.1.2
      mask: 24
      next_hop: 3.1.1.2
      description: 'Configured by Ansible'
      aftype: v4
      provider: "{{ cli }}"
  - name: Config a ipv4 static route ,next hop is an interface and that it has the proper description
    ce_static_route:
      prefix: 2.1.1.2
      mask: 24
      next_hop: 10GE1/0/1
      description: 'Configured by Ansible'
      aftype: v4
      provider: "{{ cli }}"
  - name: Config a ipv6 static route, next hop is an address and that it has the proper description
    ce_static_route:
      prefix: fc00:0:0:2001::1
      mask: 64
      next_hop: fc00:0:0:2004::1
      description: 'Configured by Ansible'
      aftype: v6
      provider: "{{ cli }}"
  - name: Config a ipv4 static route, next hop is an interface and that it has the proper description
    ce_static_route:
      prefix: fc00:0:0:2001::1
      mask: 64
      next_hop: 10GE1/0/1
      description: 'Configured by Ansible'
      aftype: v6
      provider: "{{ cli }}"
  - name: Config a VRF and set ipv4 static route, next hop is an address and that it has the proper description
    ce_static_route:
      vrf: vpna
      prefix: 2.1.1.2
      mask: 24
      next_hop: 3.1.1.2
      description: 'Configured by Ansible'
      aftype: v4
      provider: "{{ cli }}"

```

#### Notes

- If no vrf is supplied, vrf is set to default. If state=absent, the route will be removed, regardless of the non-required parameters.
 

---

## ce_stp

Manages STP configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages STP configurations on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| bpdu_filter | no |  | <ul><li>enable</li><li>disable</li></ul> | Specify a port as a BPDU filter port. |
| bpdu_protection | no |  | <ul><li>enable</li><li>disable</li></ul> | Configure BPDU protection on an edge port. This function prevents network flapping caused by attack packets. |
| cost | no |  |  | Set the path cost of the current port. The default instance is 0. |
| edged_port | no |  | <ul><li>enable</li><li>disable</li></ul> | Set the current port as an edge port. |
| interface | no |  |  | Interface name. If the value is all, will apply configuration to all interfaces. if the value is a special name, only support input the full name. |
| loop_protection | no |  | <ul><li>enable</li><li>disable</li></ul> | Enable loop protection on the current port. |
| root_protection | no |  | <ul><li>enable</li><li>disable</li></ul> | Enable root protection on the current port. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| stp_converge | no |  | <ul><li>fast</li><li>normal</li></ul> | STP convergence mode. Fast means set STP aging mode to Fast. Normal means set STP aging mode to Normal. |
| stp_enable | no |  | <ul><li>enable</li><li>disable</li></ul> | Enable or disable STP on a switch. |
| stp_mode | no |  | <ul><li>stp</li><li>rstp</li><li>mstp</li></ul> | Set an operation mode for the current MSTP process. The mode can be STP, RSTP, or MSTP. |
| tc_protection | no |  | <ul><li>enable</li><li>disable</li></ul> | Configure the TC BPDU protection function for an MSTP process. |
| tc_protection_interval | no |  |  | Set the time the MSTP device takes to handle the maximum number of TC BPDUs and immediately refresh forwarding entries. The value is an integer ranging from 1 to 600, in seconds. |
| tc_protection_threshold | no |  |  | Set the maximum number of TC BPDUs that the MSTP can handle. The value is an integer ranging from 1 to 255. The default value is 1. |
#### Examples

```

- name: CloudEngine stp test
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

  - name: "Config stp mode"
    ce_stp:
      state:  present
      stp_mode:  stp
      provider: "{{ cli }}"

  - name: "Undo stp mode"
    ce_stp:
      state:  absent
      stp_mode:  stp
      provider: "{{ cli }}"

  - name: "Enable bpdu protection"
    ce_stp:
      state:  present
      bpdu_protection:  enable
      provider: "{{ cli }}"

  - name: "Disable bpdu protection"
    ce_stp:
      state:  present
      bpdu_protection:  disable
      provider: "{{ cli }}"

```

---

## ce_switchport

Manages Layer 2 switchport interfaces.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages Layer 2 switchport interfaces.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| access_vlan | no |  |  | If C(mode=access), used as the access VLAN ID, in the range from 1 to 4094. |
| interface | yes |  |  | Full name of the interface, i.e. 40GE1/0/22. |
| mode | no |  | <ul><li>access</li><li>trunk</li></ul> | The link type of an interface. |
| native_vlan | no |  |  | If C(mode=trunk), used as the trunk native VLAN ID, in the range from 1 to 4094. |
| state | no | present | <ul><li>present</li><li>absent</li><li>unconfigured</li></ul> | Manage the state of the resource. |
| trunk_vlans | no |  |  | If C(mode=trunk), used as the VLAN range to ADD or REMOVE from the trunk, such as 2-10 or 2,5,10-15, etc. |
#### Examples

```
- name: switchport module test
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
  - name: Ensure 10GE1/0/22 is in its default switchport state
    ce_switchport:
      interface: 10GE1/0/22
      state: unconfigured
      provider: '{{ cli }}'

  - name: Ensure 10GE1/0/22 is configured for access vlan 20
    ce_switchport:
      interface: 10GE1/0/22
      mode: access
      access_vlan: 20
      provider: '{{ cli }}'

  - name: Ensure 10GE1/0/22 only has vlans 5-10 as trunk vlans
    ce_switchport:
      interface: 10GE1/0/22
      mode: trunk
      native_vlan: 10
      trunk_vlans: 5-10
      provider: '{{ cli }}'

  - name: Ensure 10GE1/0/22 is a trunk port and ensure 2-50 are being tagged (doesn't mean others aren't also being tagged)
    ce_switchport:
      interface: 10GE1/0/22
      mode: trunk
      native_vlan: 10
      trunk_vlans: 2-50
      provider: '{{ cli }}'

  - name: Ensure these VLANs are not being tagged on the trunk
    ce_switchport:
      interface: 10GE1/0/22
      mode: trunk
      trunk_vlans: 51-4000
      state: absent
      provider: '{{ cli }}'

```

#### Notes

- When C(state=absent), VLANs can be added/removed from trunk links and the existing access VLAN can be 'unconfigured' to just having VLAN 1 on that interface.
- When working with trunks VLANs the keywords add/remove are always sent in the `port trunk allow-pass vlan` command. Use verbose mode to see commands sent.
- When C(state=unconfigured), the interface will result with having a default Layer 2 interface, i.e. vlan 1 in access mode.
 

---

## ce_vlan

Manages VLAN resources and attributes.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages VLAN configurations on Huawei CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| description | no |  |  | Specify VLAN description, in the range from 1 to 80. |
| name | no |  |  | Name of VLAN, in the range from 1 to 31. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
| vlan_id | no |  |  | Single VLAN ID, in the range from 1 to 4094. |
| vlan_range | no |  |  | Range of VLANs such as 2-10 or 2,5,10-15, etc. |
#### Examples

```
- name: vlan module test
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

  - name: Ensure a range of VLANs are not present on the switch
    ce_vlan:
      vlan_range: "2-10,20,50,55-60,100-150"
      state: absent
      provider: "{{ cli }}"

  - name: Ensure VLAN 50 exists with the name WEB
    ce_vlan:
      vlan_id: 50
      name: WEB
      state: absent
      provider: "{{ cli }}"

  - name: Ensure VLAN is NOT on the device
    ce_vlan:
      vlan_id: 50
      state: absent
      provider: "{{ cli }}"


```

---

## ce_vrf

Manages VPN instance.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages VPN instance of Huawei CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| description | no |  |  | Description of the vrf,the string length is 1 - 242 . |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
| vrf | yes |  |  | VPN instance,the length of vrf name is 1 - 31,i.e. "test",but can not be _public_. |
#### Examples

```
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

```

#### Notes

- If no vrf is supplied, vrf is set to default. If state==absent, the route will be removed, regardless of the non-required parameters.
 

---

## ce_vrf_af

Manages VPN instance address family.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages VPN instance address family of Huawei CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| evpn | no |  | <ul><li>true</li><li>false</li></ul> | Is extend vpn or normal vpn. |
| route_distinguisher | no |  |  | VPN instance route distinguisher,the RD used to distinguish same route prefix from different vpn. The RD must be setted before setting vpn_target_value. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the af. |
| vpn_target_state | no |  | <ul><li>present</li><li>absent</li></ul> | Manage the state of the vpn target. |
| vpn_target_type | no |  | <ul><li>export_extcommunity</li><li>import_extcommunity</li></ul> | VPN instance vpn target type. |
| vpn_target_value | no |  |  | VPN instance target value. Such as X.X.X.X:number<0-65535> or number<0-65535>:number<0-4294967295> or number<0-65535>.number<0-65535>:number<0-65535> or number<65536-4294967295>:number<0-65535> but not support 0:0 and 0.0:0. |
| vrf | yes |  |  | VPN instance. |
| vrf_aftype | no | v4 | <ul><li>v4</li><li>v6</li></ul> | VPN instance address family. |
#### Examples

```
- name: vrf af module test
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

  - name: Config vpna, set address family is ipv4
    ce_vrf_af:
      vrf: vpna
      vrf_aftype: v4
      state: present
      provider: "{{ cli }}"
  - name: Config vpna, delete address family is ipv4
    ce_vrf_af:
      vrf: vpna
      vrf_aftype: v4
      state: absent
      provider: "{{ cli }}"
  - name: Config vpna, set address family is ipv4,rd=1:1,set vpn_target_type=export_extcommunity,vpn_target_value=2:2
    ce_vrf_af:
      vrf: vpna
      vrf_aftype: v4
      route_distinguisher: 1:1
      vpn_target_type: export_extcommunity
      vpn_target_value: 2:2
      vpn_target_state: present
      state: present
      provider: "{{ cli }}"
  - name: Config vpna, set address family is ipv4,rd=1:1,delete vpn_target_type=export_extcommunity,vpn_target_value=2:2
    ce_vrf_af:
      vrf: vpna
      vrf_aftype: v4
      route_distinguisher: 1:1
      vpn_target_type: export_extcommunity
      vpn_target_value: 2:2
      vpn_target_state: absent
      state: present
      provider: "{{ cli }}"

```

#### Notes

- If no vrf is supplied, the module will return error. If state=absent, the vrf will be removed, regardless of the non-required parameters.
 

---

## ce_vrf_interface

Manages interface specific VPN configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages interface specific VPN configuration of Huawei CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
| vpn_interface | yes |  |  | An interface that can binding VPN instance, i.e. 40GE1/0/22, Vlanif10. Must be fully qualified interface name. Interface types, such as 10GE, 40GE, 100GE, LoopBack, MEth, Tunnel, Vlanif.... |
| vrf | yes |  |  | VPN instance, the length of vrf name is 1 ~ 31,i.e. "test", but can not be _public_. |
#### Examples

```
- name: VRF interface test
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

  - name: "Configure a VPN instance for the interface"
    ce_vrf_interface:
      vpn_interface: 40GE1/0/2
      vrf: test
      state: present
      provider: "{{ cli }}"

  - name: "Disable the association between a VPN instance and an interface"
    ce_vrf_interface:
      vpn_interface: 40GE1/0/2
      vrf: test
      state: absent
      provider: "{{ cli }}"

```

#### Notes

- Ensure that a VPN instance has been created and the IPv4 address family has been enabled for the VPN instance.
 

---

## ce_vrrp

Manages VRRP interfaces.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages VRRP interface attributes on CloudEngine switches.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| admin_flowdown | no |  |  | Disable the flowdown function for service VRRP. |
| admin_ignore_if_down | no |  |  | mVRRP ignores an interface Down event. |
| admin_interface | no |  |  | Tracked mVRRP interface name. The value is a string of 1 to 63 characters. |
| admin_vrid | no |  |  | Tracked mVRRP ID. The value is an integer ranging from 1 to 255. |
| advertise_interval | no |  |  | Configured interval between sending advertisements, in milliseconds. Only the master router sends VRRP advertisements. The default value is 1000 milliseconds. |
| auth_key | no |  |  | This object is set based on the authentication type. When noAuthentication is specified, the value is empty. When simpleTextPassword or md5Authentication is specified, the value is a string of 1 to 8 characters in plaintext and displayed as a blank text for security. |
| auth_mode | no |  | <ul><li>simple</li><li>md5</li><li>none</li></ul> | Authentication type used for VRRP packet exchanges between virtual routers. The values are noAuthentication, simpleTextPassword, md5Authentication. The default value is noAuthentication. |
| fast_resume | no |  | <ul><li>enable</li><li>disable</li></ul> | mVRRP's fast resume mode. |
| gratuitous_arp_interval | no |  |  | Interval at which gratuitous ARP packets are sent, in seconds. The value ranges from 30 to 1200.The default value is 300. |
| holding_multiplier | no |  |  | The configured holdMultiplier.The value is an integer ranging from 3 to 10. The default value is 3. |
| interface | no |  |  | Name of an interface. The value is a string of 1 to 63 characters. |
| is_plain | no |  |  | Select the display mode of an authentication key. By default, an authentication key is displayed in ciphertext. |
| preempt_timer_delay | no |  |  | Preemption delay. The value is an integer ranging from 0 to 3600. The default value is 0. |
| priority | no |  |  | Configured VRRP priority. The value ranges from 1 to 254. The default value is 100. A larger value indicates a higher priority. |
| recover_delay | no |  |  | Delay in recovering after an interface goes Up. The delay is used for interface flapping suppression. The value is an integer ranging from 0 to 3600. The default value is 0 seconds. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource. |
| version | no |  | <ul><li>v2</li><li>v3</li></ul> | VRRP version. The default version is v2. |
| virtual_ip | no |  |  | Virtual IP address. The value is a string of 0 to 255 characters. |
| vrid | no | present |  | VRRP backup group ID. The value is an integer ranging from 1 to 255. |
| vrrp_type | no |  | <ul><li>normal</li><li>member</li><li>admin</li></ul> | Type of a VRRP backup group. |
#### Examples

```
- name: vrrp module test
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

  - name: Set vrrp version
    ce_vrrp:
      version: v3
      provider: "{{ cli }}"

  - name: Set vrrp gratuitous-arp interval
    ce_vrrp:
      gratuitous_arp_interval: 40
      mlag_id: 4
      provider: "{{ cli }}"

  - name: Set vrrp recover-delay
    ce_vrrp:
      recover_delay: 10
      provider: "{{ cli }}"

  - name: Set vrrp vrid virtual-ip
    ce_vrrp:
      interface: 40GE2/0/8
      vrid: 1
      virtual_ip: 10.14.2.7
      provider: "{{ cli }}"

  - name: Set vrrp vrid admin
    ce_vrrp:
      interface: 40GE2/0/8
      vrid: 1
      vrrp_type: admin
      provider: "{{ cli }}"

  - name: Set vrrp vrid fast_resume
    ce_vrrp:
      interface: 40GE2/0/8
      vrid: 1
      fast_resume: enable
      provider: "{{ cli }}"

  - name: Set vrrp vrid holding-multiplier
    ce_vrrp:
      interface: 40GE2/0/8
      vrid: 1
      holding_multiplier: 4
      provider: "{{ cli }}"

  - name: Set vrrp vrid preempt timer delay
    ce_vrrp:
      interface: 40GE2/0/8
      vrid: 1
      preempt_timer_delay: 10
      provider: "{{ cli }}"

  - name: Set vrrp vrid admin-vrrp
    ce_vrrp:
      interface: 40GE2/0/8
      vrid: 1
      admin_interface: 40GE2/0/9
      admin_vrid: 2
      vrrp_type: member
      provider: "{{ cli }}"

  - name: Set vrrp vrid authentication-mode
    ce_vrrp:
      interface: 40GE2/0/8
      vrid: 1
      is_plain: true
      auth_mode: simple
      auth_key: aaa
      provider: "{{ cli }}"

```

---

## ce_vxlan_arp

Manages ARP attributes of VXLAN.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages ARP attributes of VXLAN.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| arp_collect_host | no |  | <ul><li>enable</li><li>disable</li></ul> | Enables EVN BGP or BGP EVPN to collect host information. |
| arp_suppress | no |  | <ul><li>enable</li><li>disable</li></ul> | Enables ARP broadcast suppression in a BD. |
| bridge_domain_id | no |  |  | Specifies a BD(bridge domain) ID. The value is an integer ranging from 1 to 16777215. |
| evn_bgp | no |  | <ul><li>enable</li><li>disable</li></ul> | Enables EVN BGP. |
| evn_peer_ip | no |  |  | Specifies the IP address of an EVN BGP peer. The value is in dotted decimal notation. |
| evn_reflect_client | no |  | <ul><li>enable</li><li>disable</li></ul> | Configures the local device as the route reflector (RR) and its peer as the client. |
| evn_server | no |  | <ul><li>enable</li><li>disable</li></ul> | Configures the local device as the router reflector (RR) on the EVN network. |
| evn_source_ip | no |  |  | Specifies the source address of an EVN BGP peer. The value is in dotted decimal notation. |
| host_collect_protocol | no |  | <ul><li>bgp</li><li>none</li></ul> | Enables EVN BGP or BGP EVPN to advertise host information. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Determines whether the config should be present or not on the device. |
| vbdif_name | no |  |  | Full name of VBDIF interface, i.e. Vbdif100. |
#### Examples

```
- name: vxlan arp module test
  hosts: ce128
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

  - name: Configure EVN BGP on Layer 2 and Layer 3 VXLAN gateways to establish EVN BGP peer relationships.
    ce_vxlan_arp:
      evn_bgp: enable
      evn_source_ip: 6.6.6.6
      evn_peer_ip: 7.7.7.7
      provider: "{{ cli }}"
  - name: Configure a Layer 3 VXLAN gateway as a BGP RR.
    ce_vxlan_arp:
      evn_bgp: enable
      evn_server: enable
      provider: "{{ cli }}"
  - name: Enable EVN BGP on a Layer 3 VXLAN gateway to collect host information.
    ce_vxlan_arp:
      vbdif_name: Vbdif100
      arp_collect_host: enable
      provider: "{{ cli }}"
  - name: Enable Layer 2 and Layer 3 VXLAN gateways to use EVN BGP to advertise host information.
    ce_vxlan_arp:
      host_collect_protocol: bgp
      provider: "{{ cli }}"
  - name: Enable ARP broadcast suppression on a Layer 2 VXLAN gateway.
    ce_vxlan_arp:
      bridge_domain_id: 100
      arp_suppress: enable
      provider: "{{ cli }}"

```

---

## ce_vxlan_gateway

Manages gateway for the VXLAN network.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Configuring Centralized All-Active Gateways or Distributed Gateway for the VXLAN Network.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| arp_direct_route | no |  | <ul><li>enable</li><li>disable</li></ul> | Enable VLINK direct route on VBDIF interface. |
| arp_distribute_gateway | no |  | <ul><li>enable</li><li>disable</li></ul> | Enable the distributed gateway function on VBDIF interface. |
| dfs_all_active | no |  | <ul><li>enable</li><li>disable</li></ul> | Creates all-active gateways. |
| dfs_id | no |  |  | Specifies the ID of a DFS group. The value must be 1. |
| dfs_peer_ip | no |  |  | Configure the IP address of an all-active gateway peer. The value is in dotted decimal notation. |
| dfs_peer_vpn | no |  |  | Specifies the name of the VPN instance that is associated with all-active gateway peer. The value is a string of 1 to 31 case-sensitive characters, spaces not supported. When double quotation marks are used around the string, spaces are allowed in the string. The value _public_ is reserved and cannot be used as the VPN instance name. |
| dfs_source_ip | no |  |  | Specifies the IPv4 address bound to a DFS group. The value is in dotted decimal notation. |
| dfs_source_vpn | no |  |  | Specifies the name of a VPN instance bound to a DFS group. The value is a string of 1 to 31 case-sensitive characters without spaces. If the character string is quoted by double quotation marks, the character string can contain spaces. The value _public_ is reserved and cannot be used as the VPN instance name. |
| dfs_udp_port | no |  |  | Specifies the UDP port number of the DFS group. The value is an integer that ranges from 1025 to 65535. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Determines whether the config should be present or not on the device. |
| vbdif_bind_vpn | no |  |  | Specifies the name of the VPN instance that is associated with the interface. The value is a string of 1 to 31 case-sensitive characters, spaces not supported. When double quotation marks are used around the string, spaces are allowed in the string. The value _public_ is reserved and cannot be used as the VPN instance name. |
| vbdif_mac | no |  |  | Specifies a MAC address for a VBDIF interface. The value is in the format of H-H-H. Each H is a 4-digit hexadecimal number, such as 00e0 or fc01. If an H contains less than four digits, 0s are added ahead. For example, e0 is equal to 00e0. A MAC address cannot be all 0s or 1s or a multicast MAC address. |
| vbdif_name | no |  |  | Full name of VBDIF interface, i.e. Vbdif100. |
| vpn_instance | no |  |  | Specifies the name of a VPN instance. The value is a string of 1 to 31 case-sensitive characters, spaces not supported. When double quotation marks are used around the string, spaces are allowed in the string. The value _public_ is reserved and cannot be used as the VPN instance name. |
| vpn_vni | no |  |  | Specifies a VNI ID. Binds a VXLAN network identifier (VNI) to a virtual private network (VPN) instance. The value is an integer ranging from 1 to 16000000. |
#### Examples

```
- name: vxlan gateway module test
  hosts: ce128
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

  - name: Configuring Centralized All-Active Gateways for the VXLAN Network
    ce_vxlan_gateway:
      dfs_id: 1
      dfs_source_ip: 6.6.6.6
      dfs_all_active: enable
      dfs_peer_ip: 7.7.7.7
      provider: "{{ cli }}"
  - name: Bind the VPN instance to a Layer 3 gateway, enable distributed gateway, and configure host route advertisement.
    ce_vxlan_gateway:
      vbdif_name: Vbdif100
      vbdif_bind_vpn: vpn1
      arp_distribute_gateway: enable
      arp_direct_route: enable
      provider: "{{ cli }}"
  - name: Assign a VNI to a VPN instance.
    ce_vxlan_gateway:
      vpn_instance: vpn1
      vpn_vni: 100
      provider: "{{ cli }}"

```

#### Notes

- Ensure All-Active Gateways or Distributed Gateway for the VXLAN Network can not configure at the same time.
 

---

## ce_vxlan_global

Manages global attributes of VXLAN and bridge domain.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages global attributes of VXLAN and bridge domain.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| bridge_domain_id | no |  |  | Specifies a bridge domain ID. The value is an integer ranging from 1 to 16777215. |
| nvo3_acl_extend | no |  | <ul><li>enable</li><li>disable</li></ul> | Enabling or disabling the VXLAN ACL extension function. |
| nvo3_ecmp_hash | no |  | <ul><li>enable</li><li>disable</li></ul> | Load balancing of VXLAN packets through ECMP in optimized mode. |
| nvo3_eth_trunk_hash | no |  | <ul><li>enable</li><li>disable</li></ul> | Eth-Trunk from load balancing VXLAN packets in optimized mode. |
| nvo3_gw_enhanced | no |  | <ul><li>l2</li><li>l3</li></ul> | Configuring the Layer 3 VXLAN Gateway to Work in Non-loopback Mode. |
| nvo3_prevent_loops | no |  | <ul><li>enable</li><li>disable</li></ul> | Loop prevention of VXLAN traffic in non-enhanced mode. When the device works in non-enhanced mode, inter-card forwarding of VXLAN traffic may result in loops. |
| nvo3_service_extend | no |  | <ul><li>enable</li><li>disable</li></ul> | Enabling or disabling the VXLAN service extension function. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Determines whether the config should be present or not on the device. |
| tunnel_mode_vxlan | no |  | <ul><li>enable</li><li>disable</li></ul> | Set the tunnel mode to VXLAN when configuring the VXLAN feature. |
#### Examples

```
- name: vxlan global module test
  hosts: cd128
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

  - name: Create bridge domain and set tunnel mode to VXLAN
    ce_vxlan_global:
      bridge_domain_id: 100
      nvo3_acl_extend: enable
      provider: "{{ cli }}"

```

---

## ce_vxlan_tunnel

Manages VXLAN tunnel configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis

This module offers the ability to set the VNI and mapped to the BD, and configure an ingress replication list on CloudEngine switch.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| bridge_domain_id | no |  |  | Specifies a bridge domain ID. The value is an integer ranging from 1 to 16777215. |
| nve_mode | no |  | <ul><li>mode-l2</li><li>mode-l3</li></ul> | Specifies the working mode of an NVE interface. |
| nve_name | no |  |  | Specifies the number of an NVE interface. The value ranges from 1 to 2. |
| peer_list_ip | no |  |  | Specifies the IP address of a remote VXLAN tunnel endpoints (VTEP). The value is in dotted decimal notation. |
| protocol_type | no |  | <ul><li>bgp</li><li>null</li></ul> | The operation type of routing protocol. |
| source_ip | no |  |  | Specifies an IP address for a source VTEP. The value is in dotted decimal notation. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Manage the state of the resource. |
| vni_id | no |  |  | Specifies a VXLAN network identifier (VNI) ID. The value is an integer ranging from 1 to 16000000. |
#### Examples

```
- name: vxlan tunnel module test
  hosts: ce128
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

  - name: Make sure nve_name is exist, ensure vni_id and protocol_type is configured on Nve1 interface.
    ce_vxlan_tunnel:
      nve_name: Nve1
      vni_id: 100
      protocol_type: bgp
      state: present
      provider: "{{ cli }}"

```

---

## ce_vxlan_vap

Manages VXLAN virtual access point.

  * Synopsis
  * Options
  * Examples

#### Synopsis

Manages VXLAN Virtual access point.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| bind_vlan_id | no |  |  | Specifies the vlan binding to a BD(Bridge Domain). The value is an integer ranging ranging from 1 to 4094. |
| bridge_domain_id | no |  |  | Specifies a bridge domain ID. The value is an integer ranging from 1 to 16777215. |
| ce_vid | no |  |  | When C(encapsulation) is 'dot1q', specifies a VLAN ID in the outer VLAN tag. When C(encapsulation) is 'qinq', specifies an outer VLAN ID for double-tagged packets to be received by a Layer 2 sub-interface. The value is an integer ranging from 1 to 4094. |
| encapsulation | no |  | <ul><li>dot1q</li><li>default</li><li>untag</li><li>qinq</li><li>none</li></ul> | Specifies an encapsulation type of packets allowed to pass through a Layer 2 sub-interface. |
| l2_sub_interface | no |  |  | Specifies an Sub-Interface full name, i.e. "10GE1/0/41.1". The value is a string of 1 to 63 case-insensitive characters, spaces supported. |
| pe_vid | no |  |  | When C(encapsulation) is 'qinq', specifies an inner VLAN ID for double-tagged packets to be received by a Layer 2 sub-interface. The value is an integer ranging from 1 to 4094. |
| state | no | present | <ul><li>present</li><li>absent</li></ul> | Determines whether the config should be present or not on the device. |
#### Examples

```
- name: vxlan vap module test
  hosts: ce128
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

  - name: Create a papping between a VLAN and a BD
    ce_vxlan_vap:
      bridge_domain_id: 100
      bind_vlan_id: 99
      provider: "{{ cli }}"

  - name: Bind a Layer 2 sub-interface to a BD
    ce_vxlan_vap:
      bridge_domain_id: 100
      l2_sub_interface: 10GE2/0/20.1
      provider: "{{ cli }}"

  - name: Configure an encapsulation type on a Layer 2 sub-interface
    ce_vxlan_vap:
      l2_sub_interface: 10GE2/0/20.1
      encapsulation: dot1q
      provider: "{{ cli }}"

```
