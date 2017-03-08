# CloudEngine Ansible Module Docs
### *Network Automation with CloudEngine and Ansible*

---
### Requirements
* Check

---
### Modules
  * [ce_aaa_server - manages AAA server global configuration](#ce_aaa_server)
  * [ce_aaa_server_host - manages AAA server host configuration](#ce_aaa_server_host)
  * [ce_acl - manages base ACL configuration](#ce_acl)
  * [ce_acl_advance - manages advanced ACL configuration](#ce_acl_advance)
  * [ce_acl_interface - manages applying ACLs to interfaces](#ce_acl_interface)
  * [ce_bgp - manages BGP configuration](#ce_bgp)
  * [ce_bgp_af - manages BGP Address-family configuration](#ce_bgp_af)
  * [ce_bgp_neighbor - manages BGP peer configuration](#ce_bgp_neighbor)
  * [ce_bgp_neighbor_af - manages BGP neighbor Address-family configuration](#ce_bgp_neighbor_af)
  * [ce_command - run arbitrary command](#ce_command)
  * [ce_config - manages configuration sections](#ce_config)
  * [ce_dldp - manages global DLDP configuration](#ce_dldp)
  * [ce_dldp_interface - manages interface DLDP configuration](#ce_dldp_interface)
  * [ce_eth_trunk - manages Eth-Trunk interfaces](#ce_eth_trunk)
  * [ce_evpn_bd_vni - manages EVPN VXLAN Network Identifier](#ce_evpn_bd_vni)
  * [ce_evpn_bgp - manages BGP EVPN configuration](#ce_evpn_bgp)
  * [ce_evpn_bgp_rr - manages RR for the VXLAN Network](#ce_evpn_bgp_rr)
  * [ce_evpn_global - manages global configuration of EVPN](#ce_evpn_global)
  * [ce_facts - gets facts about CloudEngine switches](#ce_facts)
  * [ce_file_copy - copy a file to a remote CloudEngine device](#ce_file_copy)
  * [ce_info_center_global - manages outputting logs](#ce_info_center_global)
  * [ce_info_center_debug - manages information center debug configuration](#ce_info_center_debug)
  * [ce_info_center_log - manages information center log configuration](#ce_info_center_log)
  * [ce_info_center_trap - manages information center trap configuration](#ce_info_center_trap)
  * [ce_interface - manages physical attributes of interfaces](#ce_interface)
  * [ce_interface_ospf - manages configuration of an OSPF interface instance](#ce_interface_ospf)
  * [ce_ip_interface - manages L3 attributes for IPv4 and IPv6 interfaces](#ce_ip_interface)
  * [ce_mtu - manages MTU settings on CloudEngine switch](#ce_mtu)
  * [ce_netconf - run arbitrary netconf command on CloudEngine devices](#ce_netconf)
  * [ce_netstream_aging - manages timeout mode of NetStream](#ce_netstream_aging)
  * [ce_netstream_export - manages NetStream export](#ce_netstream_export)
  * [ce_netstream_global - manages NetStream global configuration](#ce_netstream_global)
  * [ce_netstream_template - manages NetStream template configuration](#ce_netstream_template)
  * [ce_ntp - manages core NTP configuration](#ce_ntp)
  * [ce_ntp_auth - manages NTP authentication configuration](#ce_ntp_auth)
  * [ce_ospf - manages configuration of an OSPF instance](#ce_ospf)
  * [ce_ospf_vrf - manages configuration of an OSPF VPN instance](#ce_ospf_vrf)
  * [ce_reboot - reboot a network device](#ce_reboot)
  * [ce_rollback - set a checkpoint or rollback to a checkpoint](#ce_rollback)
  * [ce_sflow - manages sFlow configuration](#ce_sflow)
  * [ce_snmp_community - manages SNMP community configuration](#ce_snmp_community)
  * [ce_snmp_contact - manages SNMP contact configuration](#ce_snmp_contact)
  * [ce_snmp_location - manages SNMP location configuration](#ce_snmp_location)
  * [ce_snmp_target_host - manages SNMP target host configuration](#ce_snmp_target_host)
  * [ce_snmp_traps - manages SNMP traps configuration](#ce_snmp_traps)
  * [ce_snmp_user - manages SNMP user configuration](#ce_snmp_user)
  * [ce_static_route - manages static route configuration](#ce_static_route)
  * [ce_stp - manages STP configuration](#ce_stp)
  * [ce_switchport - manages Layer 2 switchport interfaces](#ce_switchport)
  * [ce_vlan - manages VLAN resources and attributes](#ce_vlan)
  * [ce_vrf - manages VPN instance](#ce_vrf)
  * [ce_vrf_af - manages VPN instance address family](#ce_vrf_af)
  * [ce_vrf_interface - manages interface specific VPN configuration](#ce_vrf_interface)
  * [ce_vxlan_arp - manages ARP attributes of VXLAN](#ce_vxlan_arp)
  * [ce_vxlan_gateway - manages gateway for the VXLAN Network](#ce_vxlan_gateway)
  * [ce_vxlan_global - manages global attributes of VXLAN and bridge domain](#ce_vxlan_global)
  * [ce_vxlan_tunnel - manages VXLAN tunnel configuration](#ce_vxlan_tunnel)
  * [ce_vxlan_vap - manages VXLAN virtual access point](#ce_vxlan_vap)


---

## ce_aaa_server
Manages AAA server global configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages AAA server global configuration

#### Options

| Parameter     | required    | default  | choices      | comments |
| ------------- |-------------| ---------|--------------|--------- |
| authen_scheme_name  |   no  |  |  |  Name of an authentication scheme.<br>The value is a string of 1 to 32 characters.  |
| first_authen_mode  |   no  |  | <ul> <li>invalid</li>  <li>local</li>  <li>hwtacacs</li>  <li>radius</li>  <li>none</li></ul> |  Preferred authentication mode  |
| author_scheme_name  |   no  |  | <ul></ul> |  Name of an authorization scheme.<br>The value is a string of 1 to 32 characters.  |
| first_author_mode  |   no  |  | <ul> <li>invalid</li>  <li>local</li>  <li>hwtacacs</li>  <li>if-authenticated</li>  <li>none</li></ul> |  Preferred authorization mode  |
| acct_scheme_name  |   no  |  | <ul> </ul> |  Accounting scheme name.<br>The value is a string of 1 to 32 characters. |
| accounting_mode  |   no  |  | <ul> <li>invalid</li>  <li>hwtacacs</li>  <li>radius</li>  <li>none</li></ul> |  Accounting Mode  |
| domain_name  |   no  |  | <ul> </ul> |  Name of a domain.<br>The value is a string of 1 to 64 characters.  |
| radius_server_group  |   no  |  | <ul> </ul> |  RADIUS server group's name.<br>The value is a string of 1 to 32 case-insensitive characters.  |
| hwtacas_template  |   no  |    | <ul> </ul> |  Name of a HWTACACS template.<br>The value is a string of 1 to 32 case-insensitive characters.  |
| local_user_group  |   no  |  | <ul></ul> |  Name of the user group.<br>The value is a string of 1 to 32 characters.  |


#### Examples

```
# radius authentication Server Basic settings
- name: "radius authentication Server Basic settings"
    ce_aaa_server:
        state:  present
        authen_scheme_name:  test1
        first_authen_mode:  radius
        radius_server_group:  test2
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo radius authentication Server Basic settings
  - name: "undo radius authentication Server Basic settings"
    ce_aaa_server:
        state:  absent
        authen_scheme_name:  test1
        first_authen_mode:  radius
        radius_server_group:  test2
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# hwtacacs accounting Server Basic settings
  - name: "hwtacacs accounting Server Basic settings"
    ce_aaa_server:
        state:  present
        acct_scheme_name:  test1
        accounting_mode:  hwtacacs
        hwtacas_template:  test2
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo hwtacacs accounting Server Basic settings
  - name: "undo hwtacacs accounting Server Basic settings"
    ce_aaa_server:
        state:  absent
        acct_scheme_name:  test1
        accounting_mode:  hwtacacs
        hwtacas_template:  test2
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}
```

---


## ce_aaa_server_host
Manages AAA server host configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages AAA server host configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| local_user_name  |   no |    | <ul></ul> |  Name of a local user.<br>The value is a string of 1 to 253 characters.  |
| local_password  |   no  |  | <ul></ul> |  Login password of a user. The password can contain letters, numbers, and special characters.<br>The value is a string of 1 to 255 characters.  |
| local_service_type  |   no  |  | <ul></ul> |  The type of local user login through, such as ftp ssh snmp telnet  |
| local_ftp_dir  |   no  |  | <ul></ul> |  FTP user directory.<br>The value is a string of 1 to 255 characters.  |
| local_user_level  |   no  |    | <ul> </ul> |  Login level of a local user.<br>The value is an integer ranging from 0 to 15.  |
| local_user_group  |   no  |    | <ul></ul> |  Name of the user group.<br>The value is a string of 1 to 32 characters.  |
| radius_group_name  |   no  |  | <ul></ul> |  RADIUS server group's name.<br>The value is a string of 1 to 32 case-insensitive characters.  |
| radius_server_type  |   no  |  | <ul></ul> |  Type of Radius Server |
| radius_server_ip  |   no  |  | <ul></ul> |  IPv4 address of configured server.<br>The value is a string of 0 to 255 characters, in dotted decimal notation.  |
| radius_server_ipv6  |   no  |   | <ul> </ul> |  IPv6 address of configured server.<br>The total length is 128 bits.  |
| radius_server_port  |   no  |    | <ul></ul> |  Configured server port for a particular server.<br>The value is an integer ranging from 1 to 65535.  |
| radius_server_mode  |   no  |  | <ul></ul> |  Configured primary or secondary server.<br>The value is a string of 1 to 31 case-sensitive characters.  |
| radius_vpn_name  |   no  |  | <ul></ul> |  Set VPN instance.<br>The value is a string of 1 to 31 case-sensitive characters.  |
| radius_server_name  |   no  |  | <ul></ul> |  Hostname of configured server.<br>The value is a string of 0 to 255 case-sensitive characters.  |
| hwtacacs_template  |   no  |   | <ul> </ul> |  Name of a HWTACACS template.<br>The value is a string of 1 to 32 case-insensitive characters.  |
| hwtacacs_server_ip  |   no  |  | <ul></ul> |  Server IPv4 address. Must be a valid unicast IP address.<br>The value is a string of 0 to 255 characters, in dotted decimal notation.  |
| hwtacacs_server_ipv6  |   no  |    | <ul>  </ul> |  Server IPv6 address.<br>The total length is 128 bits.  |
| hwtacacs_server_type  |   no  |    | <ul><li>Authentication</li>  <li>Authorization</li> <li>Accounting</li>  <li>Common</li> </ul> |  Hwtacacs server type  |
| hwtacacs_is_secondary_server  |   no  | false | <ul><li>true</li>  <li>false</li></ul> |  Whether the server is secondary or not  |
| hwtacacs_vpn_name  |   no  |  | <ul></ul> |  VPN instance name  |
| hwtacacs_is_public_net  |   no  | false | <ul><li>true</li>  <li>false</li></ul> |  Set the public-net  |
| hwtacacs_server_host_name  |   no  |   | <ul>  </ul> |  Hwtacacs server host name |
| state  |   no  |  present  | <ul> <li>present</li>  <li>absent</li> </ul> |  Manage the state of the resource  |

#### Examples

```
# config local user when use local scheme
  - name: "config local user when use local scheme"
    ce_aaa_server_host:
        state:  present
        local_user_name:  user1
        local_password:  123456
        host:  {{inventory_hostname}}
        port:  {{ansible_ssh_port}}
        username:  {{username}}
        password:  {{password}}

# undo local user when use local scheme
  - name: "undo local user when use local scheme"
    ce_aaa_server_host:
        state:  absent
        local_user_name:  user1
        local_password:  123456
        host:  {{inventory_hostname}}
        port:  {{ansible_ssh_port}}
        username:  {{username}}
        password:  {{password}}

# config radius server ip
  - name: "config radius server ip"
    ce_aaa_server_host:
        state:  present
        radius_group_name:  group1
        raduis_server_type:  Authentication
        radius_server_ip:  10.1.10.1
        radius_server_port:  2000
        radius_server_mode:  Primary-server
        radius_vpn_name:  _public_
        host:  {{inventory_hostname}}
        port:  {{ansible_ssh_port}}
        username:  {{username}}
        password:  {{password}}

# undo radius server ip
  - name: "undo radius server ip"
    ce_aaa_server_host:
        state:  absent
        radius_group_name:  group1
        raduis_server_type:  Authentication
        radius_server_ip:  10.1.10.1
        radius_server_port:  2000
        radius_server_mode:  Primary-server
        radius_vpn_name:  _public_
        host:  {{inventory_hostname}}
        port:  {{ansible_ssh_port}}
        username:  {{username}}
        password:  {{password}}

# config hwtacacs server ip
  - name: "config hwtacacs server ip"
    ce_aaa_server_host:
        state:  present
        hwtacacs_template:  template
        hwtacacs_server_ip:  10.10.10.10
        hwtacacs_server_type:  Authorization
        hwtacacs_vpn_name:  _public_
        host:  {{inventory_hostname}}
        port:  {{ansible_ssh_port}}
        username:  {{username}}
        password:  {{password}}

# undo hwtacacs server ip
  - name: "undo hwtacacs server ip"
    ce_aaa_server_host:
        state:  absent
        hwtacacs_template:  template
        hwtacacs_server_ip:  10.10.10.10
        hwtacacs_server_type:  Authorization
        hwtacacs_vpn_name:  _public_
        host:  {{inventory_hostname}}
        port:  {{ansible_ssh_port}}
        username:  {{username}}
        password:  {{password}}

```


---


## ce_acl
Manages base ACL configurations

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages base ACL configurations

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   no  |  present  | <ul><li>present</li>  <li>absent</li>  <li>delete_acl</li></ul> |  Specify desired state of the resource  |
| acl_name  |   no  |   | <ul></ul> |  ACL number or name.<br>For a numbered rule group, the value ranging from 2000 to 2999 indicates a basic ACL.<br>For a named rule group, the value is a string of 1 to 32 case-sensitive characters starting with a letter, spaces not supported.  |
| acl_num  |   no  |   | <ul>  </ul> |  ACL number.<br>The value is an integer ranging from 2000 to 2999.  |
| acl_step  |   no  |  | <ul>  </ul> |  ACL step.<br>The value is an integer ranging from 1 to 20. The default value is 5.  |
| acl_description  |   no  |  | <ul></ul> |  ACL description.<br>The value is a string of 1 to 127 characters.  |
| rule_name  |   no  |  | <ul></ul> |  Name of a basic ACL rule.<br>The value is a string of 1 to 32 characters.<br>The value is case-insensitive, and cannot contain spaces or begin with an underscore (_).  |
| rule_id  |   no  |    | <ul></ul> |  ID of a basic ACL rule in configuration mode.<br>The value is an integer ranging from 0 to 4294967294.  |
| rule_action  |   no  |  | <ul> <li>permit</li>  <li>deny</li> </ul> |  Matching mode of basic ACL rules  |
| source_ip  |   no  |  | <ul>  </ul> |  Source IP address.The value is a string of 0 to 255 characters.The default value is 0.0.0.0.<br>The value is in dotted decimal notation.  |
| src_mask  |   no  |  | <ul>  </ul> |  Mask of a source IP address.<br>The value is an integer ranging from 1 to 32.  |
| frag_type  |   no  |  | <ul>  </ul> |  Type of packet fragmentation  |
| vrf_name  |   no  |   | <ul>  </ul> |  VPN instance name.<br>The value is a string of 1 to 31 characters.The default value is _public_.  |
| time_range  |   no  |  | <ul>  </ul> |  Name of a time range in which an ACL rule takes effect.<br>The value is a string of 1 to 32 characters.<br>The value is case-insensitive, and cannot contain spaces. The name must start with an uppercase or lowercase letter. In addition, the word "all" cannot be specified as a time range name.  |
| rule_description  |   no  |  | <ul></ul> |  Description about an ACL rule.<br>The value is a string of 1 to 127 characters.  |
| log_flag  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Flag of logging matched data packets  |


#### Examples

```
# config ACL
  - name: "config ACL"
    ce_acl:
        state:  present
        acl_name:  2200
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}
# undo ACL
  - name: "undo ACL"
    ce_acl:
        state:  delete_acl
        acl_name:  2200
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}
# config ACL base rule
  - name: "config ACL base rule"
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
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}
# undo ACL base rule
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
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```


---


## ce_acl_advance
Manages advanced ACL configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages advanced ACL configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   no  |  present  | <ul> <li>present</li><li>absent</li><li>delete_acl</li> </ul> |  Specify desired state of the resource  |
| acl_name  |   no  |  | <ul></ul> |  ACL number or name  |
| acl_num  |   no  |  | <ul></ul> |  ACL number  |
| acl_step  |   no  |  | <ul></ul> |  ACL step  |
| acl_description  |   no  |   | <ul>  </ul> |  ACL description  |
| rule_name  |   no  |   | <ul></ul> |  Name of a basic ACL rule  |
| rule_id  |   no  |  | <ul></ul> |  ID of a basic ACL rule in configuration mode  |
| rule_action  |   no  |  | <ul><li>permit</li><li>deny</li></ul> |  Matching mode of basic ACL rules  |
| protocol  |   no  |  | <ul><li>ip</li><li>icmp</li><li>igmp</li><li>ipinip</li><li>tcp</li><li>udp</li><li>gre</li>  <li>ospf</li></ul> |  Protocol type  |
| source_ip  |   no  |    | <ul>  </ul> |  Source IP address  |
| src_mask  |   no  |    | <ul></ul> |  Source IP address mask  |
| src_pool_name  |   no  |  | <ul></ul> |  Name of a source pool  |
| dest_ip  |   yes  |  | <ul></ul> |  Destination IP address  |
| dest_mask  |   no  |  | <ul></ul> |  Destination IP address mask  |
| dest_pool_name  |   no  |   | <ul>  </ul> |  Name of a destination pool  |
| src_port_op  |   no  |    | <ul><li>lt</li><li>eq</li><li>gt</li><li>range</li></ul> |  Range type of the source port  |
| src_port_begin  |   no  |  | <ul></ul> |  Start port number of the source port  |
| src_port_end  |   no  |  | <ul></ul> |  End port number of the source port  |
| src_port_pool_name  |   no  |  | <ul></ul> |  Name of a source port pool  |
| dest_port_op  |   no  |    | <ul> <li>lt</li><li>eq</li><li>gt</li><li>range</li> </ul> |  Range type of the destination port  |
| dest_port_begin  |   no  |  | <ul></ul> |  Start port number of the destination port  |
| dest_port_end  |   no  |    | <ul>  </ul> |  End port number of the destination port  |
| dest_port_pool_name  |   no  |    | <ul></ul> |  Name of a destination port pool  |
| frag_type  |   no  |  | <ul><li>fragment</li><li>clear_fragment</li></ul> |  Type of packet fragmentation  |
| precedence  |   no  |  | <ul></ul> |  Data packets can be filtered based on the priority field  |
| tos  |   no  |  | <ul></ul> |  ToS value on which data packet filtering is based  |
| dscp  |   no  |  | <ul></ul> |  Differentiated Services Code Point  |
| icmp_name  |   no  |   | <ul> <li>unconfiged</li>  <li>echo</li> <li>echo-reply</li>  <li>fragmentneed-DFset</li><li>host-redirect</li>  <li>host-tos-redirect</li><li>host-unreachable</li>  <li>information-reply</li><li>information-request</li>  <li>net-redirect</li><li>net-tos-redirect</li>  <li>net-unreachable</li><li>parameter-problem</li>  <li>port-unreachable</li><li>protocol-unreachable</li>  <li>reassembly-timeout</li><li>source-quench</li>  <li>source-route-failed</li><li>timestamp-reply</li>  <li>timestamp-request</li><li>address-mask-reply</li>  <li>ttl-exceeded</li><li>address-mask-request</li><li>custom</li></ul> |  ICMP name  |
| icmp_type  |   no  |    | <ul></ul> |  ICMP type  |
| icmp_code  |   no  |  | <ul></ul> |  ICMP message code  |
| ttl_expired  |   no  |  | <ul><li>true</li><li>false</li></ul> |  Whether TTL Expired is matched, with the TTL value of 1  |
| vrf_name  |   no  |  | <ul></ul> |  VPN instance name  |
| syn_flag  |   no  |   | <ul> </ul> |  TCP flag value |
| tcp_flag_mask  |   no  |  | <ul></ul> |  TCP flag mask value  |
| established  |   no  |    | <ul> <li>true</li>  <li>false</li> </ul> |  Match established connections  |
| time_range  |   no  |    | <ul></ul> |  Name of a time range in which an ACL rule takes effect  |
| rule_description  |   no  |  | <ul></ul> |  Description about an ACL rule  |
| igmp_type  |   no  |  | <ul><li>host-query</li>  <li>mrouter-adver</li> <li>mrouter-solic</li>  <li>mrouter-termi</li><li>mtrace-resp</li><li>mtrace-route</li><li>v1host-report</li>  <li>v2host-report</li><li>v2leave-group</li>  <li>v3host-report</li></ul> |  Internet Group Management Protocol  |
| log_flag  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Flag of logging matched data packets  |


#### Examples

```
# config ACL
  - name: "config ACL"
    ce_acl:
        state:  present
        acl_name:  3200
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo ACL
  - name: "undo ACL"
    ce_acl:
        state:  delete_acl
        acl_name:  3200
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config ACL advance rule
  - name: "config ACL advance rule"
    ce_acl:
        state:  present
        acl_name:  test
        rule_name:  test_rule
        rule_id:  111
        rule_action:  permit
        protocol:  tcp
        source_ip:  10.10.10.10
        src_mask:  24
        frag_type:  fragment
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo ACL advance rule
  - name: "undo ACL advance rule"
    ce_acl:
        state:  absent
        acl_name:  test
        rule_name:  test_rule
        rule_id:  111
        rule_action:  permit
        protocol:  tcp
        source_ip:  10.10.10.10
        src_mask:  24
        frag_type:  fragment
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```


---


## ce_acl_interface
Manages applying ACLs to interfaces

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages applying ACLs to interfaces

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| acl_name  |   yes  |  | <ul></ul> |  ACL number or name  |
| interface  |   yes  |  | <ul></ul> |  Interface name  |
| direction  |   yes  |  | <ul><li>inbound</li>  <li>outbound</li></ul> |  Direction ACL to be applied in on the interface |
| state  |   no  |  present  | <ul> <li>present</li>  <li>absent</li> </ul> |  Specify desired state of the resource  |


#### Examples

```
# apply acl to interface
  - name: "apply acl to interface"
    ce_acl_interface:
        state:  present
        acl_name:  2000
        interface:  40GE2/0/1
        direction:  outbound
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo acl from interface
  - name: "undo acl from interface"
    ce_acl_interface:
        state:  absent
        acl_name:  2000
        interface:  40GE2/0/1
        direction:  outbound
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```


---


## ce_bgp
Manages BGP configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages BGP configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   no  |  present | <ul><li>present</li>  <li>absent</li></ul> |  Specify desired state of the resource  |
| as_number  |   no  |   | <ul>  </ul> |  Local AS number  |
| graceful_restart  |   |  | <ul><li>true</li>  <li>false</li></ul> |  Enable GR of the BGP speaker in the specified address family, peer address, or peer group  |
| time_wait_for_rib  |   no  |    | <ul>  </ul> |  Period of waiting for the End-Of-RIB flag  |
| as_path_limit  |   no  |    | <ul>  </ul> |  Maximum number of AS numbers in the AS_Path attribute  |
| check_first_as  |   no  |  | <ul><li>true</li>  <li>false</li></ul></ul> |  Check the first AS in the AS_Path of the update messages from EBGP peers  |
| confed_id_number  |   no  |  | <ul></ul> |  Confederation ID  |
| confed_nonstanded  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Configure the device to be compatible with devices in a nonstandard confederation |
| bgp_rid_auto_sel  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  The function to automatically select router IDs for all VPN BGP instances is enabled  |
| keep_all_routes  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, the system stores all route update messages received from all peers (groups) after BGP connection setup.<br> If the value is false, the system stores only BGP update messages that are received from peers and pass the configured import policy.|
| memory_limit  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Support BGP RIB memory protection  |
| gr_peer_reset  |   no  |    | <ul> <li>present</li>  <li>absent</li> </ul> |  Peer disconnection through GR  |
| is_shutdown  |   no  |  | <ul><li>true</li><li>false</li></ul> |  Interrupt BGP all neighbor  |
| suppress_interval  |   no  |  | <ul></ul> |  Suppress interval  |
| hold_interval  |   no  |  | <ul></ul> |  Hold interval  |
| clear_interval  |   no  |  | <ul></ul> |  Clear interval  |
| confed_peer_as_num  |   no  |   | <ul> </ul> |  Confederation AS number, in two-byte or four-byte format  |
| vrf_name  |   no  |  | <ul></ul> |  Name of a BGP instance |
| vrf_rid_auto_sel  |   no  |  | <ul> <li>true</li>  <li>false</li> </ul> |  If the value is true, VPN BGP instances are enabled to automatically select router IDs. <br>If the value is false, VPN BGP instances are disabled from automatically selecting router IDs.  |
| router_id  |   no  |  | <ul></ul> |  ID of a router that is in IPv4 address format  |
| keepalive_time  |   no  |  | <ul></ul> |  If the value of a timer changes, the BGP peer relationship between the routers is disconnected  |
| hold_time  |   no  |  | <ul></ul> |  Hold time, in seconds  |
| min_hold_time  |   no  |   | <ul>  </ul> |  Min hold time, in seconds  |
| conn_retry_time  |   no  |  | <ul></ul> |  Connect retry interval   |
| ebgp_if_sensitive  |   no  |  | <ul></ul> |  If the value is true, After the fast EBGP interface awareness function is enabled, EBGP sessions on an interface are deleted immediately when the interface goes Down. <br> If the value is  false, After the fast EBGP interface awareness function is enabled, EBGP sessions on an interface are not deleted immediately when the interface goes Down.  |
| default_af_type  |   no  |  | <ul></ul> |  Type of a created address family, which can be IPv4 unicast or IPv6 unicast  |


#### Examples

```
# enable BGP
  - name: "enable BGP"
    ce_bgp:
        state:  present
        as_number:  100
        confed_id_number:  250
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# disable BGP
  - name: "disable BGP"
    ce_bgp:
        state:  absent
        as_number:  100
        confed_id_number:  250
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# create confederation peer AS num
  - name: "create confederation peer AS num"
    ce_bgp:
        state:  present
        confed_peer_as_num:  260
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}

# undo confederation peer AS num
  - name: "undo confederation peer AS num"
    ce_bgp:
        state:  absent
        confed_peer_as_num:  260
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}

```


---


## ce_bgp_af
Manages BGP Address-family configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages BGP Address-family configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |    |  present | <ul><li>present</li><li>absent</li> </ul></ul> |  Specify desired state of the resource  |
| vrf_name  |    |  _public_ | <ul></ul> |  Name of a BGP instance. The name is a case-sensitive string of characters  |
| af_type  |  yes  |    | <ul> <li>ipv4uni</li>  <li>ipv4multi</li> <li>ipv4vpn</li><li>ipv6uni</li><li>ipv6vpn</li><li>evpn</li></ul> |  Address family type of a BGP instance  |
| max_load_ibgp_num  |   no  |  | <ul></ul> |  Specify the maximum number of equal-cost IBGP routes  |
| ibgp_ecmp_nexthop_changed  |   no  |    | <ul><li>true</li><li>false</li>  </ul> |  If the value is true, the next hop of an advertised route is changed to the advertiser itself in IBGP load-balancing scenarios. <br> If the value is false, the next hop of an advertised route is not changed to the advertiser itself in IBGP load-balancing scenarios. |
| max_load_ebgp_num  |   no  |  | <ul></ul> |  Specify the maximum number of equal-cost EBGP routes  |
| ebgp_ecmp_nexthop_changed  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, the next hop of an advertised route is changed to the advertiser itself in EBGP load-balancing scenarios.<br> If the value is false, the next hop of an advertised route is not changed to the advertiser itself in EBGP load-balancing scenarios.  |
| maximum_load_balance  |   no  |  | <ul></ul> |  Specify the maximum number of equal-cost routes in the BGP routing table  |
| ecmp_nexthop_changed  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, the next hop of an advertised route is changed to the advertiser itself in BGP load-balancing scenarios.<br> If the value is false, the next hop of an advertised route is not changed to the advertiser itself in BGP load-balancing scenarios. |
| default_local_pref  |   no  |   | <ul>  </ul> |  Set the Local-Preference attribute. The value is an integer.  |
| default_med  |   no  |  | <ul></ul> |  Specify the Multi-Exit-Discriminator (MED) of BGP routes  |
| default_rt_import_enable  |   no  |   | <ul> <li>true</li>  <li>false</li> </ul> |  If the value is true, importing default routes to the BGP routing table is allowed.<br> If the value is false, importing default routes to the BGP routing table is not allowed. |
| router_id  |   no  |  | <ul></ul> |  ID of a router that is in IPv4 address format  |
| vrf_rid_auto_sel  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, VPN BGP instances are enabled to automatically select router IDs. <br>If the value is false, VPN BGP instances are disabled from automatically selecting router IDs.  |
| nexthop_third_party  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, the third-party next hop function is enabled.<br>If the value is false, the third-party next hop function is disabled.  |
| summary_automatic  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, automatic aggregation is enabled for locally imported routes.<br> If the value is false, automatic aggregation is disabled for locally imported routes. |
| auto_frr_enable  |   no  |   | <ul> <li>true</li><li>false</li> </ul> |  If the value is true, BGP auto FRR is enabled.<br> If the value is false, BGP auto FRR is disabled. |
| load_balancing_as_path_ignore  |   no  |  | <ul><li>true</li><li>false</li></ul> |  load balancing as path ignore  |
| rib_only_enable  |   no  |   | <ul> <li>true</li><li>false</li> </ul> |  If the value is true, BGP routes cannot be advertised to the IP routing table.<br>If the value is false, Routes preferred by BGP are advertised to the IP routing table. |
| rib_only_policy_name  |   no  |  | <ul></ul> |  Specify the name of a routing policy  |
| active_route_advertise  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, BGP is enabled to advertise only optimal routes in the RM to peers. <br> If the value is false, BGP is not enabled to advertise only optimal routes in the RM to peers.  |
| as_path_neglect  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, the AS path attribute is ignored when BGP selects an optimal route.<br> If the value is false, the AS path attribute is not ignored when BGP selects an optimal route. |
| med_none_as_maximum  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, when BGP selects an optimal route, the system uses 4294967295 as the MED value of a route if the route's attribute does not carry a MED value.<br> If the value is false, the system uses 0 as the MED value of a route if the route's attribute does not carry a MED value.|
| router_id_neglect  |   no  |  | <ul> <li>true</li><li>false</li> </ul> |  If the value is true, the router ID attribute is ignored when BGP selects the optimal route.<br> If the value is false, the router ID attribute is not ignored when BGP selects the optimal route.  |
| igp_metric_ignore  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, the metrics of next-hop IGP routes are not compared when BGP selects an optimal route.<br> If the value is false, the metrics of next-hop IGP routes are not compared when BGP selects an optimal route. |
| always_compare_med  |   no  |   | <ul> <li>true</li><li>false</li> </ul> |  If the value is true, the MEDs of routes learned from peers in different autonomous systems are compared when BGP selects an optimal route. <br>If the value is false, the MEDs of routes learned from peers in different autonomous systems are not compared when BGP selects an optimal route.  |
| determin_med  |   no  |  | <ul><li>true</li><li>false</li> </ul> |  If the value is true, BGP deterministic-MED is enabled.<br> If the value is false, BGP deterministic-MED is disabled.|
| preference_external  |   no  |  | <ul></ul> |  Set the protocol priority of EBGP routes |
| preference_internal  |   no  |  | <ul></ul> |  Set the protocol priority of IBGP routes |
| preference_local  |   no  |  | <ul></ul> |  Set the protocol priority of a local BGP route  |
| prefrence_policy_name  |   no  |  | <ul></ul> |  Set a routing policy to filter routes so that a configured priority is applied to the routes that match the specified policy  |
| reflect_between_client  |   no  |   | <ul> <li>true</li>  <li>false</li> </ul> | If the value is true, route reflection is enabled between clients.<br> If the value is false, route reflection is disabled between clients. |
| reflector_cluster_id  |   no  |  | <ul></ul> |  Set a cluster ID |
| reflector_cluster_ipv4  |   no  |  | <ul></ul> |  Set a cluster ip  |
| rr_filter_number  |   no  |  | <ul></ul> |  Set the number of the extended community filter supported by an RR group  |
| policy_vpn_target  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, VPN-Target filtering function is performed for received VPN routes.<br> If the value is false, VPN-Target filtering function is not performed for received VPN routes. |
| next_hop_sel_depend_type  |   no  |    | <ul> <li>default</li><li>dependTunnel</li><li>dependIp</li> </ul> |  Next hop select depend type  |
| nhp_relay_route_policy_name  |   no  |  | <ul></ul> |  Specify the name of a route-policy for route iteration  |
| ebgp_if_sensitive  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, after the fast EBGP interface awareness function is enabled, EBGP sessions on an interface are deleted immediately when the interface goes Down.<br>If the value is false, after the fast EBGP interface awareness function is enabled, EBGP sessions on an interface are not deleted immediately when the interface goes Down.  |
| reflect_chg_path  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the route reflector is enabled to modify route path attributes based on an export policy.<br> If the value is false, the route reflector is disabled from modifying route path attributes based on an export policy.  |
| add_path_sel_num  |   no  |  | <ul></ul> |  Number of Add-Path routes  |
| route_sel_delay  |   no  |   | <ul> </ul> |  Route selection delay  |
| allow_invalid_as  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Allow routes with BGP origin AS validation result Invalid to be selected  |
| policy_ext_comm_enable  |   no  |  | <ul> <li>true</li>  <li>false</li> </ul> |  If the value is true, modifying extended community attributes is allowed. <br> If the value is false, modifying extended community attributes is not allowed.  |
| supernet_uni_adv  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the function to advertise supernetwork unicast routes is enabled.<br>If the value is false, the function to advertise supernetwork unicast routes is disabled.  |
| supernet_label_adv  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the function to advertise supernetwork label is enabled.<br>If the value is false, the function to advertise supernetwork label is disabled.  |
| ingress_lsp_policy_name  |   no  |  | <ul></ul> |  Ingress lsp policy name.  |
| originator_prior  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Originator prior  |
| lowest_priority  |   no  |   | <ul> <li>true</li>  <li>false</li> </ul> |  If the value is true, enable reduce priority to advertise route.<br>If the value is false, disable reduce priority to advertise route.  |
| relay_delay_enable  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, relay delay enable.<br>If the value is false, relay delay disable.  |
| import_protocol  |   no  |  | <ul><li>direct</li>  <li>ospf</li><li>isis</li>  <li>static</li><li>rip</li>  <li>ospfv3</li><li>ripng</li></ul> |  Routing protocol from which routes can be imported  |
| import_process_id  |   no  |  | <ul></ul> |  Process ID of an imported routing protocol  |
| network_address  |   no  |  | <ul></ul> |  Specify the IP address advertised by BGP  |
| mask_len  |   no  |   | <ul> </ul> |  Specify the mask length of an IP address |

#### Examples

```
# config BGP Address_Family
  - name: "config BGP Address_Family"
    ce_bgp_af:
        state:  present
        vrf_name:  js
        af_type:  ipv4uni
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo BGP Address_Family
  - name: "undo BGP Address_Family"
    ce_bgp_af:
        state:  absent
        vrf_name:  js
        af_type:  ipv4uni
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config import route
  - name: "config import route"
    ce_bgp_af:
        state:  present
        vrf_name:  js
        af_type:  ipv4uni
        import_protocol:  ospf
        import_process_id:  123
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}

# undo import route
  - name: "undo import route"
    ce_bgp_af:
        state:  absent
        vrf_name:  js
        af_type:  ipv4uni
        import_protocol:  ospf
        import_process_id:  123
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}

# config network route
  - name: "config network route"
    ce_bgp_af:
        state:  present
        vrf_name:  js
        af_type:  ipv4uni
        network_address:  1.1.1.1
        mask_len:  24
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}

# undo network route
  - name: "undo network route"
    ce_bgp_af:
        state:  absent
        vrf_name:  js
        af_type:  ipv4uni
        network_address:  1.1.1.1
        mask_len:  24
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}

```


---


## ce_bgp_neighbor
Manages BGP peer configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages BGP peer configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   no  | present | <ul><li>present</li>  <li>absent</li></ul> |  Specify desired state of the resource  |
| vrf_name  |   no  | _public_ | <ul></ul> |  Name of a BGP instance  |
| peer_addr  |   yes  |  | <ul>  </ul> |  Connection address of a peer, which can be an IPv4 or IPv6 address  |
| remote_as  |   yes  |  | <ul></ul> |  AS number of a peer |
| description  |   no  |   | <ul>  </ul> |  Description of a peer, which can be letters or digits  |
| fake_as  |   no  |  | <ul></ul> |  Fake AS number that is specified for a local peer  |
| dual_as  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the EBGP peer can use either a fake AS number or the actual AS number.<br>If the value is false, the EBGP peer can only use a fake AS number. |
| conventional  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the router has all extended capabilities.<br>If the value is false, the router does not have all extended capabilities  |
| route_refresh  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, BGP is enabled to advertise REFRESH packets.<br>If the value is false, the route refresh function is enabled.  |
| is_ignore  |   no  |   | <ul><li>true</li>  <li>false</li> </ul> |  If the value is true, the session with a specified peer is torn down and all related routing entries are cleared. <br>If the value is false, the session with a specified peer is retained.  |
| local_if_name  |   no  |  | <ul></ul> |  Name of a source interface that sends BGP packets  |
| ebgp_max_hop  |   no  |    | <ul> </ul> |  Maximum number of hops in an indirect EBGP connection  |
| valid_ttl_hops  |   no  |  | <ul></ul> |  Enable GTSM on a peer or peer group  |
| connect_mode  |   no  |  | <ul></ul> |  The value can be Connect-only, Listen-only, or Both  |
| is_log_change  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, BGP is enabled to record peer session status and event information. <br>If the value is false, BGP is disabled from recording peer session status and event information  |
| pswd_type  |   no  |  | <ul><li>null</li>  <li>cipher</li><li>simple</li></ul> |  Enable BGP peers to establish a TCP connection and perform the Message Digest 5 (MD5) authentication for BGP messages  |
| pswd_cipher_text  |   no  |    | <ul>  </ul> |  The character string in a password identifies the contents of the password, spaces not supported  |
| keep_alive_time  |   no  |  | <ul></ul> |  Specify the Keepalive time of a peer or peer group  |
| hold_time  |   no  |    | <ul>  </ul> |  Specify the Hold time of a peer or peer group |
| min_hold_time  |   no  |  | <ul></ul> |  Specify the Min hold time of a peer or peer group  |
| key_chain_name  |   no  |  | <ul></ul> |  Specify the Keychain authentication name used when BGP peers establish a TCP connection  |
| conn_retry_time  |   no  |  | <ul></ul> |  ConnectRetry interval  |
| tcp_MSS  |   no  |  | <ul></ul> |  Maximum TCP MSS value used for TCP connection establishment for a peer  |
| mpls_local_ifnet_disable  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, peer create MPLS Local IFNET disable.<br>If the value is false, peer create MPLS Local IFNET enable  |
| prepend_global_as  |   no  |  | <ul></ul> |  Add the global AS number to the Update packets to be advertised  |
| prepend_fake_as  |   no  |  | <ul></ul> |  Add the Fake AS number to received Update packets  |
| is_bfd_block  |   no  |    | <ul> <li>true</li>  <li>false</li> </ul> |  If the value is true, peers are enabled to inherit the BFD function from the peer group.<br>If the value is false, peers are disabled to inherit the BFD function from the peer group. |
| multiplier  |   no  |  | <ul></ul> |  Specify the detection multiplier  |
| is_bfd_enable  |   no  |    | <ul><li>true</li>  <li>false</li>  </ul> |  If the value is true, BFD is enabled.<br>If the value is false, BFD is disabled |
| rx_interval  |   no  |  | <ul></ul> |  Specify the minimum interval at which BFD packets are received  |
| tx_interval  |   no  |  | <ul></ul> |  Specify the minimum interval at which BFD packets are sent  |
| is_single_hop  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the system is enabled to preferentially use the single-hop mode for BFD session setup between IBGP peers.<br>If the value is false, the system is disabled from preferentially using the single-hop mode for BFD session setup between IBGP peers.  |

#### Examples

```
# config bgp peer
  - name: "config bgp peer"
    ce_bgp_neighbor:
        state:  present
        peer_addr:  192.168.10.10
        remote_as:  500
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# delete bgp peer
  - name: "config bgp route id"
    ce_bgp_neighbor:
        state:  absent
        peer_addr:  192.168.10.10
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```


---


## ce_bgp_neighbor_af
Manages BGP neighbor Address-family configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages BGP neighbor Address-family configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   no  | present | <ul><li>present</li>  <li>absent</li></ul> |  Specify desired state of the resource  |
| vrf_name  |   no  | _public_ | <ul></ul> |  Name of a BGP instance  |
| af_type  |   yes  |   | <ul> <li>ipv4uni</li><li>ipv4multi</li><li>ipv4uni</li><li>ipv6uni</li><li>ipv6vpn</li>  <li>evpn</li> </ul> |  Address family type of a BGP instance  |
| remote_address  |   yes  |  | <ul></ul> |  IPv4 or IPv6 peer connection address  |
| advertise_irb  |   no  |    | <ul> <li>true</li>  <li>false</li> </ul> |  If the value is true, advertised IRB routes are distinguished.<br>If the value is false, advertised IRB routes are not distinguished  |
| advertise_arp  |   no  |  | <ul><li>true</li>  <li>false</li> </ul> |  If the value is true, advertised ARP routes are distinguished.<br>If the value is false, advertised ARP routes are not distinguished.  |
| advertise_remote_nexthop  |   no  |  | <ul><li>true</li>  <li>false</li> </ul> |  If the value is true, the remote next-hop attribute is advertised to peers.<br>If the value is false, the remote next-hop attribute is not advertised to any peers.  |
| advertise_community  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the community attribute is advertised to peers.<br>If the value is false, the community attribute is not advertised to peers.  |
| advertise_ext_community  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the extended community attribute is advertised to peers.<br>If the value is false, the extended community attribute is not advertised to peers. |
| discard_ext_community  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the extended community attribute in the peer route information is discarded.<br>If the value is false, the extended community attribute in the peer route information is not discarded.  |
| allow_as_loop_enable  |   no  |   | <ul> <li>true</li>  <li>false</li></ul> |  If the value is true, repetitive local AS numbers are allowed.<br>If the value is false, repetitive local AS numbers are not allowed.  |
| allow_as_loop_limit  |   no  |  | <ul></ul> |  Set the maximum number of repetitive local AS number  |
| keep_all_routes  |   no  |   | <ul> <li>true</li>  <li>false</li> </ul> |  If the value is true, the system stores all route update messages received from all peers (groups) after BGP connection setup.<br>If the value is false, the system stores only BGP update messages that are received from peers and pass the configured import policy.  |
| nexthop_configure  |   no  |  | <ul><li>null</li>  <li>local</li><li>invariable</li></ul> |  null, The next hop is not changed.<br>local, The next hop is changed to the local IP address.<br>invariable, Prevent the device from changing the next hop of each imported IGP route when advertising it to its BGP peers.  |
| preferred_value  |   no  |  | <ul></ul> |  Assign a preferred value for the routes learned from a specified peer  |
| public_as_only  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, sent BGP update messages carry only the public AS number but do not carry private AS numbers.<br>If the value is false, sent BGP update messages can carry private AS numbers.  |
| public_as_only_force  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, sent BGP update messages carry only the public AS number but do not carry private AS numbers.<br>If the value is false, sent BGP update messages can carry private AS numbers.  |
| public_as_only_limited  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  limited use public as number  |
| af_type  |   no  |    | <ul> <li>true</li>  <li>false</li> </ul> |  Dictates connection protocol to use for NX-API  |
| public_as_only_replace  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  private as replaced by public as number  |
| public_as_only_skip_peer_as  |   no  |   | <ul> <li>true</li>  <li>false</li> </ul> |  Manages desired state of the resource  |
| route_limit  |   no  |  | <ul></ul> |  Configure the maximum number of routes that can be accepted from a peer  |
| route_limit_percent  |   no  |  | <ul></ul> |  Specify the percentage of routes when a router starts to generate an alarm  |
| route_limit_type  |   no  |  | <ul><li>noparameter</li>  <li>alertOnly</li><li>idleForever</li>  <li>idleTimeout</li></ul> |  noparameter, After the number of received routes exceeds the threshold and the timeout timer expires,no action.<br>alertOnly, An alarm is generated and no additional routes will be accepted if the maximum number of routes allowed have been received.<br>idleForever, The connection that is interrupted is not automatically re-established if the maximum number of routes allowed have been received.<br>idleTimeout, After the number of received routes exceeds the threshold and the timeout timer expires, the connection that is interrupted is automatically re-established.  |
| route_limit_idle_timeout  |   no  |  | <ul><li>present</li>  <li>absent</li></ul> |  Specify the value of the idle-timeout timer to automatically reestablish the connections after they are cut off when the number of routes exceeds the set threshold.  |
| rt_updt_interval  |   no  |  | <ul></ul> |  Specify the minimum interval at which Update packets are sent. The value is an integer, in seconds |
| redirect_ip  |   no  |   | <ul> <li>true</li>  <li>false</li> </ul> |  Dredirect ip |
| redirect_ip_vaildation  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  redirect ip vaildation  |
| reflect_client  |   no  |   | <ul><li>true</li><li>false</li> </ul> | If the value is true, the local device functions as the route reflector and a peer functions as a client of the route reflector. <br>If the value is false, the route reflector and client functions are not configured.  |
| substitute_as_enable  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the function to replace a specified peer's AS number in the AS-Path attribute with the local AS number is enabled.<br>If the value is false, the function to replace a specified peer's AS number in the AS-Path attribute with the local AS number is disabled  |
| import_rt_policy_name  |   no  |  | <ul></ul> |  Specify the filtering policy applied to the routes learned from a peer  |
| export_rt_policy_name  |   no  |  | <ul></ul> |  Specify the filtering policy applied to the routes to be advertised to a peer  |
| import_pref_filt_name  |   no  |  | <ul></ul> |  Specify the IPv4 filtering policy applied to the routes received from a specified peer  |
| export_pref_filt_name  |   no  |  | <ul></ul> |  Specify the IPv4 filtering policy applied to the routes to be advertised to a specified peer  |
| import_as_path_filter  |   no  |  | <ul></ul> |  Apply an AS_Path-based filtering policy to the routes received from a specified peer |
| export_as_path_filter  |   no  |  | <ul></ul> |  Apply an AS_Path-based filtering policy to the routes to be advertised to a specified peer  |
| import_as_path_name_or_num  |   no  |  | <ul></ul> |  A routing strategy based on the AS path list for routing received by a designated peer  |
| export_as_path_name_or_num  |   no  |  | <ul> </ul> |  Application of a AS path list based filtering policy to the routing of a specified peer  |
| import_acl_name_or_num  |   no  |  | <ul></ul> |  Apply an IPv4 ACL-based filtering policy to the routes received from a specified peer  |
| export_acl_name_or_num  |   no  |  | <ul> </ul> |  Apply an IPv4 ACL-based filtering policy to the routes to be advertised to a specified peer  |
| ipprefix_orf_enable  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, the address prefix-based Outbound Route Filter (ORF) capability is enabled for peers. <br>If the value is false, the address prefix-based Outbound Route Filter (ORF) capability is disabled for peers.  |
| is_nonstd_ipprefix_mod  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  If the value is true, Non-standard capability codes are used during capability negotiation.<br>If the value is false, RFC-defined standard ORF capability codes are used during capability negotiation. |
| orftype  |   no  |  | <ul></ul> |  ORF Type  |
| orf_mode  |   no  |  | <ul><li>null</li><li>receive</li><li>send</li><li>both</li></ul> |  null, Default value.<br>receive, ORF for incoming packets.<br>send, ORF for outgoing packets.<br>both, ORF for incoming and outgoing packets.  |
| soostring  |   no  |  | <ul></ul> |  Configure the Site-of-Origin (SoO) extended community attribute  |
| default_rt_adv_enable  |   no  |  | <ul><li>true</li>  <li>false</li> </ul> |  If the value is true, the function to advertise default routes to peers is enabled.<br> If the value is false, the function to advertise default routes to peers is disabled.  |
| default_rt_adv_policy  |   no  |  | <ul></ul> |  Specify the name of a used policy. The value is a string |
| default_rt_match_mode  |   no  |  | <ul> <li>null</li>  <li>matchall</li><li>matchany</li> </ul> | null, Null.<br>matchall, Advertise the default route if all matching conditions are met.<br>matchany, Advertise the default route if any matching condition is met.  |
| add_path_mode  |   no  |  | <ul><li>null</li><li>receive</li><li>send</li><li>both</li></ul> |  null, Null.<br>receive, Support receiving Add-Path routes.<br>send, Support sending Add-Path routes.<br>both, Support receiving and sending Add-Path routes.  |
| adv_add_path_num  |   no  |  | <ul></ul> |  The number of addPath advertise route  |
| origin_as_valid  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, Application results of route announcement.<br>If the value is false, Routing application results are not notified.  |
| vpls_enable  |   no  |  | <ul><li>true</li><li>false</li></ul> |  If the value is true, vpls enable.<br>If the value is false, vpls disable.  |
| vpls_ad_disable  |   no  |  | <ul><li>true</li>  <li>false</li></ul> | If the value is true, enable vpls-ad.<br>If the value is false, disable vpls-ad.  |
| update_pkt_standard_compatible  |   no  |  | <ul><li>true</li><li>false</li></ul> |  DIf the value is true, When the vpnv4 multicast neighbor receives and updates the message, the message has no label.<br>If the value is false, When the vpnv4 multicast neighbor receives and updates the message, the message has label.  |

#### Examples

```
# config BGP peer Address_Family
  - name: "config BGP peer Address_Family"
    ce_bgp_neighbor_af:
        state:  present
        vrf_name:  js
        af_type:  ipv4uni
        remote_address:  192.168.10.10
        nexthop_configure:  null
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo BGP peer Address_Family
  - name: "undo BGP peer Address_Family"
    ce_bgp_neighbor_af:
        state:  absent
        vrf_name:  js
        af_type:  ipv4uni
        remote_address:  192.168.10.10
        nexthop_configure:  null
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```


---


## ce_command
Run arbitrary command

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Run arbitrary command

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| commands  |   no  |  | <ul></ul> |  The commands to send to the remote HUAWEI CloudEngine device over the configured provider  |
| wait_for  |   no  |  | <ul> <li>waitfor</li>  |  Specifies what to evaluate from the output of the command and what conditionals to apply |
| match  |   no  |  | <ul></ul> |  The I(match) argument is used in conjunction with the I(wait_for) argument to specify the match policy.  |
| retries  |   no  |    | <ul> </ul> |  Specifies the number of retries a command should by tried before it is considered failed.  |
| interval  |   no  |  | <ul></ul> |  Configures the interval in seconds to wait between retries of the command.  |


#### Examples

```
# Note: examples below use the following provider dict to handle transport and authentication to the node.
vars:
  cli:
    host: "{{ inventory_hostname }}"
    username: admin
    password: admin
    transport: cli

- name: run display version on remote devices
  ce_command:
    commands: display version
    provider: "{{ cli }}"

- name: run display version and check to see if output contains HUAWEI
  ce_command:
    commands: display version
    wait_for: result[0] contains HUAWEI
    provider: "{{ cli }}"

- name: run multiple commands on remote nodes
  ce_command:
    commands:
      - display version
      - display device
    provider: "{{ cli }}"

- name: run multiple commands and evaluate the output
  ce_command:
    commands:
      - display version
      - display device
    wait_for:
      - result[0] contains HUAWEI
      - result[1] contains Device
    provider: "{{ cli }}"

- name: run commands and specify the output format
  ce_command:
    commands:
      - command: display version
        output: version info
    provider: "{{ cli }}"
```


---


## ce_config
Manages configuration sections

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages configuration sections

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| lines  |   no  |  | <ul></ul> |  The ordered set of commands that should be configured in the section  |
| parents  |   no  |   | <ul></ul> |  The ordered set of parents that uniquely identify the section the commands should be checked against |
| src  |   no  |  | <ul></ul> |  IP Address or hostname (resolvable by Ansible control host) of the target NX-API enabled switch  |
| before  |   no  |   | <ul></ul> |  The ordered set of commands to push on to the command stack if a change needs to be made.  |
| after  |   no  |  | <ul></ul> |  The ordered set of commands to append to the end of the command stack if a change needs to be made  |
| match  |   no  |  | <ul><li>line</li> <li>strict</li><li>exact</li> <li>none</li></ul> |  Instructs the module on the way to perform the matching of the set of commands against the current device config |
| replace  |   no  |  | <ul><li>line</li>  <li>block</li></ul> |  Instructs the module on the way to perform the configuration on the device  |
| backup  |   no  |   | <ul><li>yes</li> <li>no</li></ul> |  This argument will cause the module to create a full backup of the current C(current-configuration) from the remote device before any changes are made  |
| config  |   no  |  | <ul></ul> |  The module, by default, will connect to the remote device and retrieve the current running-config to use as a base for comparing against the contents of source  |
| defaults  |   no  |  | <ul></ul> |  The I(defaults) argument will influence how the running-config is collected from the device. |
| save  |   no  |  | <ul></ul> |  The C(save) argument instructs the module to save the running-config to startup-config  |


#### Examples

```
# Note: examples below use the following provider dict to handle transport and authentication to the node.
vars:
  cli:
    host: "{{ inventory_hostname }}"
    username: admin
    password: admin
    transport: cli

- name: configure top level configuration and save it
  cd_config:
    lines: sysname {{ inventory_hostname }}
    save: yes
    provider: "{{ cli }}"

- cd_config:
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

- cd_config:
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
Manages global DLDP configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages global DLDP configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| enable  |   no  |  | <ul></ul> |  Set global DLDP enable state  |
| work_mode  |   no  |    | <ul> <li>enhance</li>  <li>normal</li> </ul> |  Set global DLDP work-mode  |
| time_internal  |   no  |  | <ul></ul> |  Set advertisement message time interval in seconds  |
| auth_mode  |   no  |  | <ul><li>md5</li><li>simple</li><li>sha</li><li>hmac-sha256</li><li>none</li></ul> |  Specifies authentication algorithm of DLDP  |
| auth_pwd  |   no  |  | <ul></ul> |  Specifies authentication password  |
| reset  |   no  |    | <ul> <li>true</li>  <li>false</li> </ul> |  Specify whether reset DLDP state of disabled interfaces  |


#### Examples

```
# Configure global DLDP enable state
- ce_dldp:
    enable: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure DLDP work-mode and ensure global DLDP state is already enabled
- ce_dldp:
    enable: true
    work_mode: normal
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure advertisement message time interval in seconds and ensure global DLDP state is already enabled
- ce_dldp:
    enable: true
    time_interval: 6
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure a DLDP authentication mode and ensure global DLDP state is already enabled
- ce_dldp:
    enable: true
    auth_mode: md5
    auth_pwd: abc
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Reset DLDP state of disabled interfaces and ensure global DLDP state is already enabled
- ce_dldp:
    enable: true
    reset: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"


```
#### Notes

- The relevant configurations will be deleted if DLDP is disabled using enable=false.
- When using auth_mode=none, it will restore the default DLDP authentication mode(By default,DLDP packets are not authenticated.).
- By default, the working mode of DLDP is enhance, so you are advised to use work_mode=enhance to restore defualt DLDP working mode.
- The default interval for sending Advertisement packets is 5 seconds, so you are advised to use time_interval=5 to restore defualt DLDP interval.

---


## ce_dldp_interface
Manages interface specific VRF configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages interface DLDP configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| interface  |   no  |  | <ul></ul> |  Must be fully qualified interface name, i.e. GE1/0/1, 10GE1/0/1, 40GE1/0/22, 100GE1/0/1  |
| enable  |   no  |    | <ul> <li>true</li>  <li>false</li> </ul> |  Set interface DLDP enable state |
| mode_enable  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Set DLDP compatible-mode enable state |
| local_mac  |   no  |    | <ul>  </ul> |  Set the source MAC address for DLDP packets sent in the DLDP-compatible mode  |
| reset  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Specify whether reseting interface DLDP state  |
| state  |   no  |  | <ul></ul> |  Manage the state of the resource  |


#### Examples

```
# Configure interface DLDP enable state and ensure global dldp enable is turned on
- ce_dldp_interface:
    enable: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configuire interface DLDP compatible-mode enable state  and ensure interface DLDP state is already enabled
- ce_dldp_interface:
    enable: true
    mode_enable:true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configuire the source MAC address for DLDP packets sent in the DLDP-compatible mode and ensure interface DLDP state and compatible-mode enable state is already enabled
- ce_dldp_interface:
    enable: true
    mode_enable:true
	local_mac=aa-aa-aa
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
# Reset DLDP state of specified interface and ensure interface DLDP state is already enabled
- ce_dldp_interface:
    enable: true
    reset=true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Unconfigure interface DLDP local mac addreess when C(state=absent)
- ce_dldp_interface:
    state=absent
    local_mac=aa-aa-aa
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
```
#### Notes

- If C(state=present, enable=false), interface DLDP enable will be turned off and related interface DLDP confuration will be cleared.
- If C(state=absent), only local_mac is supported to configure.


---


## ce_eth_trunk
Manages Eth-Trunk interfaces

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages Eth-Trunk interfaces

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| trunk_id  |   yes  |  | <ul></ul> |  Eth-Trunk interface number.The value is an integer. |
| mode  |   no  |    | <ul> <li>manual</li><li>lacp-dynamic</li><li>lacp-static</li></ul> |  Specifies the working mode of an Eth-Trunk interface |
| min_links  |   no  |  | <ul></ul> |  Specifies the minimum number of Eth-Trunk member links in the Up state  |
| hash_type  |   no  |    | <ul><li>src-dst-ip</li><li>src-dst-mac</li><li>enhanced</li><li>dst-ip</li><li>dst-mac</li>  <li>src-ip</li><li>src-mac</li>  </ul> |  Hash algorithm used for load balancing among Eth-Trunk member interfaces  |
| members  |   no  |  | <ul></ul> |  List of interfaces that will be managed in a given Eth-Trunk  |
| force  |   no  | false | <ul><li>true</li>  <li>false</li></ul> |  When true it forces Eth-Trunk members to match what is declared in the members param |
| state  |   no  | present  | <ul><li>present</li>  <li>absent</li></ul> |  Manage the state of the resource  |


#### Examples

```
# Ensure Eth-Trunk100 is created, add two members, and set to mode lacp-static
- ce_eth_trunk:
    trunk_id: 100
    members: ['40GE1/0/24','40GE1/0/25']
    mode: 'lacp-static'
    state: present
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```
#### Notes

- C(state=absent) removes the Eth-Trunk config and interface if it already exists. If members to be removed are not explicitly passed, all existing members (if any), are removed, and Eth-Trunk removed.
- Members must be a list.

---


## ce_evpn_bd_vni
Manages EVPN VXLAN Network Identifier

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages EVPN VXLAN Network Identifier

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| bridge_domain_id  |   yes  |  | <ul></ul> |  Specify an existed bridge domain (BD)  |
| evpn  |   no  |  true  | <ul> <li>true</li><li>false</li></ul> |  Specifies the working mode of an Eth-Trunk interface |
| route_distinguisher  |   no  |  | <ul></ul> |  Configure a route distinguisher (RD) for a BD EVPN instance |
| vpn_target_both  |   no  |    | <ul> </ul> |  Add VPN targets to both the import and export VPN target lists of a BD EVPN instance the format is the same as route_distinguisher  |
| vpn_target_import  |   no  |  | <ul></ul> |  Add VPN targets to the import VPN target list of a BD EVPN instance the format is the same as route_distinguisher  |
| vpn_target_export  |   no  |  | <ul></ul> |  Add VPN targets to the export VPN target list of a BD EVPN instance the format is the same as route_distinguisher |
| state  |   no  | present  | <ul><li>present</li>  <li>absent</li></ul> |  Manage the state of the resource  |


#### Examples

```
# Configure an EVPN instance for a VXLAN in BD view
- ce_evpn_bd_vni:
    evpn: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure a route distinguisher (RD) for a BD EVPN instance
- ce_evpn_bd_vni:
    route_distinguisher: 22:22
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure VPN targets to both the import and export VPN target lists of a BD EVPN instance
- ce_evpn_bd_vni:
    vpn_target_both: 22:100,22:101
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure VPN targets to the import VPN target list of a BD EVPN instance
- ce_evpn_bd_vni:
    vpn_target_import: 22:22,22:23
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure VPN targets to the export VPN target list of a BD EVPN instance
- ce_evpn_bd_vni:
    vpn_target_export: 22:38,22:39
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure an EVPN instance for a VXLAN in BD view disable
- ce_evpn_bd_vni:
    evpn: false
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

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
Manages BGP EVPN configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages BGP EVPN configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| bgp_instance  |   yes  |  | <ul></ul> |  Name of a BGP instance  |
| as_number  |   no  |    | <ul> <li>manual</li><li>lacp-dynamic</li><li>lacp-static</li></ul> |  Specifies the working mode of an Eth-Trunk interface |
| peer_address  |   no  |  | <ul></ul> |  Specifies the IPv4 address of a BGP EVPN peer  |
| peer_group_name  |   no  |    | <ul> </ul> |  Specify the name of a peer group that BGP peers need to join  |
| peer_enable  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Enable or disable a BGP device to exchange routes with a specified peer or peer group in the address family view  |
| advertise_router_type  |   no  |  | <ul><li>arp</li>  <li>irb</li></ul> |  Configures a device to advertise routes to its BGP EVPN peers |
| vpn_name  |   no  |  | <ul></ul> |  List of interfaces that will be managed in a given Eth-Trunk  |
| advertise_l2vpn_evpn  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Enable or disable a device to advertise IP routes imported to a VPN instance to its EVPN instance |
| state  |   no  | present  | <ul><li>present</li>  <li>absent</li></ul> |  Manage the state of the resource  |


#### Examples

```
# Enable peer address
    - name: "peer enable"
    ce_evpn_bgp:
        bgp_instance: 100
        peer_address: 1.1.1.1
        as_number: 100
        peer_enable: true
        username: "{{ un }}"
        password: "{{ pwd }}"
        host: "{{ inventory_hostname }}"

# Enable peer group arp
    - name: "peer group arp"
    ce_evpn_bgp:
        bgp_instance: 100
        peer_group_name: aaa
        advertise_router_type: arp
        username: "{{ un }}"
        password: "{{ pwd }}"
        host: "{{ inventory_hostname }}"

# Enable advertise l2vpn evpn
    - name: "advertise l2vpn evpn"
    ce_evpn_bgp:
        bgp_instance: 100
        vpn_name: aaa
        advertise_l2vpn_evpn: true
        username: "{{ un }}"
        password: "{{ pwd }}"
        host: "{{ inventory_hostname }}"

```
#### Notes
- Ensure that EVPN has been configured to serve as the VXLAN control plane when state is present.
- Ensure that a bridge domain (BD) has existed when state is present.

---


## ce_evpn_bgp_rr
Manages RR for the VXLAN Network
  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages RR for the VXLAN Network

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| as_number  |   yes  |  | <ul></ul> |  Specifies the number of the AS, in integer format  |
| bgp_instance  |   no  |    | <ul> </ul> |  Specifies the name of a BGP instance |
| bgp_evpn_enable  |   no  |  true | <ul><li>true</li>  <li>false</li></ul> |  Enable or disable the BGP-EVPN address family  |
| peer_type  |   no  |    | <ul><li>group_name</li><li>ipv4_address</li></ul> |  Specify the peer type  |
| peer  |   no  |  | <ul></ul> |  Specifies the IPv4 address or the group name of a peer |
| reflect_client  |   no  |  | <ul><li>true</li>  <li>false</li></ul> |  Configure the local device as the route reflector and the peer or peer group as the client of the route reflector |
| policy_vpn_target  |   no  |   | <ul><li>true</li>  <li>false</li></ul> |  Enable or disable the VPN-Target filtering  |


#### Examples

```
# Configure BGP-EVPN address family view and ensure that BGP view has existed.
- ce_evpn_bgp_rr:
    as_number: 20
    bgp_evpn_enable: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure reflect client and ensure peer has existed.
- ce_evpn_bgp_rr:
    as_number: 20
    peer_type: ipv4_address
	peer: 192.8.3.3
	reflect_client: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure the VPN-Target filtering.
- ce_evpn_bgp_rr:
    as_number: 20
    policy_vpn_target: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure an RR in BGP-EVPN address family view.
- ce_evpn_bgp_rr:
    as_number: 20
    bgp_evpn_enable: true
	peer_type: ipv4_address
	peer: 192.8.3.3
	reflect_client: true
	policy_vpn_target: false
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
```
#### Notes
- Ensure that BGP view is existed.
- The peer, peer_type, and reflect_client arguments must all exist or not exist.

---


## ce_evpn_global
Manages global configuration of EVPN

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages global configuration of EVPN

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| evpn_overlay_enable  |   yes  |  | <ul><li>true</li><li>false</li></ul> |  Configure EVPN as the VXLAN control plane  |


#### Examples

```
# Enable EVPN as the VXLAN control plan
- ce_evpn_global:
    evpn_overlay_enable: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
# Disable EVPN as the VXLAN control plan
- ce_evpn_global:
    evpn_overlay_enable: false
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```
#### Notes
- Before configuring evpn_overlay_enable=false, delete other EVPN configurations.

---


## ce_facts
Gets facts about CloudEngine switches

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Gets facts about CloudEngine switches

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| gather_subset  |  no  | !config | <ul></ul> |  When supplied, this argument will restrict the facts collected to a given subset.  Possible values for this argument include all, hardware, config, legacy, and interfaces.  Can specify a list of values to include a larger subset.  Values can also be used with an initial C(M(!)) to specify that a specific subset should not be collected. |


#### Examples

```
# Collect all of facts
- ce_facts:
    gather_subset: all
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Collect only the config and default facts
- ce_facts:
    gather_subset: config
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Do not collect hardware facts
- ce_facts:
    gather_subset: !hardware
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

```

---


## ce_file_copy
Copy a file to a remote CloudEngine device

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Copy a file to a remote CloudEngine device

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| local_file  |   yes  |  | <ul></ul> |  Path to local file  |
| remote_file  |   no  |    | <ul> </ul> |  Remote file path of the copy |
| file_system  |   no  | flash: | <ul></ul> |  The remote file system of the device  |


#### Examples

```
#Copy a local file to remote device
- ce_file_copy:
    local_file=/usr/vrpcfg.cfg
    remote_file=/vrpcfg.cfg
    file_system=flash:
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

```
#### Notes
- The feature must be enabled with feature scp-server.
- If the file is already present, no transfer will take place.

---


## ce_info_center_global
Manages outputting Logs

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages outputting Logs

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| info_center_enable  |   no  |  | <ul><li>true</li><li>false</li></ul> |  Whether the info-center function is enabled. <br>The value is of the Boolean type.  |
| packet_priority  |   no  |    | <ul> </ul> |  Set the priority of the syslog packet.<br>The value is an integer ranging from 0 to 7. The default value is 0. |
| suppress_enable  |   no  |  | <ul><li>true</li><li>false</li></ul> |  Whether a device is enabled to suppress duplicate statistics.<br>The value is of the Boolean type.  |
| logfile_max_num  |   no  |  | <ul></ul> |  Maximum number of log files of the same type. <br>The default value is 200.  |
| logfile_max_size  |   no  |    | <ul><li>4</li><li>8</li><li>16</li><li>32</li> </ul> |  Maximum size (in MB) of a log file. <br>The default value is 32. |
| channel_id  |   no  |  | <ul></ul> |  Number for channel. <br>The value is an integer ranging from 0 to 9. <br>The default value is 0.  |
| channel_cfg_name  |   no  |  | <ul></ul> |  Channel name.<br>The value is a string of 1 to 30 case-sensitive characters.<br>The default value is console  |
| channel_out_direct  |   no  |    | <ul><li>console</li><li>monitor</li><li>trapbuffer</li><li>logbuffer</li><li>snmp</li><li>logfile</li></ul> |  Direction of information output |
| filter_feature_name  |   no  |  | <ul></ul> |  Feature name of the filtered log. <br>The value is a string of 1 to 31 case-insensitive characters  |
| filter_log_name  |   no  |  | <ul></ul> |  Name of the filtered log.<br>The value is a string of 1 to 63 case-sensitive characters  |
| ip_type  |   no  |    | <ul><li>ipv4</li><li>ipv6</li> </ul> |  Log server address type, IPv4 or IPv6. |
| server_ip  |   no  |  | <ul></ul> |  Log server address, IPv4 or IPv6 type. <br>The value is a string of 0 to 255 characters.<br>The value can be an valid IPv4 or IPv6 address.  |
| server_domain  |   no  |  | <ul></ul> |  Server name. <br>The value is a string of 1 to 255 case-sensitive characters |
| is_default_vpn  |   no  |    | <ul><li>true</li><li>false</li> </ul> |  Use the default VPN or not |
| vrf_name  |   no  |  | <ul></ul> |  VPN name on a log server. The value is a string of 1 to 31 case-sensitive characters.<br>The default value is _public_.  |
| level  |   no  |  | <ul><li>emergencies</li><li>alert</li><li>critical</li><li>error</li><li>warning</li><li>notification</li><li>informational</li><li>debugging</li></ul> |  Level of logs saved on a log server  |
| server_port  |   no  |    | <ul> </ul> |  Number of a port sending logs.<br>The value is an integer ranging from 1 to 65535.<br>For UDP, the default value is 514. <br>For TCP, the default value is 601. For TSL, the default value is 6514. |
| facility  |   no  |  | <ul><li>local0</li><li>local1</li><li>local2</li><li>local3</li><li>local4</li><li>local5</li><li>local6</li><li>local7</li></ul> |  Log record tool  |
| channel_name  |   no  |  | <ul></ul> |  Channel name. <br>The value is a string of 1 to 30 case-sensitive characters  |
| timestamp  |   no  |    | <ul><li>UTC</li><li>localtime</li></ul> |  Log server timestamp. <br>The value is of the enumerated type and case-sensitive. |
| transport_mode  |   no  |  | <ul><li>tcp</li><li>udp</li></ul> |  Transport mode. <br>The value is of the enumerated type and case-sensitive.  |
| ssl_policy_name  |   no  |  | <ul></ul> |  SSL policy name. The value is a string of 1 to 23 case-sensitive characters  |
| source_ip  |   no  |    | <ul> </ul> |  Log source ip address, IPv4 or IPv6 type. <br>The value is a string of 0 to 255.<br>The value can be an valid IPv4 or IPv6 address. |
| state  |   no  | present | <ul><li>present</li><li>absent</li></ul> |  Specify desired state of the resource  |

#### Examples

```
# config info-center enable
- ce_info_center_global:
    info_center_enable:true
    state: present
    host: {{inventory_hostname}}
    username: {{username}}
    password: {{password}}
    port:{{ansible_ssh_port}}

# config statistic-suppress enable
 - ce_info_center_global:
    suppress_enable:true
    state: present
    host: {{inventory_hostname}}
    username: {{username}}
    password: {{password}}
    port:{{ansible_ssh_port}}

# config info-center syslog packet-priority 1
 - ce_info_center_global:
    packet_priority:2
    state: present
    host: {{inventory_hostname}}
    username: {{username}}
    password: {{password}}
    port:{{ansible_ssh_port}}

# config info-center channel 1 name aaa
 - ce_info_center_global:
    channel_id: 1
    channel_cfg_name: aaa
    state: present
    host: {{inventory_hostname}}
    username: {{username}}
    password: {{password}}
    port:{{ansible_ssh_port}}

# config info-center logfile size 10
 - ce_info_center_global:
    logfile_max_num: 10
    state: present
    host: {{inventory_hostname}}
    username: {{username}}
    password: {{password}}
    port:{{ansible_ssh_port}}

# config info-center console channel 1
 - ce_info_center_global:
    channel_out_direct: console
    channel_id: 1
    state: present
    host: {{inventory_hostname}}
    username: {{username}}
    password: {{password}}
    port:{{ansible_ssh_port}}

# config info-center filter-id bymodule-alias snmp snmp_ipunlock
 - ce_info_center_global:
    filter_feature_name: SNMP
    filter_log_name: SNMP_IPLOCK
    state: present
    host: {{inventory_hostname}}
    username: {{username}}
    password: {{password}}
    port:{{ansible_ssh_port}}

# config info-center max-logfile-number 16
 - ce_info_center_global:
    logfile_max_size: 16
    state: present
    host: {{inventory_hostname}}
    username: {{username}}
    password: {{password}}
    port:{{ansible_ssh_port}}

# config syslog loghost domain.
- ce_info_center_global:
    server_domain: aaa
    vrf_name: aaa
    channel_id: 1
    transport_mode: tcp
    facility: local4
    server_port: 100
    level: alert
    timestamp: UTC
    state: present
    host: {{inventory_hostname}}
    username: {{username}}
    password: {{password}}
    port:{{ansible_ssh_port}}

```


---


## ce_info_center_debug
Manages information center debug configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages information center debug configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   no  |  present | <ul><li>present</li><li>absent</li></ul> |  Specify desired state of the resource  |
| debug_time_stamp  |   no  |    | <ul> <li>date_boot</li><li>date_second</li><li>date_tenthsecond</li><li>date_millisecond</li><li>shortdate_second</li><li>shortdate_tenthsecond</li><li>shortdate_millisecond</li><li>formatdate_second</li><li>formatdate_tenthsecond</li><li>formatdate_millisecond</li></ul> |  Timestamp type of debugging information |
| module_name  |   no  |  | <ul></ul> |  Module name of the rule.<br>The value is a string of 1 to 31 case-insensitive characters. The default value is default.<br>Please use lower-case letter, such as [aaa, acl, arp, bfd].  |
| channel_id  |   no  |   | <ul></ul> |  Number of a channel.<br>The value is an integer ranging from 0 to 9. <br>The default value is 0.  |
| debug_enable  |   no  |    | <ul><li>true</li><li>false</li> </ul> |  Whether a device is enabled to output debugging information. |
| debug_level  |   no  |  | <ul><li>emergencies</li><li>alert</li><li>critical</li><li>error</li><li>warning</li><li>notification</li><li>informational</li><li>debugging</li></ul> |  Debug level permitted to output  |

#### Examples

```
# config debug time stamp
  - name: "config debug time stamp"
    ce_info_center_debug:
        state:  present
        debug_time_stamp:  date_boot
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo debug time stamp
  - name: "undo debug time stamp"
    ce_info_center_debug:
        state:  absent
        debug_time_stamp:  date_boot
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config debug module log level
  - name: "config debug module log level"
    ce_info_center_debug:
        state:  present
        module_name:  aaa
        channel_id:  1
        debug_enable:  true
        debug_level:  error
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo debug module log level
  - name: "undo debug module log level"
    ce_info_center_debug:
        state:  absent
        module_name:  aaa
        channel_id:  1
        debug_enable:  true
        debug_level:  error
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```


---


## ce_info_center_log
Manages information center log configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages information center log configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| log_time_stamp  |   no  |  | <ul><li>date_boot</li><li>date_second</li><li>date_tenthsecond</li><li>date_millisecond</li><li>shortdate_second</li><li>shortdate_tenthsecond</li><li>shortdate_millisecond</li><li>formatdate_second</li><li>formatdate_tenthsecond</li><li>formatdate_millisecond</li></ul> |  Sets the timestamp format of logs  |
| log_buff_enable  |   no  |    | <ul><li>true</li><li>false</li> </ul> |  Enables the Switch to send logs to the log buffer. |
| log_buff_size  |   no  |  | <ul></ul> |  Specifies the maximum number of logs in the log buffer.<br>The value is an integer that ranges from 0 to 10240. If logbuffer-size is 0, logs are not displayed. |
| module_name  |   no  |    | <ul> </ul> |  Specifies the name of a module.<br>The value is a module name in registration logs. |
| channel_id  |   no  |  | <ul></ul> |  Specifies a channel ID.<br>The value is an integer ranging from 0 to 9.  |
| log_enable  |   no  |  | <ul><li>true</li><li>false</li></ul> |  Indicates whether log filtering is enabled  |
| log_level  |   no  |    | <ul><li>emergencies</li><li>alert</li><li>critical</li><li>error</li><li>warning</li><li>notification</li><li>informational</li><li>debugging</li> </ul> |  Specifies a log severity. |
| state  |   no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Setting the Timestamp Format of Logs
- ce_info_center_log:
    log_time_stamp: date_tenthsecond
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Enabled to output information to the log buffer.
- ce_info_center_log:
    log_buff_enable: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Set the maximum number of logs in the log buffer.
- ce_info_center_log:
    log_buff_size: 100
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Set a rule for outputting logs to a channel
- ce_info_center_log:
    module_name: aaa
    channel_id: 1
    log_enable: true
    log_level: critical
    sample_direction: inbound
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```


---


## ce_info_center_trap
Manages info center trap configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages info center trap configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |
| trap_time_stamp  |   no  |  | <ul><li>date_boot</li><li>date_second</li><li>date_tenthsecond</li><li>date_millisecond</li><li>shortdate_second</li><li>shortdate_tenthsecond</li><li>shortdate_millisecond</li><li>formatdate_second</li><li>formatdate_tenthsecond</li><li>formatdate_millisecond</li></ul> |  Timestamp format of alarm information  |
| trap_buff_enable  |   no  |    | <ul><li>true</li><li>false</li> </ul> |  Whether a trap buffer is enabled to output information. |
| trap_buff_size  |   no  |  | <ul></ul> |  Size of a trap buffer.<br>The value is an integer ranging from 0 to 1024. The default value is 256. |
| module_name  |   no  |  | <ul></ul> |  Module name of the rule.<br>The value is a string of 1 to 31 case-insensitive characters. The default value is default.<br>Please use lower-case letter, such as [aaa, acl, arp, bfd].  |
| channel_id  |   no  |   | <ul></ul> |  Number of a channel.<br>The value is an integer ranging from 0 to 9. <br>The default value is 0.  |
| trap_enable  |   no  |    | <ul><li>true</li><li>false</li> </ul> |  Whether a device is enabled to output alarms. |
| trap_level  |   no  |  | <ul><li>emergencies</li><li>alert</li><li>critical</li><li>error</li><li>warning</li><li>notification</li><li>informational</li><li>debugging</li></ul> |  Trap level permitted to output.  |


#### Examples

```
# config trap buffer
  - name: "config trap buffer"
    ce_info_center_trap:
        state:  present
        trap_buff_enable:  true
        trap_buff_size:  768
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo trap buffer
  - name: "undo trap buffer"
    ce_info_center_trap:
        state:  absent
        trap_buff_enable:  true
        trap_buff_size:  768
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config trap module log level
  - name: "config trap module log level"
    ce_info_center_trap:
        state:  present
        module_name:  aaa
        channel_id:  1
        trap_enable:  true
        trap_level:  error
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo trap module log level
  - name: "undo trap module log level"
    ce_info_center_trap:
        state:  absent
        module_name:  aaa
        channel_id:  1
        trap_enable:  true
        trap_level:  error
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```



---


## ce_interface
Manages physical attributes of interfaces

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages physical attributes of interfaces

#### Options

| Parameter     | required    | default  |     choices    | comments |
| ------------- |-------------| ---------|--------------- |--------- |
| interface  |   no  |  | <ul></ul> |  Full name of interface, i.e. 40GE1/0/10, Tunnel1.  |
| interface_type  |   no  |    | <ul><li>ge</li><li>10ge</li><li>40ge</li><li>100ge</li><li>vlanif</li><li>loopback</li><li>meth</li><li>eth-trunk</li><li>nve</li><li>tunnel</li><li>ethernet</li><li>fcoe-port</li><li>fabric-port</li><li>stack-port</li><li>null</li> </ul> |  Interface type to be configured from the device. |
| admin_state  |   no  |    | <ul><li>up</li><li>down</li></ul> |  Specifies the interface management status.<br>The value is an enumerated type.<br>up, An interface is in the administrative Up state.<br>down, An interface is in the administrative Down state.  |
| description  |   no  |  | <ul></ul> |  Specifies an interface description.<br>The value is a string of 1 to 242 case-sensitive characters,spaces supported but question marks (?) not supported.  |
| mode  |   no  |    | <ul><li>true</li><li>false</li> </ul> |  Manage Layer 2 or Layer 3 state of the interface. |
| l2sub  |   no  |  | <ul><li>layer2</li><li>layer3</li></ul> |  Specifies whether the interface is a Layer 2 sub-interface  |
| state  |    | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Ensure an interface is a Layer 3 port and that it has the proper description
- ce_interface:
    interface: 40GE1/0/22
    description: 'Configured by Ansible'
    mode: layer3
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Admin down an interface
- ce_interface:
    interface: 40GE1/0/22
    admin_state: down
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Remove all tunnel interfaces
- ce_interface:
	interface_type: tunnel
	state: absent
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Admin up all 40GE interfaces
- ce_interface:
	interface_type: 40GE
	state: up
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

```
#### Notes
- This module is also used to create logical interfaces such as vlanif and loopbacks.


---


## ce_interface_ospf
Manages configuration of an OSPF interface instance

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages configuration of an OSPF interface instance

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| interface  |   yes  |  | <ul></ul> |  Full name of interface, i.e. 40GE1/0/22, vlanif10.  |
| process_id  |   yes  |    | <ul> </ul> |  Specifies a process ID.<br> The value is an integer ranging from 1 to 4294967295. |
| area  |   yes  |  | <ul></ul> |  Ospf area associated with this ospf process.<br>Valid values are a string, formatted as an IP address (i.e. "0.0.0.0") or as an integer between 1 and 4294967295. |
| cost  |   no  |    | <ul> </ul> |  The cost associated with this interface.<br>Valid values are an integer in the range from 1 to 65535. |
| hello_interval  |    |  | <ul></ul> | Time between sending successive hello packets.<br>Valid values are an integer in the range from 1 to 65535. |
| dead_interval  |   no  |  | <ul></ul> |  Time interval an ospf neighbor waits for a hello packet before tearing down adjacencies. <br>Valid values are an integer in the range from 1 to 235926000.  |
| silent_interface  |   no  |    | <ul><li>true</li><li>false</li> </ul> |  Setting to true will prevent this interface from receiving HELLO packets. <br>Valid values are 'true' and 'false'.. |
| auth_mode  |   no  |  | <ul><li>none</li><li>null</li><li>hmac-sha256</li><li>md5</li><li>hmac-md5</li><li>simple</li></ul> |  Specifies the authentication type.  |
| auth_text_simple  |   no  |    | <ul> </ul> |  Specifies a password for simple authentication.<br>The value is a string of 1 to 8 characters. |
| auth_key_id  |    |  | <ul></ul> | Authentication key id when C(auth_mode) is 'hmac-sha256', 'md5' or 'hmac-md5.<br>Valid value is an integer is in the range from 1 to 255.  |
| auth_text_md5  |   no  |  | <ul></ul> |  Specifies a password for MD5, HMAC-MD5, or HMAC-SHA256 authentication.<br>The value is a string of 1 to 255 case-sensitive characters, spaces not supported.  |
| state  |    | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |
#### Examples

```
# Enables OSPF and sets the cost on an interface
- ce_interface_ospf:
    interface: 40GE2/0/30
    process_id: 1
    area: 100
    cost: 100
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Sets the dead interval of the OSPF neighbor
- ce_interface_ospf:
    interface: 40GE2/0/30
    process_id: 1
    area: 100
    dead_interval: 10
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Sets the interval for sending Hello packets on an interface
- ce_interface_ospf:
    interface: 40GE2/0/30
    process_id: 1
    area: 100
    hello_interval: 2
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

#disables an interface from receiving and sending OSPF packets
- ce_interface_ospf:
    interface: 40GE2/0/30
    process_id: 1
    area: 100
    silent_interface: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
```


---


## ce_ip_interface
Manages L3 attributes for IPv4 and IPv6 interfaces

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages L3 attributes for IPv4 and IPv6 interfaces

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| interface  |   yes  |  | <ul></ul> |  Full name of interface, i.e. 40GE1/0/22, vlanif10.  |
| addr  |   no  |    | <ul> </ul> |  IPv4 or IPv6 Address. |
| mask  |   no  |  | <ul></ul> |  Subnet mask for IPv4 or IPv6 Address in decimal format.  |
| version  |   no  |  v4  | <ul><li>v4</li><li>v6</li> </ul> |  IP address version. |
| ipv4_type  |   no  |  main  | <ul><li>main</li><li>sub</li> </ul> |  Specifies an address type. <br>The value is an enumerated type.<br>main, primary IP address.<br>sub, secondary IP address. |
| state  |    | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |


#### Examples

```
# ensure ipv4 address is configured on 40GE1/0/22
- ce_ip_interface: interface=40GE1/0/22 version=v4 state=present addr=20.20.20.20 mask=24
    interface: 40GE1/0/22
    version: v4
    state: present
    addr: 20.20.20.20
    mask: 24
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# ensure ipv4 secondary address is configured on 40GE1/0/22
- ce_ip_interface: interface=40GE1/0/22 version=v4 state=present addr=30.30.30.30 ipv4_type=sub mask=24
    interface: 40GE1/0/22
    version: v4
    state: present
    addr: 30.30.30.30
    mask: 24
    ipv4_type: sub
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# ensure ipv6 is enabled on 40GE1/0/22
- ce_ip_interface: interface=40GE1/0/22 version=v6 state=present
	interface: 40GE1/0/22
	version: v6
	state: present
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# ensure ipv6 address is configured on 40GE1/0/22
- ce_ip_interface:
	interface: 40GE1/0/22
	version: v6
	state: present
	addr: 2001::db8:800:200c:cccb
	mask: 64
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

```
#### Notes
- Interface must already be a L3 port when using this module.
- Logical interfaces (loopback, vlanif) must be created first.
- C(mask) must be inserted in decimal format (i.e. 24) for both IPv6 and IPv4.
- A single interface can have multiple IPv6 configured.

---


## ce_mtu
Manages MTU settings on CloudEngine switch

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages MTU settings on CloudEngine switch

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| interface  |   no  |  | <ul></ul> |  Full name of interface, i.e. 40GE1/0/22  |
| mtu  |   no  |    | <ul> </ul> |  MTU for a specific interface. <br>The value is an integer ranging from 46 to 9600, in bytes. |
| jumbo_max  |   no  |  | <ul></ul> |  Maximum frame size. The default value is 9216.<br>The value is an integer and expressed in bytes. The value range is 1536 to 12224 for the CE12800 and 1536 to 12288 for ToR switches.  |
| jumbo_min  |   no  |  | <ul></ul> |  Non-jumbo frame size threshod. The default value is 1518.<br>The value is an integer that ranges from 1518 to jumbo_max, in bytes.  |
| state  |    | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Config jumboframe on 40GE1/0/22
- ce_mtu:
    jumbo_max: 9000
    jumbo_min: 8000
    host: {{ inventory_hostname }}
    username: {{ un }}
    password: {{ pwd }}

# Config mtu on 40GE1/0/22 (routed interface)
- ce_mtu:
    interface: 40GE1/0/22
    mtu: 1600
    host: {{ inventory_hostname }}
    username: {{ un }}
    password: {{ pwd }}

# Config mtu on 40GE1/0/23 (switched interface)
- ce_mtu:
    interface: 40GE1/0/23
    mtu: 9216
    host: {{ inventory_hostname }}
    username: {{ un }}
    password: {{ pwd }}

# Config mtu and jumboframe on 40GE1/0/22 (routed interface)
- ce_mtu:
    interface: 40GE1/0/22
    mtu: 1601
    jumbo_max: 9001
    jumbo_min: 8001
    host: {{ inventory_hostname }}
    username: {{ un }}
    password: {{ pwd }}

# Unconfigure mtu and jumboframe on a given interface
- ce_mtu:
    interface: 40GE1/0/22
    host: {{ inventory_hostname }}
    username: {{ un }}
    password: {{ pwd }}
    state: absent

```
#### Notes
- Either C(sysmtu) param is required or C(interface) AND C(mtu) params are req'd.
- C(state=absent) unconfigures a given MTU if that value is currently present.

---


## ce_netconf
Run arbitrary netconf command on CloudEngine devices

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Run arbitrary netconf command on CloudEngine devices

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| rpc  |   yes  |  | <ul><li>get</li><li>edit-config</li><li>execute-action</li><li>execute-cli</li></ul> |  The type of rpc  |
| cfg_xml  |   yes  |    | <ul> </ul> |  The config xml string |

#### Examples

```
# netconf get operation
  - name: "netconf get operation"
    ce_netconf:
        rpc:  get
        cfg_xml:  "<filter type=\"subtree\"><vlan xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\"
                   format-version=\"1.0\"><vlans><vlan><vlanId>10</vlanId><vlanif><ifName></ifName><cfgBand>
                   </cfgBand><dampTime></dampTime></vlanif></vlan></vlans></vlan></filter>"
        host:  {{inventory_hostname}}
        port:  {{ansible_ssh_port}}
        username:  {{username}}
        password:  {{password}}

# netconf edit-config operation
  - name: "netconf edit-config operation"
    ce_netconf:
        rpc:  edit-config
        cfg_xml:  "<config><aaa xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\"
                   format-version=\"1.0\"><authenticationSchemes><authenticationScheme operation=\"create\">
                   <authenSchemeName>default_wdz</authenSchemeName><firstAuthenMode>local</firstAuthenMode>
                   <secondAuthenMode>invalid</secondAuthenMode></authenticationScheme></authenticationSchemes>
                   </aaa></config>"
        host:  {{inventory_hostname}}
        port:  {{ansible_ssh_port}}
        username:  {{username}}
        password:  {{password}}

# netconf execute-action operation
  - name: "netconf execute-action operation"
    ce_netconf:
        rpc:  execute-action
        cfg_xml:  "<action><l2mc xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\"
                   format-version=\"1.0\"><l2McResetAllVlanStatis><addrFamily>ipv4unicast</addrFamily>
                   </l2McResetAllVlanStatis></l2mc></action>"
        host:  {{inventory_hostname}}
        port:  {{ansible_ssh_port}}
        username:  {{username}}
        password:  {{password}}

# netconf execute-cli operation
  - name: "netconf execute-cli operation"
    ce_netconf:
        rpc:  execute-cli
        cfg_xml:  "<cmd><id>1</id><cmdline>display current-configuration</cmdline></cmd>"
        host:  {{inventory_hostname}}
        port:  {{ansible_ssh_port}}
        username:  {{username}}
        password:  {{password}}

```
#### Notes
- The rpc parameter is always required.

---


## ce_netstream_aging
Manages timeout mode of NetStream

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages timeout mode of NetStream

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| timeout_interval  |  no | 30 | <ul></ul> |  Netstream timeout interval.<br>If is active type the interval is 1-60.<br>If is inactive ,the interval is 5-600. |
| type  |  no  |    | <ul> <li>ip</li><li>vxlan</li></ul> |  Specifies the packet type of netstream timeout active interval. |
| timeout_type  |  no |  | <ul><li>active</li><li>inactive</li><li>tcp-session</li><li>manual</li></ul> |  Netstream timeout type.  |
| manual_slot  |   no  |    | <ul> </ul> |  Specifies the slot number of netstream manual timeout. |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |


#### Examples

```
# Configure netstream ip timeout active interval , the interval is 40 minutes.
- ce_netstream_aging:
    timeout_interval: 40
    type: ip
    timeout_type: active
    state: present
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure netstream vxlan timeout active interval , the interval is 40 minutes.
- ce_netstream_aging:
    timeout_interval: 40
    type: vxlan
    timeout_type: active
    active_state: present
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Delete netstream ip timeout active interval , set the ip timeout interval to 30 minutes.
- ce_netstream_aging:
    type: ip
    timeout_type: active
    state: absent
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Delete netstream vxlan timeout active interval , set the vxlan timeout interval to 30 minutes.
- ce_netstream_aging:
    type: vxlan
    timeout_type: active
    state: absent
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Enable netstream ip tcp session timeout.
- ce_netstream_aging:
    type: ip
    timeout_type: tcp-session
    state: present
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Enable netstream vxlan tcp session timeout.
- ce_netstream_aging:
    type: vxlan
    timeout_type: tcp-session
    state: present
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Disable netstream ip tcp session timeout.
- ce_netstream_aging:
    type: ip
    timeout_type: tcp-session
    state: absent
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Disable netstream vxlan tcp session timeout.
- ce_netstream_aging:
    type: vxlan
    timeout_type: tcp-session
    state: absent
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```


---


## ce_netstream_export
Manages NetStream export configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages NetStream export configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| type  |   no |  | <ul><li>ip</li><li>vxlan</li></ul> |  Specifies NetStream feature.  |
| source_ip  |   no  |    | <ul> </ul> |  Specifies source address of the exported NetStream packet. |
| host_ip  |   no |  | <ul></ul> |  Specifies destination address of the exported NetStream packet.  |
| host_port  |   no  |    | <ul> </ul> |  Specifies the destination UDP port number of the exported packets.<br>The value is an integer that ranges from 1 to 65535. |
| host_vpn  |   no |  | <ul></ul> |  Specifies the VPN instance of the exported packets carrying flow statistics.<br>Ensure the VPN instance has been created on the device.  |
| version  |   no  |    | <ul><li>5</li><li>9</li> </ul> |  Sets the version of exported packets. |
| as_option  |   no |  | <ul><li>origin</li><li>peer</li></ul> |  Specifies the AS number recorded in the statistics as the original or the peer AS number.  |
| bgp_nexthop  |   no  |    | <ul> <li>true</li><li>false</li></ul> |  Configures the statistics to carry BGP next hop information. Currently, only V9 supports the exported packets carrying BGP next hop information. |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |


#### Examples

```
# Configures the source address for the exported packets carrying IPv4 flow statistics.
- ce_netstream_export:
    type: ip
    source_ip: 192.8.2.2
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

#Configures the source IP address for the exported packets carrying VXLAN flexible flow statistics.
- ce_netstream_export:
    type: vxlan
    source_ip: 192.8.2.3
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

#Configures the destination IP address and destination UDP port number for the exported packets carrying IPv4 flow statistics.
- ce_netstream_export:
    type: ip
    host_ip: 192.8.2.4
    host_port: 25
    host_vpn: test
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

#Configures the destination IP address and destination UDP port number for the exported packets carrying VXLAN flexible flow statistics.
- ce_netstream_export:
    type: vxlan
    host_ip: 192.8.2.5
    host_port: 26
    host_vpn: test
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

#Configures the version number of the exported packets carrying IPv4 flow statistics.
- ce_netstream_export:
    type: ip
    version: 9
    as_option: origin
    bgp_nexthop: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

#Configures the version for the exported packets carrying VXLAN flexible flow statistics.
- ce_netstream_export:
    type: vxlan
    version: 9
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```


---


## ce_netstream_global
Manages NetStream global configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages NetStream global configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| type  |   no | ip | <ul><li>ip</li><li>vxlan</li></ul> |  Specifies the type of netstream global.  |
| interface  |   no  |    | <ul> </ul> |  Netstream global interface. |
| sampler_interval  |   no |  | <ul></ul> |  Specifies the netstream sampler interval, length is 1 - 65535.  |
| sampler_direction  |   no  |    | <ul><li>inbound</li><li>outbound</li> </ul> |  Specifies the netstream sampler direction. |
| statistics_direction  |   no  |    | <ul><li>inbound</li><li>outbound</li> </ul> |  Specifies the netstream statistic direction. |
| statistics_record  |   no |  | <ul></ul> |  Specifies the flexible netstream statistic record, length is 1 - 32.  |
| index_switch  |   no  |  16  | <ul><li>16</li><li>32</li> </ul> |  Specifies the netstream index-switch. |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |


#### Examples

```
# Configure a netstream sampler at interface 10ge1/0/2, direction is outbound,interval is 30.
- ce_netstream_global:
    interface: 10ge1/0/2
    type: ip
    sampler_interval: 30
    sampler_direction: outbound
    state: present
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure a netstream flexible statistic at interface 10ge1/0/2, record is test1, type is ip.
- ce_netstream_global:
    type: ip
    interface: 10ge1/0/2
    statistics_record: test1
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Set the vxlan index-switch to 32.
- ce_netstream_global:
    type: vxlan
    interface: all
    index_switch: 32
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```


---


## ce_netstream_template
Manages NetStream template configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages NetStream template configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| type  |   no |  | <ul><li>ip</li><li>vxlan</li></ul> |  Specifies the type of netstream record.  |
| record_name  |   no  |    | <ul> </ul> |  Configure the name of netstream record.<br>The value is a string of 1 to 32 case-insensitive characters. |
| match  |   no |  | <ul><li>destination-address</li><li>destination-port</li><li>tos</li><li>protocol</li><li>source-address</li><li>source-port</li></ul> |  Configure flexible flow statistics template keywords.  |
| collect_counter  |   no  |    | <ul><li>inbound</li><li>outbound</li> </ul> |  Configure the number of packets and bytes that are included in the flexible flow statistics sent to NSC. |
| collect_interface  |   no |  | <ul><li>input</li><li>output</li></ul> |  Configure the input or output interface that are included in the flexible flow statistics sent to NSC.  |
| description  |   no  |   | <ul> </ul> |  Configure the description of netstream record.<br>The value is a string of 1 to 80 case-insensitive characters. |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |


#### Examples

```
# config ipv4 netstream record
  - name: "config ipv4 netstream record"
    ce_netstream_template:
        state:  present
        type:  ip
        record_name:  test
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo ipv4 netstream record
  - name: "undo ipv4 netstream record"
    ce_netstream_template:
        state:  absent
        type:  ip
        record_name:  test
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config ipv4 netstream record collect_counter
  - name: "config ipv4 netstream record collect_counter"
    ce_netstream_template:
        state:  present
        type:  ip
        record_name:  test
        collect_counter:  bytes
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo ipv4 netstream record collect_counter
  - name: "undo ipv4 netstream record collect_counter"
    ce_netstream_template:
        state:  absent
        type:  ip
        record_name:  test
        collect_counter:  bytes
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```


---


## ce_ntp
Manages core NTP configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages core NTP configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| server  |   no  |  | <ul></ul> |  Network address of NTP server  |
| peer  |   no  |  | <ul></ul> |  Network address of NTP peer  |
| key_id  |   no  |    | <ul> </ul> |  Authentication key identifier to use with given NTP server or peer. |
| is_preferred  |   no  |  | <ul><li>true</li><li>false</li></ul> |  Makes given NTP server or peer the preferred NTP server or peer for the device.  |
| vpn_name  |   no  | _public_ | <ul></ul> |  Makes the device communicate with the given <br>NTP server or peer over a specific vpn.  |
| source_int  |   no  |    | <ul> </ul> |  Local source interface from which NTP messages are sent.<br>Must be fully qualified interface name, i.e. 40GE1/0/22, vlanif10.<br>Interface types, such as 10GE, 40GE, 100GE, Eth-Trunk, LoopBack, MEth, NULL, Tunnel, Vlanif... |
| state  |  no | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Set NTP Server with parameters
- ce_ntp:
    server: 192.8.2.6
    vpn_name: js
    source_int: vlanif4001
    is_preferred: true
    key_id: 32
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Set NTP Peer with parameters
- ce_ntp:
    peer: 192.8.2.6
    vpn_name: js
    source_int: vlanif4001
    is_preferred: true
    key_id: 32
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

```

---


## ce_ntp_auth
Manages NTP authentication configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages NTP authentication configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| key_id  |   yes  |  | <ul></ul> |  Authentication key identifier (numeric)  |
| auth_pwd  |   no  |    | <ul> </ul> |  Plain text with length of 1 to 255, encrypted text with length of 20 to 392 |
| auth_mode  |   no  |  | <ul><li>md5</li><li>hmac-sha256</li></ul> |  Specify authentication algorithm md5 or hmac-sha256  |
| auth_type  |   no  | encrypt | <ul><li>text</li><li>encrypt</li></ul> |  Whether the given password is in cleartext or has been encrypted. <br>If in cleartext, the device will encrypt it before storing it. |
| trusted_key  |   no  |  false  | <ul><li>true</li><li>false</li></ul> |  Whether the given key is required to be supplied by a time source for the device to synchronize to the time source |
| authentication  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Configure ntp authentication enable or unconfigure ntp authentication enable  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |
#### Examples

```
# ntp authentication-keyid
- ce_ntp_auth:
    key_id: 32
    auth_mode: md5
    auth_pwd: 1111
    host: {{ inventory_hostname }}
    username: {{ un }}
    password: {{ pwd }}

# ntp authentication-keyid and ntp trusted authentication-keyid
- ce_ntp_auth:
    key_id: 32
    auth_mode: md5
    auth_pwd: 1111
    trusted_key:true
    host: {{ inventory_hostname }}
    username: {{ un }}
    password: {{ pwd }}

# ntp authentication-keyid and ntp authentication enable
- ce_ntp_auth:
    key_id: 32
    auth_mode: md5
    auth_pwd: 1111
    authentication:enable
    host: {{ inventory_hostname }}
    username: {{ un }}
    password: {{ pwd }}

# undo ntp authentication-keyid and undo ntp trusted authentication-keyid
- ce_ntp_auth:
    key_id: 32
    host: {{ inventory_hostname }}
    username: {{ un }}
    password: {{ pwd }}

# undo ntp authentication-keyid and undo ntp authentication enable
- ce_ntp_auth:
    key_id: 32
    authentication:enable
    host: {{ inventory_hostname }}
    username: {{ un }}
    password: {{ pwd }}

```
#### Notes
- If C(state=absent), the module will attempt to remove the given key configuration.
- If a matching key configuration isn't found on the device, the module will fail.
- If C(state=absent) and C(authentication=on), authentication will be turned on.
- If C(state=absent) and C(authentication=off), authentication will be turned off.

---


## ce_ospf
Manages configuration of an OSPF instance

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages configuration of an OSPF instance

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| process_id  |   yes  |  | <ul></ul> |  Specifies a process ID.<br> The value is an integer ranging from 1 to 4294967295  |
| area  |   no  |    | <ul> </ul> |  Specifies the area ID. The area with the area-id being 0 is a backbone area.<br>Valid values are a string, formatted as an IP address (i.e. "0.0.0.0") or as an integer between 1 and 4294967295. |
| addr  |   no  |  | <ul></ul> |  Specifies the address of the network segment where the interface resides.<br>The value is in dotted decimal notation.  |
| mask  |   no  |  | <ul></ul> |  IP network wildcard bits in decimal format between 0 and 32 |
| auth_mode  |   no  |   | <ul><li>none</li><li>hmac-sha256</li><li>md5</li><li>hmac-md5</li><li>simple</li></ul> |  Specifies the authentication type |
| auth_text_simple  |   no  |  | <ul></ul> |  Specifies a password for simple authentication.<br>The value is a string of 1 to 8 characters.  |
| auth_key_id  |   no  |  | <ul></ul> |  Authentication key id when C(auth_mode) is 'hmac-sha256', 'md5' or 'hmac-md5.<br>Valid value is an integer is in the range from 1 to 255.  |
| auth_text_md5  |   no  |    | <ul> </ul> |  Specifies a password for MD5, HMAC-MD5, or HMAC-SHA256 authentication.<br>The value is a string of 1 to 255 case-sensitive characters, spaces not supported. |
| nexthop_addr  |   no  |  | <ul></ul> |  IPv4 address for configure next-hop address's weight.<br>Valid values are a string, formatted as an IP address.  |
| nexthop_weight  |   no  |  | <ul></ul> |  Indicates the weight of the next hop.<br>The smaller the value is, the higher the preference of the route is.<br>It is an integer that ranges from 1 to 254. |
| max_load_balance  |   no  |    | <ul></ul> |  The maximum number of paths for forward packets over multiple paths.<br>Valid value is an integer in the range from 1 to 64. |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |


#### Examples

```
- ce_ospf:
    process_id: 1
    area: 100
    state: present
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```


---


## ce_ospf_vrf
Manages configuration of an OSPF VPN instance

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages configuration of an OSPF VPN instance

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| ospf  |   yes  |  | <ul></ul> |  The ID of the ospf process.<br>Valid values are an integer, 1 - 4294967295, the default value is 1.  |
| route_id  |   no  |    | <ul> </ul> |  Specifies the ospf private route id.<br>Valid values are a string, formatted as an IP address (i.e. "10.1.1.1") the length is 0 - 20.|
| vrf  |   no  | _public_ | <ul></ul> |  Specifies the VPN instance which use ospf,length is 1 - 31.<br>Valid values are a string.  |
| description  |   no  |  | <ul></ul> |  Specifies the description information of ospf process. |
| bandwidth  |   no  |   | <ul></ul> |  Specifies the reference bandwidth used to assign ospf cost.<br>Valid values are an integer, in Mbps, 1 - 2147483648, the default value is 100. |
| lsaalflag  |   no  | false | <ul><li>true</li><li>false</li></ul> |  Specifies the mode of timer to calculate interval of arrive LSA.<br>If set the parameter but noe specifies value ,the default will be used.<br>If true use general timer.<br>If false use intelligent timer.|
| lsaainterval  |   no  |  | <ul></ul> |  Specifies the interval of arrive LSA when use the general timer.<br>Valid value is an integer , in millisecond , from 0 to 10000.|
| lsaamaxinterval  |   no  |    | <ul> </ul> |  Specifies the max interval of arrive LSA when use the intelligent timer.<br>Valid value is an integer , in millisecond , from 0 to 10000, the default value is 1000.|
| lsaastartinterval  |   no  |  | <ul></ul> |  Specifies the start interval of arrive LSA when use the intelligent timer.<br>Valid value is an integer , in millisecond , from 0 to 10000, the default value is 500.|
| lsaaholdinterval  |   no  |  | <ul></ul> |  Specifies the hold interval of arrive LSA when use the intelligent timer.<br>Valid value is an integer , in millisecond , from 0 to 10000, the default value is 500.|
| lsaointervalflag  |   no  |  false  | <ul><li>true</li><li>false</li></ul> |  Specifies whether cancel the interval of LSA originate or not.<br>If set the parameter but noe specifies value ,the default will be used.<br>true:cancel the interval of LSA originate,the interval is 0. <br>false:do not cancel the interval of LSA originate |
| lsaointerval  |   yes  |  | <ul></ul> |  Specifies the interval of originate LSA .<br>Valid value is an integer , in second , from 0 to 10, the default value is 5.|
| lsaomaxinterval  |   no  |    | <ul> </ul> |  Specifies the max interval of originate LSA.<br>Valid value is an integer , in millisecond , from 1 to 10000, the default value is 5000.|
| lsaostartinterval  |   no  |  | <ul></ul> |  Specifies the interval of originate LSA.<br>Valid value is an integer , in millisecond , from 0 to 1000, the default value is 500.|
| lsaoholdinterval  |   no  |  | <ul></ul> |  Specifies the interval of originate LSA.<br>Valid value is an integer , in millisecond , from 0 to 5000, the default value is 1000.|
| spfintervaltype  |   no  | intelligent_timer  | <ul><li>intelligent_timer</li><li>timer</li><li>millisecond</li></ul> |  Specifies the mode of timer which used to calculate SPF.<br>If set the parameter but noe specifies value ,the default will be used. <br>If is intelligent_timer, then use intelligent timer. <br>If is timer, then use second level  timer. <br>If is millisecond, then use millisecond  level timer |
| spfinterval  |   no  |  | <ul></ul> |  Specifies the interval to calculate SPF when use second level  timer.<br>Valid value is an integer , in second , from 1 to 10. |
| spfintervalmi  |   no  |    | <ul></ul> |  Specifies the interval to calculate SPF when use millisecond level timer.<br>Valid value is an integer , in millisecond , from 1 to 10000. |
| spfmaxinterval  |   no  |  | <ul></ul> |  Specifies the max interval to calculate SPF when use intelligent timer.<br>Valid value is an integer , in millisecond , from 1 to 20000, the default value is 5000.|
| spfstartinterval  |   no  |  | <ul></ul> |  Specifies the start interval to calculate SPF when use intelligent timer.<br>Valid value is an integer , in millisecond , from 1 to 1000, the default value is 50.|
| spfholdinterval  |   no  |   | <ul></ul> |  Specifies the hold interval to calculate SPF when use intelligent timer.<br>Valid value is an integer , in millisecond , from 1 to 5000, the default value is 200.|
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
- ce_ospf_vrf:
    ospf=2
    route_id=2.2.2.2
    lsaointervalflag=false
    lsaointerval=2
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```
---


## ce_reboot
Reboot a network device

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Reboot a network device

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| confirm  |   yes  |  | <ul></ul> |  Safeguard boolean. <br>Set to true if you're sure you want to reboot.  |
| save_config  |   no  |    | <ul> </ul> |  Flag indicating whether to save the configuration. |


#### Examples

```
- ce_reboot:
    confirm: true
    save_config: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```

---


## ce_rollback
Set a checkpoint or rollback to a checkpoint

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Set a checkpoint or rollback to a checkpoint

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| commit_id  |   no  |  | <ul></ul> |  Specifies the label of the configuration rollback point to which system configurations are expected to roll back.<br>The value is an integer that the system generates automatically.  |
| label  |   no  |    | <ul> </ul> |  Specifies a user label for a configuration rollback point.<br>The value is a string of 1 to 256 case-sensitive ASCII characters, spaces not supported.<br>The value must start with a letter and cannot be presented in a single hyphen (-). |
| filename  |  no |  | <ul></ul> |  Specifies a configuration file for configuration rollback.<br>The value is a string of 5 to 64 case-sensitive characters in the format of *.zip, *.cfg, or *.dat,spaces not supported.  |
| last  |    |  | <ul></ul> | Specifies the number of configuration rollback points.<br>The value is an integer that ranges from 1 to 80.  |
| oldest  |   no  |  | <ul></ul> |  Specifies the number of configuration rollback points.<br>The value is an integer that ranges from 1 to 80.  |
| action  |   no  |    | <ul><li>rollback</li><li>clear</li><li>set</li><li>display</li><li>commit</li>  </ul> |  The operation of configuration rollback. |
| auto_save_switch  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Enable or disable checkpoint autosave switch. |

#### Examples

```
# Ensure commit_id is exist, and specifies the label of the configuration rollback point to which system configurations are expected to roll back.
- ce_rollback:
    commit_id: 1000000748
    action: rollback
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
```
---


## ce_sflow
Manages sFlow configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages sFlow configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| agent_ip  |   no  |  | <ul></ul> |  Specifies the IPv4/IPv6 address of an sFlow agent  |
| source_ip  |   no  |    | <ul></ul> |  Specifies the source IPv4/IPv6 address of sFlow packets |
| collector_id  |   no  |  | <ul><li>1</li><li>2</li></ul> |  Specifies the ID of an sFlow collector. This ID is used when you specify the collector in subsequent sFlow configuration.<br>The value is an integer that can be 1 or 2.  |
| collector_ip  |   no  |    | <ul> </ul> |  Specifies the IPv4/IPv6 address of the sFlow collector. |
| collector_ip_vpn  |  no |  | <ul></ul> |  Specifies the name of a VPN instance.<br>The value is a string of 1 to 31 case-sensitive characters, spaces not supported.<br>When double quotation marks are used around the string, spaces are allowed in the string.<br>The value _public_ is reserved and cannot be used as the VPN instance name.  |
| collector_datagram_size  |    |  | <ul></ul> | Specifies the maximum length of sFlow packets sent from an sFlow agent to an sFlow collector.<br>The value is an integer, in bytes. It ranges from 1024 to 8100. The default value is 1400.  |
| collector_udp_port  |   no  |  | <ul></ul> |  Specifies the UDP destination port number of sFlow packets.<br>The value is an integer that ranges from 1 to 65535. The default value is 6343.  |
| collector_meth  |   no  |    | <ul><li>meth</li><li>enhanced</li></ul> |  Configures the device to send sFlow packets through service interfaces,enhancing the sFlow packet forwarding capability.<br>The enhanced parameter is optional. No matter whether you configure the enhanced mode,the switch determines to send sFlow packets through service cards or management port based on the routing information on the collector.<br>When the value is meth, the device forwards sFlow packets at the control plane.<br>When the value is enhanced, the device forwards sFlow packets at the forwarding plane to enhance the sFlow packet forwarding capacity. |
| collector_description  |   no  |  | <ul></ul> |  Specifies the description of an sFlow collector.<br>The value is a string of 1 to 255 case-sensitive characters without spaces. |
| sflow_interface  |   no  |  | <ul></ul> |  Full name of interface for Flow Sampling or Counter.<br>It must be a physical interface, Eth-Trunk, or Layer 2 subinterface.  |
| sample_collector  |   no  |   | <ul> </ul> |  Indicates the ID list of the collector. |
| sample_rate  |   no  |  | <ul></ul> |  Specifies the flow sampling rate in the format 1/rate.<br>The value is an integer and ranges from 1 to 4294967295. The default value is 8192.  |
| sample_length  |   no  |    | <ul> </ul> |  Specifies the maximum length of sampled packets.<br>The value is an integer and ranges from 18 to 512, in bytes. The default value is 128. |
| sample_direction  |  no |  | <ul><li>inbound</li><li>outbound</li><li>both</li></ul> |  Enables flow sampling in the inbound or outbound direction.  |
| counter_collector  |    |  | <ul></ul> | Indicates the ID list of the counter collector.  |
| counter_interval  |   no  |  | <ul></ul> |  Indicates the the counter sampling interval.<br>The value is an integer that ranges from 10 to 4294967295, in seconds. The default value is 20. |
| export_route  |   no  |    | <ul><li>enable</li><li>disable</li> </ul> |  Configures the sFlow packets sent by the switch not to carry routing information. |
| rate_limit  |   no  |  | <ul></ul> |  Specifies the rate of sFlow packets sent from a card to the control plane.<br>The value is an integer that ranges from 100 to 1500, in pps. |
| rate_limit_slot  |   no  |  | <ul></ul> |  Specifies the slot where the rate of output sFlow packets is limited.<br>If this parameter is not specified, the rate of sFlow packets sent from all cards to the control plane is limited.<br>The value is an integer or a string of characters.  |
| forward_enp_slot  |   no  |    | <ul> </ul> |  Enable the Embedded Network Processor (ENP) chip function.<br>The switch uses the ENP chip to perform sFlow sampling,and the maximum sFlow sampling interval is 65535.<br>If you set the sampling interval to be larger than 65535, the switch automatically restores it to 65535. <br>The value is an integer or 'all'. |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Configuring sFlow Agent
- ce_sflow:
    agent_ip: 6.6.6.6
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configuring sFlow Collector
- ce_sflow:
    collector_id: 1
    collector_ip: 7.7.7.7
    collector_ip_vpn: vpn1
    collector_description: Collector1
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure flow sampling.
- ce_sflow:
    sflow_interface: 10GE2/0/2
    sample_collector: 1
    sample_direction: inbound
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure counter sampling.
- ce_sflow:
    sflow_interface: 10GE2/0/2
    counter_collector: 1
    counter_interval: 1000
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```

---


## ce_snmp_community
Manages SNMP community configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages SNMP community configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| acl_number  |   no  |  | <ul></ul> |  Access control list number.  |
| community_name  |   no  |    | <ul></ul> |  Unique name to identify the community  |
| access_right  |   no  |  | <ul><li>read</li><li>write</li></ul> |  Access right read or write.  |
| community_mib_view  |   no  |  | <ul></ul> |  Mib view name.  |
| group_name  |   no  |    | <ul> </ul> |  Unique name to identify the SNMPv3 group.  |
| security_level  |   no  |  | <ul><li>noAuthNoPriv</li><li>authentication</li><li>privacy</li></ul> |  Security level indicating whether to use authentication and encryption. |
| read_view  |   no  |  | <ul></ul> |  Mib view name for read.  |
| write_view  |   no  |  | <ul></ul> |  Mib view name for write.  |
| notify_view  |   no  |    | <ul> </ul> |  Mib view name for notification. |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# config SNMP community
  - name: "config SNMP community"
    ce_snmp_community:
        state:  present
        community_name:  Wdz123
        access_right:  write
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo SNMP community
  - name: "undo SNMP community"
    ce_snmp_community:
        state:  absent
        community_name:  Wdz123
        access_right:  write
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config SNMP group
  - name: "config SNMP group"
    ce_snmp_community:
        state:  present
        group_name:  wdz_group
        security_level:  noAuthNoPriv
        acl_number:  2000
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo SNMP group
  - name: "undo SNMP group"
    ce_snmp_community:
        state:  absent
        group_name:  wdz_group
        security_level:  noAuthNoPriv
        acl_number:  2000
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```

---


## ce_snmp_contact
Manages SNMP contact configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages SNMP contact configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| contact  |   yes  |  | <ul></ul> |  Contact information  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |
#### Examples

```
# config SNMP contact
  - name: "config SNMP contact"
    ce_snmp_contact:
        state:  present
        contact:  call Operator at 010-99999999
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo SNMP contact
  - name: "undo SNMP contact"
    ce_snmp_contact:
        state:  absent
        contact:  call Operator at 010-99999999
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```

---


## ce_snmp_location
Manages SNMP location configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages SNMP location configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| location  |   yes  |  | <ul></ul> |  Location information.  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |
#### Examples

```
# config SNMP location
  - name: "config SNMP location"
    ce_snmp_location:
        state:  present
        location:  nanjing China
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo SNMP location
  - name: "undo SNMP location"
    location:
        state:  absent
        location:  nanjing China
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```

---


## ce_snmp_target_host
Manages SNMP target host configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages SNMP target host configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| version  |   no  |  | <ul><li>none</li><li>v1</li><li>v2c</li><li>v3</li><li>v1v2c</li><li>v1v3</li><li>v2cv3</li><li>all</li></ul> |  Version(s) Supported by SNMP Engine.  |
| connect_port  |   no  |    | <ul> </ul> |  Udp port used by SNMP agent to connect the Network management. |
| host_name  |   no  |   | <ul></ul> |  Unique name to identify target host entry.  |
| address  |   no  |  | <ul></ul> |  Network Address.  |
| notify_type  |   no  |    | <ul><li>trap</li><li>inform</li></ul> |  To configure notify type as trap or inform. |
| vpn_name  |   no  |  | <ul></ul> |  VPN instance Name  |
| recv_port  |   no  |  | <ul></ul> |  UDP Port number used by network management to receive alarm messages  |
| security_model  |   no  |    | <ul> <li>v1</li><li>v2c</li><li>v3</li></ul> |  Security Model. |
| security_name  |   no  |  | <ul></ul> |  Security Name.  |
| security_name_v3  |   no  |  | <ul></ul> |  Security Name V3.  |
| security_level  |   no  |    | <ul> <li>noAuthNoPriv</li><li>authentication</li><li>privacy</li></ul> |  Security level indicating whether to use authentication and encryption. |
| is_public_net  |   no  |  | <ul><li>true</li><li>false</li></ul> |   To enable or disable Public Net-manager for target Host.  |
| interface_name  |   no  |  | <ul></ul> |  Name of the interface to send the trap message.  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# config SNMP version
  - name: "config SNMP version"
    ce_snmp_target_host:
        state:  present
        version:  v2cv3
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config SNMP connect port
  - name: "config SNMP connect port"
    ce_snmp_target_host:
        state:  present
        connect_port:  12345
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config SNMP target host
  - name: "config SNMP target host"
    ce_snmp_target_host:
        state:  present
        host_name:  test1
        address:  1.1.1.1
        notify_type:  trap
        vpn_name:  js
        security_model:  v2c
        security_name:  wdz
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```

---


## ce_snmp_traps
Manages SNMP traps configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages SNMP traps configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| feature_name  |   no  |  | <ul><li>aaa</li><li>arp</li><li>bfd</li><li>bgp</li><li>cfg</li><li>configuration</li><li>dad</li><li>devm</li><li>dhcpsnp</li><li>dldp</li> <li>driver</li> <li>efm</li> <li>erps</li> <li>error-down</li> <li>fcoe</li><li>fei</li> <li>fei_comm</li> <li>fm</li> <li>ifnet</li> <li>info</li> <li>ipsg</li> <li>ipv6</li> <li>isis</li><li>l3vpn</li> <li>lacp</li> <li>lcs</li> <li>ldm</li> <li>ldp</li> <li>ldt</li> <li>lldp</li> <li>mpls_lspm</li><li>msdp</li> <li>mstp</li> <li>nd</li> <li>netconf</li> <li>nqa</li> <li>nvo3</li> <li>openflow</li> <li>ospf</li><li>ospfv3</li> <li>pim</li> <li>pim-std</li> <li>qos</li> <li>radius</li> <li>rm</li> <li>rmon</li> <li>securitytrap</li><li>smlktrap</li> <li>snmp</li> <li>ssh</li> <li>stackmng</li> <li>sysclock</li> <li>sysom</li> <li>system</li><li>tcp</li> <li>telnet</li> <li>trill</li> <li>trunk</li> <li>tty</li> <li>vbst</li> <li>vfs</li> <li>virtual-perception</li><li>vrrp</li> <li>vstm</li> <li>all</li></ul> |  Alarm feature name.  |
| trap_name  |   no  |   | <ul> </ul> |  Alarm trap name. |
| interface_type  |   no  |   | <ul><li>Ethernet</li><li>Eth-Trunk</li><li>Tunnel</li><li>NULL</li><li>LoopBack</li><li>Vlanif</li><li>MTunnel</li><li>MEth</li><li>Vbdif</li><li>Nve</li><li>GE</li><li>10GE</li><li>40GE</li><li>100GE</li></ul> |  Interface type.  |
| interface_number  |   no  |  | <ul></ul> |  Interface number.  |
| port_number  |   no  |   | <ul> </ul> |  Source port number. |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |


#### Examples

```
# config SNMP trap all enable
  - name: "config SNMP trap all enable"
    ce_snmp_traps:
        state:  present
        feature_name:  all
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config SNMP trap interface
  - name: "config SNMP trap interface"
    ce_snmp_traps:
        state:  present
        interface_type:  40GE
        interface_number:  2/0/1
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config SNMP trap port
  - name: "config SNMP trap port"
    ce_snmp_traps:
        state:  present
        port_number:  2222
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}
```

---


## ce_snmp_user
Manages SNMP user configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages SNMP user configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| acl_number  |   no  |   | <ul></ul> |  Access control list number.  |
| usm_user_name  |   no  |   | <ul> </ul> |  Unique name to identify the USM user.  |
| remote_engine_id  |   no  |   | <ul></ul> |  Remote Engine ID of the USM user.  |
| user_group  |   no  |   | <ul></ul> |  Name of the group where user belongs to. |
| auth_protocol  |   no  |   | <ul><li>noAuth</li><li>md5</li><li>sha</li></ul> |  Authentication protocol ( md5 | sha ). |
| auth_key  |   no  |   | <ul></ul> |  The Authentication Password. Simple password length <8-255>. Field max.  |
| priv_protocol  |   no  |   | <ul><li>noPriv</li><li>des56</li><li>3des168</li><li>aes128</li><li>aes192</li><li>aes256</li></ul> |  Encryption Protocol.  |
| priv_key  |   no  |   | <ul> </ul> |  The Encryption Password. Simple password length <8-255>. Field max. |
| aaa_local_user  |   no  |   | <ul></ul> |  Unique name to identify the Local user.  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# config SNMP usm user
  - name: "config SNMP usm user"
    ce_snmp_user:
        state:  present
        usm_user_name:  wdz_snmp
        remote_engine_id:  800007DB03389222111200
        acl_number:  2000
        user_group:  wdz_group
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo SNMP usm user
  - name: "undo SNMP usm user"
    ce_snmp_user:
        state:  absent
        usm_user_name:  wdz_snmp
        remote_engine_id:  800007DB03389222111200
        acl_number:  2000
        user_group:  wdz_group
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# config SNMP local user
  - name: "config SNMP local user"
    ce_snmp_user:
        state:  present
        aaa_local_user:  wdz_user
        auth_protocol:  md5
        auth_key:  huawei123
        priv_protocol:  des56
        priv_key:  huawei123
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

# undo SNMP local user
  - name: "config SNMP local user"
    ce_snmp_user:
        state:  absent
        aaa_local_user:  wdz_user
        auth_protocol:  md5
        auth_key:  huawei123
        priv_protocol:  des56
        priv_key:  huawei123
        host:  {{inventory_hostname}}
        username:  {{username}}
        password:  {{password}}

```

---


## ce_static_route
Manages static route configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages static route configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| prefix  |   yes  |  | <ul></ul> |  Destination ip address of static route.  |
| mask  |   yes  |    | <ul> </ul> |  Destination ip mask of static route. |
| aftype  |   yes  |  | <ul><li>v4</li><li>v6</li></ul> |  Destination ip address family type of static route.  |
| next_hop  |   no  |  | <ul></ul> |  Next hop address of static route.  |
| nhp_interface  |   no  |    | <ul> </ul> |  Next hop interface full name of static route. |
| vrf  |   no  |  | <ul></ul> |  VPN instance of destination ip address.  |
| destvrf  |   no  |  | <ul></ul> |  VPN instance of next hop ip address.  |
| tag  |   no  |    | <ul> </ul> |  Route tag value (numeric). |
| description  |   no  |  | <ul></ul> |  Name of the route. Used with the name parameter on the CLI.  |
| pref  |   no  |  | <ul></ul> |  Preference or administrative difference of route (range 1-255).  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Config a ipv4 static route, next hop is 3.1.1.2, destination address is 2.1.1.0/24
- ce_static_route:
    prefix: 2.1.1.2
    mask: 24
    next_hop: 3.1.1.2
    description: 'Configured by Ansible'
    aftype: v4
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Config a ipv4 static route ,next hop is an interface 10GE1/0/1, destination address is 2.1.1.0/24
- ce_static_route:
    prefix: 2.1.1.2
    mask: 24
    next_interface: 10GE1/0/1
    description: 'Configured by Ansible'
    aftype: v4
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Config a ipv6 static route, next hop is an address and that it has the proper description
- ce_static_route:
    prefix: fc00:0:0:2001::
    mask: 64
    next_hop: fc00:0:0:2004::1
    description: 'Configured by Ansible'
    aftype: v6
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Config a ipv4 static route, next hop is an interface and that it has the proper description
- ce_static_route:
- ce_static_route:
    mask: 64
    next_hop: 10GE1/0/1
    description: 'Configured by Ansible'
    aftype: v6
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Config a VRF and set ipv4 static route, next hop is an address and that it has the proper description
- ce_static_route:
    vrf: vpna
    prefix: 2.1.1.2
    mask: 24
    next_hop: 3.1.1.2
    description: 'Configured by Ansible'
    aftype:v4
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"
```
#### Notes

- If no vrf is supplied, vrf is set to default.
- If state=absent, the route will be removed, regardless of the non-required parameters.

---


## ce_stp
Manages STP configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages STP configuration

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| stp_mode  |   no  |  | <ul><li>stp</li><li>rstp</li><li>mstp</li></ul> |  Set an operation mode for the current MSTP process.<br> The mode can be STP, RSTP, and MSTP.  |
| stp_enable  |   no  |    | <ul> <li>enable</li><li>disable</ul> |  Enable or disable STP on a switch. |
| stp_converge  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Enable or disable STP on a switch.  |
| bpdu_protection  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Configure BPDU protection on an edge port.<br>This function prevents network flapping caused by attack packets.  |
| tc_protection  |   no  |    | <ul><li>enable</li><li>disable</li> </ul> |  Configure the TC BPDU protection function for an MSTP process. |
| tc_protection_interval  |   no  |  | <ul></ul> |  Set the time the MSTP device takes to handle the maximum number of TC BPDUs and immediately refresh forwarding entries.<br>The value is an integer ranging from 1 to 600, in seconds. |
| tc_protection_threshold  |   no  |  | <ul></ul> |  Set the maximum number of TC BPDUs that the MSTP can handle.<br>The value is an integer ranging from 1 to 255. The default value is 1.  |
| interface  |   no  |    | <ul> </ul> |  Interface name. <br>If the value is all, will apply configuration to all interfaces.<br>If the value is a special name, only support input the full name. |
| edged_port  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Set the current port as an edge port.e  |
| bpdu_filter  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Specify a port as a BPDU filter port.  |
| cost  |   no  |    | <ul> </ul> |  Set the path cost of the current port.<br>The default instance is 0. |
| root_protection  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Enable root protection on the current port.  |
| loop_protection  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Enable loop protection on the current port.  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |
#### Examples

```
# config stp mode
  - name: "config stp mode"
    ce_stp:
        state: present
        stp_mode: stp
        host: {{inventory_hostname}}
        username: {{username}}
        password: {{password}}

# undo stp mode
  - name: "undo stp mode"
    ce_stp:
        state: absent
        stp_mode: stp
        host: {{inventory_hostname}}
        username: {{username}}
        password: {{password}}

# enable bpdu protection
  - name: "enable bpdu protection"
    ce_stp:
        state: present
        bpdu_protection: enable
        host: {{inventory_hostname}}
        username: {{username}}
        password: {{password}}

# disable bpdu protection
  - name: "disable bpdu protection"
    ce_stp:
        state: present
        bpdu_protection: disable
        host: {{inventory_hostname}}
        username: {{username}}
        password: {{password}}

```

---


## ce_switchport
Manages Layer 2 switchport interfaces

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages Layer 2 switchport interfaces

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| interface  |   yes  |  | <ul></ul> |  Full name of the interface, i.e. 40GE1/0/22.  |
| mode  |   no  |    | <ul><li>access</li><li>trunk</li> </ul> |  The link type of an interface. |
| access_vlan  |   no  |  | <ul></ul> |  If C(mode=access), used as the access VLAN ID, in the range from 1 to 4094.  |
| native_vlan  |   no  |  | <ul></ul> |  If C(mode=trunk), used as the trunk native VLAN ID, in the range from 1 to 4094.  |
| trunk_vlans  |   no  |    | <ul> </ul> |  If C(mode=trunk), used as the VLAN range to ADD or REMOVE from the trunk, such as 2-10 or 2,5,10-15, etc. |
| state  |  no  | present | <ul><li>present</li><li>absent</li><li>unconfigured</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# ENSURE 40GE1/0/22 is in its default switchport state
- ce_switchport:
    interface: 40GE1/0/22
    state:unconfigured
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# ENSURE 40GE1/0/22 is configured for access vlan 20
- ce_switchport:
    interface: 40GE1/0/22
    mode: access
    access_vlan: 20
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# ENSURE 40GE1/0/22 only has vlans 5-10 as trunk vlans
- ce_switchport:
    interface: 40GE1/0/22
    mode: trunk
    native_vlan: 10
    trunk_vlans: 5-10
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Ensure 40GE1/0/22 is a trunk port and ensure 2-50 are being tagged (doesn't mean others aren't also being tagged)
- ce_switchport:
    interface: 40GE1/0/22
    mode: trunk
    native_vlan: 10
    trunk_vlans: 2-50
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Ensure these VLANs are not being tagged on the trunk
- ce_switchport:
    interface: 40GE1/0/22
    mode: trunk
    trunk_vlans: 51-4000
    state=absent
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"
```
#### Notes
- When C(state=absent), VLANs can be added/removed from trunk links and the existing access VLAN can be 'unconfigured' to just having VLAN 1 on that interface.
- When working with trunks VLANs the keywords add/remove are always sent in the `port trunk allow-pass vlan` command. Use verbose mode to see commands sent.
- When C(state=unconfigured), the interface will result with having a default Layer 2 interface, i.e. vlan 1 in access mode.

---


## ce_vlan
Manages VLAN resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages VLAN resources and attributes

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| vlan_id  |  no  |  | <ul></ul> |  Single VLAN ID, in the range from 1 to 4094.  |
| vlan_range  |   no  |    | <ul></ul> |  Range of VLANs such as 2-10 or 2,5,10-15, etc. |
| name  |   no  |  | <ul></ul> |  Name of VLAN, in the range from 1 to 31.  |
| description  |   no  |  | <ul></ul> |  Specify VLAN description, in the range from 1 to 80.  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Ensure a range of VLANs are not present on the switch
- ce_vlan:
    vlan_range: "2-10,20,50,55-60,100-150"
    state: absent
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Ensure VLAN 50 exists with the name WEB
- ce_vlan:
    vlan_id: 50
    name: WEB
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Ensure VLAN is NOT on the device
- ce_vlan:
    vlan_id: 50
    state: absent
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"
```

---


## ce_vrf
Manage VPN instance

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manage VPN instance

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| vrf  |   yes  |  | <ul></ul> |  VPN instance,the length of vrf name is 1 - 31,i.e. "test",but can not be _public_.  |
| description  |   no  |  | <ul> </ul> |  Description of the vrf,the string length is 1 - 242 . |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Config a vpn install named vpna, description is test
- ce_vrf:
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
    vrf=vpna description=test state=present

# Delete a vpn install named vpna
- ce_vrf:
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
    vrf=vpna state=absent

```

---


## ce_vrf_af
Manage VPN instance address family

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manage VPN instance address family

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| vrf  |   yes  |  | <ul></ul> |  VPN instance.  |
| vrf_aftype  |   no  |  v4  | <ul><li>v4</li><li>v6</li> </ul> |  VPN instance address family. |
| route_distinguisher  |   no  |  | <ul></ul> |  VPN instance route distinguisher,the RD used to distinguish same route prefix from different vpn.<br>The RD must be setted before setting vpn_target_value.  |
| vpn_target_state  |   no  |    | <ul><li>present</li><li>absent</li> </ul> |  Manage the state of the vpn target. |
| vpn_target_type  |   no  |  | <ul><li>export_extcommunity</li><li>import_extcommunity</li></ul> |  VPN instance vpn target type.  |
| vpn_target_value  |   no  |    | <ul> </ul> |  VPN instance target value.<br>X.X.X.X:number<0-65535> or number<0-65535>:number<0-4294967295> or number<0-65535>.number<0-65535>:number<0-65535> or number<65536-4294967295>:number<0-65535> but not support 0:0 |
| evpn  |   no  | false | <ul><li>true</li><li>false</li> </ul> |  Is extend vpn or normal vpn.  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Config vpna, set address family is ipv4
- ce_vrf_af:
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
    vrf: vpna
    vrf_aftype: v4
    state: present

# Config vpna, delete address family is ipv4
- ce_vrf_af:
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
    vrf: vpna
    vrf_aftype: v4
    state: absent

# Config vpna, set address family is ipv4,rd=1:1,set vpn_target_type=export_extcommunity,vpn_target_value=2:2
- ce_vrf_af:
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
    vrf: vpna
    vrf_aftype: v4
    route_distinguisher: 1:1
    vpn_target_type: export_extcommunity
    vpn_target_value: 2:2
    vpn_target_state: present
    state: present

# Config vpna, set address family is ipv4,rd=1:1,delete vpn_target_type=export_extcommunity,vpn_target_value=2:2
- ce_vrf_af:
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
    vrf: vpna
    vrf_aftype: v4
    route_distinguisher: 1:1
    vpn_target_type: export_extcommunity
    vpn_target_value: 2:2
    vpn_target_state: absent
    state=present

```
#### Notes
- If no vrf is supplied, the module will return error.
- If state=absent, the vrf will be removed, regardless of the non-required parameters.

---


## ce_vrf_interface
Manages interface specific VPN configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages interface specific VPN configuration.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| vrf  |   yes  |    | <ul> </ul> |  VPN instance, the length of vrf name is 1 ~ 31,i.e. "test", but can not be _public_. |
| vpn_interface  |   yes  |  | <ul></ul> |  An interface that can binding VPN instance, i.e. 40GE1/0/22, Vlanif10.<br>Must be fully qualified interface name.<br>Interface types, such as 10GE, 40GE, 100GE, LoopBack, MEth, Tunnel, Vlanif....  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |


#### Examples

```
# Configure a VPN instance for the interface
- ce_vrf_interface:
    vpn_interface: 40GE1/0/2
    vrf: test
    state: present
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"

# Disable the association between a VPN instance and an interface
- ce_vrf_interface:
    vpn_interface: 40GE1/0/2
    vrf: test
    state: absent
    host: "{{ inventory_hostname }}"
    username: "{{ un }}"
    password: "{{ pwd }}"
```
#### Notes

- Ensure that a VPN instance has been created and the IPv4 address family has been enabled for the VPN instance.

---


## ce_vxlan_arp
Manages ARP attributes of VXLAN

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages ARP attributes of VXLAN

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| evn_bgp  |   no  |    | <ul><li>enable</li><li>disable</li> </ul> |  Enables EVN BGP |
| evn_source_ip  |   no  |  | <ul></ul> |  Specifies the source address of an EVN BGP peer.<br>The value is in dotted decimal notation.  |
| evn_peer_ip  |   no  |    | <ul> </ul> |  Specifies the IP address of an EVN BGP peer.<br>The value is in dotted decimal notation. |
| evn_server  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Configures the local device as the router reflector (RR) on the EVN network.  |
| evn_reflect_client  |   no  |    | <ul><li>true</li><li>false</li> </ul> |  Configures the local device as the route reflector (RR) and its peer as the client. |
| vbdif_name  |   no  |  | <ul></ul> |  Full name of VBDIF interface, i.e. Vbdif100.  |
| arp_collect_host  |   no  |    | <ul><li>enable</li><li>disable</li> </ul> |  Enables EVN BGP or BGP EVPN to collect host information. |
| host_collect_protocol  |   no  |  | <ul><li>bgp</li><li>none</li></ul> |  Enables EVN BGP or BGP EVPN to advertise host information.  |
| bridge_domain_id  |   no  |    | <ul> </ul> |  Specifies a BD(bridge domain) ID.<br>The value is an integer ranging from 1 to 16777215. |
| arp_suppress  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Enables ARP broadcast suppression in a BD.  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |


#### Examples

```
# Configure EVN BGP on Layer 2 and Layer 3 VXLAN gateways to establish EVN BGP peer relationships.
- ce_vxlan_arp:
    evn_bgp: enable
    evn_source_ip: 6.6.6.6
    evn_peer_ip: 7.7.7.7
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure a Layer 3 VXLAN gateway as a BGP RR.
- ce_vxlan_arp:
    evn_bgp: enable
    evn_server: enable
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Enable EVN BGP on a Layer 3 VXLAN gateway to collect host information.
- ce_vxlan_arp:
    vbdif_name: Vbdif100
    arp_collect_host: true
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Enable Layer 2 and Layer 3 VXLAN gateways to use EVN BGP to advertise host information.
- ce_vxlan_arp:
    host_collect_protocol: enable
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Enable ARP broadcast suppression on a Layer 2 VXLAN gateway.
- ce_vxlan_arp:
    bridge_domain_id: 100
    arp_suppress: enable
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```

---


## ce_vxlan_gateway
Manages gateway for the VXLAN Network

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages gateway for the VXLAN Network

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| dfs_id  |  no  |   | <ul></ul> |  Specifies the ID of a DFS group.<br>The value must be 1.  |
| dfs_source_ip  |   no  |   | <ul> </ul> |  Specifies the IPv4 address bound to a DFS group.<br>The value is in dotted decimal notation. |
| dfs_source_vpn  |   no  |   | <ul></ul> |  Specifies the name of a VPN instance bound to a DFS group.<br>The value is a string of 1 to 31 case-sensitive characters without spaces.<br>If the character string is quoted by double quotation marks, the character string can contain spaces.<br>The value _public_ is reserved and cannot be used as the VPN instance name.  |
| dfs_udp_port  |  no  |   | <ul></ul> |  Specifies the UDP port number of the DFS group.<br>The value is an integer that ranges from 1025 to 65535.  |
| dfs_all_active  |   no  |   | <ul> <li>enable</li><li>disable</li></ul> |  Creates all-active gateways. |
| dfs_peer_ip  |   no  |   | <ul></ul> |  Configure the IP address of an all-active gateway peer.<br>The value is in dotted decimal notation.  |
| dfs_peer_vpn  |   no  |   | <ul> </ul> |  Specifies the name of the VPN instance that is associated with all-active gateway peer.<br>The value is a string of 1 to 31 case-sensitive characters, spaces not supported.<br>When double quotation marks are used around the string, spaces are allowed in the string.<br>The value _public_ is reserved and cannot be used as the VPN instance name. |
| vpn_instance  |   no  |   | <ul></ul> |  Specifies the name of a VPN instance.<br>The value is a string of 1 to 31 case-sensitive characters, spaces not supported.<br> When double quotation marks are used around the string, spaces are allowed in the string.<br>The value _public_ is reserved and cannot be used as the VPN instance name.  |
| vpn_vni  |  no  |   | <ul></ul> |  Specifies a VNI ID.<br> Binds a VXLAN network identifier (VNI) to a virtual private network (VPN) instance.<br>The value is an integer ranging from 1 to 16000000. |
| vbdif_name  |   no  |   | <ul> </ul> |  Full name of VBDIF interface, i.e. Vbdif100. |
| vbdif_bind_vpn  |   no  |   | <ul></ul> |  Specifies the name of the VPN instance that is associated with the interface.<br>The value is a string of 1 to 31 case-sensitive characters, spaces not supported.<br>When double quotation marks are used around the string, spaces are allowed in the string.<br>The value _public_ is reserved and cannot be used as the VPN instance name.  |
| vbdif_mac  |  no  |   | <ul></ul> |  Specifies a MAC address for a VBDIF interface.<br>The value is in the format of H-H-H. Each H is a 4-digit hexadecimal number, such as 00e0 or fc01.<br>If an H contains less than four digits, 0s are added ahead. For example, e0 is equal to 00e0.<br>A MAC address cannot be all 0s or 1s or a multicast MAC address.  |
| arp_distribute_gateway  |   no  |   | <ul><li>enable</li><li>disable</li> </ul> |  Enable the distributed gateway function on VBDIF interface. |
| arp_direct_route  |   no  |   | <ul><li>enable</li><li>disable</li></ul> |  Enable VLINK direct route on VBDIF interface.  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Configuring Centralized All-Active Gateways for the VXLAN Network
- ce_vxlan_gateway:
    dfs_id: 1
    dfs_source_ip: 6.6.6.6
    dfs_all_active: enable
    dfs_peer_ip: 7.7.7.7
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Bind the VPN instance to a Layer 3 gateway, enable distributed gateway, and configure host route advertisement.
- ce_vxlan_gateway:
    vbdif_name: Vbdif100
    vbdif_bind_vpn: vpn1
    arp_distribute_gateway: enable
    arp_direct_route: enable
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Assign a VNI to a VPN instance.
- ce_vxlan_gateway:
    vpn_instance: vpn1
    vpn_vni: 100
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```

---


## ce_vxlan_global
Manages global attributes of VXLAN and bridge domain

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages global attributes of VXLAN and bridge domain

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| bridge_domain_id  |   no  |  | <ul></ul> |  Specifies a bridge domain ID.<br>The value is an integer ranging from 1 to 16777215.  |
| tunnel_mode_vxlan  |   no  |   | <ul><li>enable</li><li>disable</li> </ul> |  Set the tunnel mode to VXLAN when configuring the VXLAN feature. |
| nvo3_prevent_loops  |   no  |   | <ul><li>enable</li><li>disable</li></ul> |  Loop prevention of VXLAN traffic in non-enhanced mode.<br>When the device works in non-enhanced mode,inter-card forwarding of VXLAN traffic may result in loops.  |
| nvo3_acl_extend  |   no  |  | <ul><li>enable</li><li>disable</li></ul> |  Enabling or disabling the VXLAN ACL extension function.  |
| nvo3_gw_enhanced  |   no  |   | <ul><li>enable</li><li>disable</li> </ul> | Configuring the Layer 3 VXLAN Gateway to Work in Non-loopback Mode. |
| nvo3_service_extend  |   no  |   | <ul><li>enable</li><li>disable</li></ul> |  Enabling or disabling the VXLAN service extension function.  |
| nvo3_eth_trunk_hash  |   no  |   | <ul><li>enable</li><li>disable</li></ul> |  Eth-Trunk from load balancing VXLAN packets in optimized mode.  |
| nvo3_ecmp_hash  |   no  |   | <ul><li>enable</li><li>disable</li></ul> |  Load balancing of VXLAN packets through ECMP in optimized mode.  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |

#### Examples

```
# Create bridge domain and set tunnel mode to VXLAN
- ce_vxlan_global:
    bridge_domain_id: 100
    nvo3_acl_extend: enable
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```

---


## ce_vxlan_tunnel
Manages VXLAN tunnel configuration

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages VXLAN tunnel configuration

#### Options

| Parameter     | required    | default  | choices      | comments |
| ------------- |-------------| ---------|------------- |--------- |
| bridge_domain_id  |   no  |  | <ul></ul> |  Specifies a bridge domain ID. <br>The value is an integer ranging from 1 to 16777215.  |
| vni_id  |   no  |    | <ul> </ul> |  Specifies a VXLAN network identifier (VNI) ID. <br>The value is an integer ranging from 1 to 16000000. |
| nve_name  |   no  |  | <ul></ul> |  Specifies the number of an NVE interface. <br>The value ranges from 1 to 2.  |
| nve_mode  |   no  |  | <ul><li>mode-l2</li><li>mode-l3</li></ul> |  Specifies the working mode of an NVE interface.  |
| peer_list_ip  |   no  |    | <ul> </ul> |  Specifies the IP address of a remote VXLAN tunnel endpoints (VTEP).<br>The value is in dotted decimal notation. |
| protocol_type  |   no  |  | <ul><li>bgp</li><li>null</li></ul> |  The operation type of routing protocol.  |
| source_ip  |   no  |  | <ul></ul> |  Specifies an IP address for a source VTEP. The value is in dotted decimal notation.  |
| state  |  no  | present | <ul><li>present</li><li>absent</li></ul> | Specify desired state of the resource.  |
#### Examples

```
# Make sure nve_name is exist, vni_id and protocol_type is configured on Nve1 interface.
- ce_vxlan_tunnel:
    nve_name: Nve1
    vni_id: 100
    protocol_type: bgp
    state: present
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"
    
# Make sure nve_name is exist, vni_id and peer_list_ip is configured on Nve1 interface.
- ce_vxlan_tunnel:
    nve_name: Nve1
    vni_id: 100
    peer_list_ip: 1.2.2.2,2.2.2.5,2.5.3.9
    state: present
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```

---


## ce_vxlan_vap
Manages VXLAN virtual access point

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages VXLAN virtual access point

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| bridge_domain_id  |   no  |  | <ul></ul> |  Specifies a bridge domain ID.<br>The value is an integer ranging from 1 to 16777215.  |
| bind_vlan_id  |   no  |    | <ul> </ul> |  Specifies the vlan binding to a BD(Bridge Domain).<br>The value is an integer ranging ranging from 1 to 4094 |
| l2_sub_interface  |   no  |  | <ul></ul> |  Specifies an Sub-Interface full name, i.e. "10GE1/0/41.1". <br> The value is a string of 1 to 63 case-insensitive characters, spaces supported.  |
| encapsulation  |   no  |  | <ul><li>dot1q</li><li>default</li><li>untag</li><li>qinq</li><li>none</li>  </ul> |  Specifies an encapsulation type of packets allowed to pass through a Layer 2 sub-interface  |
| ce_vid  |   no  |    | <ul> </ul> |  When C(encapsulation) is 'dot1q', specifies a VLAN ID in the outer VLAN tag.<br>When C(encapsulation) is 'qinq', specifies an outer VLAN ID for double-tagged packets to be received by a Layer 2 sub-interface. |
| pe_vid  |   no  | flash: | <ul></ul> |  When C(encapsulation) is 'qinq', specifies an inner VLAN ID for double-tagged packets to be received by a Layer 2 sub-interface  |
| state  |   no  | present | <ul><li>present</li>  <li>absent</li></ul> |  Determines whether the config should be present or not on the device  |

#### Examples

```
# Create a papping between a VLAN and a BD
- ce_vxlan_vap:
    bridge_domain_id: 100
    bind_vlan_id: 99
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Bind a Layer 2 sub-interface to a BD
- ce_vxlan_vap:
    bridge_domain_id: 100
    l2_sub_interface: 10GE3/0/40.1
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

# Configure an encapsulation type on a Layer 2 sub-interface
- ce_vxlan_vap:
    l2_sub_interface: 10GE3/0/40.1
    encapsulation: dot1q
    username: "{{ un }}"
    password: "{{ pwd }}"
    host: "{{ inventory_hostname }}"

```
------



