## ABOUT

Huawei CloudEngine Switch support for using Ansible to deploy devices. The Huawei CloudEngine Ansible library, enables you to use Ansible to perform specific operational and configuration tasks on CloudEngine devices.

## OVERVIEW OF MODULES

- ce_aaa_server - Manages AAA server global configuration.
- ce_aaa_server_host - Manages AAA server host configuration.
- ce_acl - Manages base acl configuration.
- ce_acl_advance - Manages advance acl configuration.
- ce_acl_interface - Manages applying ACLs to interfaces.
- ce_bgp - Manages BGP configuration.
- ce_bgp_af - Manages BGP Address-family configuration.
- ce_bgp_neighbor - Manages BGP peer configuration.
- ce_bgp_neighbor_af - Manages BGP neighbor Address-family configuration.
- ce_command - Run arbitrary command on Huawei CloudEngine devices.
- ce_config - Manage Huawei CloudEngine configuration sections.
- ce_dldp - Manages global DLDP configration.
- ce_dldp_interface - Manages interface DLDP configuration.
- ce_eth_trunk - Manages Eth-Trunk interfaces.
- ce_evpn_bd_vni - Manages Huawei EVPN VXLAN Network Identifier (VNI).
- ce_evpn_bgp - Manages BGP EVPN configuration.
- ce_evpn_bgp_rr - Manages RR for the VXLAN Network.
- ce_evpn_global - Manage global configration of EVPN.
- ce_facts - Gets facts about HUAWEI CloudEngine switches.
- ce_file_copy - Copy a file to a remote cloudengine device over SCP.
- ce_info_center_debug - Manages info center debug configuration.
- ce_info_center_global - Manages outputting Logs.
- ce_info_center_log - Manages Log Output.
- ce_info_center_trap - Manages info center trap configuration.
- ce_interface - Manages physical attributes of interfaces.
- ce_interface_ospf - Manages configuration of an OSPF interface instance.
- ce_ip_interface - Manages L3 attributes for IPv4 and IPv6 interfaces.
- ce_mtu - Manages MTU settings on CloudEngine switch.
- ce_netconf - Run arbitrary netconf command on cloudengine devices.
- ce_netstream_aging - Manages timeout mode of netstream.
- ce_netstream_export - Configure NetStream flow statistics exporting and versions for exported packets.
- ce_netstream_global - Manages global parameters of netstream.
- ce_netstream_template - Manages netstream template configuration.
- ce_ntp - Manages core NTP configuration.
- ce_ntp_auth - Manages NTP authentication.
- ce_ospf - Manages configuration of an ospf instance.
- ce_ospf_vrf - Manages configuration of an ospf vpn instance.
- ce_reboot - Reboot a network device.
- ce_rollback - Set a checkpoint or rollback to a checkpoint.
- ce_sflow - Manages sFlow.
- ce_snmp_community - Manages SNMP Community configuration.
- ce_snmp_contact - Manages SNMP contact configuration.
- ce_snmp_location - Manages SNMP location configuration.
- ce_snmp_target_host - Manages SNMP target host configuration.
- ce_snmp_traps - Manages SNMP traps configuration.
- ce_snmp_user - Manages SNMP Community configuration.
- ce_static_route - Config or delete static route.
- ce_stp - Manages stp configuration.
- ce_switchport - Manages Layer 2 switchport interfaces.
- ce_vlan - Manages VLAN resources and attributes.
- ce_vrf - Manage vpn instance.
- ce_vrf_af - Manage vpn instance address family.
- ce_vrf_interface - Manage VPN Instance to an Interface.
- ce_vxlan_arp - Manages arp attributes of VXLAN.
- ce_vxlan_gateway - Manages Gateway for the VXLAN Network.
- ce_vxlan_global - Manages global attributes of VXLAN and bridge domain.
- ce_vxlan_tunnel - A VNI is created and mapped to the BD, and configure an ingress replication list.
- ce_vxlan_vap - Manages VXLAN virtual access point.


## INSTALLATION

Circumstance instruction:
Ansible network module is suitable for ansible version 2.2. The available ncclient version is 0.5.2.

Main steps:

Install suitable Ansible master
Install suitable ncclient library
Install Huawei Ansible library

## EXAMPLE USAGE
An example of static manifest for CloudEngine switch is followed. The network functions is satisfied based on the assumed that Ansible moudle is available.
```
root@localhost:~# ansible -m ce_command -a "commands='display vlan summary' transport='cli' host=192.168.1.1 port=22 username=huawei password=huawei123" localhost --connection local
localhost | SUCCESS => {
    "changed": false, 
    "stdout": [
        "Number of static VLAN: 3\nVLAN ID: 1 4001 to 4002 \n\nNumber of dynamic VLAN: 0\nVLAN ID: \n\nNumber of service VLAN: 62\nVLAN ID: 4030 to 4060 4064 to 4094 "
    ], 
    "stdout_lines": [
        [
            "Number of static VLAN: 3", 
            "VLAN ID: 1 4001 to 4002 ", 
            "", 
            "Number of dynamic VLAN: 0", 
            "VLAN ID: ", 
            "", 
            "Number of service VLAN: 62", 
            "VLAN ID: 4030 to 4060 4064 to 4094 "
        ]
    ], 
    "warnings": []
}
```

## DEPENDENCIES

Thes modules require the following to be installed on the Ansible server:

* Python 2.6 or 2.7
* [Ansible](http://www.ansible.com) 2.2 or later
* [ncclient](https://github.com/ncclient/ncclient) 0.5.2 or later
* [Huawei support](http://www.huawei.com/en/)
