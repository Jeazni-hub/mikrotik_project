import paramiko
import threading


def send_exec_cmd(cmd):
    """ Take the command we want to execute in parameter and retun the answer of the target or none.
    var: cmd and out,
    fonct: exec_cmd
    """
    cmd = cmd.strip()
    out = exec_cmd(cmd)
    out = out[1].read().decode().strip()
    if out != "":
        print(out)
    else:
        pass


def exec_cmd(cmd):
    """Take the command to send to the target.
    var: cmd and out
    function: paramiko function
    """
    out = stdin, stdout, stderr = session.exec_command(cmd)
    return out


def get_info():
    """ print system information """
    info = exec_cmd("system resource print")
    print(info[1].read().decode().strip())


def auto_config():
    """configure automatically the system after get some information to the user
    var: None
    function: config"""
    for elt in config():
        for each_elt in elt:
            thd = threading.Thread(target=send_exec_cmd(each_elt))
            thd.start()
            thd.join()
    print("complete.")


def reset_config():
    """initialize configuration"""
    exec_cmd("system reset-configuation")


def reboot_system():
    """reboot the system """
    exec_cmd("system reboot")
    exec_cmd("y")


def shut_downs_sytem():
    """turning off the system"""
    exec_cmd("system shutdown")


def ip_calculator(address_range_cidr):
    """ ask the information which will use to configure the system. It return list of 5 variables
    var: address, network_address, address_range, address_range_cidr, addr_with_mask
    function: None"""
    network_address = address_range_cidr.split("/")
    slash = network_address[1]
    network_address = network_address[0] # 2
    address = network_address.split(".")
    address.pop()
    memo_min_addr = list(address)
    memo_max_addr = list(address)

    address.append("254")
    address = ".".join(address) # 1

    memo_min_addr.append("10")
    min_addr = ".".join(memo_min_addr)

    memo_max_addr.append("253")
    max_addr = ".".join(memo_max_addr)

    address_range = [min_addr, "-", max_addr] # 3
    address_range = "".join(address_range) # 4
    addr_with_mask = [address, "/", slash]
    addr_with_mask = "".join(addr_with_mask) # 5

    return address, network_address, address_range, address_range_cidr, addr_with_mask


def get_hotspot_lan_conf_info():

    global hotspot_dns_name, hotspot_bridge_name, hotspot_net_cidr, hotspot_address, hotspot_network_addr
    global hotspot_dhcp_range, hotspot_addr_with_mask, lan_bridge_name, lan_net_cidr, lan_address
    global lan_network_addr, lan_dhcp_range, lan_addr_with_mask, hotspot_name

    hotspot_dns_name = input(" hotspot dns name (i.e. www.hostpotname.tg):\n ")
    # hotspot_dns_name = "www.wifiname.tg"
    hotspot_name = hotspot_dns_name.split(".")[1]
    hotspot_bridge_name = "HOTSPOT"
    hotspot_net_cidr = input("hotspot network address in CIDR format (i.e '10.0.0.0/24')\n ")
    # hotspot_net_cidr = "172.16.0.0/24"
    hotspot_address, hotspot_network_addr, hotspot_dhcp_range, _, hotspot_addr_with_mask = ip_calculator \
        (hotspot_net_cidr)
    lan_bridge_name = "LAN"
    lan_net_cidr = input("LAN network address in CIDR format (i.e '192.168.100.0/24')\n ")
    # lan_net_cidr = "192.168.0.0/24"
    lan_address, lan_network_addr, lan_dhcp_range, _, lan_addr_with_mask = ip_calculator(lan_net_cidr)


def config():

    get_hotspot_lan_conf_info()
    # interface bridge
    interf_bridg = [f"interface bridge add name={hotspot_bridge_name}",
                    f"interface bridge add name={lan_bridge_name}"]
    # interface ethernet
    interf_ether = [f"interface ethernet set [ find default-name=ether1 ] name=WAN"]

    # ip hotspot profile
    ip_hotspot_profile = [f"ip hotspot profile add dns-name={hotspot_dns_name} hotspot-address={hotspot_address}\
     http-cookie-lifetime=1d name={hotspot_name.capitalize()} use-radius=yes"]
    # ip pool
    ip_pool = [f"ip pool add name=hs-pool-7 ranges={hotspot_dhcp_range}"]
    # ip dhcp-server
    ip_dhcp_server = [f"ip dhcp-server add address-pool=hs-pool-7 disabled=no interface={hotspot_bridge_name}\
     lease-time=1h name=dhcp1"]
    # ip hotspot
    ip_hotspot = [f"ip hotspot add address-pool=hs-pool-7 addresses-per-mac=1 disabled=no\
     interface={hotspot_bridge_name} name={hotspot_name.upper()} profile={hotspot_name.capitalize()}"]
    # ip address
    ip_addr = [f"ip address add address={lan_addr_with_mask} interface={lan_bridge_name} network={lan_network_addr}",
               f"ip address add address={hotspot_addr_with_mask} interface={hotspot_bridge_name}\
     network={hotspot_network_addr}"]
    # ip dhcp-client
    ip_dhcp_client = [f"ip dhcp-client add disabled=no interface=WAN"]
    # ip dhcp-server network
    ip_dhcp_server_net = [f'ip dhcp-server network add address={hotspot_net_cidr} comment="hotspot network"\
     gateway={hotspot_address}']
    # ip dns
    ip_dns = [f"ip dns set servers=8.8.8.8,8.8.4.4"]
    # ip firewall filter
    ip_firewall_filter = [f'ip firewall filter add action=passthrough chain=unused-hs-chain\
     comment="place hotspot rules here" disabled=yes']

    # ip firewall nat
    # # 1 et 3
    ip_firewall_nat = [f'ip firewall nat add action=passthrough chain=unused-hs-chain comment="place\
     hotspot rules here" disabled=yes',
                       f"ip firewall nat add action=masquerade chain=srcnat out-interface=WAN\
     src-address={lan_net_cidr}",
                       f'ip firewall nat add action=masquerade chain=srcnat comment="masquerade\
     hotspot network" src-address={hotspot_net_cidr}']
    # ip hotspot user
    ip_hotspot_user = [f"ip hotspot user add name=admin"]

    conf = [interf_bridg, interf_ether, ip_hotspot_profile, ip_pool, ip_dhcp_server, ip_hotspot,
              ip_addr, ip_dhcp_client, ip_dhcp_server_net, ip_dns, ip_firewall_filter, ip_firewall_nat, ip_hotspot_user]

    return conf


# hotspot and lan variables which are global
hotspot_dns_name = ""
hotspot_bridge_name = ""
hotspot_net_cidr = ""
hotspot_address = ""
hotspot_network_addr = ""
hotspot_dhcp_range = ""
hotspot_addr_with_mask = ""
lan_bridge_name = ""
lan_net_cidr = ""
lan_address = ""
lan_network_addr = ""
lan_dhcp_range = ""
lan_addr_with_mask = ""


# target information
Target = input("Target :\n ")
# Target = "192.168.144.26"
user = input("User name:\n ")
# user = "admin"
pwd = input("User password:\n ")
# pwd = ""

# open session
session = paramiko.SSHClient()
session.set_missing_host_key_policy(paramiko.AutoAddPolicy)
session.connect(hostname=Target, username=user, password=pwd)

# main loop
cmd = ""
while cmd != "exit":
    cmd = input('> ')
    if cmd == "":
        continue
    elif cmd == "help" or cmd == "??":
        print("User manuel:\n"
              "   auto config        -------------> automatic configuration of router\n"
              "   info / system info -------------> get information about router\n"
              "   reset              -------------> reset the system configuration\n"
              "   reboot             -------------> reboot the system\n"
              "   shutdown / init 0  -------------> shutdown the system\n"

              )
    elif cmd == "auto config":
        auto_config()
    elif cmd == "info" or cmd == "system info":
        get_info()
    elif cmd == "reset":
        reset_config()
        cmd = "exit"
    elif cmd == "reboot":
        reboot_system()
        cmd = "exit"
    elif cmd == "shutdown" or cmd == "init 0":
        shut_downs_sytem()
        cmd = "exit"
    else:
        send_exec_cmd(cmd)
session.close()