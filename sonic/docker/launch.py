#!/usr/bin/env python3

import datetime
import logging
import os
import re
import signal
import subprocess
import sys

import vrnetlab

CONFIG_FILE = "/config/config_db.json"
DEFAULT_USER = "admin"
DEFAULT_PASSWORD = "YourPaSsWoRd"


def handle_SIGCHLD(_signal, _frame):
    os.waitpid(-1, os.WNOHANG)


def handle_SIGTERM(_signal, _frame):
    sys.exit(0)


signal.signal(signal.SIGINT, handle_SIGTERM)
signal.signal(signal.SIGTERM, handle_SIGTERM)
signal.signal(signal.SIGCHLD, handle_SIGCHLD)

TRACE_LEVEL_NUM = 9
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")


def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)


logging.Logger.trace = trace


class SONiC_vm(vrnetlab.VM):
    def __init__(self, hostname, username, password, conn_mode):
        disk_image = "/"
        for e in os.listdir("/"):
            if re.search(".qcow2$", e):
                disk_image = "/" + e
                break
        super(SONiC_vm, self).__init__(
            username, password, disk_image=disk_image, ram=4096
        )
        self.qemu_args.extend(["-smp", "2"])
        self.nic_type = "virtio-net-pci"
        self.conn_mode = conn_mode
        self.num_nics = 96
        self.hostname = hostname
        # Whether the management interface is pass-through or host-forwarded.
        # Host-forwarded is the original vrnetlab mode where a VM gets a static IP for its management address,
        # which **does not** match the eth0 interface of a container.
        # In pass-through mode the VM container uses the same IP as the container's eth0 interface and transparently forwards traffic between the two interfaces.
        # See https://github.com/hellt/vrnetlab/issues/286
        self.mgmt_passthrough = mgmt_passthrough
        mgmt_passthrough_override = os.environ.get("CLAB_MGMT_PASSTHROUGH", "")
        if mgmt_passthrough_override:
            self.mgmt_passthrough = mgmt_passthrough_override.lower() == "true"
        # Populate management IP and gateway
        if self.mgmt_passthrough:
            self.mgmt_address_ipv4, self.mgmt_address_ipv6 = self.get_mgmt_address()
            self.mgmt_gw_ipv4, self.mgmt_gw_ipv6 = self.get_mgmt_gw()
        else:
            self.mgmt_address_ipv4 = "10.0.0.15/24"
            self.mgmt_address_ipv6 = "2001:db8::2/64"
            self.mgmt_gw_ipv4 = "10.0.0.2"
            self.mgmt_gw_ipv6 = "2001:db8::1"
    
    def create_tc_tap_mgmt_ifup(self):
        # this is used when using pass-through mode for mgmt connectivity
        """Create tap ifup script that is used in tc datapath mode, specifically for the management interface"""
        ifup_script = """#!/bin/bash

        ip link set tap0 up
        ip link set tap0 mtu 65000

        # create tc eth<->tap redirect rules

        tc qdisc add dev eth0 clsact
        # exception for TCP ports 5000-5007
        tc filter add dev eth0 ingress prio 1 protocol ip flower ip_proto tcp dst_port 5000-5007 action pass
        # mirror ARP traffic to container
        tc filter add dev eth0 ingress prio 2 protocol arp flower action mirred egress mirror dev tap0
        # redirect rest of ingress traffic of eth0 to egress of tap0
        tc filter add dev eth0 ingress prio 3 flower action mirred egress redirect dev tap0
        # redirect all ingress traffic of tap0 to egress of eth0
        tc filter add dev tap0 ingress flower action mirred egress redirect dev eth0

        # clone management MAC of the VM
        ip link set dev eth0 address {MGMT_MAC}

        # configure the ip address of the namespace as it was the host and remove the temporary one
        ip netns exec fakehost ip addr add {MGMT_CONTAINER_GW}/{MGMT_IP_PREFIXLEN} dev FA
        ip netns exec fakehost ip addr del  169.254.254.254/16 dev FA
        """

        mgmt_ip_v4_address, mgmt_ip_v4_prefixlen = self.mgmt_address_ipv4.split("/")

        ifup_script = ifup_script.replace("{MGMT_MAC}", self.mgmt_mac)
        ifup_script = ifup_script.replace(
            "{FAKEHOST_VETH_MAC_ADDR}", FAKEHOST_VETH_MAC_ADDR
        )
        ifup_script = ifup_script.replace("{MGMT_CONTAINER_GW}", self.mgmt_gw_ipv4)
        ifup_script = ifup_script.replace("{MGMT_IP_PREFIXLEN}", mgmt_ip_v4_prefixlen)
        ifup_script = ifup_script.replace("{MGMT_IP_ADDRESS}", mgmt_ip_v4_address)

        with open("/etc/tc-tap-mgmt-ifup", "w") as f:
            f.write(ifup_script)
        os.chmod("/etc/tc-tap-mgmt-ifup", 0o777)
    
    def bootstrap_spin(self):
        """This function should be called periodically to do work."""

        if self.spins > 300:
            # too many spins with no result ->  give up
            self.stop()
            self.start()
            return

        ridx, match, res = self.tn.expect([b"login:"], 1)
        if match and ridx == 0:  # login
            self.logger.info("VM started")

            # Login
            self.wait_write("\r", None)
            self.wait_write(DEFAULT_USER, wait="login:")
            self.wait_write(DEFAULT_PASSWORD, wait="Password:")
            self.wait_write("", wait="%s@" % (self.username))
            self.logger.info("Login completed")

            # run main config!
            self.bootstrap_config()
            self.startup_config()
            # close telnet connection
            self.tn.close()
            # startup time?
            startup_time = datetime.datetime.now() - self.start_time
            self.logger.info(f"Startup complete in: {startup_time}")
            # mark as running
            self.running = True
            return

        # no match, if we saw some output from the router it's probably
        # booting, so let's give it some more time
        if res != b"":
            self.logger.trace("OUTPUT: %s" % res.decode())
            # reset spins if we saw some output
            self.spins = 0

        self.spins += 1

        return

    def bootstrap_config(self):
        """Do the actual bootstrap config"""
        self.logger.info("applying bootstrap configuration")
        self.wait_write("sudo -i", "$")

        if self.mgmt_passthrough:
            self.mgmt_address_ipv4, self.mgmt_address_ipv6 = self.get_mgmt_address()
            self.mgmt_gw_ipv4, self.mgmt_gw_ipv6 = self.get_mgmt_gw()
        else:
            self.wait_write("/usr/sbin/ip address add 10.0.0.15/24 dev eth0", "#")

        self.wait_write("passwd -q %s" % (self.username))
        self.wait_write(self.password, "New password:")
        self.wait_write(self.password, "password:")
        self.wait_write("sleep 1", "#")
        self.wait_write("hostnamectl set-hostname %s" % (self.hostname))
        self.wait_write("sleep 1", "#")
        self.wait_write("printf '127.0.0.1\\t%s\\n' >> /etc/hosts" % (self.hostname))
        self.wait_write("sleep 1", "#")
        self.logger.info("completed bootstrap configuration")

    def startup_config(self):
        """Load additional config provided by user."""

        if not os.path.exists(CONFIG_FILE):
            self.logger.trace(f"Backup file {CONFIG_FILE} not found")
            return

        self.logger.trace(f"Backup file {CONFIG_FILE} exists")

        subprocess.run(
            f"/backup.sh -u {self.username} -p {self.password} restore",
            check=True,
            shell=True,
        )


class SONiC(vrnetlab.VR):
    def __init__(self, hostname, username, password, conn_mode):
        super().__init__(username, password)
        self.vms = [SONiC_vm(hostname, username, password, conn_mode)]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="")
    parser.add_argument(
        "--trace", action="store_true", help="enable trace level logging"
    )
    parser.add_argument("--hostname", default="sonic", help="SONiC hostname")
    parser.add_argument("--username", default="admin", help="Username")
    parser.add_argument("--password", default="admin", help="Password")
    parser.add_argument(
        "--connection-mode", default="tc", help="Connection mode to use in the datapath"
    )
    args = parser.parse_args()

    LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)
    if args.trace:
        logger.setLevel(1)

    vr = SONiC(
        args.hostname,
        args.username,
        args.password,
        conn_mode=args.connection_mode,
    )
    vr.start()
