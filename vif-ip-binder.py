#!/usr/bin/python -u
# -*- coding: utf-8 -*-
# Author: Varstahl
"""Service that automatically rebinds an IP address to a Single-Server Private Network
   assigned to a specific VM.

   Both the VM and the SSPN are found by labels and should be defined in the constants below
"""

from contextlib import contextmanager
from signal import signal, SIGTERM, SIGHUP
import socket
from xmlrpclib import Fault as XmlRPCFault
import XenAPI

CONFIG_FILE = '/root/vif-ip-binder.json'


class Ping(object):
    """Derived from the work of the python-ping team

       Modifications include the removal of outputs and the introduction of
       the live() function, which signals if a host has replied, disregarding
       the delay of the response.

       https://pypi.org/project/python-ping/
       Copyleft: 1989-2011 by the python-ping team
       License: GNU GPL v2
    """

    def __init__(self, destination, timeout=1000, packet_size=55, own_id=None):
        from time import time
        from os import getpid
        self.timer = time
        self.destination = destination
        self.timeout = timeout
        self.packet_size = packet_size
        if own_id is None:
            self.own_id = getpid() & 0xFFFF
        else:
            self.own_id = own_id

        self.seq_number = 0

    def live(self, count=1, timeout=None):
        """Pings a host to check if it's alive"""
        if None is not timeout:
            self.timeout = timeout
        try:
            count = int(count)
        except Exception:
            count = 1
        if 1 > count:
            count = 1
        for pony in xrange(count):
            if None is not self.do():
                return True
        return False

    def do(self):
        """Send one ICMP ECHO_REQUEST and receive the response until self.timeout"""
        from sys import exc_info
        try: # One could use UDP here, but it's obscure
            current_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        except socket.error, (errno, msg):
            if errno == 1:
                # Operation not permitted - Add more information to traceback
                etype, evalue, etb = exc_info()
                evalue = etype(
                    "%s - Note that ICMP messages can only be send from processes running as root." % evalue
                )
                raise etype, evalue, etb
            raise # raise the original error
        self.seq_number += 1
        send_time = self.send_one_ping(current_socket)
        if send_time == None:
            return

        receive_time, packet_size, ip, ip_header, icmp_header = self.receive_one_ping(current_socket)
        current_socket.close()

        if receive_time:
            return (receive_time - send_time) * 1000.0

    def send_one_ping(self, current_socket):
        """Send one ICMP ECHO_REQUEST"""
        from struct import pack
        from sys import byteorder

        def calculate_checksum(source_string):
            """A port of the functionality of in_cksum() from ping.c
               Ideally this would act on the string as a series of 16-bit ints (host
               packed), but this works.
               Network data is big-endian, hosts are typically little-endian
            """
            countTo = (int(len(source_string) / 2)) * 2
            sum = 0
            count = 0

            # Handle bytes in pairs (decoding as short ints)
            loByte = 0
            hiByte = 0
            while count < countTo:
                if (byteorder == "little"):
                    loByte = source_string[count]
                    hiByte = source_string[count + 1]
                else:
                    loByte = source_string[count + 1]
                    hiByte = source_string[count]
                sum = sum + (ord(hiByte) * 256 + ord(loByte))
                count += 2

            # Handle last byte if applicable (odd-number of bytes)
            # Endianness should be irrelevant in this case
            if countTo < len(source_string): # Check for odd length
                loByte = source_string[len(source_string) - 1]
                sum += ord(loByte)

            sum &= 0xffffffff # Truncate sum to 32 bits (a variance from ping.c, which
                            # uses signed ints, but overflow is unlikely in ping)

            sum = (sum >> 16) + (sum & 0xffff)    # Add high 16 bits to low 16 bits
            sum += (sum >> 16)                    # Add carry from above (if any)
            answer = ~sum & 0xffff                # Invert and truncate to 16 bits
            answer = socket.htons(answer)

            return answer

        ICMP_ECHO = 8 # Echo request (per RFC792)

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        checksum = 0

        # Make a dummy header with a 0 checksum.
        header = pack(
            "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number
        )

        padBytes = []
        startVal = 0x42
        for i in range(startVal, startVal + (self.packet_size)):
            padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
        data = bytes(padBytes)

        # Calculate the checksum on the data and the dummy header.
        checksum = calculate_checksum(header + data) # Checksum is in network order

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = pack(
            "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number
        )

        packet = header + data

        send_time = self.timer()

        try:
            current_socket.sendto(packet, (self.destination, 1)) # Port number is irrelevant for ICMP
        except socket.error as e:
            current_socket.close()
            return

        return send_time

    def receive_one_ping(self, current_socket):
        """Receive the ping from the socket. timeout = in ms"""
        import select
        from struct import pack, unpack

        class HeaderInformation(dict):
            """ Simple storage received IP and ICMP header informations """
            def __init__(self, names, struct_format, data):
                unpacked_data = unpack(struct_format, data)
                dict.__init__(self, dict(zip(names, unpacked_data)))

        ICMP_MAX_RECV = 2048 # Max size of incoming buffer
        timeout = self.timeout / 1000.0

        while True: # Loop while waiting for packet or timeou+t
            select_start = self.timer()
            inputready, outputready, exceptready = select.select([current_socket], [], [], timeout)
            select_duration = (self.timer() - select_start)
            if inputready == []: # timeout
                return None, 0, 0, 0, 0

            receive_time = self.timer()

            packet_data, address = current_socket.recvfrom(ICMP_MAX_RECV)

            icmp_header = HeaderInformation(
                names=[
                    "type", "code", "checksum",
                    "packet_id", "seq_number"
                ],
                struct_format="!BBHHH",
                data=packet_data[20:28]
            )

            if icmp_header["packet_id"] == self.own_id: # Our packet
                ip_header = HeaderInformation(
                    names=[
                        "version", "type", "length",
                        "id", "flags", "ttl", "protocol",
                        "checksum", "src_ip", "dest_ip"
                    ],
                    struct_format="!BBHHHBBHII",
                    data=packet_data[:20]
                )
                packet_size = len(packet_data) - 28
                ip = socket.inet_ntoa(pack("!I", ip_header["src_ip"]))
                # XXX: Why not ip = address[0] ???
                return receive_time, packet_size, ip, ip_header, icmp_header

            timeout = timeout - select_duration
            if timeout <= 0:
                return None, 0, 0, 0, 0


@contextmanager
def xenapi_session():
    """XAPI session manager"""
    global USER, PASSWORD, session

    from time import sleep

    # Obtain a valid session or die trying
    session = XenAPI.xapi_local()
    while True:
        try:
            session.xenapi.login_with_password(USER, PASSWORD, '1.0', 'vif-ip-binder.py')
            break
        except socket.error:
            # Toolstack restarted or momentarily unavailable
            sleep(3)
        except XenAPI.Failure as e:
            print('Failed to acquire a session: {}'.format(e.details))
            sleep(3)

    # Provide the XenAPI session
    try:
        yield session.xenapi
    except XenAPI.Failure as e:
        print('XenAPI failure: {}'.format(e.details))

    # Cleanup
    try:
        session.xenapi.session.logout()
    except (socket.error, AttributeError):
        # Toolstack restarted/unavailable or erased by sigterm_handler
        pass


def spopen(target):
    import subprocess
    return subprocess.Popen(
        target,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    ).communicate()


def rebind_ip_address(ifname):
    """Checks if the IP is already bound, binds it otherwise"""
    global IP, IPSHW, IPADD, IPROUTE_REMOVE, IPROUTE_ADD
    import re

    # Grab a list of all IPs
    response = spopen(IPSHW + [ifname])[0]
    if IP in re.findall(r'inet\s*((?:\.?[0-9]{1,3}){4})/', response):
        return False

    # IP not bound, add it to the interface and reset the gateway
    spopen(IPADD + [ifname])
    print('Adding {} to {}'.format(IPADD[3], ifname))
    if IPROUTE_REMOVE:
        spopen(IPROUTE_REMOVE)
        spopen(IPROUTE_ADD)
        print('Adding default route via {}'.format(IPROUTE_ADD[5]))
    return True


def get_host_ref():
    """Return the current host ObscureRef"""
    # Find current host's UUID
    with open('/etc/xensource-inventory', 'r') as f:
        uuid = f.read(-1)
    uuid = uuid[19+uuid.find('INSTALLATION_UUID='):].split("'")[0]
    return uuid


def plug_pbds(x, uuid):
    """Plug all network SRs specified in the config"""
    sr_ref = x.SR.get_by_uuid(uuid)
    sr_rec = x.SR.get_record(sr_ref)
    for pbd_ref in sr_rec['PBDs']:
        pbd_rec = x.PBD.get_record(pbd_ref)
        if not pbd_rec['currently_attached']:
            print('Plugging SR "{2}"\'s {0} "{1}" PBD'.format(
                pbd_rec['device_config']['type'],
                pbd_rec['device_config']['location'],
                sr_rec['name_label']
            ))
            x.PBD.plug(pbd_ref)


def keep_vifs_bound():
    """Listens to VM events and checks if a virtual interface
       needs rebinding when the VM is started or resumed
    """
    global EVT_TIMEOUT, NETSRS

    while bEndless:
        with xenapi_session() as x:
            try:
                vms = x.VM.get_all_records()  # Get a list of VMs for multiple uses

                # If the host is in maintenance mode end it and auto start VMs
                host_ref = x.host.get_by_uuid(get_host_ref())
                if not x.host.get_enabled(host_ref):
                    x.host.enable(host_ref)  # End maintenance mode

                    # Get a list of suitable VMs to start, ordered by ha restart priority
                    autostart_list = [(vms[k]['order'], k, float(vms[k]['start_delay'])) for k in vms.keys() if (
                        (not vms[k]['is_a_snapshot']) and
                        (not vms[k]['is_a_template']) and
                        (not vms[k]['is_control_domain']) and
                        (('auto_poweron' in vms[k]['other_config']) and (vms[k]['other_config']['auto_poweron'])) and
                        ('Halted' == vms[k]['power_state'])
                    )]
                    # We avoid .sort with a lambda to be able to delete the vms list
                    from operator import itemgetter
                    autostart_list.sort(key=itemgetter(0))

                    # Attempt to start the VMs, while respecting the delays
                    for i in range(len(autostart_list)):
                        vm_ref = autostart_list[i][1]
                        try:
                            x.VM.start(vm_ref, False, False)
                        except:
                            pass
                        finally:
                            from time import sleep
                            if i < (len(autostart_list) - 1):
                                sleep(autostart_list[i][2])

                    del autostart_list  # Clean up

                # Find the ObscureRef of the target VM
                try:
                    vmref = [k for k in vms.keys() if vms[k]['name_label'] == VMNAME][0]
                except:
                    print('Unable to find a VM named "{}"'.format(VMNAME))
                    exit(4)
                vifs = x.VM.get_VIFs(vmref)
                bNetworkFound = False
                for vif in vifs:
                    if SSPNNAME == x.network.get_record(x.VIF.get_network(vif))['name_label']:
                        bNetworkFound = True
                        break
                if not bNetworkFound:
                    print('Unable to find a network named "{}" attached to the "{}" VM'.format(SSPNNAME, VMNAME))
                    exit(5)

                # Clean up
                del vifs
                del vms

                # Non-blocking listen for VM events
                token = ''  # Initial token
                while bEndless:
                    output = x.event_from(['VM'], token, EVT_TIMEOUT)
                    token = output['token']  # Current token

                    for event in output['events']:
                        # Check the IP assigned to the VIFs of the target VM, if it's running
                        if (('add' == event['operation']) or
                                ('mod' == event['operation'])) and \
                                (vmref == event['ref']) and \
                                ('Running' == x.VM.get_power_state(vmref)):
                            if 'snapshot' not in event:
                                continue
                            vifs = event['snapshot']['VIFs']  # Virtual interfaces list
                            for vif in vifs:
                                net = x.VIF.get_network(vif)  # Network ref
                                netrec = x.network.get_record(net)  # Network record
                                if SSPNNAME != netrec['name_label']:
                                    continue
                                if rebind_ip_address(netrec['bridge']) and NETSRS:
                                    for sr in NETSRS:
                                        # Check if the destination is live for a maximum of 2 minutes and a half,
                                        # and if it goes live replug the target SRs
                                        (sr_uuid, pingTarget), = sr.items()
                                        p = Ping(pingTarget, 5000)
                                        if p.live(30):
                                            plug_pbds(x, sr_uuid)

            except (socket.error, XmlRPCFault):
                # Toolstack restarted/unavailable or SIGTERM'd
                pass


def sigterm_handler(_signo, _stack_frame):
    """Stop the endless loops and exit"""
    global bEndless, session
    bEndless = False
    session.xenapi.session.logout()  # Force logout to avoid long timeouts


def sighup_handler(_signo, _stack_frame):
    """Ignore SIGHUP"""
    pass


def is_exe(fpath):
    """Tests to check that the ip binary is both existing and executable"""
    import os
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)


if __name__ == '__main__':
    from json import load as loadJSON

    # Load the configuration file
    try:
        with open(CONFIG_FILE, 'r') as f:
            data = loadJSON(f)
    except Exception as e:
        eName = type(e).__name__
        if ('IOError' == eName) or ('FileNotFoundError' == eName):
            print('Unable to find/load the configuration file "{}"'.format(CONFIG_FILE))
        elif ('ValueError' == eName) or ('json.decoder.JSONDecodeError' == eName):
            print('Invalid JSON configuration file "{}", comments still within?'.format(CONFIG_FILE))
        else:
            print('Unknown exception "{}" while loading the configuration file "{}":\n- {}'.format(eName, CONFIG_FILE, e))
        exit(1)

    # Initialise global configuration
    USER = data.get('user')  # User
    PASSWORD = data.get('password')  # Password
    VMNAME = data.get('vmName')  # Label of the virtual machine
    SSPNNAME = data.get('sspnName')  # Label of the SSPN
    BRNAME = data.get('brName')  # Management bridge name
    IP = data.get('address')  # SSPN IP to assign
    GW = data.get('gateway')  # Gateway
    NETSRS = data.get('netSRs')  # List of SRs with network PBDs (NFS/CIFS) to be 
    try:
        EVT_TIMEOUT = float(data.get('timeout')) or 30.0  # Event.From timeout. 30s seems to be the accepted default
    except:
        EVT_TIMEOUT = 30.0
    if 0 >= EVT_TIMEOUT:
        EVT_TIMEOUT = 30.0
    IPBIN = data.get('ipBinary') or '/usr/sbin/ip'  # Location of ip binary
    del data

    if (None is USER) or (None is PASSWORD) or (None is VMNAME) or (None is SSPNNAME) or (None is BRNAME) or (None is IP) or ('/' not in IP):
        print('Invalid JSON configuration file "{}", required parameters missing')
        exit(2)
    
    if not is_exe(IPBIN):
        print('The ip binary location provided is not valid: "{}"'.format(IPBIN))
        exit(3)

    # Build the ip commands
    bIPv6 = ':' in IP
    IPSHW = [IPBIN, 'addr', 'show', 'dev']  # Show IPs
    IPADD = [IPBIN, 'addr', 'add', IP, 'dev']  # Add IP
    IPROUTE_REMOVE = [IPBIN, 'route', 'del', 'default'] if GW else None  # Remove the GW
    IPROUTE_ADD = [IPBIN, 'route', 'add', 'default', 'via', GW] if GW else None  # Add the GW
    print('Initialised to add v{} {}{} to {}\'s network {} using {} (XAPI timeout: {}s)'.format(
        '6' if bIPv6 else '4',
        IP,
        ' via {}'.format(GW) if GW else '',
        VMNAME,
        SSPNNAME,
        IPBIN,
        EVT_TIMEOUT,
    ))
    IP = IP.split('/')[0]  # SSPN IP to assign
    IPADDMGMT = IPADD + [BRNAME]
    IPADDMGMT[3] = IP + ('/128' if bIPv6 else '/32')
    if bIPv6:
        IPSHW.insert(1, '-6')
        IPADD.insert(1, '-6')
        IPADDMGMT.insert(1, '-6')
        IPROUTE_REMOVE.insert(1, '-6')
        IPROUTE_ADD.insert(1, '-6')

    # First things first, add the management ip
    spopen(IPADDMGMT)
    print('Adding {} to the management interface {}'.format(IPADDMGMT[3], IPADDMGMT[5]))

    # Initialise global vars, hook the signal handlers and start the service
    session = None  # Global XAPI session variable
    bEndless = True  # Not-really endless flag
    signal(SIGTERM, sigterm_handler)
    signal(SIGHUP, sighup_handler)
    try:
        keep_vifs_bound()
    except KeyboardInterrupt:
        print('')
