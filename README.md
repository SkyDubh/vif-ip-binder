# Virtual Interface IP re-binder for the dom0’s SSPN

This software aims to remove a few of the hindrances born from a dom0 without physical NICs access. If you want to passthrough all the physical NICs to your UTM appliance, then you need this service to avoid being locked out of the dom0.

It has been developed for and onto an XCP-ng 7.6.0 hypervisor, and uses the `XenAPI` python module provided with the dom0 along with the `ip` command. It might work for other XCP/XCP-ng/XenServer hypervisors with little to no changes, but has not been tested on anything else.

## Features

Automatically:

* Attach IPs to a dynamically spawning Virtual Interface bridge.
* Change the default gateway after the IP/net is assigned to the VIF.
* Re-plug network SRs as soon as the IP/net is attached to the VIF.
* Fix an unreachable dom0 that booted in maintenance mode (best-effort).

## Limitations

* Currently supports only a single address to add to a single SSPN connected to a single VM.
* Currently supports only IPv4 as pingable targets for SR reattachment.
* Does nothing to resurrect a running locked down dom0: if it went in maintenance mode shutting down every VM and you’re locked out, you’d better start plugging video and keyboard.
* Not a limitation with the software itself rather with the no-PIF approach, but still worth mentioning: using XCP-ng Center “Reboot” will lock you out of the dom0.

## Setup

* Place `vif-ip-binder.py` where you want (default `/root/`), and update `vif-ip-binder.service` accordingly.
* Rename `vif-ip-binder.json.sample` into `vif-ip-binder.json`, change the necessary fields (more about this in the [configuration](#configuration) section), place it where you want (default `/root/` with `0400` mask), and update `vif-ip-binder.py` accordingly.
* Place the `vif-ip-binder.service` where your installation expects you to (default `/etc/systemd/system/`).
* Issue the `systemctl enable vif-ip-binder.service` command.

## Configuration

The configuration file (`vif-ip-binder.json`) will need the login credentials for the pool in order to use the XAPI functionalities (`user` and `password` fields), on top of the target VM and SSPN labels (`vmName` and `sspnName` fields), as shown below:

![VM and SSPN labels](https://user-images.githubusercontent.com/284077/56675664-f877db00-66bc-11e9-8b7a-21a0d498338b.png)

The labels are used for triggers and to retrieve the appropriate network bridge to apply the ip to.

### Management network bridge

In order to retain functionalities (console/performance monitors) it is of vital importance to add the same ip we use to reach the dom0 to the network bridge XAPI uses to generate management links. To avoid invalid configuration or network problems, we add the ip with a /32 (v4) or /128 (v6) mask.

### Address

The address to be assigned to the bridge relative to the virtual interfaces that spawns attached to the target VM, in the form of `address/netmask`. Supports both IPv4 and IPv6. 

### Default gateway (optional)

If you’re sitting on a dom0 with no physical interfaces (or no WAN PIF at the very least), you’ll need to route the traffic through your firewall/UTM. This parameter allows you to change the default gateway dynamically as the target VM is started. The gateway must be of the same family as the specified [address](#address) (v4/v6).

### Net SRs to reattach (optional)

A useful option if you’re using SRs over the network and not on the host server (NFS/CIFS). The parameter is list of single key:value dictionaries containing the target SR UUID and the address to ping before trying to re-plug its PBDs. Currently only v4 addresses are pingable.

To find the appropriate targets you can use the `xe sr-list` on the dom0:

```
# xe sr-list
uuid ( RO)                : 00000000-0000-0000-0000-000000000000
          name-label ( RW): ISO Repository
    name-description ( RW): SMB ISO Library [\\192.168.0.1\ISO]
                host ( RO): XCP
                type ( RO): iso
        content-type ( RO): iso
```

You can use the remote server’s IP as the ping target for the verification, but is not necessary. In the following example I’m going to, but I could just ping the UTM instead for (approximately) the same result. Alternative network targets can be also useful due to the current v4 limitation.

```json
    "netSRs": [{"00000000-0000-0000-0000-000000000000": "192.168.0.1"}],
```

If you have multiple SRs you want to reattach, simply add more dictionaries to the list:

```json
    "netSRs": [
        {"00000000-0000-0000-0000-000000000000": "192.168.0.1"},
        {"11111111-1111-1111-1111-111111111111": "192.168.1.2"},
        {"22222222-2222-2222-2222-222222222222": "10.0.0.1"}
    ],
```

The service scans all the specified SRs for PBDs, scans the latter, finds the offline ones and attempts to re-plug them in best-effort.

By default up to 30 pings are performed towards the target, with a 5 seconds timeout, resulting in a maximum of 2 minutes and a half potential lockdown, but this takes place only *after both the IP and the gateway are set* (if necessary). In my tests, on a single cold booted host, the first VM (with order 0) loads in ~42 seconds. Since the wait is rather inconsequential I just added a bit of margin to be on the safe side, but you’re free to test and change it to your heart’s content.

### Timeout (optional)

While run, the software perpetually responds to events targeting the VM, and the `XAPI.event_from` method takes a timeout as a form of non-perpetual locking. You can make this value as big or as small as you want, or you can omit it from the configuration altogether.

*Defaults to 30 seconds.*

### IP binary (optional)

The fully qualified path to the `ip` binary, necessary to add ips, and to add and remove the default gateway.

*Defaults to `/usr/sbin/ip`.*
