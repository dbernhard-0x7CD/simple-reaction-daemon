# Simple Reconnect Daemon

This program allows to configure certain actions which will be executed if pings to a certain host fail for a given amount of time. Currently implemented actions are:

* restart another systemd-service (f.ex: systemd-networkd, iwd or wpa_supplicant)
* restart the system
* execute custom command as user

It can be installed as a systemd service to run in the background (see Installation).
Do not forget to enable and start (`systemctl enable srd`, `systemctl start srd` respectively) the service. The motivation for this service is to log disconnects and have some actions in place which may bring the device back online or act as a dead man's switch.

<br />

# Building

Simply run `make` in the root folder of the project.

You need glibc, libconfig and headers for systemd.

<br />

# Installation

There are two available installation methods:

* ## Installation - ArchLinux

    Enter the folder `arch-pkg` and run `makepkg` and then you can install the packaged \*.tar.xz file.

* ## Installation - Manual

    Build with `make` and copy/install srd binary to custom location.

<br />

# Configuration

The service is configured by so called **target files** in `/etc/srd/` (with arbitrary name) which follow the following format:
They can be dependent on eachother by configuring *depends*.

```
# destination IP
destination = "127.0.0.1[,192.168.0.5]"

# Period of the pings in s
period = 60

# timeout for one ping in s
timeout = 10

actions = (
    {
        action = "reboot";
        # delay in seconds
        delay = 1800;
    },
    {
        action = "service-restart";
        name = "systemd-networkd.service";
        delay = 60;
    }
)

```

**destination**: IP or domain to ping regularly

**period**: Delay between the pings in seconds

**timeout**: Time to wait for a ping response in seconds

**depends**: IP of another target. If the ping to depends is not successful, then this target won't get checked and no actions performed.

<br />

## srd.conf
This file may also contain the loglevel configuration:
```
# available loglevels: DEBUG, INFO
loglevel = "INFO"
```

<br />

## Actions
**Note**: The delay denotes the amount of time passed (in seconds) since the last successful ping (`period + timeout`) until this action is performed.

* *reboot*:

```
{
    action = "reboot";
    delay = 3600; # 1 hour
}
```

* *restart a service*:

```
{
    action = "service-restart";
    name = "systemd-networkd.service";
    delay = 600; # 10 minutes
}
```

* *execute command as a user*:

```
{
    action = "command";
    delay = 10;
    user = "root";
    cmd = "echo \"down at `date`\" >> /var/log/srd.log";
}
```


# Use case - wireguard VPN

If you have a wireguard VPN with a dynamic IP it'll disconnect if the IP changes. Using srd you can mitigate this with the following *target file*:


```
# destination IP; This is the IP of the VPN server
destination = "10.10.0.1"

# Period of the pings in s
period = 60

# timeout for one ping in s
timeout = 10

actions = (
    {
        action = "service-restart";
        name = "wg-quick@wg0.service";
        delay = 300; # 5 minutes
    },
    {
        action = "service-restart";
        name = "systemd-networkd.service";
        delay = 1800; # 30 minutes
    }
)
```
