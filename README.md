# Simple Reconnect Daemon

This program allows to configure certain actions which will be executed if a ping to a certain host fails for a given amount of time. Currently implemented actions are:

* restart another systemd-service
* restart the system
* execute custom command as user

It can be installed as a systemd service to run in the background (see Installation).
Do not forget to enable (`systemctl enable srd`) and start (`systemctl start srd`) the service. The motivation for this service is to log disconnects and have some actions in place which may bring the device back online or act as a dead man's switch.

## Building

Simply run `make` in the root folder of the project.

You need glibc, headers for systemd and libconfig.

## Installation

There are two available installation methods:

### Installation - ArchLinux

Enter the folder `arch-pkg` and run `makepkg` and then you can install the packaged \*.tar.xz file.

### Installation - Manual

Build with `make` and copy/install srd binary to custom location.

## Configuration of the systemd-service

The service is configured by files in `/etc/srd/` (with arbitrary name) which follow the following format:

```
# destination IP
destination = "127.0.0.1"

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
        name = "systemd_2dnetworkd_2eservice";
        delay = 60;
    }
)

```

**destination**: IP or domain to ping regularly

**period**: Delay between the pings in seconds

**timeout**: Time to wait for a ping response in seconds

**loglevel**: "INFO" or "DEBUG"

## srd.conf
This file may also contain the loglevel configuration:
```
# available loglevels: DEBUG, INFO
loglevel = "INFO"
```

## Actions
**actions**: Supported actions: <br /> **Note**: The delay denotes the amount of time passed since the last successful ping. The first time is after `period + timeout`.

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
    name = "systemd_2dnetworkd_2eservice";
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
