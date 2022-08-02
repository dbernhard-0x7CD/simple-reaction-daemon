# Simple Reaction Daemon

This program allows to configure certain actions which will be executed if pings to a certain host fail/succeed for a given amount of time. Currently implemented actions are:

* restart another systemd-service (f.ex: systemd-networkd, iwd or wpa_supplicant)
* log to a file
* restart the system
* execute custom command as user
    * f.ex: Send wake-on-lan packet to host, send an email, ...


It can be installed as a systemd service to run in the background (see Installation).
Do not forget to enable and start (`systemctl enable srd`, `systemctl start srd` respectively) the service.

The motivation for this service is to log disconnects (or the time an IP is reachable) or have some actions in place which may bring the device back online or act as a dead man's switch.

<br />

# Building

After cloning this repository you have to run `git submodule init` and `git submodule update`.

Then simply run `make` in the root folder of the project.

You need glibc, libconfig and headers for systemd.

On Debian: `libconfig-dev libsystemd-dev`

On Arch: `libconfig systemd`

<br />

# Installation

There are two available installation methods:

* ## Installation - ArchLinux
    * AUR: `[paru|yay|your-favourite-aur-helper] simple-reaction-daemon` 
    * Manual: <br />
        Enter the folder `arch-pkg` and run `makepkg` and then you can install the packaged \*.tar.zst file (or simply run `makepkg -si`).

* ## Installation - Manual

    Build with `make` and copy/install srd binary to custom location.

<br />

# Configuration

The service is configured by so called **target files** in `/etc/srd/NAME.conf` (with arbitrary name) which follow the following format:
They can be dependent on eachother by configuring `depends`.

```
# destination IP
destination = "127.0.0.1[,192.168.0.5]"

# Period of the pings in s
period = 60

# timeout for one ping in s
timeout = 10

# number of pings to send
num_pings = 1

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
    
* Can also be `%gw` to ping the gateway
* **Note**: this is currently only set at startup. So changes of the gateway are not yet supported

<br />

**period**: Delay between the pings in seconds

<br />

**timeout**: Time to wait for a ping response in seconds

<br />

[optional] **num_pings**: Amount of sequential pings sent. Defaults to 1. This should be used if the period is high. If one of the pings succeeds we deem the host as UP.

**depends**: IP of another target. If the ping to depends is not successful, then this target won't get checked and no actions performed.

* Can also be `%gw` to ping the gateway
* **Note**: this is currently only set at startup. So changes of the gateway are not yet supported

<br />

## srd.conf
This file may also contain the `loglevel` configuration:
```
# available loglevels: DEBUG, INFO
loglevel = "INFO"
```

Also `datetime_format` is configurable, by default it's:
```
datetime_format = "%Y-%m-%d %H:%M:%S"
```
See here for the exact format: [https://strftime.org/](https://strftime.org/)

<br />

## Actions
**Note**: The `delay` configuration denotes the amount of time passed (in seconds) since the last successful ping (`period + num_pings * timeout`) until this action is performed. `num_pings` is how many pings are sent in sequential order (only one has to succeed) and worst case takes `num_pings * timeout` time. This makes sense if you have a high period but you don't want to have a host labeled as 'down' if a ping gets lost.

* **reboot**:

```
{
    action = "reboot";
    delay = 3600; # 1 hour
}
```

* **restart a service**:

```
{
    action = "service-restart";
    name = "systemd-networkd.service";
    delay = 600; # 10 minutes
}
```

* **log to a file**:
```
{
    action = "log";
    message = "Host %ip was down from %sdt until %now";
    path = "SOME_PATH/downtimes.log";
}
```
* Notes for `message`:
    * You can use `%ip` as a placeholder for the actual IP of the current target (if you use multiple destination IPs)
    * When `run_if = "up-again"`: You can use `%sdt` (**s**tart **d**own**t**ime) as a placeholder for the start of the downtime 
    * You can use `%lat_ms` as a placeholder for the latency in milliseconds
    * You can use `%downtime` as a placeholder for the downtime in days,hours, minutes and seconds
    * `%status` is a placeholder for `success` or `failed` depending if a ping succeeded
* With `user` you can define the owner of the file
    * This is only set when creating the file

* **execute arbitrary command as a user**:

If a host is **down**:
```
{
    action = "command";
    delay = 10;
    user = "root";
    cmd = "echo \"DOWN at `date`\" >> /var/log/srd.log";
}
```
Or if he's **up**:
```
{
    action = "command";
    run_if = "up";
    user = "root";
    cmd = "echo \"UP at `date`\" >> /var/log/srd.log";
}
```
* Notes for `cmd`
    * You can use `%ip` as a placeholder for the actual IP of the current target (if you use multiple destination IPs)
    * When `run_if = "up-again"`: You can use `%sdt` (**s**tart **d**own**t**ime) as a placeholder for the start of the downtime 
    * You can use `%lat_ms` as a placeholder for the latency in milliseconds
    * You can use `%downtime` as a placeholder for the downtime in days,hours, minutes and seconds
    * `%status` is a placeholder for `success` or `failed` depending if a ping succeeded

<br />

### Conditional actions - run_if
Valid values for `run_if`:
* `up` - Run everytime a ping succeeds (approximately every `period` seconds)
* `up-again` (first ping successfull after one or more failed pings)
    * In this case `command.delay` denotes how long the downtime at least had to be to trigger this action
* `down` (default)
    * After `command.delay` seconds this target is seen as down and this action executed
* `down-again` Executes once if a target was reachable before and now isn't
    * After `command.delay` seconds this target is seen as down
* `always`

<br />

# Use case - wireguard VPN

If you have a wireguard VPN with a dynamic IP it'll disconnect if the IP of the server changes. 

Using srd you can mitigate this with the following *target file*:


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

# Use case - monitoring of the clients inside a VPN

In this scenario you have some clients which must be online all the time and you want to monitor their reachability.
You also could define a command to send an email to you, etc.

```
# destination IP; This is the IP of the VPN server
destination = "10.10.0.1,10.10.0.2,10.0.0.3[,10.10.0.X,...]"

# Period of the pings in s
period = 60

# timeout for one ping in s
timeout = 10

# uncomment, if you also have your gateway as a target
# depends = "%gw"

actions = ( 
    {   
        action = "command";
        delay = 60; 
        user = "REPLACE-ME!";
        cmd = "echo \"`date`: %ip is down\" >> PATH_WHICH_EXISTS/vpn_clients_avail.log";
    }
)

```

Here's the file to check the gateway. This is used to not check the vpn clients if the gateway is unreachable (and unnecessarily log that they are down).

```
# destination IP
destination = "%gw"

# Period of the pings in s
period = 5

# timeout in seconds of one ping
timeout = 5

actions = (
    {
        action = "command";
        delay = 10;
        user = "david";
        cmd = "notify-send \"gateway %ip is down\"";
    }
)
```
