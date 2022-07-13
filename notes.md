
# Development notes

* Reboot with dbus
    * `sudo busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager Reboot`


* Restart systemd-networkd
    * `busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/systemd_2dnetworkd_2eservice org.freedesktop.systemd1.Unit Restart s "fail"`

* setting capabilities for srd binary to create sockets
    * `sudo setcap 'CAP_NET_RAW+eip' ./srd`

# Resources
* Dbus stuff: https://www.freedesktop.org/wiki/Software/systemd/dbus/

* example PKGBUILD: https://github.com/archlinux/svntogit-packages/tree/packages/openssh/trunk

* systemd sd bus api: http://0pointer.de/blog/the-new-sd-bus-api-of-systemd.html


# TODO
* configure amount of pings
    * compare if 2 pings detects less outages
* compare between ARM and x86 time values
    * running on LM and bubbleon
* action on successful ping
    * run = "failure|success|always|up-again"
* test if error in IP is easy to understand
    * not detected
* dependency as config name (f.ex: gw.conf or just gw)


# VM (testing):
* mount shared folder: 
    `sudo mount -t vboxsf -o uid=$USER,gid=vboxsf Desktop /mnt/shared`
* mount guest additions: 
    `mkdir /mnt/guest_additions`
    `sudo mount /dev/cdrom /mnt/guest_additions`

* stopping when running with valgrind:
    * `kill -SIGALRM 276436 (obtained with ps -aux | grep "srd")`

