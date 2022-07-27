
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


# VM (testing):
* mount shared folder: 
    `sudo mount -t vboxsf -o uid=$USER,gid=vboxsf Desktop /mnt/shared`
* mount guest additions: 
    `mkdir /mnt/guest_additions`
    `sudo mount /dev/cdrom /mnt/guest_additions`

* stopping when running with valgrind:
    * `kill -SIGALRM 276436 (obtained with ps -aux | grep "srd")`

* kill srd (send SIGALRM)
    * `ps -aux | grep srd | grep -v "grep" | cut -f 5 -d ' ' | xargs kill -SIGALRM`
