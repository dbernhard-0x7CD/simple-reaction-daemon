
# Development notes

* Reboot
    * `sudo busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager Reboot`


* Restart systemd-networkd
    * `busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/systemd_2dnetworkd_2eservice org.freedesktop.systemd1.Unit Restart s "fail"`


https://www.freedesktop.org/wiki/Software/systemd/dbus/

https://github.com/archlinux/svntogit-packages/tree/packages/openssh/trunk

http://0pointer.de/blog/the-new-sd-bus-api-of-systemd.html


# TODO
* dependency as config name (f.ex: gw.conf or just gw)
* list of IPs as target?


# VM (testing):
* mount shared folder: 
    `sudo mount -t vboxsf -o uid=$USER,gid=vboxsf Desktop /mnt/shared`
* mount guest additions: 
    `mkdir /mnt/guest_additions`
    `sudo mount /dev/cdrom /mnt/guest_additions`

* stopping when running with valgrind:
    * `kill -SIGALRM 276436 (obtained with ps -aux | grep "srd")`
