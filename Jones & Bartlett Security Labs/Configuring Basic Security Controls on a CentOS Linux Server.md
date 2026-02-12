# Configuring Basic Security Controls on a CentOS Linux Server (3e)

## Background

Endpoint security best practices mandate that you install multiple security controls to protect the device from unauthorized access and compromise. Some of the key functions of these controls includes filtering traffic to and from the device, providing secure connection to the server for end users, disabling features that are unneeded, access control and memory control, and segregation. It is important to find the right balance between securing the system and ensuring that it can provide its function for the company.

Information security on Linux systems is, to a large degree, no different than information security on Microsoft or Apple systems. As an administrator, you will take many of the same steps that you would in every other system. You will create firewalls, set up bastions, manage users, encrypt file systems, configure servers, customize applications, and work with intrusion prevention and detection systems. The Linux paradigm is different in some ways, however. With Linux, you can customize the kernel and set up mandatory access control with Application Armor (AppArmor) or Security Enhanced Linux (SELinux), a set of security enhancements built into the Linux kernel.

## Description

In this lab, you will secure a Linux server system. You will secure the boot loader, enable iptables firewall, and run SELinux to help lock down the Linux OS. By securing the boot loader, you can prevent access to single-user mode and the GRUB (Grand Unified Boot Loader) Console during the boot of the system. Enabling iptables and applying firewall rules can ensure that only the applications you trust have the ability to reach into or out from your computer. You also will apply access control lists (ACLs) to directories and files within the lab to secure the file and data access and then verify those permissions on the system.

---

## Lab Overview

Each section of this lab is assigned at your instructor's discretion. Please consult your instructor to confirm which sections you are required to complete for your lab assignment.

### SECTION 1

Section 1 has six parts which should be completed in the order specified.

1. **Part 1** — Harden the GRUB boot loader, which can load a variety of free and proprietary operating systems.
2. **Part 2** — Confirm SELinux is enabled.
3. **Part 3** — Enable iptables to help lock down services on a Linux system to only those who require network access and deny external connections to any other unnecessary port or service.
4. **Part 4** — Create a new group and enable sudo user access for the existing wheel group.
5. **Part 5** — Experiment with the immutable permission extended file attribute.
6. **Part 6** — Set access control list permissions on a file.

### SECTION 2

Apply what you learned in Section 1 with less guidance and different deliverables, as well as some expanded tasks and alternative methods. You will complete these same actions on an Xubuntu server.

### SECTION 3

Explore the virtual environment on your own to answer a set of questions and challenges that allow you to use the skills you learned in the lab to conduct independent, unguided work — similar to what you will encounter in a real-world situation.

---

## Learning Objectives

Upon completing this lab, you will be able to:

- Configure the bootloader with the timeout set to 1 second and a password credential to mitigate tampering with the GRUB loader and the boot sequence of the server.
- Enable SELinux on a CentOS Linux Server and set it to enforcing mode.
- Create a student user account and add it to a user group for managing permissions and applying access controls across the system.
- Configure user groups with limited sudo access (with password credentials) to log and properly monitor access across the system.
- Configure iptables to enable an internal, host-based IP stateful firewall.
- Set restrictions and permissions for user access to files and system log files.

---

## Topology

This lab contains the following virtual machines:

- **TargetLinux01** — CentOS Linux
- **TargetLinux02** — Xubuntu Linux

---

## Tools and Software

The following software and/or utilities are required to complete this lab. Students are encouraged to explore the Internet to learn more about the products and tools used in this lab.

- iptables
- Terminal
- vi Editor

---

## Deliverables

Upon completion of this lab, you are required to provide the following deliverables to your instructor:

### SECTION 1

**Lab Report file, including screen captures of the following:**

- Boot loader menu
- Current mode line of the SELinux configuration
- Iptables policy list
- New command assignments
- New file attributes
- Result of the ls command
- Updated permissions for the log file

### SECTION 2

**Lab Report file, including screen captures of the following:**

- Yourname in the updated grub.cfg file
- Iptables -nvL output and the ufw status
- Sudo command output
- Warning message in the vi Editor
- Updated permissions for the log file

### SECTION 3

**Lab Report file, including screen captures of the following:**

- Public and private ssh key
- Successful SSH connection using ssh keys

**Additional information as directed by the lab:**

- Use the Internet to research Linux security hardening best practices and describe 10 recommendations.

---

## Lab Report — Section 1

### Part 1: Boot Loader Menu

The GRUB boot loader was hardened on the CentOS Linux 7 (Core) system. The boot menu was configured with a timeout of 1 second and password protection was applied to prevent unauthorized access to single-user mode and the GRUB console. The boot menu displays the following entries:

- CentOS Linux 7 (Core), with Linux 3.10.0-1160.el7.x86_64
- CentOS Linux 7 (Core), with Linux 0-rescue-\<id>

The timeout was set to 1 second (`timeout=1`) in the GRUB configuration to minimize the window for unauthorized boot modification.

![Boot Loader Menu](screenshots/01-boot-loader-menu.png)

### Part 2: SELinux Configuration — Current Mode

The SELinux configuration file (`/etc/selinux/config`) was verified to confirm SELinux is enabled and set to enforcing mode. Key configuration lines:

```
SELINUX=enforcing
SELINUXTYPE=targeted
```

- **SELINUX=enforcing** — SELinux security policy is enforced. SELinux denies access based on policy rules.
- **SELINUXTYPE=targeted** — Targeted processes are protected by SELinux policy. Only targeted network daemons are protected.

![SELinux Configuration](screenshots/02-selinux-config.png)

### Part 3: Iptables Policy List

The `iptables` firewall was enabled and configured with the following ruleset (output of `iptables -L`):

```
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED
ACCEPT     icmp --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere
ACCEPT     tcp  --  anywhere             anywhere             state NEW tcp dpt:ssh
REJECT     all  --  anywhere             anywhere             reject-with icmp-host-prohibited

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
REJECT     all  --  anywhere             anywhere             reject-with icmp-host-prohibited

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```

This configuration:
- Accepts established and related connections
- Allows ICMP (ping) traffic
- Allows loopback traffic
- Permits new inbound SSH connections
- Rejects all other inbound and forwarded traffic with ICMP host-prohibited

![Iptables Policy List](screenshots/03-iptables-policy-list.png)

### Part 4: New Command Assignments

The `visudo` editor was used to configure sudo access for the `wheel` group. The following line was uncommented in the sudoers file:

```
%wheel  ALL=(ALL)       ALL
```

This grants all members of the `wheel` group the ability to execute any command as any user via `sudo`, with password authentication required. This ensures that privileged access is logged and monitored across the system.

![New Command Assignments](screenshots/04-new-command-assignments.png)

### Part 5: New File Attributes

The immutable extended file attribute was applied and verified using `lsattr`. The output shows the `i` (immutable) flag set on a file:

```
----i----------- ./testfile
```

When the immutable attribute is set, the file cannot be modified, deleted, renamed, or linked — even by the root user — until the attribute is removed with `chattr -i`. This provides an additional layer of protection for critical files.

![New File Attributes](screenshots/05-new-file-attributes.png)

### Part 6: Result of the ls Command and File Operations

A new student user was created and added to the `wheel` group, and file operations were performed to demonstrate attribute controls:

```
[root@TargetLinux01 ~]# useradd -G wheel student
[root@TargetLinux01 ~]# passwd student
[root@TargetLinux01 ~]# touch /tmp/mytest
[root@TargetLinux01 ~]# chattr +i /tmp/mytest
[root@TargetLinux01 ~]# lsattr /tmp/mytest
----i----------- /tmp/mytest
[root@TargetLinux01 ~]# rm /tmp/mytest
rm: cannot remove '/tmp/mytest': Operation not permitted
[root@TargetLinux01 ~]# mv /tmp/mytest /tmp/mytest2
mv: cannot move '/tmp/mytest' to '/tmp/mytest2': Operation not permitted
```

The immutable attribute prevented both deletion (`rm`) and renaming (`mv`) of the file, demonstrating the enforcement of extended file attributes on the system.

![Result of ls Command](screenshots/06-ls-command-result.png)

### Part 7: Updated Permissions for the Log File

Access control lists (ACLs) were applied to `/var/log/messages` to grant the `wheel` group read access. The `getfacl` command was used before and after the change to verify:

**Before ACL:**
```
# file: var/log/messages
# owner: root
# group: root
user::rw-
group::---
other::---
```

**ACL command applied:**
```
[root@TargetLinux01 ~]# setfacl -m g:wheel:r /var/log/messages
```

**After ACL:**
```
# file: var/log/messages
# owner: root
# group: root
user::rw-
group::---
group:wheel:r--
mask::r--
other::---
```

The `wheel` group now has read-only access to the system log file, allowing members of the group to review logs for monitoring purposes without granting write or execute permissions.

![Updated Log File Permissions](screenshots/07-updated-log-permissions.png)

---

## Lab Report — Section 2

### Part 1: Yourname in the Updated grub.cfg File

On the TargetLinux02 (Xubuntu) system, the GRUB configuration was updated to set a superuser with password protection. The `grub.cfg` file shows:

```
set superusers="jacobphillips"
password_pbkdf2 jacobphillips grub.pbkdf2.sha512.10000.<hash>
```

This configures GRUB to require the `jacobphillips` superuser credentials before allowing access to edit boot entries or access the GRUB console, preventing unauthorized boot sequence modifications.

![Grub.cfg Superuser](screenshots/08-grub-cfg-superuser.png)

### Part 2: Iptables -nvL Output and UFW Status

On the TargetLinux02 (Xubuntu) system, the firewall was configured using both iptables and UFW (Uncomplicated Firewall):

**iptables -nvL output (before UFW):**
```
Chain INPUT (policy ACCEPT)
 pkts bytes target     prot opt in     out     source               destination

Chain FORWARD (policy ACCEPT)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT)
 pkts bytes target     prot opt in     out     source               destination
```

**UFW enabled and status:**
```
student@TargetLinux02:~$ sudo ufw enable
Firewall is active and enabled on system startup
student@TargetLinux02:~$ sudo ufw status
Status: active
```

UFW was enabled to provide a simplified interface for managing iptables rules on the Xubuntu system, complementing the direct iptables configuration used on CentOS.

![Iptables and UFW Status](screenshots/09-iptables-ufw-status.png)

### Part 3: Sudo Command Output

The sudoers configuration on TargetLinux02 was reviewed, showing the default Ubuntu/Xubuntu sudo group configuration:

```
# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
```

This configuration grants:
- **root** — full sudo privileges
- **%admin group** — full sudo privileges for legacy compatibility
- **%sudo group** — full sudo privileges (the standard Ubuntu mechanism, equivalent to CentOS `wheel` group)

![Sudo Command Output](screenshots/10-sudo-command-output.png)
