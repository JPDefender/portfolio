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

### Part 4: Warning Message in the vi Editor

On TargetLinux02, the immutable file attribute was tested. A file was created and the immutable flag was set using `chattr +i`:

```
student@TargetLinux02:~$ sudo touch /tmp/s2
student@TargetLinux02:~$ sudo chattr +i /tmp/s2
student@TargetLinux02:~$ sudo lsattr /tmp/s2
----i---------e--- /tmp/s2
```

When attempting to edit the immutable file with `sudo vi /tmp/s2`, the vi editor displayed a warning message indicating the file could not be modified. This demonstrates that even with root privileges via sudo, the immutable attribute enforced by the filesystem prevents any changes to the file until the attribute is explicitly removed.

![Warning Message in vi Editor](screenshots/11-vi-editor-warning.png)

### Part 5: Updated Permissions for the Log File

Access control lists (ACLs) were applied to `/var/log/syslog` on the Xubuntu system to grant the `sudo` group read access (the Xubuntu equivalent of the CentOS `wheel` group). The `getfacl` command was used before and after the change:

**Before ACL:**
```
# file: var/log/syslog
# owner: syslog
# group: adm
user::rw-
group::r--
other::---
```

**ACL command applied:**
```
student@TargetLinux02:~$ sudo setfacl -m g:sudo:r /var/log/syslog
```

**After ACL:**
```
# file: var/log/syslog
# owner: syslog
# group: adm
user::rw-
group::r--
group:sudo:r--
mask::r--
other::---
```

The `sudo` group now has read-only access to the syslog file, mirroring the same ACL approach used on CentOS with the `wheel` group and `/var/log/messages`.

![Updated Log File Permissions — Xubuntu](screenshots/12-updated-log-permissions-xubuntu.png)

---

## Lab Report — Section 3

### Part 1: Public and Private SSH Key

An RSA 3072-bit SSH key pair was generated using `ssh-keygen`:

```
student@TargetLinux02:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/student/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/student/.ssh/id_rsa
Your public key has been saved in /home/student/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:<fingerprint> student@TargetLinux02
```

The key pair was verified by displaying both the public and private keys:

```
student@TargetLinux02:~$ cat ~/.ssh/id_rsa.pub
ssh-rsa AAAA... student@TargetLinux02

student@TargetLinux02:~$ cat ~/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
<private key content>
-----END OPENSSH PRIVATE KEY-----
```

The public key (`id_rsa.pub`) is shared with remote servers for authentication, while the private key (`id_rsa`) remains securely stored on the local system and should never be shared.

![SSH Key Generation](screenshots/13-ssh-keygen.png)
![SSH Key Contents](screenshots/14-ssh-key-contents.png)

### Part 2: Successful SSH Connection Using SSH Keys

SSH key-based authentication was configured and tested. The root login was disabled via SSH configuration and the firewall was verified:

```
student@TargetLinux02:~$ sudo grep PermitRootLogin /etc/ssh/sshd_config
PermitRootLogin no

student@TargetLinux02:~$ sudo ufw status verbose
Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
```

This confirms that SSH is allowed through the firewall on port 22, while direct root login is disabled — forcing users to authenticate with SSH keys and then escalate privileges via `sudo` as needed.

![SSH Connection and Verification](screenshots/15-ssh-connection.png)

### Written Response: Linux Security Hardening Best Practices

#### How SELinux Works, Its Benefits, and Why It Should Remain Enabled

SELinux is a mandatory access control system that enforces what processes can actually do on your system, creating a critical safety net that traditional permissions can't provide. Even if an attacker compromises a service or gains root access, SELinux restricts that process to only the resources it's supposed to touch — a hacked web server can't suddenly read SSH keys or modify system configurations because the policy simply won't allow it. Yes, it's frustrating when it blocks legitimate operations and forces you to troubleshoot obscure denials, but those "annoying" restrictions are exactly what contains a breach when something inevitably goes wrong. Every internet-facing server is under constant attack, and SELinux is often the difference between a minor incident and complete system compromise. Disabling it for convenience is like removing your seatbelt because it's uncomfortable — the temporary relief isn't worth the catastrophic risk. For anyone running production servers, especially those handling sensitive data or operating in regulated environments, keeping SELinux enabled isn't just best practice, it's essential. Learn to work with it rather than fight it, and you'll have a security foundation that actually holds up when it matters most.

#### 10 Linux Security Hardening Recommendations

**Recommendation 1: Disable Root SSH Login**

*Why:* Prevents attackers from directly logging in as root over SSH, forcing them to first compromise a regular user account.

*Steps:*

1. Edit the SSH configuration:
   ```bash
   sudo nano /etc/ssh/sshd_config
   ```
2. Find the line `PermitRootLogin` and change it to:
   ```
   PermitRootLogin no
   ```
3. Save and exit (Ctrl+O, Enter, Ctrl+X).
4. Restart SSH:
   ```bash
   sudo systemctl restart sshd
   ```
5. Verify:
   ```bash
   sudo grep PermitRootLogin /etc/ssh/sshd_config
   ```

**Recommendation 2: Enable Automatic Security Updates**

*Why:* Automatically installs security patches to keep the system protected.

*Steps:*

1. Install the package:
   ```bash
   sudo apt update
   sudo apt install unattended-upgrades -y
   ```
2. Enable automatic updates:
   ```bash
   sudo dpkg-reconfigure -plow unattended-upgrades
   ```
   (Select "Yes")
3. Verify it's running:
   ```bash
   sudo systemctl status unattended-upgrades
   ```

**Recommendation 3: Configure Firewall (UFW)**

*Why:* Blocks all incoming traffic except what you specifically allow.

*Steps:*

1. Install UFW:
   ```bash
   sudo apt install ufw -y
   ```
2. Set default rules:
   ```bash
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   ```
3. Allow SSH (important — do this before enabling!):
   ```bash
   sudo ufw allow ssh
   ```
4. Enable the firewall:
   ```bash
   sudo ufw enable
   ```
   (Type "y" to confirm)
5. Check status:
   ```bash
   sudo ufw status verbose
   ```

**Recommendation 4: Enforce Strong Password Policies**

*Why:* Weak passwords are one of the most common attack vectors. Strong password policies reduce the risk of brute-force attacks.

*Steps:*

1. Install the PAM password quality module:
   ```bash
   sudo apt install libpam-pwquality -y
   ```
2. Configure password requirements in `/etc/security/pwquality.conf`:
   ```
   minlen = 12
   dcredit = -1
   ucredit = -1
   lcredit = -1
   ocredit = -1
   ```

**Recommendation 5: Disable Unused Services**

*Why:* Every running service is a potential attack surface. Disabling unnecessary services reduces exposure.

*Steps:*

1. List active services:
   ```bash
   sudo systemctl list-units --type=service --state=active
   ```
2. Disable unnecessary services:
   ```bash
   sudo systemctl disable <service-name>
   sudo systemctl stop <service-name>
   ```

**Recommendation 6: Configure SSH Key-Based Authentication**

*Why:* SSH keys are far more secure than passwords, as they are nearly impossible to brute-force.

*Steps:*

1. Generate a key pair:
   ```bash
   ssh-keygen -t rsa -b 4096
   ```
2. Copy the public key to the server:
   ```bash
   ssh-copy-id user@server
   ```
3. Disable password authentication in `/etc/ssh/sshd_config`:
   ```
   PasswordAuthentication no
   ```
4. Restart SSH:
   ```bash
   sudo systemctl restart sshd
   ```

**Recommendation 7: Enable Audit Logging (auditd)**

*Why:* Provides detailed logs of system events for security monitoring and forensic investigation.

*Steps:*

1. Install auditd:
   ```bash
   sudo apt install auditd -y
   ```
2. Enable and start the service:
   ```bash
   sudo systemctl enable auditd
   sudo systemctl start auditd
   ```
3. Add audit rules (e.g., monitor `/etc/passwd`):
   ```bash
   sudo auditctl -w /etc/passwd -p wa -k passwd_changes
   ```

**Recommendation 8: Implement File Integrity Monitoring (AIDE)**

*Why:* Detects unauthorized changes to critical system files, alerting administrators to potential compromise.

*Steps:*

1. Install AIDE:
   ```bash
   sudo apt install aide -y
   ```
2. Initialize the database:
   ```bash
   sudo aideinit
   ```
3. Run a check:
   ```bash
   sudo aide --check
   ```

**Recommendation 9: Set Up Fail2Ban**

*Why:* Automatically bans IP addresses that show malicious behavior (e.g., repeated failed login attempts).

*Steps:*

1. Install Fail2Ban:
   ```bash
   sudo apt install fail2ban -y
   ```
2. Create a local configuration:
   ```bash
   sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
   ```
3. Enable and start:
   ```bash
   sudo systemctl enable fail2ban
   sudo systemctl start fail2ban
   ```
4. Check status:
   ```bash
   sudo fail2ban-client status sshd
   ```

**Recommendation 10: Restrict Kernel Parameters with sysctl**

*Why:* Hardens the network stack and kernel behavior to prevent common attacks like IP spoofing and SYN floods.

*Steps:*

1. Edit `/etc/sysctl.conf` and add:
   ```
   net.ipv4.conf.all.rp_filter = 1
   net.ipv4.conf.default.rp_filter = 1
   net.ipv4.tcp_syncookies = 1
   net.ipv4.conf.all.accept_redirects = 0
   net.ipv4.conf.all.send_redirects = 0
   net.ipv4.icmp_echo_ignore_broadcasts = 1
   ```
2. Apply the changes:
   ```bash
   sudo sysctl -p
   ```
