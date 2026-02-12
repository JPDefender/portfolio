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
