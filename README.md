# Debian & Proxmox VE Security Hardening (Ansible Roles)

A modular, production-ready collection of Ansible roles designed to secure and harden Debian-based systems (Debian 10, 11, 12, 13) and Proxmox VE (PVE 7+) hypervisors.

> [!CAUTION]
> Please note, that some tasks within the role can introduce breaking changes! Always perform a dry-run (`--check --diff`) first.

---

## Overview of Roles

The repository provides three focused, composable Ansible roles:

| Role                                                | Target                | Description                                                                                                                                                                                                                               |
| :-------------------------------------------------- | :-------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **[`secure-system-setup`](#1-secure-system-setup)** | Debian / Ubuntu / LXC | Base OS hardening: security packages, sysctl kernel parameters, driver blacklisting, strict file permissions, automated security upgrades (`unattended-upgrades`), and Fail2ban intrusion prevention with optional Discord notifications. |
| **[`ssh-setup`](#2-ssh-setup)**                     | Debian / Ubuntu / PVE | Hardened OpenSSH daemon configuration with modern cryptography (Post-Quantum & Curve25519 KEX), public-key-only authentication, access control groups, and inter-node cluster SSH integration for Proxmox VE.                             |
| **[`firewall-setup`](#3-firewall-setup)**           | Debian / Ubuntu / PVE | Dual-mode firewall automation: applies **UFW** on standard Debian/Ubuntu systems and manages the **Proxmox VE Cluster Firewall** (`/etc/pve/firewall/cluster.fw`) with safe staging to prevent management lockouts.                |

---

## Requirements & Dependencies

Install required Ansible collections:

```bash
ansible-galaxy collection install ansible.posix community.general community.proxmox
```

Or add to your `requirements.yml`:

```yaml
---
collections:
  - name: ansible.posix
    version: ">=1.5.4"
  - name: community.general
    version: ">=8.0.0"
  - name: community.proxmox
    version: ">=1.0.0"
```

---

## 1. `secure-system-setup`

Hardens the operating system and base environment against common attack vectors. Automatically detects containerized environments (LXC) and safely skips kernel parameter modifications and hardware driver disabling.

### Features
* **Essential Security Packages**: Installs `auditd`, `ufw`, `fail2ban`, `unattended-upgrades`, `debsums`, `needrestart`, `chkrootkit`, and audit utilities (LXC containers automatically omit hardware-bound packages like `auditd`, `rng-tools`, `powermgmt-base`).
* **System Settings**: Enforces password quality and hashing rounds (SHA-512 with 1,000,000 rounds in `/etc/login.defs`), disables core dumps in `/etc/security/limits.conf`, sets default `UMASK 027`, and purges obsolete networking packages (`telnet`, `nis`, `ntpdate`).
* **Kernel Hardening**: Configures 24+ sysctl security parameters (`kernel.dmesg_restrict`, `kernel.kptr_restrict`, `fs.suid_dumpable`, `net.ipv4.tcp_syncookies`, `fs.protected_fifos`, `kernel.yama.ptrace_scope`, etc.) written to `/etc/sysctl.d/99-hvs-hardening.conf`.
* **Driver & Filesystem Blacklisting**: Blacklists legacy and uncommon filesystems (`cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `gfs2`), obscure network protocols (`dccp`, `sctp`, `rds`, `tipc`), FireWire, and unused sound drivers.
* **File Permissions**: Enforces restrictive permissions on sensitive system paths (`/etc/shadow` `0600`, `/etc/crontab` `0600`, `/etc/cron.*` `0700`, `/etc/sudoers.d` `0750`, bootloader `/boot/grub/grub.cfg` `0600`).
* **Unattended Upgrades**: Configures automated package updates and cleanup via `/etc/apt/apt.conf.d/90-ansible-unattended-upgrades` with validated `systemd` calendar timers.
* **Fail2ban**: Pre-seeds `/etc/fail2ban/jail.local` and `/etc/fail2ban/jail.d/ssh.local` with progressive ban-time scaling (`bantime.increment`), subnet whitelisting, and optional real-time Discord webhook alerts.

### Key Variables (`defaults/main.yml`)

```yaml
# Root account password lock (skipped on PVE nodes and LXC containers)
lock_root_account: true

# Mount /proc with hidepid=2 (disabled by default to prevent systemd user session issues)
secure_proc_hidepid: false

# Management user for permissions
ansible_service_user: "ansible"

# Fail2ban settings
fail2ban_bantime: 600
fail2ban_bantime_increment: true
fail2ban_bantime_factor: 1
fail2ban_findtime: 600
fail2ban_maxretry: 10
fail2ban_banaction_allports: "iptables-allports"
fail2ban_ignoreips:
  - "127.0.0.1/8"
  - "::1"
# vault_discord_webhook_url_f2b: "https://discord.com/api/webhooks/..."

# Unattended upgrades
origins:
  - "origin=*"
unattended_package_blacklist:
  - "linux-image"
  - "linux-headers"
unattended_mail: ""
unattended_mail_sender: "update-notification@{{ ansible_facts['hostname'] }}"
unattended_mail_report: "always"
unattended_autoclean_interval: 7
unattended_apt_daily_oncalendar: "*-*-* 6,18:00"
unattended_apt_daily_upgrade_oncalendar: "*-*-* 6:00"
```

### Tags
* `secure-system-setup` (full role)
* `secure-system-pkgs`
* `secure-system-settings`
* `secure-system-kernel`
* `secure-system-drivers`
* `secure-system-permissions`
* `setup-system-unattended-patches`
* `secure-system-fail2ban`

---

## 2. `ssh-setup`

Deploys a hardened `sshd_config` aligned with modern cryptographic recommendations and zero-trust access control.

### Features
* **Public Key Authentication Only**: Passwords and keyboard-interactive authentication are disabled by default.
* **Modern Cryptography**:
  * **KEX**: Post-Quantum (`sntrup761x25519-sha512`), Curve25519 (`curve25519-sha256`), and high-strength ECDH.
  * **Ciphers**: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`.
  * **MACs**: Encrypt-then-MAC (`hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`).
* **Access Control**: Enforces `AllowGroups ssh _ssh`. System accounts in `ssh_admin_users` are automatically added to access groups.
* **Proxmox VE Cluster Auto-Detection**: Dynamically detects Proxmox VE hypervisors (`/etc/pve`):
  * Sets `PermitRootLogin prohibit-password` (or if `permit_root_login: true` is set).
  * Automatically includes `/etc/pve/priv/authorized_keys` in `AuthorizedKeysFile`.
  * Optionally configures `/root/.ssh/config` for inter-node communication across cluster subnets (`StrictHostKeyChecking accept-new`) when `ssh_pve_cluster_hosts` is defined.
  * Enables TCP and Agent forwarding required for live migration and GUI console tunnels (or if `ssh_tunnel: true` is set).
* **Optional 2FA**: Google Authenticator PAM installation and checks are gated behind `ssh_enable_2fa: true`.

### Key Variables (`defaults/main.yml`)

```yaml
# SSH listening port
ssh_port: 22

# Allowed Linux groups
ssh_groups_allow: "ssh _ssh"

# Service & administrative users allowed public-key SSH access
ssh_service_user: "ansible"
ssh_admin_users:
  - "ansible"

# Proxmox cluster inter-node client configuration pattern (empty by default)
ssh_pve_cluster_hosts: ""

# Privilege & tunneling settings (auto-enabled on PVE nodes, or manually overridden)
permit_root_login: false
ssh_tunnel: false
ssh_enable_2fa: false

# Session timeouts (disconnects unresponsive sessions after 10 minutes)
ssh_client_alive_interval: 300
ssh_client_alive_count_max: 2
```

### Tags
* `ssh-setup`

---

## 3. `firewall-setup`

Provides firewall management tailored to the host environment:

> [!IMPORTANT]
> **Host Firewall Scope & LXC Recommendations**:
> * **Proxmox Node Firewall (`host.fw`)**: Node-specific host firewall configurations (`/etc/pve/nodes/<hostname>/host.fw`) are intentionally out-of-scope for this role. Node-level overrides or options should be managed directly through Proxmox VE (GUI or CLI).
> * **Recommended Firewall for LXC Containers**: For LXC containers running on Proxmox VE, it is strongly recommended to use the **Proxmox Host / Hypervisor Firewall** (configured at the container or datacenter level via `/etc/pve/firewall/<vmid>.fw` or the PVE Web GUI) rather than running an in-guest firewall such as `ufw`.

### Modes
1. **Standard Debian/Ubuntu Nodes (`setup-firewall.debian.yml`)**:
   * Uses **UFW** with default incoming policy `deny` and outgoing policy `allow`.
   * Maps group-based and variable-based open ports via `vars/firewall-ports-mapping.yml`.
   * Automatically guarantees that the configured `ssh_port` is allowed to prevent accidental lockouts.
   * Automatically skips UFW execution inside LXC containers (`ansible_facts['virtualization_type'] == 'lxc'` or `is_lxc: true`).
2. **Proxmox VE Hypervisors (`setup-firewall.pve.yml`)**:
   * Generates and validates the cluster/datacenter firewall configuration (`/etc/pve/firewall/cluster.fw`).
   * **Safe Staging Workflow**: Deploys the configuration in Stage 1 with `policy_in: ACCEPT`, verifies that the security group (`basic-ruleset`) is active in `pvesh get /cluster/firewall/rules`, and only then applies the final `policy_in: DROP`.
   * Automatically allows PVE Web GUI (8006), SPICE Proxy (3128), VNC (5900-5999), Corosync (5404-5412), Ceph, Live Migration (60000-60050), and SSH.

### Key Variables (`defaults/main.yml`)

```yaml
# UFW Settings (standard Debian/Ubuntu)
ufw_enabled: true
ufw_reset_rules: false

# Proxmox VE Firewall Settings
pve_firewall_enable: 1
pve_firewall_policy_in: DROP
pve_firewall_policy_out: ACCEPT
pve_firewall_group_name: basic-ruleset

# Interfaces to bind rules to (empty list binds to all interfaces)
pve_firewall_interfaces: []

# Custom rules appended to the security group
pve_firewall_custom_rules: []
```

### Tags
* `firewall-setup`
* `ufw-setup` (UFW only)
* `pve-firewall-setup` (Proxmox VE only)

---

## Example Usage

### 1. Hardening a Standalone Debian Server

```yaml
---
- name: Apply security hardening to Debian servers
  hosts: servers
  become: true
  vars:
    ssh_port: 22
    ssh_admin_users:
      - ansible
      - devops
    ufw_allowed_services:
      all:
        - port: 22
          proto: tcp
          description: "SSH"
      webserver:
        - port: 80
          proto: tcp
          description: "HTTP"
        - port: 443
          proto: tcp
          description: "HTTPS"
  roles:
    - secure-system-setup
    - ssh-setup
    - firewall-setup
```

### 2. Hardening a Proxmox VE Cluster Node

```yaml
---
- name: Apply security hardening to Proxmox VE cluster
  hosts: pve
  become: true
  vars:
    ssh_pve_cluster_hosts: "10.10.10.* 192.168.1.* pve-node*"
    pve_firewall_policy_in: "DROP"
    pve_firewall_custom_rules:
      - "IN ACCEPT -p tcp -dport 9100 -log nolog # Prometheus Node Exporter"
  roles:
    - secure-system-setup
    - ssh-setup
    - firewall-setup
```

### 3. Running Specific Hardening Steps

```bash
# Apply only SSH hardening
ansible-playbook -i inventory site.yml --tags ssh-setup

# Apply only UFW firewall configuration
ansible-playbook -i inventory site.yml --tags ufw-setup

# Update Fail2ban configuration and restart service
ansible-playbook -i inventory site.yml --tags secure-system-fail2ban
```

---

## License

This project is licensed under the [MIT License](LICENSE).
