# ISE5901 Ansible Bundle

This bundle contains the Ansible playbooks and tuning files used for the lab runs in the paper.

## Controller requirements

Install these packages on the machine where you run Ansible:

- `git`
- `openssh-client`
- `python3`
- `python3-venv`
- `ansible-core` 2.15 or newer

Ubuntu example:

```bash
sudo apt update
sudo apt install -y git openssh-client python3 python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "ansible-core>=2.15,<2.18"
```

Verify the install:

```bash
source .venv/bin/activate
ansible --version
ansible-playbook --version
```

This bundle uses built-in Ansible modules only, so no separate `collections/requirements.yml` file is required.

## What is included

- `playbooks/` for lab bootstrapping, preflight checks, tuning deployment, single Empire runs, single Sliver runs, and RITA post-run analysis.
- `tuning/` with the custom Suricata and Zeek tuning files used in the tuned phase.
- `inventory.yaml.example` as a starting inventory.
- `ansible.cfg` pointing Ansible at the bundled inventory file and `.vault_pass`.

## Assumptions

This bundle preserves the original lab pathing and host layout.

- The controller path is expected to be `/home/ubuntu/ise5901-lab`.
- Several playbooks write run artifacts under `/home/ubuntu/ise5901-lab/runs/`.
- `playbooks/boot-lab.yml`, `playbooks/reset-victims.yml`, `playbooks/revert-and-boot.yml`, and the snapshot helpers expect VirtualBox `VBoxManage.exe` to be available at `/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe`.
- Remote hosts are expected to already have Empire, Sliver, Zeek, Suricata, Security Onion, and RITA installed.

## Setup

1. Place the bundle at `/home/ubuntu/ise5901-lab` or adjust the playbooks to match your local pathing.
2. Create and activate the local virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "ansible-core>=2.15,<2.18"
```

3. Copy `inventory.yaml.example` to `inventory.yaml` and update it with your real SSH key path, usernames, and host IPs.
4. Create `.vault_pass` in the bundle root if you use the bundled `ansible.cfg` vault setting.
5. Provide `vault_become_password` through Ansible Vault or another override mechanism.

## Typical usage

From the bundle root:

```bash
ansible-playbook playbooks/boot-lab.yml -e "boot_targets=sensors"
ansible-playbook playbooks/preflight.yml
ansible-playbook playbooks/preflight-sensors.yml
ansible-playbook playbooks/reset-victims.yml
ansible-playbook playbooks/empire/run-single.yml -e "run_id=EMP-HTTP-WIN-DEF-01 profile=http victim=windows"
ansible-playbook playbooks/sliver/run-single.yml -e "run_id=SLV-HTTP-LNX-TUN-01 profile=http victim=linux config_phase=tuned"
ansible-playbook playbooks/rita-analyze.yml -e "run_id=EMP-HTTP-WIN-DEF-01"
```

For tuned runs, deploy the custom rules and Zeek scripts before starting experiments:

```bash
ansible-playbook playbooks/apply-tuning.yml
```

## Notes

- Empire uses `beacon_jitter` as a fraction, default `0.1`.
- Sliver uses `beacon_jitter` as seconds, default `6`.
- The run playbooks already perform log rotation, capture startup, artifact collection, and metadata finalization.