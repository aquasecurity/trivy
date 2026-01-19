# Ansible

Trivy analyzes tasks in playbooks and roles for misconfigurations in cloud resources.

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

!!! warning "LIMITATIONS"
    Not all Ansible features are supported. See the [Limitations](#limitations) section for a detailed list.

## Misconfigurations

Trivy recursively scans directories starting from the root and detects Ansible projects by the presence of key files and folders:

- `ansible.cfg`, `inventory`, `group_vars`, `host_vars`, `roles` and `playbooks`
- YAML files that resemble playbooks

For each project, Trivy performs the following steps:

- **Playbook discovery** — determines entry points, i.e., playbooks that are not used as imports in other playbooks.
- **Task and variable resolution** — Trivy resolves tasks and variables from plays, imports, and roles.
- **Module analysis** — modules used in tasks are scanned for insecure configurations. Currently, only cloud resource modules are supported.

### Project scanning

The Ansible scanner is enabled by default. To run only this scanner, use the `--misconfig-scanners ansible` flag:

```bash
trivy conf --misconfig-scanners ansible .
```

Example playbook:

```yaml
- name: Example playbook
  hosts: localhost
  connection: local
  tasks:
    - name: Create S3 bucket
      amazon.aws.s3_bucket:
        name: "{{ bucket_name }}"
        region: "{{ bucket_region }}"
        state: present
```

Scan result:

```bash
AVD-AWS-0093 (HIGH): Public access block does not restrict public buckets
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
S3 buckets should restrict public policies for the bucket. By enabling, the restrict_public_buckets, only the bucket owner and AWS Services can access if it has a public policy.


See https://avd.aquasec.com/misconfig/avd-aws-0093
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 test.yaml:6-9
   via test.yaml:5-9 (tasks)
    via test.yaml:1-9 (play)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   - name: Example playbook
   2     hosts: localhost
   3     connection: local
   4     tasks:
   5       - name: Create S3 bucket
   6 ┌       amazon.aws.s3_bucket:
   7 │         name: "{{ bucket_name }}"
   8 │         region: "{{ bucket_region }}"
   9 └         state: present
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

If the project defines a collection (contains a `galaxy.yaml` file), Trivy can resolve roles using the full name `namespace.collection.role` within the project.

Example `galaxy.yaml`:
```yaml
namespace: myorg
name: mycollection
version: 1.0.0
```

Project structure:
```bash
roles/
  myrole/
    tasks/
      main.yml
galaxy.yaml
```

Using the role in a playbook:
```yaml
- name: Apply custom role
  hosts: localhost
  tasks:
    - name: Run role from collection
      include_role:
        name: myorg.mycollection.myrole
```

Trivy can correctly locate and analyze the `myrole` role via the full collection name.


### Scanning specific playbooks

To limit scanning to specific playbooks instead of automatically discovering them, use the `--ansible-playbook` flag (can be repeated) with the path to the playbook:

```bash
trivy config --ansible-playbook playbooks/main.yaml .
```

### Using inventory

By default, Trivy searches for inventory [in the default location](https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html#how-to-build-your-inventory): `/etc/ansible/hosts`. If an `ansible.cfg` file exists at the project root, the inventory path is taken from it.

To specify a custom inventory source, use the `--ansible-inventory` flag (same as Ansible’s `--inventory`). The flag can be repeated:

```bash
trivy config --ansible-inventory hosts.ini \
    --ansible-inventory inventory .
```

### Passing extra variables

To pass extra variables, use the `--ansible-extra-vars` flag (same as Ansible’s `--extra-vars`). The flag can be repeated:

```bash
trivy config --ansible-extra-vars region=us-east-1 \
    --ansible-extra-vars @vars.json .
```

### Rendering misconfiguration snippet

To display the rendered snippet, use the `--render-cause` flag.

Example output for an S3 bucket task using the `amazon.aws.s3_bucket` module:

```bash
trivy config --render-cause ansible .
...
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 447       - name: "Hetzner Cloud: Create Object Storage (S3 bucket) {{ hetzner_object_storage_name }}"
 448 ┌       amazon.aws.s3_bucket:
 449 │         endpoint_url: "{{ hetzner_object_storage_endpoint }}"
 450 │         ceph: true
 451 │         aws_access_key: "{{ hetzner_object_storage_access_key }}"
 452 │         aws_secret_key: "{{ hetzner_object_storage_secret_key }}"
 453 │         name: "{{ hetzner_object_storage_name }}"
 454 │         region: "{{ hetzner_object_storage_region }}"
 455 └         requester_pays: false
 ...   
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Rendered cause:
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
amazon.aws.s3_bucket:
    endpoint_url: https://us-east-1.your-objectstorage.com
    ceph: true
    aws_access_key: ""
    aws_secret_key: ""
    name: test-pgcluster-backup
    region: us-east-1
    requester_pays: false
    state: present

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

## Limitations

Ansible scanning has several limitations and does not support the following:

- Resolving remote collections
- Inventory, lookup, and filter plugins (except `dirname`)
- Setting facts (`set_fact`)
- Loops: `loop`, `with_<lookup>`, etc.
- Patterns in a play’s hosts field
- Host ranges in inventory, e.g., `www[01:50:2].example.com`
- Only supports the following services: AWS S3. If you have other services or clouds that you would like to see support for, please open a discussion in the Trivy project.