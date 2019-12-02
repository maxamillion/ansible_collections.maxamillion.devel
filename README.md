# ansible_collections.maxamillion.devel
Various in-development or prototype
[Ansible](https://github.com/ansible/ansible)
[Collections](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html)

This is not and should never be considered stable or production ready.

## NOTE: Requires Ansible Version 2.9.0 or higher

### VirusTotal

Example implementation of Virus Total as both an `*_info` module and as a lookup
plugin.

Example playbook:

```yaml
- name: Example maxamillion.devel Collection Virus Total lookup and module playbook
  hosts: localhost
  vars:
    super_secret_api_key: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" # This should be in a Vault
    vt_lookup_eval: >
      {{ lookup("maxamillion.devel.virustotal",
        type="domain", data="ansible.com",
        api_key=super_secret_api_key)
      }}
  tasks:
    - name: debug the output of the lookup plugin
      debug:
        var: vt_lookup_eval

    - name: test doing a virustotal query via info module
      maxamillion.devel.virustotal_info:
        type: "domain"
        data: "ansible.com"
        api_key: "{{ super_secret_api_key }}"
      register: vt_info_module_output

    - name: debug the registered output of the info module
      debug:
        var: vt_info_module_output['info']

```
