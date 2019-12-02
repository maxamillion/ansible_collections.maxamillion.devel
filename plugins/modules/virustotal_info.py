#!/usr/bin/python

# (c) 2019 Adam Miller <admiller@redhat.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    module: maxamillion.devel.virustotal
    author:
      -  Adam Miller <admiller@redhat.com>
    version_added: "2.10"
    requirements:
      - virustotal-api
    short_description: query virustotal (virustotal.com) API
    description:
      - run queries against virtustotal.com
    options:
      api_key:
        description: virustotal.com API KEY
        required: True
        type: str
      type:
        description: type of query
        default: 'url'
        choices:
          - url
          - file
          - ip
          - domain
          - hash
        type: str
      data:
        description:
          - Data correlating to type.
          - When paired with C('url') type, this would be the actual URL to check
          - When paired with C('file') type, this would be the path to the file to check
          - When paired with C('ip') type, this would be the ip address to check
          - When paired with C('domain') type, this would be the domain name to check
          - When paried with C('hash') type, this would be the literal hash to check
        required: True
        type: str
      timeout:
        description: amount of time to wait for virustotal.com to complete a report
        default: 600
        type: int
      polling_interval:
        description: time to wait between polling attempts against current virustotal.com scan
        default: 60
        type: int
"""

EXAMPLES = """
- name: Grab report from VirtusTotal for Ansible.com
  debug:
      msg: "{{ lookup('maxamillion.devel.virustotal', api_key='xxxx', type='url', data='https://ansible.com'}}"
"""

RETURN = """
  info:
    description: response from Virus Total
"""

from ansible.module_utils._text import to_bytes, to_text
from ansible.plugins.lookup import LookupBase

from virus_total_apis import PublicApi as VirusTotal
import os
import time

import json

RC_NOT_FOUND = 0
RC_READY = 1
RC_IN_QUEUE = -2

HTTP_OK = 200
HTTP_RATE_LIMIT = 204
HTTP_FORBIDDEN = 403

from ansible.module_utils.basic import AnsibleModule

def return_response(module, response, callback, start_time):
    """
    parse the response and return the json results if successful
    :param resp:
    :return:
    """
    global HTTP_OK
    global HTTP_RATE_LIMIT
    global HTTP_FORBIDDEN

    if response and type(response) is not dict:
        raise module.fail_json(
            "Invalid response from virtustotal.com: {}".format(response)
        )

    status = response.get("response_code", -1)

    if status == HTTP_RATE_LIMIT:
        raise module.fail_json("API rate limit exceeded on virtustotal.com")

    if status == HTTP_FORBIDDEN:
        raise module.fail_json("virustotal.com API Key provided is invalid")

    if status != HTTP_OK:
        raise module.fail_json(
            "Invalid response status from virustotal.com: {}".format(status)
        )

    return check_results(module, response["results"], callback, start_time)

def check_results(module, results, callback, start_time):
    '''
    continue checking for the scans to complete
    :param results: possibly interim results
    :return: final results of scan
    '''
    global RC_READY
    global RC_NOT_FOUND
    global RC_IN_QUEUE
    code = results.get('response_code', None)
    scan_id = results.get('scan_id', None)
    if code == RC_READY or code == RC_NOT_FOUND:
        return results

    elif code == RC_IN_QUEUE:
        curr_time = time.time()
        if int(curr_time - start_time)/1000 >= int(module.params['timeout']):
            raise module.fail_json("maxamillion.devel.virustotal lookup plugin exceeded max wait time: {}".format(module.params['timeout']))

        if callback:
            time.sleep(int(module.params['polling_interval']))
            # start again to review results
            response = callback(id)
            results = return_response(module, response, callback, start_time)
        else:
            raise module.fail_json("maxamillion.devel.virustotal: no callback function specified with response code: {} scan id {}".format(code, scan_id))
    else:
        raise module.fail_json("maxamillion.devel.virustotal: unexpected response code: {} for scan_id {}".format(code, scan_id))

    return results

def run_module():

    global RC_NOT_FOUND

    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        api_key=dict(type='str', required=True),
        type=dict(type='str', required=False, default='url'),
        data=dict(type='str', required=True),
        timeout=dict(type='int', required=False, default=600),
        polling_interval=dict(type='int', required=False, default=60),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        info={},
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    vt_type = module.params['type']
    vt_data = module.params['data']
    vt_api_key = module.params['api_key']

    vt = VirusTotal(api_key=vt_api_key)

    # determine next steps based on the API call to make
    if vt_type.lower() == "file":
        # Create a temporary file to write the binary data to.
        if not os.path.exists(vt_data):
            module.fail_json(
                msg="Invalid file path provided for maxamillion.devel.virustotal lookup plugin: {0}".format(
                    vt_data
                )
            )
        try:
            response = vt.scan_file(vt_data)
        except Exception as err:
            raise err

        file_result = return_response(
            module, response, vt.get_file_report, time.time()
        )

        ## was a sha-256 returned? try an existing report first
        if file_result.get("sha256"):
            response = vt.get_file_report(file_result.get("sha256"))
            report_result = return_response(module, response, None, time.time())

            if (
                report_result.get("response_code")
                and report_result.get("response_code") == 1
            ):
                result['info'] = report_result
            else:
                result['info'] = file_result

    elif vt_type.lower() == "url":
        # attempt to see if a report already exists
        response = vt.get_url_report(vt_data)
        result['info'] = return_response(module, response, None, time.time())

        # check if result is not found, meaning no report exists
        if result["response_code"] == RC_NOT_FOUND:
            response = vt.scan_url(vt_data)

            result['info'] = return_response(
                module, response, vt.get_url_report, time.time()
            )

    elif vt_type.lower() == "ip":
        response = vt.get_ip_report(vt_data)
        result['info'] = return_response(module, response, None, time.time())

    elif vt_type.lower() == "domain":
        response = vt.get_domain_report(vt_data)
        result['info'] = return_response(module, response, None, time.time())

    elif vt_type.lower() == "hash":
        response = vt.get_file_report(vt_data)
        result['info'] = return_response(module, response, None, time.time())

    else:
        raise module.fail_json(
            "Unknown type field for maxamillion.devel.virustotal lookup plugin: {}.".format(
                vt_type
            )
        )

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()


