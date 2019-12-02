# (c) 2019 Adam Miller <admiller@redhat.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    lookup: maxamillion.devel.virustotal
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
"""

EXAMPLES = """
- name: Grab report from VirtusTotal for Ansible.com
  debug:
      msg: "{{ lookup('maxamillion.devel.virustotal', api_key='xxxx', type='url', data='https://ansible.com'}}"
"""

RETURN = """
  _raw:
    description: secrets stored
"""

from ansible.errors import AnsibleError
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


class LookupModule(LookupBase):

    def return_response(self, response, callback, start_time):
        """
        parse the response and return the json results if successful
        :param resp:
        :return:
        """
        global HTTP_OK
        global HTTP_RATE_LIMIT
        global HTTP_FORBIDDEN

        if response and type(response) is not dict:
            raise AnsibleError(
                "Invalid response from virtustotal.com: {}".format(response)
            )

        status = response.get("response_code", -1)

        if status == HTTP_RATE_LIMIT:
            raise AnsibleError("API rate limit exceeded on virtustotal.com")

        if status == HTTP_FORBIDDEN:
            raise AnsibleError("virustotal.com API Key provided is invalid")

        if status != HTTP_OK:
            raise AnsibleError(
                "Invalid response status from virustotal.com: {}".format(status)
            )

        return self.check_results(response["results"], callback, start_time)

    def check_results(self, results, callback, start_time):
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
            if int(curr_time - start_time)/1000 >= int(self.vt_timeout):
                raise AnsibleError("maxamillion.devel.virustotal lookup plugin exceeded max wait time: {}".format(self.vt_timeout))

            if callback:
                time.sleep(int(vt_polling_interval))
                # start again to review results
                response = callback(id)
                results = self.return_response(response, callback, start_time)
            else:
                raise AnsibleError("maxamillion.devel.virustotal: no callback function specified with response code: {} scan id {}".format(code, scan_id))
        else:
            raise AnsibleError("maxamillion.devel.virustotal: unexpected response code: {} for scan_id {}".format(code, scan_id))

        self.log.debug(results)
        return results

    def run(self, terms, variables=None, **kwargs):

        global RC_NOT_FOUND

        vt_type = kwargs.get("type", "url")
        vt_data = kwargs.get("data", None)
        vt_api_key = kwargs.get("api_key", None)
        self.vt_timeout = kwargs.get("timout", 300)
        self.vt_polling_interval = self.vt_timeout / 10 # Seems like a sane default

        if not vt_data:
            AnsibleError(
                "No vt_data provided to maxamillion.devel.virustotal lookup but required."
            )
        if not vt_api_key:
            AnsibleError(
                "No vt_api_key provided to maxamillion.devel.virustotal lookup but required."
            )

        vt = VirusTotal(api_key=vt_api_key)

        # determine next steps based on the API call to make
        if vt_type.lower() == "file":
            # Create a temporary file to write the binary data to.
            if not os.path.exists(vt_data):
                AnsibleError(
                    "Invalid file path provided for maxamillion.devel.virustotal lookup plugin: {0}".format(
                        vt_data
                    )
                )
            try:
                response = vt.scan_file(vt_data)
            except Exception as err:
                raise err

            file_result = self.return_response(
                response, vt.get_file_report, time.time()
            )

            ## was a sha-256 returned? try an existing report first
            if file_result.get("sha256"):
                response = vt.get_file_report(file_result.get("sha256"))
                report_result = self.return_response(response, None, time.time())

                if (
                    report_result.get("response_code")
                    and report_result.get("response_code") == 1
                ):
                    result = report_result
                else:
                    result = file_result

        elif vt_type.lower() == "url":
            # attempt to see if a report already exists
            response = vt.get_url_report(vt_data)
            result = self.return_response(response, None, time.time())

            # check if result is not found, meaning no report exists
            if result["response_code"] == RC_NOT_FOUND:
                response = vt.scan_url(vt_data)

                result = self.return_response(
                    response, vt.get_url_report, time.time()
                )

        elif vt_type.lower() == "ip":
            response = vt.get_ip_report(vt_data)
            result = self.return_response(response, None, time.time())

        elif vt_type.lower() == "domain":
            response = vt.get_domain_report(vt_data)
            result = self.return_response(response, None, time.time())

        elif vt_type.lower() == "hash":
            response = vt.get_file_report(vt_data)
            result = self.return_response(response, None, time.time())

        else:
            raise AnsibleError(
                "Unknown type field for maxamillion.devel.virustotal lookup plugin: {}.".format(
                    vt_type
                )
            )

        return [result]
