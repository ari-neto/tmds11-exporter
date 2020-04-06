# standard library
import datetime
import os
import re

# 3rd party libraries

# project libraries
import core
import computers
import environments
import policies
import translation

class Manager(core.CoreApi):
  def __init__(self,
      hostname='app.deepsecurity.trendmicro.com',
      port='4119',
      tenant=None,
      username=None,
      password=None,
      prefix="",
      ignore_ssl_validation=False
      ):
    core.CoreApi.__init__(self)
    self._hostname = None
    self._port = port
    self._tenant = None
    self._username = None
    self._password = None
    self._prefix = prefix
    self.ignore_ssl_validation = ignore_ssl_validation
    self.hostname = hostname

    self._get_local_config_file()

    # allow for explicit override
    if tenant:
      self._tenant = unicode(tenant, "utf-8")
    if username:
      self._username = unicode(username, "utf-8")
    if password:
      self._password = unicode(password, "utf-8")

    self.computer_groups = computers.ComputerGroups(manager=self)
    self.computers = computers.Computers(manager=self)
    self.policies = policies.Policies(manager=self)
    self.rules = policies.Rules(manager=self)
    self.ip_lists = policies.IPLists(manager=self)
    self.cloud_accounts = environments.CloudAccounts(manager=self)

  def __del__(self):
    """
    Try to gracefully clean up the session
    """
    try:
      self.sign_out()
    except Exception, err: pass

  def __str__(self):
    """
    Return a better string representation
    """
    dsm_port = ":{}".format(self.port) if self.port else ""
    return "Manager <{}{}>".format(self.hostname, dsm_port)

  # *******************************************************************
  # properties
  # *******************************************************************
  @property
  def hostname(self): return self._hostname
  
  @hostname.setter
  def hostname(self, value):
    if value == 'app.deepsecurity.trendmicro.com': # Deep Security as a Service
      self.port = 443
    self._hostname = value
    self._set_endpoints()
  
  @property
  def port(self): return self._port

  @port.setter
  def port(self, value):
    self._port = int(value) if value else None
    self._set_endpoints()

  @property
  def tenant(self): return self._tenant

  @tenant.setter
  def tenant(self, value):
    self._tenant = value
    self._reset_session()

  @property
  def username(self): return self._username
  
  @username.setter
  def username(self, value):
    self._username = value
    self._reset_session()

  @property
  def password(self): return self._password

  @password.setter
  def password(self, value):
    self._password = value
    self._reset_session()

  @property
  def prefix(self): return self._prefix

  @prefix.setter
  def prefix(self, value):
    if not value or not type(value) in [type(''), type(u'')]: value = ""
    self._prefix = value

  # *******************************************************************
  # methods
  # *******************************************************************
  def _set_endpoints(self):
    """
    Set the API endpoints based on the current configuration
    """
    dsm_port = ":{}".format(self.port) if self.port else "" # allow for endpoints with no port specified
    self._rest_api_endpoint = "https://{}{}/{}rest".format(self.hostname, dsm_port, self.prefix)
    self._soap_api_endpoint = "https://{}{}/{}webservice/Manager".format(self.hostname, dsm_port, self.prefix)

  def _reset_session(self):
    """
    Reset the current session due to a credentials change
    """
    self.sign_out()
    self.sign_in()

  def _get_local_config_file(self):
    """
    Look for a local config file containing the credentials similar to the AWS CLI

    Path checked is ( via os.path.expanduser(path) ):
      ~/.deepsecurity/credentials
      C:\Users\USERNAME\.deepsecurity\credentials

    !!! Remember that by storing credentials on the local disk you are increasing the
        risk of compromise as you've expanded the attack surface. If an attacker gains
        access to your local machine then can now get the credentials to your Deep Security
        installation and compromise the security of other systems.

        Use the role-based access control in Deep Security to ensure that you reduce the
        permissions assigned to the account your using to automate the system
    """
    user_credentials_path = os.path.expanduser('~/.deepsecurity/credentials')
    if os.path.exists(user_credentials_path):
      self.log("Found local credentials file at [{}]".format(user_credentials_path))
      credentials = {
        'username': None,
        'password': None,
        'tenant': None,
      }
      try:
        credential_line_pattern = re.compile(r'(?P<key>\w+) = (?P<val>[^\n]+)')
        with open(user_credentials_path, 'r') as fh:
          for line in fh:
            m = credential_line_pattern.search(line)
            if m:
              if not credentials.has_key(m.group('key')): credentials[m.group('key')] = None
              credentials[m.group('key')] = m.group('val')
      except Exception, err:
        self.log("Could not read and process local credentials file.", err=err)

      # verify credentials
      for k, v in credentials.items():
        if v:
          if k in dir(self):
            try:
              setattr(self, "_{}".format(k), v)
              self.log("Loaded {} from local credentials file".format(k))
            except Exception, err:
              self.log("Unable to load {} from local credentials file".format(k))
  
  def sign_in(self):
    """
    Sign in to the Deep Security APIs
    """
    # first the SOAP API
    soap_call = self._get_request_format()
    soap_call['data'] = {
      'username': self.username,
      'password': self.password,
      }
    if self.tenant:
      soap_call['call'] = 'authenticateTenant'
      soap_call['data']['tenantName'] = self.tenant
    else:
      soap_call['call'] = 'authenticate'

    response = self._request(soap_call, auth_required=False)
    if response and response['data']: self._sessions[self.API_TYPE_SOAP] = response['data']

    # then the REST API
    rest_call = self._get_request_format(api=self.API_TYPE_REST)
    rest_call['data'] = {
      'dsCredentials':
          {
            'userName': self.username,
            'password': self.password,
          }
    }
    if self.tenant:
      rest_call['call'] = 'authentication/login'
      rest_call['data']['dsCredentials']['tenantName'] = self.tenant
    else:
      rest_call['call'] = 'authentication/login/primary'

    response = self._request(rest_call, auth_required=False)
    if response and response['raw']: self._sessions[self.API_TYPE_REST] = response['raw']

    if self._sessions[self.API_TYPE_REST] and self._sessions[self.API_TYPE_SOAP]:
      return True
    else:
      return False

  def sign_out(self):
    """
    Sign out to the Deep Security APIs
    """
    # first the SOAP API
    soap_call = self._get_request_format(call='endSession')
    if self._sessions[self.API_TYPE_SOAP]:
      response = self._request(soap_call)
      if response and response['status'] == 200: self._sessions[self.API_TYPE_SOAP] = None

    # then the REST API
    rest_call = self._get_request_format(api=self.API_TYPE_REST, call='authentication/logout')
    if self._sessions[self.API_TYPE_REST]:
      response = self._request(rest_call)
      if response and response['status'] == 200: self._sessions[self.API_TYPE_REST] = None

    if self._sessions[self.API_TYPE_REST] or self._sessions[self.API_TYPE_SOAP]:
      return False
    else:
      return True

  def get_api_version(self):
    """
    Get the version of the REST and SOAP APIs current running on the Manager
    """
    versions = {
      self.API_TYPE_REST: None,
      self.API_TYPE_SOAP: None,
    }

    # first the SOAP API
    soap_call = self._get_request_format(call='getApiVersion')
    response = self._request(soap_call, auth_required=False)
    if response and response['status'] == 200 and response['data']:
      versions[self.API_TYPE_SOAP] = response['data']

    # then the REST API
    rest_call = self._get_request_format(api=self.API_TYPE_REST, call='apiVersion')
    response = self._request(rest_call, auth_required=False)
    if response and response['status'] == 200 and response['data']:
      versions[self.API_TYPE_REST] = response['data']

    return versions
  
  def get_time(self):
    """
    Get the current time as set on the Manager
    """
    result = None
    soap_call = self._get_request_format(call='getManagerTime')
    response = self._request(soap_call, auth_required=False)
    if response and response['status'] == 200 and response['data'].has_key('#text'):
      result = datetime.datetime.strptime(response['data']['#text'], "%Y-%m-%dT%H:%M:%S.%fZ")
  
    return result
  
  def is_up(self):
    """
    Check to see if the Manager is up and responding to requests
    """
    result = None
    rest_call = self._get_request_format(api=self.API_TYPE_REST, call='status/manager/ping')
    response = self._request(rest_call, auth_required=False)
    if response and response['status'] == 200:
      result = True
    else:
      result = False

    return result

  # *******************************************************************
  # mirrored on the computers.Computer and computers.ComputerGroup 
  # objects
  # *******************************************************************
  def request_events_from_computer(self, computer_id):
    """
    Ask the computer to send the latest events it's seen to the DSM
    """
    result = False

    soap_call = self._get_request_format(call='hostGetEventsNow')
    soap_call['data'] = {
      'hostID': computer_id
      }
    response = self._request(soap_call)
    if response and response['status'] == 200: result = True
    
    return result

  def clear_alerts_and_warnings_from_computers(self, computer_ids):
    """
    Clear any alerts or warnings for the specified computers
    """
    result = False

    if not type(computer_ids) == type([]): computer_ids = [computer_ids]

    soap_call = self._get_request_format(call='hostClearWarningsErrors')
    soap_call['data'] = {
      'hostIDs': computer_ids
      }
    response = self._request(soap_call)
    if response and response['status'] == 200: result = True
    
    return result

  def scan_computers_for_malware(self, computer_ids):
    """
    Request a malware scan be run on the specified computers
    """
    result = False

    if not type(computer_ids) == type([]): computer_ids = [computer_ids]

    soap_call = self._get_request_format(call='hostAntiMalwareScan')
    soap_call['data'] = {
      'hostIDs': computer_ids
      }
    response = self._request(soap_call)
    if response and response['status'] == 200: result = True
    
    return result

  def scan_computers_for_integrity(self, computer_ids):
    """
    Request an integrity scan be run on the specified computers
    """
    result = False

    if not type(computer_ids) == type([]): computer_ids = [computer_ids]

    soap_call = self._get_request_format(call='hostIntegrityScan')
    soap_call['data'] = {
      'hostIDs': computer_ids
      }
    response = self._request(soap_call)
    if response and response['status'] == 200: result = True
    
    return result

  def scan_computers_for_recommendations(self, computer_ids):
    """
    Request a recommendation scan be run on the specified computers
    """
    result = False

    if not type(computer_ids) == type([]): computer_ids = [computer_ids]

    soap_call = self._get_request_format(call='hostRecommendationScan')
    soap_call['data'] = {
      'hostIDs': computer_ids
      }
    response = self._request(soap_call)
    if response and response['status'] == 200: result = True
    
    return result 

  def assign_policy_to_computers(self, policy_id, computer_ids):
    """   
    Assign the specified policy to the specified computers
    """
    result = False

    if not type(computer_ids) == type([]): computer_ids = [computer_ids]

    soap_call = self._get_request_format(call='securityProfileAssignToHost')
    soap_call['data'] = {
      'hostIDs': computer_ids,
      'securityProfileID': policy_id,
      }
    response = self._request(soap_call)
    if response and response['status'] == 200: result = True
    
    return result

  def get_rule_recommendations_for_computer(self, computer_id):
    """
    Get the recommended rule set (applied or not) for the specified computer
    """
    results = {
      'total_recommedations': 0
      }

    rules_types = { # values align with rule type ENUM
      'DPIRuleRetrieveAll': 2,
      'firewallRuleRetrieveAll': 3,
      'integrityRuleRetrieveAll': 4,
      'logInspectionRuleRetrieveAll': 5,
      'applicationTypeRetrieveAll': 1,
      }

    for rule_type, type_enum_val in rules_types.items():
      rule_key = translation.Terms.get(rule_type).replace('_retrieve_all', '').replace('_rule', '')
      results[rule_key] = []

      soap_call = self._get_request_format(call='hostRecommendationRuleIDsRetrieve')
      soap_call['data'] = {
        'hostID': computer_id,
        'type': type_enum_val,
        'onlyunassigned': False,
        }
      response = self._request(soap_call)
      if response and response['status'] == 200:
        # response contains the internal rule ID
        for internal_rule_id in response['data']:
          if internal_rule_id == u'@xmlns': continue
          results[rule_key].append(internal_rule_id)
          results['total_recommedations'] += 1

    return results