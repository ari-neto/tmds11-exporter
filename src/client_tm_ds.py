from __future__ import print_function
import deepsecurity
import re
import logging
import config
import base64
from os import environ
from envparse import env
from datetime import datetime, timedelta


# Logging configuration
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=config.LOG_LEVEL)

# Deep Security configuration
try:
    ds_host = env.str(
        "DS_HOST", default=config.DS_HOST)
    ds_port = env.str(
        "DS_PORT", default=config.DS_PORT)
    ds_user = env.str(
        "DS_USER", default=config.DS_USER)
    ds_pass = env.str(
        "DS_PASS", default=config.DS_PASS)
    ds_ver_ssl = env.str(
        "DS_VERIFY_SSL", default=config.DS_IGNORE_VERIFY_SSL)
except Exception as e:
    logging.info('failed to load configurations...')    


ds_user = (base64.b64decode(ds_user))
ds_pass = (base64.b64decode(ds_pass))

linux_regex = 'linux|amazon|debian|ubuntu|oracle|centos|red\shat'

summary = {
    'timestamp': 0
}

# mgr = deepsecurity.dsm.Manager(
#     username=ds_config.ds_user, password=ds_config.ds_pass, tenant=ds_config.ds_account)


def ds_get():
    mgr = deepsecurity.dsm.Manager(
    hostname=ds_host, port = ds_port, username=ds_user, password=ds_pass, ignore_ssl_validation=ds_ver_ssl)

    logging.info('logging on deep security manager...')
    mgr.sign_in()
    logging.info('retrieving computers on deep security manager..')
    mgr.computers.get()
    try:
        # for computer_id in mgr.computers.find(computer_group_id=computer_group_id):
        # for computer_id in mgr.computers.find(platform = '.*'):
        for computer_id in mgr.computers.find(name='.*'):
            computer = mgr.computers[computer_id]
            # security_profile_name = computer.security_profile_name
            name = computer.name
            platform = computer.platform
            # computer_group_name = computer.computer_group_name
            # computer_group_id = computer.computer_group_id
            # recommended_rules = computer.get_recommended_rules()
            # print(recommended_rules)
            overall_status = computer.overall_status
            overall_version = computer.overall_version
            overall_anti_malware_status = computer.overall_anti_malware_status
            overall_firewall_status = computer.overall_firewall_status
            overall_intrusion_prevention_status = computer.overall_intrusion_prevention_status

            fw_rules = get_rules(overall_firewall_status)
            ips_rules = get_rules(overall_intrusion_prevention_status)
            overall_web_reputation_status = computer.overall_web_reputation_status
            overall_integrity_monitoring_status = computer.overall_integrity_monitoring_status
            overall_log_inspection_status = computer.overall_log_inspection_status
            im_rules = get_rules(overall_integrity_monitoring_status)
            li_rules = get_rules(overall_log_inspection_status)

            anti_malware_classic_pattern_version = computer.anti_malware_classic_pattern_version
            anti_malware_engine_version = computer.anti_malware_engine_version
            anti_malware_intelli_trap_exception_version = computer.anti_malware_intelli_trap_exception_version
            anti_malware_intelli_trap_version = computer.anti_malware_intelli_trap_version
            anti_malware_smart_scan_pattern_version = computer.anti_malware_smart_scan_pattern_version
            anti_malware_spyware_pattern_version = computer.anti_malware_spyware_pattern_version
            last_anti_malware_event = computer.last_anti_malware_event
            last_web_reputation_event = computer.last_web_reputation_event
            cloud_object_type = computer.cloud_object_type
            cloud_object_instance_id = computer.cloud_object_instance_id
            # security_profile_id = computer.security_profile_id
            print("Computer_ID: {}".format(computer_id))
            print("Computer Name: {}".format(name))
            print("Instance ID: {}".format(cloud_object_instance_id))
            print("Platform: {}".format(platform))
            # print("Group Name: {}".format(computer_group_name))
            # print("Group ID: {}".format(computer_group_id))
            # print("Security Profile Name: {}".format(security_profile_name))
            # print("Security Profile ID: {}".format(security_profile_id))
            print("Cloud Object Type: {}".format(cloud_object_type))
            # print("Get Recommended Rules: {}".format(recommended_rules))
            print("Overall Status: {}".format(overall_status))
            print("Overal Version: {}".format(overall_version))
            # print("Component Names: {}".format(computer.component_names))
            # print("Component Types: {}".format(computer.component_types))
            # print("Component Versions: {}".format(computer.component_versions))
            print("Overall Anti Malware Status: {}".format(
                overall_anti_malware_status))
            # print ("Overall Anti Malware Classic Pattern Vr: %s" % anti_malware_classic_pattern_version)
            # print ("Overall Anti Malware Engine Vr: %s" % anti_malware_engine_version)
            # print ("Overall Anti Malware Intelli Trap Exception Vr: %s" % anti_malware_intelli_trap_exception_version)
            print("Overall Anti Malware Intelli Trap Vr: {}".format(anti_malware_intelli_trap_version))
            print("Overall Anti Malware Smart Scan Pattern Vr: {}".format(
                anti_malware_smart_scan_pattern_version))
            print("Overall Anti Malware Spyware Pattern Vr: {}".format(anti_malware_spyware_pattern_version))
            print("Last Anti Malware Event: {}".format(last_anti_malware_event))
            print("Last Web Reputation Event: {}".format(last_web_reputation_event))
            print("Overall Anti Firewall Status: {}".format(overall_firewall_status))
            print("Overall Anti IPS Status: {}".format(
                overall_intrusion_prevention_status))
            print("Overall Web Reputation Status: {}".format(overall_web_reputation_status))
            print("Overall Integrity Monitoring Status: {}".format(
                overall_integrity_monitoring_status))
            print("Overall Log Inspection Status: {}".format(
                overall_log_inspection_status))
            print("FW Rules: {}".format(fw_rules))
            print("IPS Rules: {}".format(ips_rules))
            print("IM Rules: {}".format(im_rules))
            print("LI Rules: {}".format(li_rules))
            print("-----------------------------")
            # computer.clear_alerts_and_warnings()
            # computer.scan_for_recommendations()
            # computer.get_recommended_rules()
            # computer.send_events()
    except Exception as e:
        print("Error {}".format(e))
    mgr.sign_out()


def print_dict(var=None, name=None):
    for key, value in var.items():
        print('{} - key: {} - value: {}'.format(name, key, value))


def add_key(key=None, var=None, value=None):
    # "value" is to differentiate when we just add +1 than when we need to add the value (i.e. ips rules)
    if value is None:
        if key in var.keys():
            var[key] += 1
        else:
            var[key] = 1
    else:
        # we are dealing with IPS rules here
        if key in var.keys():
            var[key] += value
        else:
            var[key] = value
    logging.debug('key: {} - value: {}'.format(key, var[key]))

def get_os(var=None):
    if 'windows' in var.lower():
        return 'os_windows'
    elif re.match(linux_regex, var):
        return 'os_linux'
    else:
        logging.debug('unknown os: {}'.format(var.lower()))
        return 'os_unknown'


def get_status(var=None, name=None):
    if name is None:
        raise NameError('name variable is Null')
    else:
        if 'on,' in var.lower() or var.lower() == 'on':
            return '{}-on'.format(name)
        else:
            return '{}-off'.format(name)


def check_none_int(item):
    try:
        if item is not None:
            return int(item)
        else:
            return 0
    except Exception:
        return 0


def delta_date(date):
    try:
        now = datetime.now()
        difference = now - date
        seconds_in_day = 24 * 60 * 60
        timedelta(0, 8, 562000)
        delta = divmod(difference.days * seconds_in_day +
                       difference.seconds, 60)
        # (0, 8)      # 0 minutes, 8 seconds
        # print('min: {}'.format(delta[0]))
        # print('sec: {}'.formart(delta[1]))
        return delta[0]
    except Exception as e:
        logging.info('delta_date_error: {}'.format(e))


def get_rules(module=None):
    # return rules quantity, extracting from module message
    if module is None:
        raise ValueError('get_rules: empty call')
    else:
        f = re.match(r'.*\s(\d+)\srules.*', module)
        rules = f.group(1)
        if 'no' in rules:
            rules = 0
        return int(rules)


def get_module_status(module=None):
    # eturn module status (on|off), extracting from module message
    if module is None:
        raise ValueError('get_module_status: empty call')
    else:
        if 'on' in module.lower():
            return 'on'
        elif 'off' in module.lower():
            return 'off'
        else:
            return 'not_config'


def get_ips_mode(module=None):
    # eturn module mode (prevent|detect), extracting from module message
    if module is None:
        raise ValueError('get_ips_mode: empty call')
    else:
        if 'prevent' in module.lower():
            return 'prevent'
        elif 'off' in module.lower():
            return 'detect'
        else:
            return 'not_config'


def get_summary(max_time=60):
    global summary
    try:
        if summary['timestamp'] != 0:
            delta_time = delta_date(summary['timestamp'])
        else:
            summary = ds_summary()
            return summary
        if delta_time >= max_time:
            logging.info('not_valid_delta_date_minutes (> {}): {}'.format(
                max_time, delta_time))
            summary = ds_summary()
            return summary
        else:
            logging.info(
                'valid_delta_date_minutes (< {}): {}'.format(max_time, delta_time))
            return summary
    except Exception as e:
        logging.info('check_timestamp_error: {}'.format(e))


def ds_summary():
    active = {}
    warning = {}
    inactive = {}
    offline = {}
    error = {}
    unknown = {}
    total = 0
    active_total = 0
    ips_rules_total = 0
    ips_rules_active_total = 0
    ips_rules_inactive_total = 0
    ips_rules_warning_total = 0
    ips_rules_error_total = 0
    ips_rules_unknown_total = 0

    logging.info('ds_summary: metric calc')
    mgr = deepsecurity.dsm.Manager(
        hostname=ds_host, port=ds_port, username=ds_user, password=ds_pass, ignore_ssl_validation=ds_ver_ssl)

    logging.info('logging on deep security manager...')
    mgr.sign_in()
    logging.info('retrieving computers on deep security manager..')
    mgr.computers.get()
    try:
        # for computer_id in mgr.computers.find(computer_group_id=computer_group_id):
        for computer_id in mgr.computers.find(platform='.*'):
            fw_rules = 0
            ips_rules = 0
            li_rules = 0
            im_rules = 0
            try:
                computer = mgr.computers[computer_id]
            except Exception:
                raise Exception('failed to get computer')
            try:
                fw_rules = get_rules(computer.overall_firewall_status)
            except Exception:
                raise Exception('failed to get firewall rules')
            try:
                ips_rules = get_rules(computer.overall_intrusion_prevention_status)
            except Exception:
                raise Exception('failed to get ips rules')
            try:
                im_rules = get_rules(computer.overall_integrity_monitoring_status)
            except Exception:
                raise Exception('failed to get im rules')
            try:
                li_rules = get_rules(computer.overall_log_inspection_status)
            except Exception:
                raise Exception('failed to get li rules')

            # convert
     
            platform = computer.platform.lower()
            agent_status = computer.overall_status.lower()
            # agent_message = str(
            #     computer.computer_status.agent_status_messages).lower()
            agent_version_major = int(computer.overall_version.split('.')[0])
            agent_version = computer.overall_version
            os_type = get_os(platform)

            am_status = str(
                computer.overall_anti_malware_status).lower()
            wr_status = str(
                computer.overall_web_reputation_status).lower()
            fw_status = str(
                computer.overall_firewall_status).lower()
            ip_status = str(
                computer.overall_intrusion_prevention_status).lower()
            im_status = str(
                computer.overall_integrity_monitoring_status).lower()
            li_status = str(
                computer.overall_log_inspection_status).lower()
            ips_status = None
            ips_mode = None
    

            total += 1

            if computer.overall_intrusion_prevention_status is not None:
                module_agent_status = get_module_status(
                    computer.overall_intrusion_prevention_status)
                protect_mode = computer.overall_intrusion_prevention_status.lower()
                # agent_mode = computer.computer_settings.firewall_setting_network_engine_mode.value.lower()

                if 'prevent' in protect_mode and not 'inactive' in protect_mode:
                    ips_status = 'prevent'
                elif 'detect' in protect_mode and not 'inactive' in protect_mode:
                    ips_status = 'detect'
                else:
                    # not activated, 'off, installed, 2 rules' and 'off, not installed, no rules' will match this case
                    ips_status = 'discovered'
                    logging.debug('ips_status - not prevent|detect: {}'.format(
                        computer.intrusion_prevention.module_status.agent_status_message.lower()))

                # if 'inline' in agent_mode and not 'inactive' in module_agent_status:
                #     ips_mode = 'inline'
                # elif 'tap' in agent_mode and not 'inactive' in module_agent_status:
                #     ips_mode = 'tap'
                ips_mode = 'inline'

            ips_rules_total += ips_rules
            if re.match('^managed.*online.*', agent_status):
                # active
                try:
                    active_total += 1
                    ips_rules_active_total += ips_rules

                    add_key(key='computer-platform-all-{}'.format(platform), var=active)
                    add_key(key='computer-platform-{}-{}'.format(os_type,
                                                                platform), var=active)

                    add_key(key='computer-os_type-all-all', var=active)
                    add_key(key='computer-os_type-{}-all'.format(os_type), var=active)
                    add_key(key='computer-os_type-{}-{}'.format(os_type,
                                                                platform), var=active)

                    add_key(
                        key='computer-agent_version-all-{}'.format(agent_version), var=active)
                    add_key(
                        key='computer-agent_version-{}-{}'.format(os_type, agent_version), var=active)
                    add_key(
                        key='computer-agent_version_major-all-{}'.format(agent_version_major), var=active)
                    add_key(key='computer-agent_version_major-{}-{}'.format(os_type,
                                                                            agent_version_major), var=active)

                    add_key(key=get_status(
                        am_status, 'module-am_status-all'), var=active)
                    add_key(key=get_status(
                        wr_status, 'module-wr_status-all'), var=active)
                    add_key(key=get_status(
                        fw_status, 'module-fw_status-all'), var=active)
                    add_key(key=get_status(
                        ip_status, 'module-ip_status-all'), var=active)
                    add_key(key=get_status(
                        im_status, 'module-im_status-all'), var=active)
                    add_key(key=get_status(
                        li_status, 'module-li_status-all'), var=active)

                    add_key(key=get_status(
                        am_status, 'module-am_status-{}'.format(os_type)), var=active)
                    add_key(key=get_status(
                        wr_status, 'module-wr_status-{}'.format(os_type)), var=active)
                    add_key(key=get_status(
                        fw_status, 'module-fw_status-{}'.format(os_type)), var=active)
                    add_key(key=get_status(
                        ip_status, 'module-ip_status-{}'.format(os_type)), var=active)
                    add_key(key=get_status(
                        im_status, 'module-im_status-{}'.format(os_type)), var=active)
                    add_key(key=get_status(
                        li_status, 'module-li_status-{}'.format(os_type)), var=active)

                    add_key(key='vulnerabilities-ips_rules-all-all-all',
                            var=active, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-all-all'.format(
                        os_type), var=active, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-all-{}-all'.format(
                        ips_status), var=active, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-all-all-{}'.format(
                        ips_mode), var=active, value=ips_rules)

                    add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                        os_type, ips_status), var=active, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                        os_type, ips_status, ips_mode), var=active, value=ips_rules)

                    add_key(key='vulnerabilities-ips_rules-all-{}-{}'.format(
                        ips_status, ips_mode), var=active, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-all-{}'.format(
                        os_type, ips_mode), var=active, value=ips_rules)
                except Exception as e:
                    logging.info('ds_summary active - error: {}'.format(e))

            elif re.match('.*warning.*', agent_status):
                # warning
                try:
                    ips_rules_warning_total += ips_rules

                    add_key(key=get_status(
                        agent_version, 'computer-platform-all-{}'.format(platform)), var=warning)
                    add_key(key=get_status(
                        agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=warning)

                    add_key(key='computer-os_type-all-all', var=warning)
                    add_key(key='computer-os_type-{}-all'.format(os_type), var=warning)
                    add_key(key='computer-os_type-{}-{}'.format(os_type,
                                                                platform), var=warning)

                    add_key(
                        key='computer-agent_version-all-{}'.format(agent_version), var=warning)
                    add_key(key='computer-agent_version-{}-{}'.format(os_type,
                                                                    agent_version), var=warning)
                    add_key(
                        key='computer-agent_version_major-all-{}'.format(agent_version_major), var=warning)
                    add_key(key='computer-agent_version_major-{}-{}'.format(os_type,
                                                                            agent_version_major), var=warning)

                    add_key(key=get_status(
                        am_status, 'module-am_status-all'), var=warning)
                    add_key(key=get_status(
                        wr_status, 'module-wr_status-all'), var=warning)
                    add_key(key=get_status(
                        fw_status, 'module-fw_status-all'), var=warning)
                    add_key(key=get_status(
                        ip_status, 'module-ip_status-all'), var=warning)
                    add_key(key=get_status(
                        im_status, 'module-im_status-all'), var=warning)
                    add_key(key=get_status(
                        li_status, 'module-li_status-all'), var=warning)

                    add_key(key=get_status(
                        am_status, 'module-am_status-{}'.format(os_type)), var=warning)
                    add_key(key=get_status(
                        wr_status, 'module-wr_status-{}'.format(os_type)), var=warning)
                    add_key(key=get_status(
                        fw_status, 'module-fw_status-{}'.format(os_type)), var=warning)
                    add_key(key=get_status(
                        ip_status, 'module-ip_status-{}'.format(os_type)), var=warning)
                    add_key(key=get_status(
                        im_status, 'module-im_status-{}'.format(os_type)), var=warning)
                    add_key(key=get_status(
                        li_status, 'module-li_status-{}'.format(os_type)), var=warning)

                    add_key(key='vulnerabilities-ips_rules-all-all-all',
                            var=warning, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-all-all'.format(
                        os_type), var=warning, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-all-{}-all'.format(
                        ips_status), var=warning, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-all-all-{}'.format(
                        ips_mode), var=warning, value=ips_rules)

                    add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                        os_type, ips_status), var=warning, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                        os_type, ips_status, ips_mode), var=warning, value=ips_rules)

                    add_key(key='vulnerabilities-ips_rules-all-{}-{}'.format(
                        ips_status, ips_mode), var=warning, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-all-{}'.format(
                        os_type, ips_mode), var=warning, value=ips_rules)
                except Exception as e:
                    logging.info('ds_summary active - warning: {}'.format(e))
            elif re.match('^unmanaged.*', agent_status):
                # inactive | unmanaged
                try:
                    ips_rules_inactive_total += ips_rules

                    add_key(key=get_status(
                        agent_version, 'computer-platform-all-{}'.format(platform)), var=inactive)
                    add_key(key=get_status(
                        agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=inactive)

                    add_key(key='computer-os_type-all-all', var=inactive)
                    add_key(key='computer-os_type-{}-all'.format(os_type), var=inactive)
                    add_key(key='computer-os_type-{}-{}'.format(os_type,
                                                                platform), var=inactive)

                    add_key(
                        key='computer-agent_version-all-{}'.format(agent_version), var=inactive)
                    add_key(key='computer-agent_version-{}-{}'.format(os_type,
                                                                    agent_version), var=inactive)
                    add_key(
                        key='computer-agent_version_major-all-{}'.format(agent_version_major), var=inactive)
                    add_key(key='computer-agent_version_major-{}-{}'.format(os_type,
                                                                            agent_version_major), var=inactive)

                    add_key(key=get_status(
                        am_status, 'module-am_status-all'), var=inactive)
                    add_key(key=get_status(
                        wr_status, 'module-wr_status-all'), var=inactive)
                    add_key(key=get_status(
                        fw_status, 'module-fw_status-all'), var=inactive)
                    add_key(key=get_status(
                        ip_status, 'module-ip_status-all'), var=inactive)
                    add_key(key=get_status(
                        im_status, 'module-im_status-all'), var=inactive)
                    add_key(key=get_status(
                        li_status, 'module-li_status-all'), var=inactive)

                    add_key(key=get_status(
                        am_status, 'module-am_status-{}'.format(os_type)), var=inactive)
                    add_key(key=get_status(
                        wr_status, 'module-wr_status-{}'.format(os_type)), var=inactive)
                    add_key(key=get_status(
                        fw_status, 'module-fw_status-{}'.format(os_type)), var=inactive)
                    add_key(key=get_status(
                        ip_status, 'module-ip_status-{}'.format(os_type)), var=inactive)
                    add_key(key=get_status(
                        im_status, 'module-im_status-{}'.format(os_type)), var=inactive)
                    add_key(key=get_status(
                        li_status, 'module-li_status-{}'.format(os_type)), var=inactive)

                    # vulnerabilities-ips_rules-os_windows-prevent-inline - value: 2

                    add_key(key='vulnerabilities-ips_rules-all-all-all',
                            var=inactive, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-all-all'.format(
                        os_type), var=inactive, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-all-{}-all'.format(
                        ips_status), var=inactive, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-all-all-{}'.format(
                        ips_mode), var=inactive, value=ips_rules)

                    add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                        os_type, ips_status), var=inactive, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                        os_type, ips_status, ips_mode), var=inactive, value=ips_rules)

                    add_key(key='vulnerabilities-ips_rules-all-{}-{}'.format(
                        ips_status, ips_mode), var=inactive, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-all-{}'.format(
                        os_type, ips_mode), var=inactive, value=ips_rules)
                except Exception as e:
                    logging.info('ds_summary inactive|unmanaged - error: {}'.format(e))

            elif re.match('^managed.*offline.*', agent_status):
                # offline | critical
                try:
                    ips_rules_error_total += ips_rules

                    add_key(key=get_status(agent_version,
                                        'computer-platform-all-{}'.format(platform)), var=error)
                    add_key(key=get_status(
                        agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=error)

                    add_key(key='computer-os_type-all-all', var=error)
                    add_key(key='computer-os_type-{}-all'.format(os_type), var=error)
                    add_key(
                        key='computer-os_type-{}-{}'.format(os_type, platform), var=error)

                    add_key(
                        key='computer-agent_version-all-{}'.format(agent_version), var=error)
                    add_key(
                        key='computer-agent_version-{}-{}'.format(os_type, agent_version), var=error)
                    add_key(
                        key='computer-agent_version_major-all-{}'.format(agent_version_major), var=error)
                    add_key(key='computer-agent_version_major-{}-{}'.format(os_type,
                                                                            agent_version_major), var=error)

                    add_key(key=get_status(
                        am_status, 'module-am_status-all'), var=error)
                    add_key(key=get_status(
                        wr_status, 'module-wr_status-all'), var=error)
                    add_key(key=get_status(
                        fw_status, 'module-fw_status-all'), var=error)
                    add_key(key=get_status(
                        ip_status, 'module-ip_status-all'), var=error)
                    add_key(key=get_status(
                        im_status, 'module-im_status-all'), var=error)
                    add_key(key=get_status(
                        li_status, 'module-li_status-all'), var=error)

                    add_key(key=get_status(
                        am_status, 'module-am_status-{}'.format(os_type)), var=error)
                    add_key(key=get_status(
                        wr_status, 'module-wr_status-{}'.format(os_type)), var=error)
                    add_key(key=get_status(
                        fw_status, 'module-fw_status-{}'.format(os_type)), var=error)
                    add_key(key=get_status(
                        ip_status, 'module-ip_status-{}'.format(os_type)), var=error)
                    add_key(key=get_status(
                        im_status, 'module-im_status-{}'.format(os_type)), var=error)
                    add_key(key=get_status(
                        li_status, 'module-li_status-{}'.format(os_type)), var=error)

                    add_key(key='vulnerabilities-ips_rules-all-all-all',
                            var=error, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-all-all'.format(
                        os_type), var=error, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-all-{}-all'.format(
                        ips_status), var=error, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-all-all-{}'.format(
                        ips_mode), var=error, value=ips_rules)

                    add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                        os_type, ips_status), var=error, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                        os_type, ips_status, ips_mode), var=error, value=ips_rules)

                    add_key(key='vulnerabilities-ips_rules-all-{}-{}'.format(
                        ips_status, ips_mode), var=error, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-all-{}'.format(
                        os_type, ips_mode), var=error, value=ips_rules)
                except Exception as e:
                    logging.info('ds_summary active - critical|offline: {}'.format(e))

            else:
                try:
                    logging.debug(
                        'unknown computer: {}'.format(computer.host_name))
                    ips_rules_unknown_total += ips_rules

                    add_key(key=get_status(
                        agent_version, 'computer-platform-all-{}'.format(platform)), var=unknown)
                    add_key(key=get_status(
                        agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=unknown)

                    add_key(key='computer-os_type-all-all', var=unknown)
                    add_key(key='computer-os_type-{}-all'.format(os_type), var=unknown)
                    add_key(key='computer-os_type-{}-{}'.format(os_type,
                                                                platform), var=unknown)

                    add_key(
                        key='computer-agent_version-all-{}'.format(agent_version), var=unknown)
                    add_key(key='computer-agent_version-{}-{}'.format(os_type,
                                                                    agent_version), var=unknown)
                    add_key(
                        key='computer-agent_version_major-all-{}'.format(agent_version_major), var=unknown)
                    add_key(key='computer-agent_version_major-{}-{}'.format(os_type,
                                                                            agent_version_major), var=unknown)

                    add_key(key=get_status(
                        am_status, 'module-am_status-all'), var=unknown)
                    add_key(key=get_status(
                        wr_status, 'module-wr_status-all'), var=unknown)
                    add_key(key=get_status(
                        fw_status, 'module-fw_status-all'), var=unknown)
                    add_key(key=get_status(
                        ip_status, 'module-ip_status-all'), var=unknown)
                    add_key(key=get_status(
                        im_status, 'module-im_status-all'), var=unknown)
                    add_key(key=get_status(
                        li_status, 'module-li_status-all'), var=unknown)

                    add_key(key=get_status(
                        am_status, 'module-am_status-{}'.format(os_type)), var=unknown)
                    add_key(key=get_status(
                        wr_status, 'module-wr_status-{}'.format(os_type)), var=unknown)
                    add_key(key=get_status(
                        fw_status, 'module-fw_status-{}'.format(os_type)), var=unknown)
                    add_key(key=get_status(
                        ip_status, 'module-ip_status-{}'.format(os_type)), var=unknown)
                    add_key(key=get_status(
                        im_status, 'module-im_status-{}'.format(os_type)), var=unknown)
                    add_key(key=get_status(
                        li_status, 'module-li_status-{}'.format(os_type)), var=unknown)

                    add_key(key='vulnerabilities-ips_rules-all-all-all',
                            var=unknown, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-all-all'.format(
                        os_type), var=unknown, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-all-{}-all'.format(
                        ips_status), var=unknown, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-all-all-{}'.format(
                        ips_mode), var=unknown, value=ips_rules)

                    add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                        os_type, ips_status), var=unknown, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                        os_type, ips_status, ips_mode), var=unknown, value=ips_rules)

                    add_key(key='vulnerabilities-ips_rules-all-{}-{}'.format(
                        ips_status, ips_mode), var=unknown, value=ips_rules)
                    add_key(key='vulnerabilities-ips_rules-{}-all-{}'.format(
                        os_type, ips_mode), var=unknown, value=ips_rules)
                except Exception as e:
                    logging.info('ds_summary unknown - error: {}'.format(e))
    except Exception as e:
        logging.info('ds_summary - error: {}'.format(e))

    # print_dict(active, 'active')
    # print('active hosts: {}'.format(active_total))
    # print_dict(inactive, 'inactive')
    # print_dict(warning, 'warning')
    # print_dict(error, 'error')
    # print_dict(unknown, 'unknown')
    # print_dict(offline, 'offline')

    # print('total: {}'.format(total))
    logging.info(
        'total ips rules found - active agents: {}'.format(ips_rules_active_total))
    logging.info(
        'total ips rules found - inactive agents: {}'.format(ips_rules_inactive_total))
    logging.info(
        'total ips rules found - warning agents: {}'.format(ips_rules_warning_total))
    logging.info(
        'total ips rules found - error agents: {}'.format(ips_rules_error_total))
    logging.info(
        'total ips rules found - unknown agents: {}'.format(ips_rules_unknown_total))
    logging.info('total ips rules found: {}'.format(ips_rules_total))

    summary = {
        'timestamp': datetime.now(),
        'managed': active,
        'warning': warning,
        'unmanaged': inactive,
        'critical': error,
        'offline': offline,
        'unknown': unknown
    }
    logging.info('ds_summary: returning metrics')
    mgr.sign_out()
    return summary


logging.info('starting application: calling get_summary')
summary = get_summary()


def main():
    ''' Run the examples from the Create and Configure Policies guide

    Each function call passes the api client configuration information
    and any required variables and prints their output.
    '''
    # ds_summary()
    # ds_get()


if __name__ == '__main__':
    main()

