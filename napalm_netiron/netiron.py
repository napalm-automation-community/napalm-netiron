"""
NAPALM Brocade/Foundry netiron IOS Handler.

Note this port is based on the Cisco IOS handler.  The following copyright is from the napalm project:

# Copyright 2015 Spotify AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

Additionally, some code was taken from https://github.com/ckishimo/napalm-extreme-netiron/tree/master. Author
Carles Kishimoto carles.kishimoto@gmail.com contributed the following which have been modified as needed:
 - get_bgp_neighbors
 - get_environment
 - get_mac_address_table

"""


from __future__ import print_function
from __future__ import unicode_literals

import functools
import json
import re
import os
import uuid
import socket
import tempfile
import logging

from itertools import islice

from napalm_netiron.netiron_file_transfer import NetironFileTransfer

from netmiko import ConnectHandler, redispatch
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ReplaceConfigException, MergeConfigException, \
            ConnectionClosedException, CommandErrorException

from netaddr import IPAddress, IPNetwork
import napalm.base.helpers

from napalm.base.helpers import textfsm_extractor

import time

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX
IPV6_ADDR_REGEX_1 = r"::"
IPV6_ADDR_REGEX_2 = r"[0-9a-fA-F:]{1,39}::[0-9a-fA-F:]{1,39}"
IPV6_ADDR_REGEX_3 = r"[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:" \
                     "[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}"
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = "(?:{}|{}|{})".format(IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3)

MAC_REGEX = r"[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}"
VLAN_REGEX = r"\d{1,4}"
RE_IPADDR = re.compile(r"{}".format(IP_ADDR_REGEX))
RE_IPADDR_STRIP = re.compile(r"({})\n".format(IP_ADDR_REGEX))
RE_MAC = re.compile(r"{}".format(MAC_REGEX))

# Period needed for 32-bit AS Numbers
ASN_REGEX = r"[\d\.]+"

'''
Per netiron 5.9 docs:
maxttl value parameter is the maximum TTL (hops) value: Possible value is 1 - 255. The default is 30 seconds.
minttl value parameter is the minimum TTL (hops) value: Possible value is 1 - 255. The default is 1 second.
timeout value parameter specifies the possible values. Possible value range is 1 - 120. Default value is 2 seconds.

Use these defaults
'''
TRACEROUTE_TTL = 30
TRACEROUTE_SOURCE = ''
TRACEROUTE_TIMEOUT = 2
TRACEROUTE_NULL_HOST_NAME = '*'
TRACEROUTE_NULL_IP_ADDRESS = '*'
TRACEROUTE_VRF = ''

'''
Per netiron 5.9 docs:

- count num parameter specifies how many ping packets the device sends. 1-4294967296 . default is 1.
- timeout msec parameter specifies how many milliseconds the device waits for a reply from the pinged device.
    1 - 4294967296 milliseconds. The default is 5000 (5 seconds).
- ttl num parameter specifies the maximum number of hops. You can specify a TTL from 1 - 255. The default is 64.
- size byte parameter specifies the size of the ICMP data portion of the packet. This is the payload and does not
    include the header. 0 - 9170. The default is 16.
'''
PING_SOURCE = ''
PING_TTL = 64
PING_TIMEOUT = 2
PING_SIZE = 16
PING_COUNT = 1
PING_VRF = ''


SUPPORTED_ROUTING_PROTOCOLS = ['bgp']

logger = logging.getLogger(__name__)


class NetIronDriver(NetworkDriver):
    """NAPALM Brocade/Foundry netiron Handler."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """NAPALM Brocade/Foundry netiron Handler."""

        if optional_args is None:
            optional_args = {}

        # super(NetIronDriver, self).__init__(hostname, username, password, timeout=60, optional_args=None)

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        # default to MLX for now
        self.family = 'MLX'

        # tmp path
        self._tmp_working_path = optional_args.get('tmp_working_path', '/tmp')

        # uuid
        self._uuid = optional_args.get('uuid', uuid.uuid4())

        # support optional SSH proxy
        self._use_proxy = optional_args.pop('use_proxy', None)

        # Retrieve file names
        self.candidate_cfg = optional_args.pop('candidate_cfg', 'candidate_config.txt')
        self.merge_cfg = optional_args.pop('merge_cfg', 'merge_config.txt')
        self.rollback_cfg = optional_args.pop(
            'rollback_cfg',
            '{0}/{1}-{2}-rollback_config.cfg'.format(
                self._tmp_working_path, self.hostname, self._uuid))

        # None will cause auto detection of dest_file_system
        self._dest_file_system = optional_args.pop('dest_file_system', '/slot1')
        self.auto_rollback_on_error = optional_args.pop('auto_rollback_on_error', False)

        # Control automatic toggling of 'file prompt quiet' for file operations
        self.auto_file_prompt = optional_args.get('auto_file_prompt', True)

        # it appears that in some cases, devices that may be impacted by network delay, incrementing
        # the netmiko delay factor will help -- I found increasing the delay may help long-running
        # commands like 'show ip bgp neighbors'
        #
        # however, setting the delay global will slow down simple processing such as authentication
        # or finding the prompt -- these commands seem to work best with a delay factor of 1
        self._show_command_delay_factor = optional_args.pop('show_command_delay_factor', 1)

        # default to send_config_from_file(...) processing using slot1 if possible
        # if line_by_line_config is specified then config updates are send a line at a time
        # and lines are validated according to line_by_line_interval
        self._line_by_line_config = optional_args.pop('line_by_line_config', False)
        self._line_by_line_interval = optional_args.pop('line_by_line_interval', 50)

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'secret': '',
            'verbose': False,
            'keepalive': 30,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
            'allow_agent': False,
        }

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {}
        for k, v in netmiko_argument_map.items():
            try:
                self.netmiko_optional_args[k] = optional_args[k]
            except KeyError:
                pass

        self.port = optional_args.get('port', 22)
        self.device = None
        self.config_replace = False

        self.profile = ["netiron"]
        self.use_canonical_interface = optional_args.get('canonical_int', False)

        # merge candidate variables used when performing line-by-line merging
        self._current_merge_candidate = None
        self._current_merge_candidate_tmp_file = False

        # used to indicate is device has a slot or not
        self._has_slot = None

    def open(self):
        """Open a connection to the device."""
        device_type = 'brocade_netiron'

        if self._use_proxy:
            logger.info('{0}: using SSH proxy {1}'.format(self.hostname, self._use_proxy))

            self.device = ConnectHandler(
                device_type='terminal_server', host=self._use_proxy,
                username=self.username, password=self.password,
                **self.netmiko_optional_args)
            logger.debug('{0}: proxy prompt: ', self.hostname, self.device.find_prompt())

            _cmd = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null  -t -l {0} {1}\n'.format(
                self.username, self.hostname)
            logger.debug('{0}: proxy cmd: {1}'.format(self.hostname, _cmd))
            self.device.write_channel(_cmd)
            time.sleep(1)

            for t in range(0, 4):
                _output = self.device.read_channel()
                # print('output: [{0}]'.format(_output))
                if 'ssword' in _output:
                    self.device.write_channel(self.password + '\n')
                    time.sleep(2)
                    _output = self.device.read_channel()
                    break
                time.sleep(1)

            redispatch(self.device, device_type=device_type)
            # print('device: {0}'.format(self.device))
        else:
            self.device = ConnectHandler(
                device_type=device_type,
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                conn_timeout=10,
                **self.netmiko_optional_args)

        # ensure in enable mode
        self.device.enable()

    def close(self):
        """Close the connection to the device."""
        self.device.disconnect()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().

        If command is a list will iterate through commands until valid command.
        """
        try:
            output = ''
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "% Invalid" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return self._send_command_postprocess(output)
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        null = chr(0)
        _status = False

        if self.device:
            # SSH
            try:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.write_channel(null)
                _status = self.device.remote_conn.transport.is_active()
            except (socket.error, EOFError):
                # If unable to send, we can tell for sure that the connection is unusable
                pass
        return {'is_alive': _status}

    @property
    def has_slot(self):
        if not self._has_slot:
            if self._line_by_line_config:
                # override if line_by_line is specified
                self._has_slot = False
            else:
                # check if slot1 exists
                _result = self.device.send_command('dir /slot1')
                if 'File not found' in _result:
                    # no slot1 then fall-back to line_by_line
                    self._has_slot = False
                    self._line_by_line_config = True
                else:
                    self._has_slot = True

        return self._has_slot

    @staticmethod
    def _create_tmp_file(config):
        """Write temp file and for use with inline config and SCP."""
        tmp_dir = tempfile.gettempdir()
        rand_fname = py23_compat.text_type(uuid.uuid4())
        filename = os.path.join(tmp_dir, rand_fname)

        logger.info('filename: {}'.format(filename))
        # logger.info('config: {}'.format(config))
        with open(filename, 'wt') as fobj:
            fobj.write(config)
        return filename

    def _load_candidate_wrapper(self, source_file=None, source_config=None, dest_file=None,
                                file_system=None):
        """
        Transfer file to remote device for either merge or replace operations

        netiron does not support merging from flash into running-config. However, MLX devices
        do support merging slot1 or slot2 into running-config.

        The workaround for devices that do not support merging from slot[1,2]:
        - maintain state as instance variables
        - state is not maintained between instances
        - maintain the merge candidate local to the system running this instance
        - when commit_config is called simply send merge candidate line-by-line

        Returns (return_status, msg)
        """
        self._current_merge_candidate = None
        self._current_merge_candidate_tmp_file = False

        print('load_candidate_wrapper')
        return_status = False
        msg = ''
        if source_file and source_config:
            raise ValueError("Cannot simultaneously set source_file and source_config")

        if self._line_by_line_config:
            # device does NOT have slot1 or line_by_line was specified
            if source_config:
                # convert to CR delimited string if config is a list
                if isinstance(source_config, list):
                    source_config = '\n'.join(source_config)

                self._current_merge_candidate = self._create_tmp_file(source_config)
                self._current_merge_candidate_tmp_file = True
                logger.info('candidate: {}'.format(self._current_merge_candidate))
            if source_file:
                if not os.path.isfile(source_file):
                    raise MergeConfigException('File {} not found'.format(source_file))
                self._current_merge_candidate = source_file

            return_status = True
        else:
            # device has slot1 so use SCP

            if source_config:
                tmp_file = self._create_tmp_file(source_config)
                print(tmp_file)
                (return_status, msg) = self._scp_file(
                    source_file=tmp_file, dest_file=dest_file, file_system=file_system)

                # remove the temp file
                if tmp_file and os.path.isfile(tmp_file):
                    os.remove(tmp_file)

            else:
                (return_status, msg) = self._scp_file(
                    source_file=source_file, dest_file=dest_file, file_system=file_system)

            if not return_status:
                if msg == '':
                    msg = "Transfer to remote device failed"

        return (return_status, msg)

    def load_replace_candidate(self, filename=None, config=None):
        """
        In our case we do NOT ever want to perform a replacement
        """
        raise NotImplementedError('config replacement is not supported on Brocade devices')

    def load_merge_candidate(self, filename=None, config=None):
        """
        Create merge candidate
        """
        self.config_replace = False
        return_status, msg = self._load_candidate_wrapper(source_file=filename,
                                                          source_config=config,
                                                          dest_file=self.merge_cfg,
                                                          file_system=self.dest_file_system)
        if not return_status:
            raise MergeConfigException(msg)

    def _normalize_compare_config(self, diff):
        """Filter out strings that should not show up in the diff."""
        ignore_strings = ['Contextual Config Diffs', 'No changes were found',
                          'ntp clock-period']
        if self.auto_file_prompt:
            ignore_strings.append('file prompt quiet')

        new_list = []
        for line in diff.splitlines():
            for ignore in ignore_strings:
                if ignore in line:
                    break
            else:  # no break
                new_list.append(line)
        return "\n".join(new_list)

    @staticmethod
    def _normalize_merge_diff_incr(diff):
        """Make the compare config output look better.

        Cisco IOS incremental-diff output

        No changes:
        !List of Commands:
        end
        !No changes were found
        """
        new_diff = []

        changes_found = False
        for line in diff.splitlines():
            if re.search(r'order-dependent line.*re-ordered', line):
                changes_found = True
            elif 'No changes were found' in line:
                # IOS in the re-order case still claims "No changes were found"
                if not changes_found:
                    return ''
                else:
                    continue

            if line.strip() == 'end':
                continue
            elif 'List of Commands' in line:
                continue
            # Filter blank lines and prepend +sign
            elif line.strip():
                if re.search(r"^no\s+", line.strip()):
                    new_diff.append('-' + line)
                else:
                    new_diff.append('+' + line)
        return "\n".join(new_diff)

    @staticmethod
    def _normalize_merge_diff(diff):
        """Make compare_config() for merge look similar to replace config diff."""
        new_diff = []
        for line in diff.splitlines():
            # Filter blank lines and prepend +sign
            if line.strip():
                new_diff.append('+' + line)
        if new_diff:
            new_diff.insert(0, '! incremental-diff failed; falling back to echo of merge file')
        else:
            new_diff.append('! No changes specified in merge file.')
        return "\n".join(new_diff)

    def compare_config(self):
        """
        show archive config differences <base_file> <new_file>.

        Default operation is to compare system:running-config to self.candidate_cfg

        Brocade does NOT support archiving.  The only way to achieve this is to copy the config from the device,
        compare it to an stored archive.
        """
        '''
        # Set defaults
        base_file = 'running-config'
        base_file_system = 'system:'
        if self.config_replace:
            new_file = self.candidate_cfg
        else:
            new_file = self.merge_cfg
        new_file_system = self.dest_file_system

        base_file_full = self._gen_full_path(filename=base_file, file_system=base_file_system)
        new_file_full = self._gen_full_path(filename=new_file, file_system=new_file_system)

        if self.config_replace:
            cmd = 'show archive config differences {} {}'.format(base_file_full, new_file_full)
            diff = self.device.send_command_expect(cmd)
            diff = self._normalize_compare_config(diff)
        else:
            # merge
            cmd = 'show archive config incremental-diffs {} ignorecase'.format(new_file_full)
            diff = self.device.send_command_expect(cmd)
            if 'error code 5' in diff or 'returned error 5' in diff:
                diff = "You have encountered the obscure 'error 5' message. This generally " \
                       "means you need to add an 'end' statement to the end of your merge changes."
            elif '% Invalid' not in diff:
                diff = self._normalize_merge_diff_incr(diff)
            else:
                cmd = 'more {}'.format(new_file_full)
                diff = self.device.send_command_expect(cmd)
                diff = self._normalize_merge_diff(diff)

        return diff.strip()
        '''
        raise NotImplemented

    def _commit_hostname_handler(self, cmd):
        """Special handler for hostname change on commit operation."""
        current_prompt = self.device.find_prompt().strip()
        terminating_char = current_prompt[-1]
        pattern = r"[>#{}]\s*$".format(terminating_char)
        # Look exclusively for trailing pattern that includes '#' and '>'
        output = self.device.send_command_expect(cmd, expect_string=pattern)
        # Reset base prompt in case hostname changed
        self.device.set_base_prompt()
        return output

    def commit_config(self, message=""):
        """
        If replacement operation, perform 'configure replace' for the entire config.

        If merge operation, perform copy <file> running-config.
        """
        output = ''

        if self.config_replace:
            # Do NOT allow config replace
            raise ReplaceConfigException('config replace not supported')

        # Always generate a rollback config on commit
        # *** disabled rollback config generation, it will be up to the caller to gen a back-up
        # self._gen_rollback_cfg()

        if self._line_by_line_config:
            if not self._check_file_exists(self.dest_file_system, self.merge_cfg):
                raise MergeConfigException("Merge source config file does not exist")

            _merge_candidate = self._current_merge_candidate

            # get netmiko logger
            _log = logging.getLogger('netmiko')

            # apply merge candidate configuration
            try:
                self.device.config_mode()
                _commands = list()
                with open(_merge_candidate) as f:
                    while True:
                        lines = [l.strip() for l in islice(f, self._line_by_line_interval)]
                        if not lines:
                            break

                        # write up-to self._line_by_line_interval commands line by line
                        logger.info('{0} processing {1} lines'.format(self.hostname, len(lines)))
                        for line_num, cmd in enumerate(lines):
                            if 'hostname' in cmd:
                                # todo add logic to handle hostname change -- prompt will change after hostname change
                                logging.warn('line skipped: hostname change is not supported: {0}:{1}'.format(
                                    line_num, cmd))
                                continue

                            self.device.write_channel(self.device.normalize_cmd(cmd))
                            time.sleep(.5)

                        # Gather output
                        _output = self.device._read_channel_timing(delay_factor=1, max_loops=150)
                        logger.info('{0} processed {1} lines'.format(self.hostname, len(lines)))
                        _log.debug("{}".format(_output))

                        output += _output

                        if 'Invalid input ->' in _output:
                            # todo add roll back
                            raise ReplaceConfigException('Invalid Input Error: {0}'.format(_output.strip()))
                        elif 'Not authorized to execute this command.' in _output:
                            raise ReplaceConfigException('Not Authorized Error: {0}'.format(_output.strip()))

                if self.device.check_config_mode():
                    output += self.device.exit_config_mode()

            finally:
                # clear/release merge candidate
                if self._current_merge_candidate_tmp_file and self._current_merge_candidate \
                        and os.path.isfile(self._current_merge_candidate):
                    os.remove(self._current_merge_candidate)
                    self._current_merge_candidate = None

        else:
            # use slot

            if not self._check_file_exists(self.dest_file_system, self.merge_cfg):
                raise MergeConfigException("Merge source config file does not exist")

            _command = 'copy slot1 running-config {}'.format(self.merge_cfg)
            _result = self.device.send_command(_command)

            if 'Configuration is successfully updated' not in _result:
                _err_header = "Configuration merge failed; automatic rollback attempted"
                raise MergeConfigException("{0}:\n{1}".format(_err_header, _result))

        # Save config to startup (both replace and merge)
        self.device.clear_buffer()
        output += self.device.send_command_expect("write mem")

        return output

    def discard_config(self):
        """Discard loaded candidate configurations."""
        self._discard_config()

    def _discard_config(self):
        """Set candidate_cfg to current running-config. Erase the merge_cfg file."""
        self._current_merge_candidate = None
        self._current_merge_candidate_tmp_file = False

        if self.has_slot:
            discard_candidate = 'copy running-config slot1 {}'.format(self.candidate_cfg)
            discard_merge = 'delete slot1 {}'.format(self.merge_cfg)
            self.device.send_command_expect(discard_candidate)
            self.device.send_command_expect(discard_merge)

    def _scp_file(self, source_file, dest_file, file_system):
        """
        SCP file to remote device.

        Return (status, msg)
        status = boolean
        msg = details on what happened
        """
        return self._xfer_file(source_file=source_file, dest_file=dest_file,
                               file_system=file_system, transfer_class=NetironFileTransfer)

    def _xfer_file(self, source_file=None, source_config=None, dest_file=None, file_system=None,
                   transfer_class=NetironFileTransfer):

        """
        Transfer file to remote device.

        Return (status, msg)
        status = boolean
        msg = details on what happened
        """
        if not source_file and not source_config:
            raise ValueError("File source not specified for transfer.")

        if not dest_file or not file_system:
            raise ValueError("Destination file or file system not specified.")

        if source_file:
            kwargs = dict(ssh_conn=self.device, source_file=source_file, dest_file=dest_file,
                          direction='put', file_system=file_system)
        else:
            kwargs = dict(ssh_conn=self.device, source_config=source_config, dest_file=dest_file,
                          direction='put', file_system=file_system)

        with transfer_class(**kwargs) as transfer:
            print(type(transfer))
            # Check if file already exists Note Brocade doesn't support checksum or MD5 sum so if it
            # exists then raise an error as we have no way to determine if the content matches the
            # desired content
            if transfer.check_file_exists():
                return (False, "File already exists")

            if not transfer.verify_space_available():
                return (False, "Insufficient space available on remote device")

            show_cmd = "sh ip ssh config | include SCP"
            output = self.device.send_command_expect(show_cmd)
            if 'Enabled' not in output:
                msg = "SCP file transfers are not enabled. " \
                      "Configure 'ip ssh scp enable' on the device."
                raise CommandErrorException(msg)

            # Transfer file
            transfer.transfer_file()

            # brocade does NOT support a checksum or md5sum functions
            # simple check for the existence of the file and size
            if transfer.verify_file():
                msg = "File successfully transferred to remote device"
                return (True, msg)
            else:
                return (False, 'File transfer to remote device failed')
        return (False, '')

    def _check_file_exists(self, cfg_path, cfg_file):
        """
        Check that the file exists on remote device using full path.

        cfg_file is full path i.e. /flash/file_name

        For example
        dir /flash/merge_config.txt
        Directory of /flash/

        06/19/2018 18:52:52                      13 merge_config.txt

                         1 File(s)               13 bytes
                         0 Dir(s)         6,553,600 bytes free


        return boolean
        """

        cmd = 'dir {0}/{1}'.format(cfg_path, cfg_file)
        output = self.device.send_command_expect(cmd)
        logger.info('cmd: {0} output: {1}'.format(cmd, output))
        if 'Error opening' in output:
            return False
        elif cfg_file in output:
            return True
        return False

    @staticmethod
    def _send_command_postprocess(output):
        """
        Cleanup actions on send_command() for NAPALM getters.

        Remove "Load for five sec; one minute if in output"
        Remove "Time source is"
        """
        output = re.sub(r"^Load for five secs.*$", "", output, flags=re.M)
        output = re.sub(r"^Time source is .*$", "", output, flags=re.M)
        return output.strip()

    def get_optics(self):
        """
        Not implemented

        Brocade will likely require "show media" followed by "show optic <slot>" for each slot

        Optionally use snmp snIfOpticalMonitoringInfoTable - ifIndex to optical parameters table
        :return:
        """
        '''
        command = 'show interfaces transceiver'
        output = self._send_command(command)

        # Check if router supports the command
        if '% Invalid input' in output:
            return {}

        # Formatting data into return data structure
        optics_detail = {}

        try:
            split_output = re.split(r'^---------.*$', output, flags=re.M)[1]
        except IndexError:
            return {}

        split_output = split_output.strip()

        for optics_entry in split_output.splitlines():
            # Example, Te1/0/1      34.6       3.29      -2.0      -3.5
            try:
                split_list = optics_entry.split()
            except ValueError:
                return {}

            int_brief = split_list[0]
            output_power = split_list[3]
            input_power = split_list[4]

            port = canonical_interface_name(int_brief)

            port_detail = {}

            port_detail['physical_channels'] = {}
            port_detail['physical_channels']['channel'] = []

            # If interface is shutdown it returns "N/A" as output power.
            # Converting that to -100.0 float
            try:
                float(output_power)
            except ValueError:
                output_power = -100.0

            # Defaulting avg, min, max values to -100.0 since device does not
            # return these values
            optic_states = {
                'index': 0,
                'state': {
                    'input_power': {
                        'instant': (float(input_power) if 'input_power' else -100.0),
                        'avg': -100.0,
                        'min': -100.0,
                        'max': -100.0
                    },
                    'output_power': {
                        'instant': (float(output_power) if 'output_power' else -100.0),
                        'avg': -100.0,
                        'min': -100.0,
                        'max': -100.0
                    },
                    'laser_bias_current': {
                        'instant': 0.0,
                        'avg': 0.0,
                        'min': 0.0,
                        'max': 0.0
                    }
                }
            }

            port_detail['physical_channels']['channel'].append(optic_states)
            optics_detail[port] = port_detail

        return optics_detail
        '''
        raise NotImplementedError

    def get_facts(self):
        """get_facts method."""
        uptime = None
        vendor = 'Brocade'
        model = None
        hostname = None
        version = 'netiron'
        serial = None

        command = 'show version'
        lines = self.device.send_command_timing(command, delay_factor=self._show_command_delay_factor)
        for line in lines.splitlines():
            r1 = re.match(r'^(System|Chassis):\s+(.*)\s+\(Serial #:\s+(\S+),(.*)', line)
            if r1:
                model = r1.group(2)
                serial = r1.group(3)

            r2 = re.match(r'^IronWare : Version\s+(\S+)\s+Copyright \(c\)\s+(.*)', line)
            if r2:
                version = r2.group(1)
                vendor = r2.group(2)

        command = 'show uptime'
        lines = self.device.send_command_timing(command, delay_factor=self._show_command_delay_factor)
        for line in lines.splitlines():
            # Get the uptime from the Active MP module
            r1 = re.match(r'\s+Active MP(.*)Uptime\s+(\d+)\s+days'
                          r'\s+(\d+)\s+hours'
                          r'\s+(\d+)\s+minutes'
                          r'\s+(\d+)\s+seconds', line)
            if r1:
                days = int(r1.group(2))
                hours = int(r1.group(3))
                minutes = int(r1.group(4))
                seconds = int(r1.group(5))
                uptime = seconds + minutes*60 + hours*3600 + days*86400

        # the following is expensive -- should use SNMP GET instead
        command = 'show running-config | include ^hostname'
        lines = self.device.send_command(command, delay_factor=self._show_command_delay_factor)
        for line in lines.splitlines():
            r1 = re.match(r'^hostname (\S+)', line)
            if r1:
                hostname = r1.group(1)

        facts = {
            'uptime': uptime,
            'vendor': str(vendor),
            'model': str(model),
            'hostname': str(hostname),
            # FIXME: fqdn
            'fqdn': str("Unknown"),
            'os_version': str(version),
            'serial_number': str(serial),
            'interface_list': []
        }

        iface = 'show interface brief wide'
        output = self.device.send_command_timing(iface, delay_factor=self._show_command_delay_factor)
        output = output.split('\n')
        output = output[2:]

        for line in output:
            fields = line.split()

            if len(line) == 0:
                continue
            elif len(fields) >= 6:
                port, link, state, speed, tag, mac = fields[:6]

                r1 = re.match(r'^(\d+)/(\d+)', port)
                if r1:
                    facts['interface_list'].append(port)
                elif re.match(r'^mgmt1', port):
                    facts['interface_list'].append(port)
                elif re.match(r'^ve(\d+)', port):
                    facts['interface_list'].append(port)
                elif re.match(r'^lb(\d+)', port):
                    facts['interface_list'].append(port)

        return facts

    @staticmethod
    def __parse_port_change__(last_str):
        r1 = re.match("(\d+) days (\d+):(\d+):(\d+)", last_str)
        if r1:
            days = int(r1.group(1))
            hours = int(r1.group(2))
            mins = int(r1.group(3))
            secs = int(r1.group(4))

            return float(secs + (mins * 60) + (hours * 60 * 60) + (days * 24 * 60 * 60))
        else:
            return float(-1.0)

    def _get_interface_detail(self, port):
        description = None
        mac = None
        if port == "mgmt1":
            command = "show interface management1"
        else:
            command = "show interface ethernet {}".format(port)
        output = self.device.send_command(command, delay_factor=self._show_command_delay_factor)
        output = output.split('\n')

        last_flap = "0.0"
        speed = "0"
        for line in output:
            # Port state change is only supported from >5.9? (no support in 5.7b)
            r0 = re.match(r"\s+Port state change time: \S+\s+\d+\s+\S+\s+\((.*) ago\)", line)
            if r0:
                last_flap = self.__class__.__parse_port_change__(r0.group(1))
            r1 = re.match(r"\s+No port name", line)
            if r1:
                description = ""
            r2 = re.match(r"\s+Port name is (.*)", line)
            if r2:
                description = r2.group(1)
            r3 = re.match(r"\s+Hardware is \S+, address is (\S+) (.+)", line)
            if r3:
                mac = r3.group(1)
            # Empty modules may not report the speed
            # Configured fiber speed auto, configured copper speed auto
            # actual unknown, configured fiber duplex fdx, configured copper duplex fdx, actual unknown
            r4 = re.match(r"\s+Configured speed (\S+),.+", line)
            if r4:
                speed = r4.group(1)
                if 'auto' in speed:
                    speed = -1
                else:
                    r = re.match(r'(\d+)([M|G])bit', speed)
                    if r:
                        speed = r.group(1)
                        if r.group(2) == 'M':
                            speed = int(speed) * 1000
                        elif r.group(2) == 'G':
                            speed = int(speed) * 1000000

        return [last_flap, description, speed, mac]

    def get_interfaces(self):
        """get_interfaces method."""
        output = self.device.send_command_timing('show interface brief wide', delay_factor=self._show_command_delay_factor)
        info = textfsm_extractor(
            self, "show_interface_brief_wide", output
        )

        result = {}
        for interface in info:
            port = interface['port']

            # Convert lbX to loopbackX
            port = re.sub('^lb(\d+)$', 'loopback\\1', port)

            # Convert speeds to MB/s
            speed = interface['speed']
            SPEED_REG = r'^(?P<number>\d+)(?P<unit>\S)$'
            speed_m = re.match(SPEED_REG, speed)
            if speed_m:
                if speed_m.group('unit') == 'M':
                    speed = int(int(speed_m.group('number')))
                elif speed_m.group('unit') == 'G':
                    speed = int(int(speed_m.group('number')) * 10E2)

            result[port] = {
                'is_up': interface['link'] == 'Up',
                'is_enabled': interface['link'] != 'Disabled',
                'description': interface['name'],
                'last_flapped': -1,
                'speed': speed,
                'mac_address': interface['mac'],
            }

        return result

    def get_interfaces_ip(self):
        """get_interfaces_ip method."""
        interfaces = {}

        command = 'show ip interface'
        output = self.device.send_command_timing(command, delay_factor=self._show_command_delay_factor)
        output = output.splitlines()
        output = output[1:]

        for line in output:
            fields = line.split()
            if len(fields) >= 8:
                iface, ifaceid, address, ok, nvram, status, protocol, vrf = fields[0:8]
                port = iface + ifaceid
                if port not in interfaces:
                    interfaces[port] = dict()

                interfaces[port]['ipv4'] = dict()
                interfaces[port]['ipv4'][address] = dict()

        # Get the prefix from the running-config interface in a single call
        iface = ""
        show_command = "show running-config interface"
        interface_output = self.device.send_command_timing(show_command, delay_factor=self._show_command_delay_factor)
        for line in interface_output.splitlines():
                r1 = re.match(r'^interface\s+(ethernet|ve|mgmt|management|loopback)\s+(\S+)\s*$', line)
                if r1:
                    port = r1.group(1)
                    if port == "ethernet":
                        port = "eth"
                    elif port == "management":
                        port = "mgmt"
                    iface = port + r1.group(2)

                if 'ip address ' in line and iface in interfaces.keys():
                    fields = line.split()
                    # ip address a.b.c.d/x ospf-ignore|ospf-passive|secondary
                    if len(fields) in [3, 4]:
                        address, subnet = fields[2].split(r'/')
                        interfaces[iface]['ipv4'][address] = {'prefix_length': subnet}

        command = 'show ipv6 interface'
        output = self.device.send_command_timing(command)
        output = output.splitlines()
        output = output[1:]

        port = ""
        for line in output:
            r1 = re.match(r'^(\S+)\s+(\S+).*fe80::(\S+).*', line)
            if r1:
                port = r1.group(1) + r1.group(2)
                address = "fe80::" + r1.group(3)
                if port not in interfaces:
                    # Interface with ipv6 only configuration
                    interfaces[port] = dict()

                interfaces[port]['ipv6'] = dict()
                interfaces[port]['ipv6'][address] = dict()
                interfaces[port]['ipv6'][address] = {'prefix_length': '64'}

            # Avoid matching: fd01:1458:300:2d::/64[Anycast]
            r2 = re.match(r'\s+(\S+)\/(\d+)\s*$', line)
            if r2:
                address = r2.group(1)
                subnet = r2.group(2)
                interfaces[port]['ipv6'][address] = {'prefix_length': subnet}

        return interfaces

    def get_interfaces_mode(self):
        interface_output = self.device.send_command_timing('show int brief wide', delay_factor=self._show_command_delay_factor)
        info = textfsm_extractor(
            self, "show_interface_brief_wide", interface_output
        )

        return {
            'tagged': [i['port'] for i in info if i['tag'] == 'Yes'],
            'untagged': [i['port'] for i in info if i['tag'] == 'No' or re.match(r'^ve', i['port'])],
        }

    def get_vlans(self):
        vlans_output = self.device.send_command('show running-config vlan')
        info = textfsm_extractor(
            self, "show_running_config_vlan", vlans_output
        )

        result = {}
        for vlan in info:
            if vlan['vlan'] == '':
                print(vlan)
            result[vlan['vlan']] = {
                'name': vlan['name'],
                'interfaces': self.interface_list_conversation(
                    vlan['ve'],
                    vlan['taggedports'],
                    vlan['untaggedports']
                )
            }
        return result

    def interface_list_conversation(self, ve, taggedports, untaggedports):
        interfaces = []
        if ve:
            interfaces.append('ve{}'.format(ve))
        if taggedports:
            interfaces.extend(self.interfaces_to_list(taggedports))
        if untaggedports:
            interfaces.extend(self.interfaces_to_list(untaggedports))
        return interfaces

    def interfaces_to_list(self, interfaces_string):
        ''' Convert string like 'ethe 2/1 ethe 2/4 to 2/5' to list of interfaces '''
        interfaces = []

        sections = interfaces_string.split('ethe')
        if '' in sections:
            sections.remove('') # Remove empty list items
        for section in sections:
            section = section.strip() # Remove leading/trailing spaces

            # Process sections like 2/4 to 2/6
            if 'to' in section:
                start_intf, end_intf = section.split(' to ')
                slot, num = start_intf.split('/')
                slot, end_num = end_intf.split('/')
                num = int(num)
                end_num = int(end_num)

                while num <= end_num:
                    intf_name = '{}/{}'.format(slot, num)
                    interfaces.append(intf_name)
                    num += 1

            # Individual ports like '2/1'
            else:
                interfaces.append(section)

        return interfaces



    @staticmethod
    def bgp_time_conversion(bgp_uptime):
        """
        Convert string time to seconds.

        Examples
        00:14:23
        00:13:40
        00:00:21
        00:00:13
        00:00:49
        1d11h
        1d17h
        1w0d
        8w5d
        1y28w
        never
        """
        bgp_uptime = bgp_uptime.strip()
        uptime_letters = set(['w', 'h', 'd'])

        if 'never' in bgp_uptime:
            return -1
        elif ':' in bgp_uptime:
            times = bgp_uptime.split(":")
            times = [int(x) for x in times]
            hours, minutes, seconds = times
            return (hours * 3600) + (minutes * 60) + seconds
        # Check if any letters 'w', 'h', 'd' are in the time string
        elif uptime_letters & set(bgp_uptime):
            form1 = r'(\d+)d(\d+)h'  # 1d17h
            form2 = r'(\d+)w(\d+)d'  # 8w5d
            form3 = r'(\d+)y(\d+)w'  # 1y28w
            match = re.search(form1, bgp_uptime)
            if match:
                days = int(match.group(1))
                hours = int(match.group(2))
                return (days * DAY_SECONDS) + (hours * 3600)
            match = re.search(form2, bgp_uptime)
            if match:
                weeks = int(match.group(1))
                days = int(match.group(2))
                return (weeks * WEEK_SECONDS) + (days * DAY_SECONDS)
            match = re.search(form3, bgp_uptime)
            if match:
                years = int(match.group(1))
                weeks = int(match.group(2))
                return (years * YEAR_SECONDS) + (weeks * WEEK_SECONDS)
        raise ValueError("Unexpected value for BGP uptime string: {}".format(bgp_uptime))

    def get_bgp_route(self, prefix):
        """
        Execute show ip[v6] bgp route <prefix> and return the output in a dictionary format

        {
          "ip_version": 4,
          "prefix": "47.186.1.43",
          "routes": [
            {
              "index": "1",
              "local_pref": "320",
              "med": "0",
              "next_hop": "74.43.96.220",
              "prefix": "47.184.0.0/14",
              "status": "BE",
              "weight": "0"
            },
            ...

        :param prefix: IPv6 or IPv6 prefix in CIDR notation
        :return: dictionary of route info on success or error message on error/no route found
        """
        _prefix_net = IPNetwork(prefix)
        if not _prefix_net:
            raise ValueError('prefix must be a valid prefix')

        command = 'show ip{0} bgp route {1}'.format('' if _prefix_net.version == 4 else 'v6', prefix)
        _lines = self.device.send_command(command)

        _routes = list()
        _last_update = None
        _num_paths_installed = None

        # if no routes found; simply return error
        r1 = re.search(r'None of the BGP4 routes match the display condition', _lines, re.MULTILINE)
        if r1:
            return {'error': 'No matching BGP routes found'}

        for line in _lines.splitlines():

            r2 = re.match(r'^\s*AS_PATH:\s+(?P<path>(.*))', line)
            if r2 and r1:
                _routes.append({
                    'index': r1.group('index'),
                    'prefix': r1.group('prefix'),
                    'next_hop': r1.group('next_hop'),
                    'med': r1.group('med'),
                    'local_pref': r1.group('local_pref'),
                    'weight': r1.group('weight'),
                    'status': r1.group('status'),
                    'best': True if 'B' in r1.group('status') else False,
                    'as_path': r2.group('path').split()
                })
                r1 = None
                continue

            r1 = re.match(r'^(?P<index>(\d+))\s+(?P<prefix>\S+)\s+(?P<next_hop>\S+)'
                          r'\s+(?P<med>\d+)\s+(?P<local_pref>\d+)\s+(?P<weight>\d+)\s+(?P<status>\S+)', line)
            if r1:
                continue

            r3 = re.match(r'^\s+Last update.*table:\s+(?P<last_update>(\S+)),\s+(?P<paths>\d+)\s+', line)
            if r3:
                _last_update = r3.group('last_update')
                _num_paths_installed = r3.group('paths')
                continue

        return {
            'success': {
                'prefix': prefix,
                'ip_version': _prefix_net.version,
                'routes': _routes,
                'routing_table': {'last_update': _last_update, 'paths_installed': _num_paths_installed},
            }
        }

    def get_route_to(self, destination='', protocol=''):
        """
        Returns a dictionary of dictionaries containing details of all available routes to a
        destination.

        Note that currently only routing protocol 'bgp' is supported.

        :param destination: The destination prefix to be used when filtering the routes.
        :param protocol: (optional) Retrieve the routes only for a specific protocol.

        Each inner dictionary contains the following fields:

            * protocol (string)
            * current_active (True/False)
            * last_active (True/False)
            * age (int)
            * next_hop (string)
            * outgoing_interface (string)
            * selected_next_hop (True/False)
            * preference (int)
            * inactive_reason (string)
            * routing_table (string)
            * protocol_attributes (dictionary)

        protocol_attributes is a dictionary with protocol-specific information, as follows:

        - BGP
            * local_as (int)
            * remote_as (int)
            * peer_id (string)
            * as_path (string)
            * communities (list)
            * local_preference (int)
            * preference2 (int)
            * metric (int)
            * metric2 (int)
        - ISIS:
            * level (int)

        Example::

            {
                "1.0.0.0/24": [
                    {
                        "protocol"          : u"BGP",
                        "inactive_reason"   : u"Local Preference",
                        "last_active"       : False,
                        "age"               : 105219,
                        "next_hop"          : u"172.17.17.17",
                        "selected_next_hop" : True,
                        "preference"        : 170,
                        "current_active"    : False,
                        "outgoing_interface": u"ae9.0",
                        "routing_table"     : "inet.0",
                        "protocol_attributes": {
                            "local_as"          : 13335,
                            "as_path"           : u"2914 8403 54113 I",
                            "communities"       : [
                                u"2914:1234",
                                u"2914:5678",
                                u"8403:1717",
                                u"54113:9999"
                            ],
                            "preference2"       : -101,
                            "remote_as"         : 2914,
                            "local_preference"  : 100
                        }
                    }
                ]
            }
        """

        protocol = protocol.lower()
        if protocol != 'bgp':
            raise ValueError('unsupported routing protocol: {0}'.format(protocol))

        _prefix_net = IPNetwork(destination)
        if not _prefix_net:
            raise ValueError('prefix must be a valid prefix')

        command = 'show ip{0} bgp route {1}'.format('' if _prefix_net.version == 4 else 'v6', destination)
        logger.info(command)
        _lines = self.device.send_command(command)
        logger.info(_lines)

        _routes = list()
        _last_update = None
        _num_paths_installed = None

        # if no routes found; simply return error
        r1 = re.search(r'None of the BGP4 routes match the display condition', _lines, re.MULTILINE)
        if r1:
            return {'error': 'No matching BGP routes found'}

        _r1v6 = None
        _previous_line = None
        for line in _lines.splitlines():
            if _r1v6:
                # v6 is rendered differently than v4 -- v6 splits prefix info into (2) lines
                # if _rlv6 is True then the 1st line containing index, prefix and next_hop was matched
                # on the previous line
                #
                # join previous line and current line and perform r1 match
                line = '{0} {1}'.format(_previous_line, line)
                r1 = re.match(r'^(?P<index>(\d+))\s+(?P<prefix>\S+)\s+(?P<next_hop>\S+)'
                              r'\s+(?P<med>\d+)\s+(?P<local_pref>\d+)\s+(?P<weight>\d+)\s+(?P<status>\S+)', line)
                _r1v6 = None

            _previous_line = line

            r2 = re.match(r'^\s*AS_PATH:\s+(?P<path>(.*))', line)
            if r2 and r1:
                _status = r1.group('status')
                _active = True if 'B' in _status else False
                _routes.append({
                    'protocol': 'eBGP' if 'E' in _status else 'iBGP',
                    'inactive_reason': 'n/a',
                    'age': 0,
                    'routing_table': 'default',
                    'next_hop': r1.group('next_hop'),
                    'outgoing_interface': None,
                    'preference': 20 if 'E' in _status else 200,
                    'current_active': _active,
                    'selected_next_hop': _active,
                    'protocol_attributes': {
                        'local_preference': r1.group('local_pref'),
                        'remote_as': 'n/a',
                        'communities': [],
                        'preference2': 0,
                        'metric': napalm_base.helpers.convert(int, r1.group('med'), 0),
                        'weight': napalm_base.helpers.convert(int, r1.group('weight'), 0),
                        'status': r1.group('status'),
                        'local_as': 22822,
                        'as_path': r2.group('path').split(),
                        'remote_address': r1.group('next_hop')
                    }
                })
                r1 = None
                _r1v6 = None
                continue

            r1 = re.match(r'^(?P<index>(\d+))\s+(?P<prefix>\S+)\s+(?P<next_hop>\S+)'
                          r'\s+(?P<med>\d+)\s+(?P<local_pref>\d+)\s+(?P<weight>\d+)\s+(?P<status>\S+)', line)

            if not r1 and _prefix_net.version == 6:
                # brocade renders differently for v6 than it does for v4 -- this is likely due to the length
                # difference between a v4 and v6 address
                # brocade renders v6 prefix over (2) lines.  The 1st line has prefix and next-hop where
                # the 2nd line has MED, LocPref...
                #        Prefix             Next Hop        MED        LocPrf     Weight Status
                # 1      2001:200:900::/40  2001:de8:8::2907:1
                #                                           0          320        0      BI
                #
                # if r1 didn't match try matching just index, prefix and next_hop
                _r1v6 = re.match(r'^(?P<index>(\d+))\s+(?P<prefix>\S+)\s+(?P<next_hop>\S+)', line)

        return {
            destination: _routes
        }

    def __get_bgp_route_stats__(self, remote_addr):

        afi = "ipv4" if remote_addr.version == 4 else 'ipv6'
        command = 'show ip{0} bgp neighbors {1} routes-summary'.format(
            '' if remote_addr.version == 4 else 'v6', str(remote_addr))
        _lines = self.device.send_command(command, delay_factor=self._show_command_delay_factor)
        _lines += _lines + '\n' if _lines else ''

        _stats = {
            'received_prefixes': -1,
            'accepted_prefixes': -1,
            'filtered_prefixes': -1,
            'sent_prefixes': -1,
            'to_send_prefixes': -1
        }

        for line in _lines.splitlines():
            r1 = re.match(r'^Routes Accepted/Installed:\s*(?P<accepted_prefixes>\d+),\s+'
                          r'Filtered/Kept:\s*(?P<filtered_kept>\d+),\s+'
                          r'Filtered:\s*(?P<filtered_prefixes>\d+)', line)
            if r1:
                _received_prefixes = int(r1.group('accepted_prefixes')) + int(r1.group('filtered_prefixes'))
                _stats['received_prefixes'] = _received_prefixes
                _stats['accepted_prefixes'] = r1.group('accepted_prefixes')
                _stats['filtered_prefixes'] = r1.group('filtered_prefixes')

            r2 = re.match(r'^Routes Advertised:\s*(?P<sent_prefixes>\d+),\s+'
                          r'To be Sent:\s*(?P<to_be_sent>\d+),\s+'
                          r'To be Withdrawn:\s*(?P<to_be_withdrawn>\d+)', line)
            if r2:
                _stats['sent_prefixes'] = r2.group('sent_prefixes')
                _stats['to_send_prefixes'] = r2.group('to_be_sent')

        return {afi: _stats}

    def get_bgp_neighbors(self):
        """
        Retrieve BGP neighbors.

        FIXME: No VRF support
        :return: dict()
        """
        bgp_data = dict()
        bgp_data['global'] = dict()
        bgp_data['global']['peers'] = dict()

        lines_summary = ''
        lines_neighbors = ''

        _stat_errors = dict()

        # retrieve both v4 and v6 BGP summary and neighbors
        for v in [4, 6]:
            command = 'show ip{0} bgp summary'.format('' if v == 4 else 'v6')
            _lines = self.device.send_command(command)
            lines_summary += _lines + '\n' if _lines else ''

            command = 'show ip{0} bgp neighbors'.format('' if v == 4 else 'v6')
            _lines = self.device.send_command(command)
            lines_neighbors += _lines + '\n' if _lines else ''

        local_as = 0
        for line in lines_summary.splitlines():
            r1 = re.match(r'^\s+Router ID:\s+(?P<router_id>({}))\s+'
                          r'Local AS Number:\s+(?P<local_as>({}))'.format(IPV4_ADDR_REGEX, ASN_REGEX), line)
            if r1:
                # FIXME: Use AS numbers check: napalm_base.helpers.as_number
                router_id = r1.group('router_id')
                local_as = r1.group('local_as')
                # FIXME check the router_id looks like an ipv4 address
                # router_id = napalm_base.helpers.ip(router_id, version=4)
                bgp_data['global']['router_id'] = router_id
                continue

            # Neighbor Address  AS#         State   Time          Rt:Accepted Filtered Sent     ToSend
            # 12.12.12.12       513         ESTAB   587d7h24m    0           0        255      0
            # NOTE: uptime is not always a single string!
            r2 = re.match(
                r'^\s+(?P<remote_addr>({}|{}))\s+(?P<remote_as>({}))\s+(?P<state>\S+)\s+'
                r'(?P<uptime>.+)'
                r'\s\s+(?P<accepted_prefixes>\d+)'
                r'\s+(?P<filtered_prefixes>\d+)'
                r'\s+(?P<sent_prefixes>\d+)'
                r'\s+(?P<tosend_prefixes>\d+)'.format(
                    IPV4_ADDR_REGEX, IPV6_ADDR_REGEX, ASN_REGEX), line)
            if r2:
                remote_addr = napalm_base.helpers.IPAddress(r2.group('remote_addr'))

                afi = "ipv4" if remote_addr.version == 4 else 'ipv6'
                received_prefixes = int(r2.group('accepted_prefixes'))+int(r2.group('filtered_prefixes'))
                bgp_data['global']['peers'][str(remote_addr)] = {
                        'local_as': local_as,
                        'remote_as': r2.group('remote_as'),
                        'address_family': {
                            afi: {
                                 'received_prefixes': received_prefixes,
                                 'accepted_prefixes': r2.group('accepted_prefixes'),
                                 'filtered_prefixes': r2.group('filtered_prefixes'),
                                 'sent_prefixes': r2.group('sent_prefixes'),
                                 'to_send_prefixes': r2.group('tosend_prefixes')
                            }
                        }
                }
                continue

            # There is a case where brocade's formatting doesn't account for overruns and numbers are displayed
            # without a space between fields:
            # 2607:f4e8::26             22822       ESTAB   349d16h40m    1466        1191838648268     0
            # in this case just grab the 1st (4) fields and add the remote_addr to the _stats_error dict
            r2 = re.match(
                r'^\s+(?P<remote_addr>({}|{})\s+(?P<remote_as>({}))\s+(?P<state>\S+)\s+'
                r'(?P<uptime>.+)\s'.format(
                    IPV4_ADDR_REGEX, IPV6_ADDR_REGEX, ASN_REGEX), line)
            if r2:
                logger.info('brocade overflow bug: line: {}'.format(line))
                logger.info(r2.group())
                try:
                    remote_addr = napalm_base.helpers.IPAddress(r2.group('remote_addr'))
                    bgp_data['global']['peers'][str(remote_addr)] = {
                        'local_as': local_as,
                        'remote_as': r2.group('remote_as'),
                        'address_family': self.__get_bgp_route_stats__(remote_addr)
                    }
                except Exception as ex:
                    logger.warn('unable to process overflow bug line: {}'.format(ex))

        # pprint.pprint(bgp_data)

        current = ""
        for line in lines_neighbors.splitlines():
            r1 = re.match(r'^\d+\s+IP Address:\s+(?P<remote_addr>\S+),'
                          r'\s+AS:\s+(?P<remote_as>({}))'
                          r'\s+\((IBGP|EBGP)\), RouterID:\s+(?P<remote_id>({})),'
                          r'\s+VRF:\s+(?P<vrf_name>\S+)'.format(ASN_REGEX, IPV4_ADDR_REGEX), line)
            if r1:
                remote_addr = r1.group('remote_addr')

                if remote_addr not in bgp_data['global']['peers']:
                    print('{0} not found'.format(remote_addr))
                    continue

                # if remote_addr in bgp_data['global']['peers']:
                #    raise ValueError('%s already exists'.format(remote_addr))

                # pprint.pprint(remote_addr)
                remote_id = r1.group('remote_id')
                bgp_data['global']['peers'][remote_addr]['remote_as'] = r1.group('remote_as')
                bgp_data['global']['peers'][remote_addr]['remote_id'] = remote_id
                current = remote_addr

            r2 = re.match(r'\s+Description:\s+(.*)', line)
            if r2:
                description = r2.group(1)
                # pprint.pprint(description)
                bgp_data['global']['peers'][current]['description'] = description

            # line:    State: ESTABLISHED, Time: 587d7h24m52s, KeepAliveTime: 10, HoldTime: 30
            r3 = re.match(r'\s+State:\s+(\S+),\s+Time:\s+(\S+),'
                          r'\s+KeepAliveTime:\s+(\d+),'
                          r'\s+HoldTime:\s+(\d+)', line)
            if r3:
                state = r3.group(1)

                bgp_data['global']['peers'][current]['state'] = state
                bgp_data['global']['peers'][current]['is_up'] = True if 'ESTABLISHED' in state else False
                bgp_data['global']['peers'][current]['is_enabled'] = False if 'ADMIN_SHUTDOWN' in state else True
                bgp_data['global']['peers'][current]['uptime'] = r3.group(2)

        return bgp_data

    def get_bgp_neighbors_detail(self, neighbor_address=''):
        """
        This code is based on the napalm.eos.get_bgp_neighbors_detail with a few variations to address
        netiron specifics

        Note that VRF support is not implemented
        :param neighbor_address: neighbor address (defaults to all if not specified)
        :return dictionary of neighbor data keyed by AS
        """

        def __process_bgp_summary_data__(lines_summary):
            """
            Process BGP summary data
            Args:
                lines_summary (str):

            Returns:
                bgp_data (dict):
            """

            bgp_data = dict()
            bgp_data['global'] = dict()
            bgp_data['global']['peers'] = dict()

            local_as = 0
            for line in lines_summary.splitlines():
                r1 = re.match(r'^\s+Router ID:\s+(?P<router_id>({}))\s+'
                              r'Local AS Number:\s+(?P<local_as>({}))'.format(IPV4_ADDR_REGEX, ASN_REGEX), line)
                if r1:
                    # FIXME: Use AS numbers check: napalm_base.helpers.as_number
                    router_id = r1.group('router_id')
                    local_as = r1.group('local_as')
                    # FIXME check the router_id looks like an ipv4 address
                    # router_id = napalm_base.helpers.ip(router_id, version=4)
                    bgp_data['global']['router_id'] = router_id
                    continue

                # Neighbor Address  AS#         State   Time          Rt:Accepted Filtered Sent     ToSend
                # 12.12.12.12       513         ESTAB   587d7h24m    0           0        255      0
                # NOTE: uptime is not always a single string!
                r2 = re.match(
                    r'^\s+(?P<remote_addr>({}|{}))\s+(?P<remote_as>({}))\s+(?P<state>\S+)\s+'
                    r'(?P<uptime>.+)'
                    r'\s\s+(?P<accepted_prefixes>\d+)'
                    r'\s+(?P<filtered_prefixes>\d+)'
                    r'\s+(?P<sent_prefixes>\d+)'
                    r'\s+(?P<tosend_prefixes>\d+)'.format(
                        IPV4_ADDR_REGEX, IPV6_ADDR_REGEX, ASN_REGEX), line)
                if r2:
                    remote_addr = napalm_base.helpers.IPAddress(r2.group('remote_addr'))

                    afi = "ipv4" if remote_addr.version == 4 else 'ipv6'
                    received_prefixes = int(r2.group('accepted_prefixes')) + int(r2.group('filtered_prefixes'))
                    bgp_data['global']['peers'][str(remote_addr)] = {
                        'local_as': local_as,
                        'remote_as': r2.group('remote_as'),
                        'address_family': {
                            afi: {
                                'received_prefixes': received_prefixes,
                                'accepted_prefixes': r2.group('accepted_prefixes'),
                                'filtered_prefixes': r2.group('filtered_prefixes'),
                                'sent_prefixes': r2.group('sent_prefixes'),
                                'to_send_prefixes': r2.group('tosend_prefixes')
                            }
                        }
                    }
                    continue

                # There is a case where brocade's formatting doesn't account for overruns and numbers are displayed
                # without a space between fields:
                # 2607:f4e8::26             22822       ESTAB   349d16h40m    1466        1191838648268     0
                # in this case just grab the 1st (4) fields and add the remote_addr to the _stats_error dict
                r2 = re.match(
                    r'^\s+(?P<remote_addr>({}|{}))\s+(?P<remote_as>({}))\s+(?P<state>\S+)\s+'
                    r'(?P<uptime>.+)\s'.format(
                        IPV4_ADDR_REGEX, IPV6_ADDR_REGEX, ASN_REGEX), line)
                if r2:
                    logger.info('brocade overflow bug: line: {}'.format(line))
                    logger.info(r2.group())
                    try:
                        remote_addr = napalm_base.helpers.IPAddress(r2.group('remote_addr'))
                        bgp_data['global']['peers'][str(remote_addr)] = {
                            'local_as': local_as,
                            'remote_as': r2.group('remote_as'),
                            'address_family': self.__get_bgp_route_stats__(remote_addr)
                        }
                    except Exception as ex:
                        logger.warn('unable to process overflow bug line: {}'.format(ex))

            return bgp_data

        def _parse_per_peer_bgp_detail(peer_output):
            """This function parses the raw data per peer and returns a
            json structure per peer.
            """

            int_fields = ['local_as', 'remote_as',
                          'local_port', 'remote_port', 'local_port',
                          'input_messages', 'output_messages', 'input_updates',
                          'output_updates', 'messages_queued_out', 'holdtime',
                          'configured_holdtime', 'keepalive',
                          'configured_keepalive', 'advertised_prefix_count',
                          'received_prefix_count']

            peer_details = []

            # Using preset template to extract peer info
            _peer_info = (
                napalm_base.helpers.textfsm_extractor(
                    self, 'bgp_detail', peer_output))

            for item in _peer_info:

                # Determining a few other fields in the final peer_info
                item['up'] = (
                    True if item['connection_state'] == "ESTABLISHED" else False)
                item['local_address_configured'] = (
                    True if item['local_address'] else False)
                item['multihop'] = (True if item['multihop'] == 'yes' else False)
                item['remove_private_as'] = (True if item['remove_private_as'] == 'yes' else False)

                # TODO: The below fields need to be retrieved
                # Currently defaulting their values to False or 0
                item['multipath'] = False
                item['suppress_4byte_as'] = False
                item['local_as_prepend'] = False
                item['flap_count'] = 0
                item['active_prefix_count'] = 0
                item['suppressed_prefix_count'] = 0

                # Converting certain fields into int
                for key in int_fields:
                    if key in item:
                        item[key] = napalm_base.helpers.convert(int, item[key], 0)

                # process maps and lists
                for f in ['route_map', 'filter_list', 'prefix_list']:
                    _val = item.get(f)
                    if _val is not None:
                        r = _val.split()
                        if r:
                            # print 'r: ', r
                            # print len(r)
                            _name = 'policy' if f == 'route_map' else f
                            if len(r) >= 2:
                                item['{0}_{1}'.format(
                                    'import' if 'in' in r[0] else 'export',
                                    _name
                                )] = napalm_base.helpers.convert(py23_compat.text_type, r[1])

                            if len(r) == 4:
                                item['{0}_{1}'.format(
                                    'import' if 'in' in r[2] else 'export',
                                    _name
                                )] = napalm_base.helpers.convert(py23_compat.text_type, r[3])

                        # remove raw data from item
                        item.pop(f, None)

                # Conforming with the datatypes defined by the base class
                item['description'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item.get('description', '')))
                item['peer_group'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item.get('peer_group', '')))
                item['remote_address'] = napalm_base.helpers.ip(item['remote_address'])
                item['previous_connection_state'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item['previous_connection_state']))
                item['connection_state'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item['connection_state']))
                item['routing_table'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item['routing_table']))
                item['router_id'] = napalm_base.helpers.ip(item['router_id'])
                item['local_address'] = napalm_base.helpers.convert(
                    napalm_base.helpers.ip, item['local_address'])

                peer_details.append(item)

            return peer_details

        def _append(bgp_dict, peer_info):

            remote_as = peer_info['remote_as']
            vrf_name = peer_info['routing_table']

            if vrf_name not in bgp_dict.keys():
                bgp_dict[vrf_name] = {}
            if remote_as not in bgp_dict[vrf_name].keys():
                bgp_dict[vrf_name][remote_as] = []

            bgp_dict[vrf_name][remote_as].append(peer_info)

        _peer_ver = None
        bgp_summary = [list(), list()]
        raw_output = [list(), list()]
        bgp_detail_info = dict()

        # used to hold Address Family specific peer info
        _peer_info_af = [list(), list()]

        if not neighbor_address:
            '''
            raw_output[0] = self.device.send_command(
                'show ip bgp neighbors', delay_factor=self._show_command_delay_factor)
            raw_output[1] = self.device.send_command(
                'show ipv6 bgp neighbors', delay_factor=self._show_command_delay_factor)
            '''
            bgp_summary[0] = __process_bgp_summary_data__(
                self.device.send_command(
                    'show ip bgp summary',
                    delay_factor=self._show_command_delay_factor))
            bgp_summary[1] = __process_bgp_summary_data__(
                self.device.send_command(
                        'show ipv6 bgp summary',
                        delay_factor=self._show_command_delay_factor))

            # Using preset template to extract peer info
            _peer_info_af[0] = _parse_per_peer_bgp_detail(
                self.device.send_command(
                    'show ip bgp neighbors', delay_factor=self._show_command_delay_factor))
            _peer_info_af[1] = _parse_per_peer_bgp_detail(
                self.device.send_command(
                    'show ipv6 bgp neighbors', delay_factor=self._show_command_delay_factor))

        else:
            try:
                _peer_ver = IPAddress(neighbor_address).version
            except Exception as e:
                raise e

            _ver = '' if _peer_ver == 4 else 'v6'

            if _peer_ver == 4:
                '''
                raw_output[0] = self.device.send_command(
                    'show ip bgp neighbors {}'.format(neighbor_address),
                    delay_factor=self._show_command_delay_factor)
                '''
                bgp_summary[0] = __process_bgp_summary_data__(
                    self.device.send_command(
                        'show ip bgp summary',
                        delay_factor=self._show_command_delay_factor))
                _peer_info_af[0] = _parse_per_peer_bgp_detail(
                    self.device.send_command(
                        'show ip bgp neighbors {}'.format(neighbor_address),
                        delay_factor=self._show_command_delay_factor))
            else:
                '''
                raw_output[1] = self.device.send_command(
                    'show ipv6 bgp neighbors {}'.format(neighbor_address),
                    delay_factor=self._show_command_delay_factor)
                '''
                bgp_summary[1] = __process_bgp_summary_data__(
                    self.device.send_command(
                        'show ipv6 bgp summary',
                        delay_factor=self._show_command_delay_factor))
                _peer_info_af[1] = _parse_per_peer_bgp_detail(self.device.send_command(
                    'show ipv6 bgp neighbors {}'.format(neighbor_address),
                    delay_factor=self._show_command_delay_factor))

        for i, info in enumerate(_peer_info_af):
            for peer_info in info:

                _peer_remote_addr = peer_info.get('remote_address')

                try:
                    _bgp_summary = bgp_summary[i]['global']['peers'].get(_peer_remote_addr)
                    if _bgp_summary:
                        peer_info['local_as'] = _bgp_summary['local_as']

                        _afi_info = _bgp_summary['address_family'].get('ipv4' if i == 0 else 'ipv6')
                        if _afi_info:
                            peer_info['suppressed_prefix_count'] = int(_afi_info.get('filtered_prefixes', 0))
                            peer_info['advertised_prefix_count'] = int(_afi_info.get('sent_prefixes', 0))
                            peer_info['accepted_prefix_count'] = int(_afi_info.get('accepted_prefixes', 0))
                except:
                    pass

                _append(bgp_detail_info, peer_info)

        return bgp_detail_info

    def get_interfaces_counters(self):
        """get_interfaces_counterd method."""
        cmd = "show statistics"
        lines = self.device.send_command(cmd)
        lines = lines.split('\n')

        counters = {}
        for line in lines:
            port_block = re.match('\s*PORT (\S+) Counters:.*', line)
            if port_block:
                interface = port_block.group(1)
                counters.setdefault(interface, {})
            elif len(line) == 0:
                continue
            else:
                octets = re.match(r"\s+InOctets\s+(\d+)\s+OutOctets\s+(\d+)\.*", line)
                if octets:
                    counters[interface]['rx_octets'] = octets.group(1)
                    counters[interface]['tx_octets'] = octets.group(2)
                    continue

                packets = re.match(r"\s+InUnicastPkts\s+(\d+)\s+OutUnicastPkts\s+(\d+)\.*", line)
                if packets:
                    counters[interface]['rx_unicast_packets'] = packets.group(1)
                    counters[interface]['tx_unicast_packets'] = packets.group(2)
                    continue

                broadcast = re.match(r"\s+InBroadcastPkts\s+(\d+)\s+OutBroadcastPkts\s+(\d+)\.*", line)
                if broadcast:
                    counters[interface]['rx_broadcast_packets'] = broadcast.group(1)
                    counters[interface]['tx_broadcast_packets'] = broadcast.group(2)
                    continue

                multicast = re.match(r"\s+InMulticastPkts\s+(\d+)\s+OutMulticastPkts\s+(\d+)\.*", line)
                if multicast:
                    counters[interface]['rx_multicast_packets'] = multicast.group(1)
                    counters[interface]['tx_multicast_packets'] = multicast.group(2)
                    continue

                error = re.match(r"\s+InErrors\s+(\d+)\s+OutErrors\s+(\d+)\.*", line)
                if error:
                    counters[interface]['rx_errors'] = error.group(1)
                    counters[interface]['tx_errors'] = error.group(2)
                    continue

                discard = re.match(r"\s+InDiscards\s+(\d+)\s+OutDiscards\s+(\d+)\.*", line)
                if discard:
                    counters[interface]['rx_discards'] = discard.group(1)
                    counters[interface]['tx_discards'] = discard.group(2)

        return counters

    def get_environment(self):
        """
        Note this only partially implemented.  Currently only
        Returns a dictionary where:

            * fans is a dictionary of dictionaries where the key is the location and the values:
                 * status (True/False) - True if it's ok, false if it's broken
            * temperature is a dict of dictionaries where the key is the location and the values:
                 * temperature (float) - Temperature in celsius the sensor is reporting.
                 * is_alert (True/False) - True if the temperature is above the alert threshold
                 * is_critical (True/False) - True if the temp is above the critical threshold
            * power is a dictionary of dictionaries where the key is the PSU id and the values:
                 * status (True/False) - True if it's ok, false if it's broken
                 * capacity (float) - Capacity in W that the power supply can support
                 * output (float) - Watts drawn by the system
            * cpu is a dictionary of dictionaries where the key is the ID and the values
                 * %usage
            * memory is a dictionary with:
                 * available_ram (int) - Total amount of RAM installed in the device
                 * used_ram (int) - RAM in use in the device
        """
        # todo: add cpu, memory
        environment = {
            'memory': {'used_ram': 0, 'available_ram': 0},
            'temperature': {},
            'cpu': [{'%usage': 0.0}],
            'power': {},
            'fans': {},
            'memory_detail': {},
            'cpu_detail': {}
        }

        lines = self.device.send_command('show cpu-utilization average all 300 | include idle')
        for line in lines.split('\n'):
            r1 = re.match(r'^idle\s+.*(\d+)$', line)
            if r1:
                environment['cpu'][0]['%usage'] = 100 - int(r1.group(1))

        _data = napalm_base.helpers.textfsm_extractor(
            self, "show_cpu_lp", self.device.send_command('show cpu-utilization lp'))
        if _data:
            for d in _data:
                _slot = d.get('slot')
                _pct = napalm_base.helpers.convert(int, d.get('util'), 0)
                if _slot:
                    environment['cpu_detail']['LP{}'.format(_slot)] = {'%usage': _pct}

        # process memory
        _data = napalm_base.helpers.textfsm_extractor(self, 'show_memory', self.device.send_command('show memory'))
        # print(json.dumps(_data, indent=2))
        if _data:
            for d in _data:
                _name = d.get('name')
                _module = d.get('module')
                _state = d.get('state')
                _avail = napalm_base.helpers.convert(int, d.get('avail_ram'), 0)
                _total = napalm_base.helpers.convert(int, d.get('total_ram'), 0)
                _used = _avail/_total if _avail > 0 else 0
                _pct = d.get('avail_ram_pct')

                if _name and _module:
                    environment['memory_detail'][_module] = {
                        'used_ram': _used,
                        'available_ram': _avail
                    }

                    if 'MP' in _module and _state and _state == 'active':
                        environment['memory'] = {
                            'available_ram': _avail,
                            'used_ram': _avail
                        }

        # todo replace with 'show chassis' tpl
        command = 'show chassis'
        lines = self.device.send_command(command)
        _data = napalm_base.helpers.textfsm_extractor(self, 'show_chassis', lines)

        _chassis_modules = {'TEMP': 'temperature', 'FAN': 'fans', 'POWER': 'power'}
        if _data:
            for d in _data:
                _module = d.get('module')
                _mod_name = _chassis_modules.get(_module)
                if not _mod_name:
                    continue

                _name = d.get('name')
                _status = d.get('status')
                if _module and _name:
                    if _module == 'TEMP':
                        environment[_mod_name][_name] = {'temperature': d.get('temp', '0')}
                    elif _module == 'FAN':
                        environment[_mod_name][_name] = {
                            'status': _status, 'speed': d.get('speed', '')
                        }
                    elif _module == 'POWER':
                        environment[_mod_name][_name] = {
                            'status': _status, 'capacity': d.get('value', 'N/A'), 'output': 'N/A'}

        '''
        print(json.dumps(_data, indent=2))

        lines = lines.split("\n")

        lines = lines[3:]
        for line in lines:
            # Power 2: Installed (Failed or Disconnected)
            r1 = re.match(r'^Power\s+(\d+):\s+Installed \(Failed or Disconnected\)', line)
            # Power 7: (23-yyyyyyyy xxxxxxxxx  - AC 1800W): Installed (OK)
            r2 = re.match(r'^Power\s+(\d+):\s+.*AC\s+(\S+)\): Installed \(OK\)', line)
            # CER: Power 1 ( 3I50    - AC 504W): Installed (OK)
            r3 = re.match(r'^Power\s+(\d+)\s+.*AC\s+(\S+)\): Installed \(OK\)', line)
            if r1:
                psu = r1.group(1)
                environment['power'][psu] = dict()
                environment[psu] = {'status': False, 'capacity': 'N/A', 'output': 'N/A'}
            elif r2:
                psu = r2.group(1)
                environment['power'][psu] = dict()
                environment['power'][psu] = {'status': True, 'capacity': r2.group(2), 'output': 'N/A'}
            elif r3:
                psu = r3.group(1)
                environment['power'][psu] = dict()
                environment['power'][psu] = {'status': True, 'capacity': r3.group(2), 'output': 'N/A'}

            # Back Fan A-1: Status = OK, Speed = MED (60%)

            r3 = re.match(r'^(.*):\s+Status = (\S+),\s+Speed\s+=\s+(\S+)\s+\((\d+)%\)', line)
            if r3:
                fan = r3.group(1)
                status = False
                if r3.group(2) == "OK":
                    status = True

                environment['fans'][fan] = {'status': status}
        '''

        return environment

    def get_arp_table(self, vrf=""):
        """
        Returns a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)

        'vrf' of null-string will default to all VRFs. Specific 'vrf' will return the ARP table
        entries for that VRFs (including potentially 'default' or 'global').

        In all cases the same data structure is returned and no reference to the VRF that was used
        is included in the output.

        Example::

            [
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5C:5E:AB:DA:3C:F0',
                    'ip'        : '172.17.17.1',
                    'age'       : 1454496274.84
                },
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5C:5E:AB:DA:3C:FF',
                    'ip'        : '172.17.17.2',
                    'age'       : 1435641582.49
                }
            ]

        """
        arp_table = list()

        arp_cmd = 'show arp {}'.format(vrf)
        output = self.device.send_command(arp_cmd)
        output = output.split('\n')
        output = output[7:]

        for line in output:
            fields = line.split()

            if len(fields) == 6:
                num, address, mac, typ, age, interface = fields
                try:
                    if age == 'None':
                        age = 0
                    age = float(age)
                except ValueError:
                    logger.warn("Unable to convert age value to float: {}".format(age))

                # Do not include 'Pending' entries
                if typ == 'Dynamic' or typ == 'Static':
                    entry = {
                        'interface': interface,
                        'mac': napalm_base.helpers.mac(mac),
                        'ip': address,
                        'age': age
                    }
                    arp_table.append(entry)

        return arp_table

    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.

        Example input:
        ['show clock', 'show calendar']

        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}

        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            output = self._send_command(command)
            if 'Invalid input detected' in output:
                raise ValueError('Unable to execute command "{}"'.format(command))
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def get_ntp_servers(self):
        """
        Returns the NTP servers configuration as dictionary.
        The keys of the dictionary represent the IP Addresses of the servers.
        Inner dictionaries do not have yet any available keys.

        Example::

            {
                '192.168.0.1': {},
                '17.72.148.53': {},
                '37.187.56.220': {},
                '162.158.20.18': {}
            }

        """
        _ntp_servers = {}

        # as a quick implementation; call get_ntp_stats to get a list of ntp servers
        _ntp_info = self.get_ntp_stats()
        if _ntp_info:
            for n in _ntp_info:
                _ntp_servers[n.get('remote')] = {}

        return _ntp_servers

    def get_ntp_stats(self):
        """
        Note this was copied from the ios driver. Need to revisit type.

        Returns a list of NTP synchronization statistics.

            * remote (string)
            * referenceid (string)
            * synchronized (True/False)
            * stratum (int)
            * type (string)
            * when (string)
            * hostpoll (int)
            * reachability (int)
            * delay (float)
            * offset (float)
            * jitter (float)

        Example::

            [
                {
                    'remote'        : u'188.114.101.4',
                    'referenceid'   : u'188.114.100.1',
                    'synchronized'  : True,
                    'stratum'       : 4,
                    'type'          : u'-',
                    'when'          : u'107',
                    'hostpoll'      : 256,
                    'reachability'  : 377,
                    'delay'         : 164.228,
                    'offset'        : -13.866,
                    'jitter'        : 2.695
                }
            ]
        """
        ntp_stats = []

        command = 'show ntp associations'
        output = self._send_command(command)

        for line in output.splitlines():
            # Skip first two lines and last line of command output
            if line == "" or 'address' in line or 'sys.peer' in line:
                continue

            if '%NTP is not enabled' in line:
                return []

            elif len(line.split()) == 9:
                address, ref_clock, st, when, poll, reach, delay, offset, disp = line.split()
                address_regex = re.match(r'(\W*)([0-9.*]*)', address)
            try:
                ntp_stats.append({
                    'remote': py23_compat.text_type(address_regex.group(2)),
                    'synchronized': ('*' in address_regex.group(1)),
                    'referenceid': py23_compat.text_type(ref_clock),
                    'stratum': int(st),
                    'type': u'-',
                    'when': py23_compat.text_type(when),
                    'hostpoll': int(poll),
                    'reachability': int(reach),
                    'delay': float(delay),
                    'offset': float(offset),
                    'jitter': float(disp)
                })
            except Exception:
                continue

        return ntp_stats

    def get_mac_address_table(self):
        """get_mac_address_table method."""
        cmd = "show mac-address"
        lines = self.device.send_command(cmd)
        lines = lines.split('\n')

        mac_address_table = []
        # Headers may change whether there are static entries, is MLX or is CER
        for line in lines:
            fields = line.split()

            r1 = re.match("(\S+)\s+(\S+)\s+(Static|\d+)\s+(\d+).*", line)
            if r1:
                vlan = -1
                age = 0
                if self.family == 'MLX':
                    if len(fields) == 4:
                        mac_address, port, age, vlan = fields
                else:
                    if len(fields) == 5:
                        mac_address, port, age, vlan, esi = fields

                is_static = bool('Static' in age)
                mac_address = napalm_base.helpers.mac(mac_address)

                entry = {
                    'mac': mac_address,
                    'interface': str(port),
                    'vlan': int(vlan),
                    'active': bool(1),
                    'static': is_static,
                    'moves': None,
                    'last_move': None
                }
                mac_address_table.append(entry)

        return mac_address_table

    def get_probes_config(self):
        raise NotImplementedError

    def get_snmp_information(self, decrypt=False):
        """
        Retrieves SNMP configuration. Note this is partially implemented in that only SNMP v2c is supported. There
        is no particular support for v3.

        Brocade Notes:
        - no support for chassis-id
        - communities are encrypted; requires config -> enable password-display in order to view communities
          in-the-clear
        - additional setting retrieval should be supported

        Example Output:

        {   'chassis_id': u'unknown',
        'community': {   u'private': {   'acl': u'12', 'mode': u'rw'},
                         u'public': {   'acl': u'11', 'mode': u'ro'},
                         u'public_named_acl': {   'acl': u'ALLOW-SNMP-ACL',
                                                  'mode': u'ro'},
                         u'public_no_acl': {   'acl': u'N/A', 'mode': u'ro'}},
        'contact': u'Joe Smith',
        'location': u'123 Anytown USA Rack 404'}

        :param decrypt: if True community strings are decrypted otherwise Brocade renders dots
        :return: dict of dicts
        """

        try:
            # enable password-display in order to display community strings decrypted/in-the-clear
            if decrypt:
                self.device.send_config_set(['enable password-display'])

            # default values
            snmp_dict = {
                'chassis_id': u'unknown',
                'community': {},
                'contact': u'unknown',
                'location': u'unknown'
            }
            command = 'show run | include snmp-server'
            output = self._send_command(command)
            for line in output.splitlines():
                fields = line.split()
                if 'snmp-server community' in line:
                    name = fields[2]
                    if 'community' not in snmp_dict.keys():
                        snmp_dict.update({'community': {}})
                    snmp_dict['community'].update({name: {}})
                    try:
                        snmp_dict['community'][name].update({'mode': fields[3].lower()})
                    except IndexError:
                        snmp_dict['community'][name].update({'mode': u'N/A'})
                    try:
                        snmp_dict['community'][name].update({'acl': fields[4]})
                    except IndexError:
                        snmp_dict['community'][name].update({'acl': u'N/A'})
                elif 'snmp-server location' in line:
                    snmp_dict['location'] = ' '.join(fields[2:])
                elif 'snmp-server contact' in line:
                    snmp_dict['contact'] = ' '.join(fields[2:])
                elif 'snmp-server chassis-id' in line:
                    snmp_dict['chassis_id'] = ' '.join(fields[2:])
                else:
                    # add any other snmp-server configuration
                    if len(fields) > 2:
                        snmp_dict[fields[1]] = ' '.join(fields[2:])

        finally:
            # disable password-display before exiting
            if decrypt:
                self.device.send_config_set(['no enable password-display'])

        return snmp_dict

    def get_users(self):
        """
                Returns a dictionary with the configured users.
                The keys of the main dictionary represents the username.
                The values represent the details of the user,
                represented by the following keys:

                    * level (int)
                    * password (str)
                    * sshkeys (list)

                *Note: need to revisit sshkeys -- I'm not sure exactly what Brocade supports


                The level is an integer between 0 and 15, where 0 is the
                lowest access and 15 represents full access to the device.
                """
        _users = {}
        _output = self._send_command('show users')
        for l in _output.split('\n'):
            _info = l.split()

            if _info and len(_info) == 4 and not re.search(r'^(Username|=======)', _info[0]):
                _users[_info[0]] = {'password': _info[1], 'sshkeys': [], 'level': _info[3]}
        return _users

    def ping(self, destination, source=PING_SOURCE, ttl=PING_TTL, timeout=50,
             size=PING_SIZE, count=PING_COUNT, vrf=PING_VRF):
        """
        Execute ping on the device and returns a dictionary with the result.  This is a direct port
        of the Cisco IOS code; modified to support Brocade netiron

        Note that a timeout=50 is the minimum supported timeout for Brocades

        Output dictionary has one of following keys:
            * success
            * error
        In case of success, inner dictionary will have the following keys:
            * probes_sent (int)
            * packet_loss (int)
            * rtt_min (float)
            * rtt_max (float)
            * rtt_avg (float)
            * rtt_stddev (float)
            * results (list)
        'results' is a list of dictionaries with the following keys:
            * ip_address (str)
            * rtt (float)
        """
        ping_dict = {}

        _ip = napalm_base.helpers.IPAddress(destination)
        if not _ip:
            raise ValueError('destination must be a valid IP Address')

        # vrf needs to be right after the ping command
        # ipv6 addresses require an additional parameter
        command = 'ping {vrf} {family} {destination} timeout {timeout} size {size} count {count} '.format(
            vrf='vrf ' + vrf if vrf else '',
            family='ipv6' if _ip.version == 6 else '',
            destination=destination,
            timeout=timeout,
            size=size,
            count=count
        )

        # apply a source-ip
        if source != '':
            command += ' source-ip {}'.format(source)

        logger.info(command)

        output = self._send_command(command)
        if 'No reply from remote host' in output:
            ping_dict['error'] = 'No reply from remote host'
        elif 'Sending' in output:
            ping_dict['success'] = {
                                'probes_sent': 0,
                                'packet_loss': 0,
                                'rtt_min': 0.0,
                                'rtt_max': 0.0,
                                'rtt_avg': 0.0,
                                'rtt_stddev': 0.0,
                                'results': []
            }

            _probe_results = list()
            for line in output.splitlines():
                fields = line.split()
                if 'Success rate is 0' in line:
                    sent_and_received = re.search(r'\((\d*)/(\d*)\)', fields[5])
                    probes_sent = int(sent_and_received.groups()[0])
                    probes_received = int(sent_and_received.groups()[1])
                    ping_dict['success']['probes_sent'] = probes_sent
                    ping_dict['success']['packet_loss'] = probes_sent - probes_received
                elif 'Success rate is' in line:
                    # brocade jams min/avg/max and values together as opposed to Cisco which uses spaces
                    # Success rate is 100 percent (3/3), round-trip min/avg/max=24/26/29 ms.
                    sent_and_received = re.search(r'\((\d*)/(\d*)\)', fields[5])
                    probes_sent = int(sent_and_received.groups()[0])
                    probes_received = int(sent_and_received.groups()[1])
                    min_avg_max = re.search(r'(\d*)/(\d*)/(\d*)', fields[7])
                    ping_dict['success']['probes_sent'] = probes_sent
                    ping_dict['success']['packet_loss'] = probes_sent - probes_received
                    ping_dict['success'].update({
                                    'rtt_min': float(min_avg_max.groups()[0]),
                                    'rtt_avg': float(min_avg_max.groups()[1]),
                                    'rtt_max': float(min_avg_max.groups()[2]),
                    })
                    results_array = []

                    # modified original cisco code to use values from 'Reply from' results. If no value
                    # is found default to 0.0 per the original code
                    for i in range(probes_received):
                        results_array.append({
                            'ip_address': py23_compat.text_type(destination),
                            'rtt': _probe_results[i] if len(_probe_results) > i else 0.0
                        })
                    ping_dict['success'].update({'results': results_array})

                elif 'Reply from ' in line:
                    # grab the time results and append a list
                    r = re.search(r'^Reply from .* time=(\d+)', line)
                    if r:
                        _probe_results.append(r.groups()[0])

        return ping_dict

    def traceroute(self, destination, source=TRACEROUTE_SOURCE,
                   ttl=TRACEROUTE_TTL, timeout=TRACEROUTE_TIMEOUT, vrf=TRACEROUTE_VRF):
        """
        Executes traceroute on the device and returns a dictionary with the result.

        :param destination: Host or IP Address of the destination
        :param source: Use a specific IP Address to execute the traceroute
        :param ttl: Maximum number of hops -> int (0-255)
        :param timeout: Number of seconds to wait for response -> int (1-3600)

        Output dictionary has one of the following keys:

            * success
            * error

        In case of success, the keys of the dictionary represent the hop ID, while values are
        dictionaries containing the probes results:
            * rtt (float)
            * ip_address (str)
            * host_name (str)
        """
        _ip = napalm_base.helpers.IPAddress(destination)
        if not _ip:
            raise ValueError('destination must be a valid IP Address')

        # perform a ping to verify if the destination will respond -- this speeds up processing -- if a
        # destination is inaccessible a traceroute will consume a lot of time; only to fail.  Where a ping
        # is relatively quick.
        #
        # note that brocade doesn't support v6 source traceroute so do NOT specify a source for
        # v6 ping check
        _res = self.ping(destination, source=source if _ip.version == 4 else '')
        if 'error' in _res:
            return _res

        # vrf needs to be right after the traceroute command
        # ipv6 addresses require an additional parameter
        command = 'traceroute {vrf} {family} {destination} '.format(
            vrf='vrf ' + vrf if vrf else '',
            family='ipv6' if _ip.version == 6 else '',
            destination=destination
        )

        if source != '' and _ip.version == 4:
            command += " source-ip {}".format(source)
        if ttl:
            if isinstance(ttl, int) and 0 <= timeout <= 255:
                command += " maxttl {}".format(str(ttl))
        if timeout:
            # Timeout should be an integer between 1 and 3600
            if isinstance(timeout, int) and 1 <= timeout <= 3600:
                command += " timeout {}".format(str(timeout))

        logger.info(command)

        # Calculation to leave enough time for traceroute to complete assumes send_command
        # delay of .2 seconds.
        max_loops = (5 * ttl * timeout) + 150
        if max_loops < 500:     # Make sure max_loops isn't set artificially low
            max_loops = 500
        output = self.device.send_command(command, max_loops=max_loops)

        if 'Not authorized to execute this command' in output:
            raise ValueError('Permissions Error: {0}: Not authorized to execute this command.'.format(self.username))

        # Prepare return dict
        traceroute_dict = dict()
        if re.search('Unrecognized host or address', output):
            traceroute_dict['error'] = 'unknown host %s' % destination
            return traceroute_dict
        else:
            traceroute_dict['success'] = dict()

        results = dict()
        # Find all hops
        hops = re.findall(r'\n\s+[0-9]{1,3}\s+.*', output)
        for h in hops:
            # lets try simply splitting the string vs. regex
            v = h.strip().split()
            if not v or len(v) < 8:
                logger.warn('expected at least 7 hop results: {0}:{1}'.format(h, hops))
                continue

            _hop = v[0]
            _ip_address = ''
            _host = '?'
            _p1 = _p2 = _p3 = '*'

            if v[1] != '*':
                if len(v) == 9:
                    _ip_address = re.sub('[\[\]]', '', v[8])
                _host = v[7]
                _p1 = v[1]
                _p2 = v[3]
                _p3 = v[5]

            results[_hop] = dict()
            results[_hop]['probes'] = dict()
            results[_hop]['probes'][1] = {'rtt': _p1, 'ip_address': _ip_address, 'host_name': _host}
            results[_hop]['probes'][2] = {'rtt': _p2, 'ip_address': _ip_address, 'host_name': _host}
            results[_hop]['probes'][3] = {'rtt': _p3, 'ip_address': _ip_address, 'host_name': _host}

        traceroute_dict['success'] = results
        return traceroute_dict

    def get_network_instances(self, name=''):

        instances = {}
        sh_vrf_detail = self._send_command('show vrf detail')
        show_ip_int_br = self._send_command('show ip interface brief')

        # retrieve all interfaces for the default VRF
        interface_dict = {}
        show_ip_int_br = show_ip_int_br.strip()
        for line in show_ip_int_br.splitlines():
            if 'Interface ' in line:
                continue
            interface = line.split()[0]
            interface_dict[interface] = {}

        instances['default'] = {
                                'name': 'default',
                                'type': 'DEFAULT_INSTANCE',
                                'state': {'route_distinguisher': ''},
                                'interfaces': {'interface': interface_dict}
                                }

        for vrf in sh_vrf_detail.split('\n\n'):

            first_part = vrf.split('Address family')[0]

            # retrieve the name of the VRF and the Route Distinguisher
            vrf_name, RD = re.match(r'^VRF (\S+).*RD (.*);', first_part).groups()
            if RD == '<not set>':
                RD = ''

            # retrieve the interfaces of the VRF
            if_regex = re.match(r'.*Interfaces:(.*)', first_part, re.DOTALL)
            if 'No interfaces' in first_part:
                interfaces = {}
            else:
                interfaces = {itf: {} for itf in if_regex.group(1).split()}

            instances[vrf_name] = {
                                   'name': vrf_name,
                                   'type': 'L3VRF',
                                   'state': {'route_distinguisher': RD},
                                   'interfaces': {'interface': interfaces}
                                   }
        return instances if not name else instances[name]

    def get_config(self, retrieve='all'):
        """Implementation of get_config for netiron.

        Returns the startup or/and running configuration as dictionary.
        The keys of the dictionary represent the type of configuration
        (startup or running). The candidate is always empty string,
        since netiron does not support candidate configuration.
        """

        configs = {
            'startup': '',
            'running': '',
            'candidate': '',
        }

        if retrieve in ('startup', 'all'):
            command = 'show configuration'
            output = self._send_command(command)
            configs['startup'] = output

        if retrieve in ('running', 'all'):
            command = 'show running-config'
            output = self._send_command(command)
            configs['running'] = output

        return configs

    def get_ipv6_neighbors_table(self):
        """
        Get IPv6 neighbors table information.
        Return a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float) in seconds
            * state (string)
        For example::
            [
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5c:5e:ab:da:3c:f0',
                    'ip'        : '2001:db8:1:1::1',
                    'age'       : 1454496274.84,
                    'state'     : 'REACH'
                },
                {
                    'interface': 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '66:0e:94:96:e0:ff',
                    'ip'        : '2001:db8:1:1::2',
                    'age'       : 1435641582.49,
                    'state'     : 'STALE'
                }
            ]
        """

        ipv6_neighbors_table = []
        command = 'show ipv6 neighbors'
        output = self._send_command(command)

        ipv6_neighbors = ''
        fields = re.split(r"^IPv6\s+Address.*Interface$", output, flags=(re.M | re.I))
        if len(fields) == 2:
            ipv6_neighbors = fields[1].strip()
        for entry in ipv6_neighbors.splitlines():
            # typical format of an entry in the IOS IPv6 neighbors table:
            # 2002:FFFF:233::1 0 2894.0fed.be30  REACH Fa3/1/2.233
            ip, age, mac, state, interface = entry.split()
            mac = '' if mac == '-' else napalm_base.helpers.mac(mac)
            ip = napalm_base.helpers.ip(ip)
            ipv6_neighbors_table.append({
                                        'interface': interface,
                                        'mac': mac,
                                        'ip': ip,
                                        'age': float(age),
                                        'state': state
                                        })
        return ipv6_neighbors_table

    @property
    def dest_file_system(self):
        """
        Return the destination file system. Since netiron only supports copying from slotX to running, it
        might not make sense to return anything but the slot info.  For now just return the value of
        self._dest_file_system which defaults to '/slot1'
        """
        return self._dest_file_system
