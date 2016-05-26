# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#*** nmeta2 - Network Metadata - Abstractions of a collection of of_switches

"""
This module is part of the nmeta suite running on top of Ryu SDN controller.
It provides functions that abstract the details of OpenFlow calls, including
differences between OpenFlow versions where practical
"""

#*** Logging Imports:
import logging
import logging.handlers

#*** General Imports:

#*** Ryu Imports:

#*** OF switch classes for nmeta2
from switch_abstraction.of_switches.ovs import OpenvSwitch

#*** Constant to use for a port not found value:
PORT_NOT_FOUND = 999999999

class Switches(object):
    """
    This class provides an abstraction for a set of OpenFlow
    Switches
    """

    _SWITCH_OVS = "Open vSwitch"

    def __init__(self, _nmeta, _config):
        self._nmeta = _nmeta
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('sa_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('sa_logging_level_c')
        _syslog_enabled = _config.get_value('syslog_enabled')
        _loghost = _config.get_value('loghost')
        _logport = _config.get_value('logport')
        _logfacility = _config.get_value('logfacility')
        _syslog_format = _config.get_value('syslog_format')
        _console_log_enabled = _config.get_value('console_log_enabled')
        _coloredlogs_enabled = _config.get_value('coloredlogs_enabled')
        _console_format = _config.get_value('console_format')
        #*** Set up Logging:
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        #*** Syslog:
        if _syslog_enabled:
            #*** Log to syslog on host specified in config.yaml:
            self.syslog_handler = logging.handlers.SysLogHandler(address=(
                                                _loghost, _logport),
                                                facility=_logfacility)
            syslog_formatter = logging.Formatter(_syslog_format)
            self.syslog_handler.setFormatter(syslog_formatter)
            self.syslog_handler.setLevel(_logging_level_s)
            #*** Add syslog log handler to logger:
            self.logger.addHandler(self.syslog_handler)
        #*** Console logging:
        if _console_log_enabled:
            #*** Log to the console:
            self.console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(_console_format)
            self.console_handler.setFormatter(console_formatter)
            self.console_handler.setLevel(_logging_level_c)
            #*** Add console log handler to logger:
            self.logger.addHandler(self.console_handler)
        #*** Registration MAC address:
        self.dpae2ctrl_mac = _config.get_value("dpae2ctrl_mac")
        #*** MAC Address idle timeouts for flow entries in switch_abstraction:
        self.mac_iim_idle_timeout = _config.get_value("mac_iim_idle_timeout")
        self.mac_fwd_idle_timeout = _config.get_value("mac_fwd_idle_timeout")
        #*** Dictionary of switch_abstraction supported by nmeta2:
        # The dict has the form: "Switch name":[list of supported software versions]
        self._supported_switches = {}
        self._supported_switches[self._SWITCH_OVS] = ["2.3.90"]
        #*** Dictionary of switch_abstraction indexed by dpid:
        self.switch = {}
        self._config = _config

    def add(self, datapath, hw_desc, sw_desc):
        """
        Add a switch to the class
        Args:
            datapath: Datapath of the switch.
            hw_desc: Switch hardware name.
            sw_desc: Switch software version.

        Returns: 1 if the switch is supported, 0 otherwise.

        """
        dpid = datapath.id
        #*** Check that nmeta2 supports the switch:
        if hw_desc not in self._supported_switches:
            self.logger.critical("Switch hardware is not supported by "
                                 "nmeta2. dpid=\"%s\" hw_desc=\"%s\"",
                                 dpid, hw_desc)
            return 0
        if sw_desc not in self._supported_switches[hw_desc]:
            self.logger.critical("Switch software version is not "
                                 "supported by nmeta2. dpid=\"%s\" "
                                 "hw_desc=\"%s\" sw_desc=\"%s\"",
                                 dpid, hw_desc, sw_desc)
            return 0
        #*** The switch is suported, instantiate a specific OF switch
        # class for the switch:
        self.logger.debug("Adding switch dpid=%s", dpid)
        if hw_desc == self._SWITCH_OVS:
            self.switch[dpid] = OpenvSwitch(self._nmeta, self.logger,
                                            self._config, datapath)
        #self.switch[dpid] = Switch(self._nmeta, self.logger,
        #                                    self._config, datapath)
        return 1

    def datapath(self, dpid):
        """
        Return a datapath for a given switch dpid
        """
        if dpid in self.switch:
            return self.switch[dpid].datapath
        else:
            self.logger.error("Unknown dpid=%s", dpid)
            return 0

    def __getitem__(self, key):
        """
        Passed a dpid key and return corresponding switch
        object, or 0 if it doesn't exist.
        Example:
            switch = switch_abstraction[dpid]
        """
        if key in self.switch:
            return self.switch[key]
        else:
            return 0
