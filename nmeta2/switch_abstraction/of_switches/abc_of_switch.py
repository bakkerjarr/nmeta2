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

import sys
from abc import ABCMeta
from abc import abstractmethod

from ..flow_tables import FlowTables
from ..mac_table import MACTable

__author__ = "Jarrod N. Bakker"


class ABCOFSwitch:
    """Interface for OpenFlow compliant switch_abstraction.
    """

    __metaclass__ = ABCMeta

    def __init__(self, _nmeta, logger, _config, datapath):
        self._nmeta = _nmeta
        self.logger = logger
        self.datapath = datapath
        self.dpid = datapath.id
        self._config = _config
        #*** Instantiate a class that represents flow tables:
        self.flowtables = FlowTables(self._nmeta, self.logger,
                                     self._config, datapath)
        #*** Instantiate a class that represents the MAC table:
        self.mactable = MACTable(self._nmeta, self.logger,
                                 self._config, datapath)

    def request_switch_desc(self):
        """
        Send an OpenFlow request to the switch asking it to
        send us it's description data
        """
        parser = self.datapath.ofproto_parser
        req = parser.OFPDescStatsRequest(self.datapath, 0)
        self.logger.debug("Sending description request to dpid=%s",
                            self.datapath.id)
        self.datapath.send_msg(req)

    def set_switch_config(self, config_flags, miss_send_len):
        """
        Set config on a switch including config flags that
        instruct fragment handling behaviour and miss_send_len
        which controls the number of bytes sent to the controller
        when the output port is specified as the controller.
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        self.logger.info("Setting config on switch "
                         "dpid=%s to config_flags flag=%s and "
                         "miss_send_len=%s bytes",
                          self.dpid, config_flags, miss_send_len)
        try:
            self.datapath.send_msg(parser.OFPSetConfig(
                                     self.datapath,
                                     config_flags,
                                     miss_send_len))
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Failed to set switch config. "
                   "Exception %s, %s, %s",
                    exc_type, exc_value, exc_traceback)
            return 0
        return 1

    def get_friendly_of_version(self, ofproto):
        """
        Passed an OF Protocol object and return a
        human-friendly version of the protocol
        revision number
        """
        if ofproto.OFP_VERSION == 1:
            _of_version = "1.0"
        elif ofproto.OFP_VERSION == 4:
            _of_version = "1.3"
        else:
            _of_version = "Unknown version " + \
                            str(ofproto.OFP_VERSION)
        return _of_version

    @abstractmethod
    def packet_out(self, data, in_port, out_port, out_queue, nq=0):
        """
        Sends a supplied packet out switch port(s) in specific queue.
        Set nq=1 if want no queueing specified (i.e. for a flooded
        packet)
        Does not support use of Buffer IDs
        """
        raise NotImplementedError("Method \'packet_out\' must be "
                                  "implemented.")
