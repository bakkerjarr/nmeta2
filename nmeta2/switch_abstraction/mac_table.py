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

#*** nmeta2 - Network Metadata - Abstractions of MAC forwarding tables

#*** Constant to use for a port not found value:
PORT_NOT_FOUND = 999999999


class MACTable(object):
    """
    This class provides an abstraction for the MAC table on
    an OpenFlow Switch that maps MAC addresses to switch ports
    """

    def __init__(self, _nmeta, logger, _config, datapath):
        self._nmeta = _nmeta
        self.logger = logger
        self.datapath = datapath
        self.dpid = datapath.id
        self._config = _config
        self.parser = datapath.ofproto_parser

    def add(self, mac, in_port, context):
        """
        Passed a MAC address and the switch port it was learnt
        via along with a context. Add this to the database and
        tidy up by removing any other entries for this MAC on
        this switch in given context.
        """
        nmeta = self._nmeta
        dpid = self.dpid

        #*** Check if MAC known in database for this switch/context:
        db_result = nmeta.dbidmac.find_one({'dpid': dpid, 'mac': mac,
                                                    'context': context})
        if db_result and db_result['port'] != in_port:
            #*** We've learnt MAC via a different port so need to update:
            self.logger.debug("MAC/port formerly known as: dpid=%s mac=%s "
                            "port=%s context=%s", dpid, mac, in_port, context)
            # TBD

        #*** Record in database:
        self.logger.debug("Adding MAC/port to DB: dpid=%s mac=%s port=%s "
                            "context=%s", dpid, mac, in_port, context)
        dbidmac_doc = {'dpid': dpid, 'mac': mac, 'port': in_port,
                         'context': context}
        db_id = nmeta.dbidmac.insert_one(dbidmac_doc).inserted_id

    def mac2port(self, mac, context):
        """
        Passed a dpid and mac address and return the switch port number
        that this mac has been learned via
        (or 999999999 if unknown)
        """
        nmeta = self._nmeta
        dpid = self.dpid
        #*** Retrieve first matching record:
        db_result = nmeta.dbidmac.find_one({'dpid': dpid, 'mac': mac,
                                                'context': context})
        if db_result:
            if not 'dpid' in db_result:
                self.logger.error("DB record didn't have a dpid...???")
                return PORT_NOT_FOUND
            dpid = db_result['dpid']
            if not 'port' in db_result:
                self.logger.error("DB record didn't have a port...???")
                return PORT_NOT_FOUND
            if not 'context' in db_result:
                self.logger.error("DB record didn't have a context...???")
                return PORT_NOT_FOUND
            if db_result['context'] != context:
                return PORT_NOT_FOUND
            port = db_result['port']
            self.logger.debug("Found mac=%s on dpid=%s port=%s context=%s",
                                        mac, dpid, port, context)
            return port
        else:
            self.logger.info("Unknown mac=%s for dpid=%s context=%s", mac,
                                        self.dpid, context)
        return PORT_NOT_FOUND