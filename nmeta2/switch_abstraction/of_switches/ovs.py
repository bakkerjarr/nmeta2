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

from abc_of_switch import ABCOFSwitch

__author__ = "Jarrod N. Bakker"


class OpenvSwitch(ABCOFSwitch):

    def packet_out(self, data, in_port, out_port, out_queue, nq=0):
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        dpid = self.datapath.id
        #*** First build OF version specific list of actions:
        if not nq:
            #*** Packet out with no queue (nq):
            actions = [self.datapath.ofproto_parser.OFPActionOutput \
                             (out_port, 0)]

        else:
            #*** Note: out_port must come last!
            actions = [
                    parser.OFPActionSetQueue(out_queue),
                    parser.OFPActionOutput(out_port, 0)]

        #*** Now have we have actions, build the packet out message:
        out = parser.OFPPacketOut(
                    datapath=self.datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port, actions=actions, data=data)

        self.logger.debug("Sending Packet-Out message dpid=%s port=%s",
                                    dpid, out_port)
        #*** Tell the switch to send the packet:
        self.datapath.send_msg(out)