"""
Nmeta2 Unit Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, type in:
    py.test tests_unit.py

"""

#*** Handle tests being in different directory branch to app code:
import sys

sys.path.insert(0, '../nmeta2')

#*** For tests that need a logger:
import logging
logger = logging.getLogger(__name__)

#*** Testing imports:
import mock

#*** Ryu imports:
from ryu.controller import controller
from ryu.app.wsgi import WSGIApplication

#*** JSON imports:

#*** nmeta2 imports:
import nmeta2
from nmeta2 import switch_abstraction
import config

#*** Instantiate Config class:
_config = config.Config()

#====================== of_switches.py Unit Tests ======================
#*** Instantiate class:
wsgi_app = WSGIApplication()
nmeta = nmeta2.Nmeta(wsgi=wsgi_app)

switches = switch_abstraction.Switches(nmeta, _config)

sock_mock = mock.Mock()
addr_mock = mock.Mock()


#*** Test Switches and Switch classes that abstract OpenFlow switch_abstraction:
def test_switches():
    with mock.patch('ryu.controller.controller.Datapath.set_state'):
        #*** Set up a fake switch datapath:
        datapath = controller.Datapath(sock_mock, addr_mock)

        #*** Add a switch
        assert switches.add(datapath) == 1

        #*** Look up by DPID:
        assert switches.datapath(datapath.id) == datapath

        _switch_test(switches[datapath.id])

def _switch_test(switch):
    """
    Test cases for a switch
    """
    #*** Constant to use for a port not found value:
    PORT_NOT_FOUND = 999999999

    #*** Test values:
    mac123 = '00:00:00:00:01:23'
    port123 = 123
    context1 = 1

    mac456 = '00:00:00:00:04:56'
    port456 = 456
    context2 = 2

    #*** Add to MAC/port pairs to switch MAC table:
    switch.mactable.add(mac123, port123, context1)
    switch.mactable.add(mac456, port456, context2)

    #*** Check that we can find mac/in_port:
    assert switch.mactable.mac2port(mac123, context1) == port123
    assert switch.mactable.mac2port(mac456, context2) == port456

    #*** Check that we can't find mac/in_port:
    assert switch.mactable.mac2port(mac123, context2) == PORT_NOT_FOUND
    assert switch.mactable.mac2port(mac456, context1) == PORT_NOT_FOUND


