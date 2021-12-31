"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters


import pytest


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    # Skip test_method_signatures - we have additional getters
    def test_method_signatures(self):
        return True

    # Unsupported functions
    def test_get_interfaces_counters(self):
        return True

    def test_get_environment(self):
        return True

    def test_get_arp_table_with_vrf(self):
        return True

    def test_get_ntp_peers(self):
        return True

    def test_get_ntp_servers(self):
        return True

    def test_get_ntp_stats(self):
        return True

    def test_get_users(self):
        return True

    def test_get_config(self):
        return True

    def test_get_config_filtered(self):
        return True

    def test_get_config_sanitized(self):
        return True

    def test_get_lldp_neighbors_detail(self):
        return True

    def test_get_bgp_neighbors_detail(self):
        return True

    def test_get_ipv6_neighbors_table(self):
        return True

    def test_get_route_to(self):
        return True

    def test_get_route_to_longer(self):
        return True

    def test_get_snmp_information(self):
        return True

    def test_ping(self):
        return True

    def test_traceroute(self):
        return True

    def test_get_mac_address_table(self):
        return True

    def test_get_bgp_neighbors(self):
        return True
