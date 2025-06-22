"""
This module contains scale tests for BundleMgr AP.
"""
# -----------------------------------------------------------------------------
# Copyright (c) 2024-2025 by Cisco Systems, Inc., and/or its affiliates.
# All rights reserved.
# -----------------------------------------------------------------------------

import pytest
import re
from .bundlemgr_ap import TestBundlemgrBasicChecks
from .bundlemgr_ap_base import ApData, BundleApBase
from logger.cafylog import CafyLog
from topology.zap.zap import Zap
from feature_lib.gRPC import Grpc
from utils.helper import Helper
from feature_lib.ltrace import Ltrace, Logstash
from utils.cafyexception import CafyException
from feature_lib.common_lib.utils_helper import VioletDataUtils
from scale.dashboard import ScaleDashboard
from collections import defaultdict
from feature_lib.ifmgr import IfMgr
from feature_lib.ip_static import IpStatic

log = CafyLog("Bundlemgr AP")


def ApData2():
    """
        Initializes ApData with test input and topology files.
    """
    test_input_file = CafyLog.test_input_file
    testbed_file = CafyLog.topology_file

    # interface configuration data
    zap = Zap(test_input_file=test_input_file, topo_file=testbed_file)

    # base configuration data
    base_configuration = zap.get_base_configuration()

def setup_module(self):
    """
        Sets up the module by initializing ApData and configuring ETM and ACL settings.
    """
    error_list = []
    try:
        ApData.initialize_data()
        # code to enable ETM as per input file
        etm = ApData.zap.get_base_configuration("etm")
        etm_port_list = ApData.zap.get_base_configuration("etm_port_list")
        # we can run only on Shadow Tower and UFI as of now. Other PODs might have mix of SE and Non-SE linecards.
        # From Release 7.5.1 we will be supporting Egress TM Feature on J2 SE (Native Mode) and UFI.
        # we cannot bundle ETM enabled and not enabled links together in same bundle, members will not come UP.
        # https://wiki.cisco.com/display/FRE/ETM+AUTOMATION
        if etm:
            for platform in ApData.etm_enabled_platforms:
                if re.match(platform, ApData.R1.platform, re.IGNORECASE):
                    try:
                        ApData.R1.qos_hw_obj.set_etm_mode_enable(install_obj=ApData.R1.install, config_obj=ApData.R1.cfg, optics_obj=ApData.R1.optics,
                                                            inv_obj=ApData.R1.inventory, enable=True,etm_port_list=etm_port_list, device=ApData.R1)
                        dut = ApData.R1
                        ApData.enabling_etm = True
                        if "short-etm" not in ApData.r1_run_conf_hw_module:
                            log.info("Enabling hw-mod cli, as we have QoS egress policy-map application & ETM as part of Bundles AP")
                            dut.qos_hw_obj.set_ipv6_short_etm_qos_enable()
                            ApData.set_v6_short_etm_qos = True
                            Helper.sleep(10,'Wait for UUT to stabilise after config')

                            log.info("Post configuring cli - hw-module profile qos ipv6 short-etm, Reloading UUT router")
                            router_reload_trigger = dut.event.ReloadAllCards(inv_obj=dut.inventory)
                            router_reload_trigger.run()
                            Helper.sleep(120,'Wait for UUT to stabilise after reload')

                            if ApData.mode == "ydk":
                                dut.disconnect()
                                dut.connect()
                    except Exception as err:
                        log.exception(f"Error while enabling ETM feature \n {err}")
                        error_list.append(err)
        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('hw_module_permit_stats','False')) == True:
                if "acl-permit" not in ApData.r1_run_conf_hw_module:
                    log.info('Enabling ACL permit stats on R1 and reloading')
                    ApData.R1.acl.set_hw_module_profile_stats_acl_permit()
                    router_reload_trigger = ApData.R1.event.ReloadAllCards(inv_obj=ApData.R1.inventory)
                    router_reload_trigger.run()
                    Helper.sleep(120,'Wait for UUT to stabilise after reload')
                else:
                    log.info('on R1 ACL permit stats on platform is already enabled')
        if ApData.configure_unused_interfaces:
            BundleApBase.set_unused_interfaces()
        # Loading TGN and start protocols
        ApData.zap.load_tgn_config_file(
            ApData.tgn_obj, ApData.tgn_config_file, ApData.port_list)

        if ApData.traffic_control:
            ApData.tgn_obj.change_traffic_rate({'type': 'percentLineRate', 'rate': ApData.traffic_load},traffic_item_list=None)

        ApData.tgn_obj.start_all_protocols()
        if ApData.bump_isis_routes:
            BundleApBase.set_isis_route_count()

    except Exception as err:
        log.error(err)
        error_list.append(err)

    ApData.R1.grpc_obj = Grpc(device=ApData.R1, mode = ApData.mode)
    credential = ApData.R1.handles_info[0]["credential"]
    ApData.R1.username = ApData.topo.credentials[credential].username
    ApData.R1.password = ApData.topo.credentials[credential].password
    ApData.dual_rp_status = ApData.R1.inventory.has_dual_rp()
    if not ApData.sim:
        if (len(ApData.R1.ipv4.get_virtual_address_status())) != 0:
            ApData.virtual_ip = ApData.R1.ipv4.get_virtual_address_status()[0].virtual_ip
        else:
            intf_name = "mgmt " + ApData.R1.active_rp + "/0"
            ApData.virtual_ip = ApData.R1.ifmgr.get_interface_detail(interface=intf_name)[0].ipv4_address
    ApData.gnmi_conn = None

    if ApData.sim:
        log.banner("Logstash integration for debug ltrace collection")
        if ApData.zap.get_parameters("logstash_config") == True:
            try:
                log.banner("Enabling LOGSTASH")
                logstash = Ltrace()
                logstash_debug_bck =   {"R1": ["show ofa trace", "show cef trace"],
                                        "R2": ["show ofa trace", "show cef trace"],
                                        "R3": ["show ofa trace", "show cef trace"]}
                logstash.enable_logstash_services_input(ApData.zap, logstash_type="setup_module",
                                                        enable=True, idt="Setup_module", logstash_debug_bck=logstash_debug_bck)
            except Exception as ee:
                log.info(f"LOGSTASH configuration failed with error : {ee}")
    ApData.gnmi_conn = None

    # adding this piece of code to take ACL get_acl_hit_count method.
    ApData.R1.byte_count = False
    ApData.R1.Version=ApData.R1.install.get_version()
    ApData.R1.ver = ApData.R1.Version.version
    ApData.R1.first_int=int(re.search(r'(\d+).(\d+).*', ApData.R1.ver).group(1))
    ApData.R1.sec_int=int(re.search(r'(\d+).(\d+).*', ApData.R1.ver).group(2))

    #increasing the glean trap meter rate on each LC CSCwh87765
    for dut in ApData.device_handles:
        log.banner("increasing the glean trap meter rate on each LC")
        for lc_obj in dut.lc_locations:
            try:
                dut.lpts.set_lpts_punt_police_exception("adjacency", ApData.glean_adjacency_trap_rate , lc_obj.location)
            except:
                log.warning(f" glean trap meter rate has not changed on {dut.name} ")

    if error_list:
        raise CafyException.CompositeError(error_list)


def teardown_module(self):
    """
        Tears down the module by cleaning up configurations and disconnecting devices.
    """
    #pusing data to violet dashboard
    if hasattr(ApData,"mgbl_enabled") and ApData.mgbl_enabled :
        log.info("Data to push to db: %s",ApData.data_to_push_to_db)
        VioletDataUtils.violet_gather_data(ApData.R1, ApData.zap, interface_dict=ApData.zap.get_interfaces(device=ApData.R1))
        dashboard = ScaleDashboard()
        device_info = ApData.R1.violet_info.inventory_data["chassis"]
        software_info = ApData.R1.violet_info.device_data
        response = dashboard.post_scale_data(scale_data= ApData.data_to_push_to_db, work_dir_path= CafyLog.work_dir,
                                                submitter_id= CafyLog.user_name, device_details= device_info,
                                                software_details= software_info)
        log.info(f"Response : {response}")

    if hasattr(ApData, "set_v6_short_etm_qos"):
        dut = ApData.R1
        dut.qos_hw_obj.set_ipv6_short_etm_qos_disable()
        del ApData.set_v6_short_etm_qos
        Helper.sleep(10,'Wait for UUT to stabilise after config')

        log.info("Post unconfiguring cli - hw-module profile qos ipv6 short-etm, Reloading UUT router")
        router_reload_trigger = dut.event.ReloadAllCards(inv_obj=dut.inventory)
        router_reload_trigger.run()
        Helper.sleep(120,'Wait for UUT to stabilise after reload')

        if ApData.mode == "ydk":
            dut.disconnect()
            dut.connect()
    #Disabling Logstash
    if ApData.sim:
        log.banner("Logstash integration for debug ltrace collection")
        if ApData.zap.get_parameters("logstash_config") == True:
            try:
                log.banner("Disabling LOGSTASH")
                logstash = Ltrace()
                logstash_debug_bck = {"R1": ["show ofa trace", "show cef trace"],
                                        "R2": ["show ofa trace", "show cef trace"],
                                        "R3": ["show ofa trace", "show cef trace"]}
                logstash.enable_logstash_services_input(ApData.zap, logstash_type="setup_module", enable=False,
                                                        idt="Setup_module", logstash_debug_bck=logstash_debug_bck)
            except Exception as ee:
                log.info(f"LOGSTASH configuration failed with error : {ee}")
    try:
        for dut in ApData.device_handles:
            log.banner("setting the glean trap meter value back to default")
            #setting the glean trap meter rate back to default
            for lc_obj in dut.lc_locations:
                try:
                    dut.lpts.set_lpts_punt_police_exception("adjacency", ApData.glean_adjacency_default_trap_rate , lc_obj.location)
                except:
                    log.warning(f" glean trap meter rate has not changed on {dut.name} ")

            dut.disconnect()
        ApData.tgn_obj.tgn_disconnect()
    except Exception as err:
        log.error(err)
        log.error("Tear Down Module")
    finally:
        if ApData.sim:
            for dut in ApData.device_handles:
                dut.sr.ssh_debug_collect()


class BasicBundleChecks():
    """
        Base class to define setup and teardown methods for all test cases.
    """
    def setup_method(self):
        """
            Setup method to be called before every test case.
        """
        log.banner("setup method that runs for every testcase")
        ApData.R1.ifmgr.get_show_interfaces_summary()
        ApData.R1.BundleMgr.get_bundle_brief()
        ApData.R1.isis.get_isis_neighbors(refresh=True)
        with pytest.allure.step("Clear asic errors and syslog before proceeding to the testcase"):
            for platform, data in ApData.platforms.items():
                if (re.match(platform, ApData.R1.platform) and data.get('verify_asic_error')) == True:
                    ApData.R1.chipfmea.clear_all_asic_errors()

    def teardown_method(self):
        """
            Teardown method to be called after every test case.
        """
        log.banner("teardown method that runs for every testcase")
        ApData.R1.ifmgr.get_show_interfaces_summary()
        ApData.R1.BundleMgr.get_bundle_brief()
        ApData.R1.isis.get_isis_neighbors(refresh=True)
        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('verify_asic_error')) == True:
                ApData.R1.chipfmea.validate_asic_errors(known_asic_err_dict=ApData.known_asic_err_dict,
                                                    unexpected_asic_err_dict=ApData.unexpected_asic_err_dict,
                                                    expected_asic_err_dict=ApData.expected_asic_err_dict,fail_on_extra=None)

@pytest.mark.Feature("BundleLacp")
class TestBundlemgrFunctionality(BasicBundleChecks,BundleApBase):
    """
        TestBundlemgrFunctionality
    """
    @classmethod
    def setup_class(self,lacp='on'):
        """
            Sets up the test class for bundle manager scale testing.
            This method configures base interfaces, retrieves bundle information,
            sets up IS-IS protocol, and starts/stops traffic generator protocols
            as part of the test setup.
        """
        BundleApBase.configure_base_interfaces(ApData.zap,
                                                connection_mode=ApData.mode,
                                                configure_ipv4_address=ApData.configure_ipv4_address,
                                                configure_ipv6_address=ApData.configure_ipv6_address)
        self.testcase_name = self.__name__
        self.bundle_info = BundleApBase.get_bundle_info(lacp=lacp)
        self.ping_ipv4 = [] if not ApData.configure_ipv4_address else self.bundle_info['cross_ipv4_ping_list'] + \
            self.bundle_info['self_ipv4_ping_list']
        self.ping_ipv6 = [] if not ApData.configure_ipv6_address else self.bundle_info['cross_ipv6_ping_list'] + \
            self.bundle_info['self_ipv6_ping_list']
        self.bundle_name = self.bundle_info['bundles_list'][0]
        self.bundle_id = self.bundle_info['bundle_id'][0]
        self.bundle_short_list = self.bundle_info['bundles_short_name_list'][0]
        self.basic_test = TestBundlemgrBasicChecks()
        self.bundle_members = BundleApBase.get_bundle_members(
            ApData.R1, self.bundle_id)
        self.bundle_member_names = [item.name for item in self.bundle_members]
        self.bundle_interface = f"Bundle-Ether{self.bundle_id}"

        BundleApBase.configure_base_isis(
            ApData.zap, connection_mode=ApData.mode)
        BundleApBase.verify_isis_neighbors(retries=3)
        BundleApBase.verify_isis_routes()
        ApData.tgn_obj.stop_all_protocols()
        Helper.sleep(30,"stopping protocols")
        ApData.tgn_obj.start_all_protocols()
        Helper.sleep(30,"starting protocols")
        log.banner("starting arp")
        ApData.tgn_obj.start_arp( )
        self.basic_test.test_verify_traffic()

    @classmethod
    def teardown_class(self):
        """
            Class teardown method to clean up after tests.

            This method unconfigures the base ISIS configuration and deletes
            the created interfaces.
        """
        BundleApBase.configure_base_isis(
            ApData.zap, connection_mode=ApData.mode, mode="unconfig")
        BundleApBase.delete_interfaces()

    def test_lacp_counters(self):
        """
            test_lacp_counters

            This test verifies the following:

            - Verifies if the counters increases when lacp short is configured

            Configuration: ISIS/IPv4 Lacp short

            Verification:
            - Verify Counter stats : Run "show lacp counters"  to verify the RX/TX values

            Triggers: None

        """
        self.test_name = "test_lacp_counters"
        log.banner('In Testcase '  + self.test_name)

        wait_time = ApData.zap.get_testcase_configuration(
            self.test_name).get("wait_time")
        buffer_wait_time = ApData.zap.get_testcase_configuration(
            self.test_name).get("buffer_wait_time")
        wait_time_with_no_lacp_short = ApData.zap.get_testcase_configuration(
            self.test_name).get("wait_time_with_no_lacp_short")
        buffer_wait_time_with_no_lacp_short = ApData.zap.get_testcase_configuration(
            self.test_name).get("buffer_wait_time_with_no_lacp_short")
        sleep_time = ApData.zap.get_testcase_configuration(
            self.test_name).get("sleep_time")
        test_devices = self.bundle_info['bundle_device_list'][self.bundle_name]
        error_list = []
        repeat_lacp_verification = False
        try:
            self.basic_test.test_bundle_bringup_with_lacp(verify_traffic=True)
        except Exception as err:
            log.error(err)
            error_list.append(err)

        try:
            with ApData.topo.config(*test_devices, thread=True):
                for device in test_devices:
                    device.bundlemgr.config_bundle_lacp_short(self.bundle_name)
        except Exception as err:
            log.error("Bundle lacp short config failed")
            error_list.append(err)

        #gettting response time for mbgl 1d scale
        if hasattr(ApData,"mgbl_enabled") and ApData.mgbl_enabled :
            kpi_id = "10041"
            ApData.data_to_push_to_db.setdefault(kpi_id, {})
            BundleApBase.get_resposnce_time_mgbl(ApData=ApData,device = ApData.R1,
                                                        kpi_id=kpi_id,
                                                        scale_qualified="1",
                                                        xpath=ApData.mgbl_config["bundle_brief_xpath"])

        if ApData.upload_to_xrvault:
            # get LC info of one of the bundles - BE1
            intf_objects =  ApData.R1.get_interfaces()
            nodes = ApData.R1.inventory.get_sysadmin_node_status()
            lc_location = str(BundleApBase.get_hw_locations_of_interface(interface=intf_objects[self.bundle_name], device=ApData.R1))[2:-2]
            lc_pid = None
            for node in nodes:
                if node.location in lc_location:
                    lc_pid = node.card_type.upper()
                    break

            # call XR Vault method to push lacp bundle short details
            log.banner("we have lacp period short configured on a bundle BE1")
            BundleApBase.push_data_to_vault(scale_id=10041, scale_category='interfaces', scale_sub_category='Bundle Interfaces',
                                            profile='LACP Timer (short in seconds)', scale_per_npu='', scale_per_lc='',
                                            scale_per_system=str('1 sec'), lc_pid=lc_pid)

        try:
            BundleApBase.check_lacp_period_short_consistency(device=test_devices[0], bundle_id=self.bundle_id,
                                                                wait_time=wait_time, buffer_wait_time=buffer_wait_time)
        except Exception as err:
            log.error(err)
            log.error("LACP verification failed. Trying for the second time")
            repeat_lacp_verification = True

        if repeat_lacp_verification:
            try:
                BundleApBase.check_lacp_period_short_consistency(device=test_devices[0], bundle_id=self.bundle_id,
                                                                    wait_time=wait_time, buffer_wait_time=buffer_wait_time)
            except Exception as err:
                log.error(err)
                error_list.append(err)

        try:
            with ApData.topo.config(*test_devices, thread=True):
                for device in test_devices:
                    device.bundlemgr.config_bundle_lacp_short(
                        self.bundle_name, config_mode='unconfig')
        except Exception as err:
            log.error("Bundle lacp short unconfig failed")
            error_list.append(err)

        try:
            BundleApBase.check_lacp_period_short_consistency(device=test_devices[0], bundle_id=self.bundle_id,
                                                                wait_time=wait_time_with_no_lacp_short,
                                                                buffer_wait_time=buffer_wait_time_with_no_lacp_short,
                                                                sleep_time=sleep_time)
        except Exception as err:
            log.error(err)
            error_list.append(err)

        if error_list:
            raise CafyException.CompositeError(error_list)


@pytest.mark.Feature("BundleLacp")
class TestBundlemgrInterfaceTriggers(BasicBundleChecks,BundleApBase):
    """
        TestBundlemgrInterfaceTriggers
    """

    @classmethod
    def setup_class(self, lacp='on'):
        """
            Description: This method sets up the initial configuration and environment for the Bundle Manager 1D scale test.

            Configuration:
            - Configures base interfaces with IPv4 and IPv6 addresses if enabled.
            - Retrieves and sets up bundle information, including bundle names, IDs, and members.
            - Configures ACLs, QoS, Segment Routing (SR), multicast, and NetFlow based on platform-specific requirements.
            - Configures ISIS neighbors and routes.

            Verification:
            - Verifies ISIS neighbors and routes.
            - Performs traffic verification to ensure the setup is functioning as expected.

        """
        BundleApBase.configure_base_interfaces(ApData.zap,
                                                connection_mode=ApData.mode,
                                                configure_ipv4_address=ApData.configure_ipv4_address,
                                                configure_ipv6_address=ApData.configure_ipv6_address)

        self.testcase_name = self.__name__
        self.configure_acl = ApData.zap.get_testcase_configuration(
            self.testcase_name).get("configure_acl")
        self.verify_acl = ApData.zap.get_testcase_configuration(
            self.testcase_name).get("verify_acl")
        self.bundle_info = BundleApBase.get_bundle_info(lacp=lacp)
        self.ping_ipv4 = [] if not ApData.configure_ipv4_address else self.bundle_info['cross_ipv4_ping_list'] + \
            self.bundle_info['self_ipv4_ping_list']
        self.ping_ipv6 = [] if not ApData.configure_ipv6_address else self.bundle_info['cross_ipv6_ping_list'] + \
            self.bundle_info['self_ipv6_ping_list']
        self.bundle_name = self.bundle_info['bundles_list'][0]
        self.bundle_id = self.bundle_info['bundle_id'][0]
        self.bundle_short_list = self.bundle_info['bundles_short_name_list'][0]
        self.basic_test = TestBundlemgrBasicChecks()
        self.bundle_members = BundleApBase.get_bundle_members(
            ApData.R1, self.bundle_id)
        self.bundle_member_names = [item.name for item in self.bundle_members]
        self.bundle_interface = f"Bundle-Ether{self.bundle_id}"
        self.peer_device_to_acl_name_mapping = BundleApBase.get_peer_by_acls()
        self.af_name_list = ["ipv4", "ipv6"]
        ApData.traffic_stream_list_with_multicast = ApData.traffic_stream_list + \
            ApData.traffic_stream_list_multicast
        ApData.platforms = ApData.zap.get_base_configuration("platform")
        BundleApBase.configure_base_isis(
            ApData.zap, connection_mode=ApData.mode)

        BundleApBase.verify_isis_neighbors(retries=3)
        BundleApBase.verify_isis_routes()
        if self.configure_acl:
            BundleApBase.configure_base_acl()

        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('config_qos')) == True:
                BundleApBase.bundle_qos_config(ApData)
                BundleApBase.bundle_qos_config_on_interfaces(ApData)

        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('config_sr')) == True:
                BundleApBase.bundle_sr_config(instance=ApData.zap.get_feature_configuration("isis/R1/instance")[0]['instance_name'],
                                                af_name_list=self.af_name_list, saf_name="unicast", sr_list=["mpls", "bundle-member-adj-sid"])
                BundleApBase.bundle_sr_config_interface(
                    af='ipv4', prefix_sid_type="absolute", prefix_sid_value=16000)
        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('config_multicast')) == True:
                BundleApBase.bundle_multicast_config(ApData)
        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('config_netflow')) == True:
                BundleApBase.bundle_netflow_config(ApData)
        self.basic_test.test_verify_traffic()

    def test_one_member_in_one_bundle_for_all_interfaces(self):
        """
            test_one_member_in_one_bundle_for_all_interfaces

            Remove base interface config and then move each interface to one bundle each for all
            interfaces for all routers.

            This test verifies the following:
            - Verify Bundle members can be shut/no-shut and traffic flows through bundle
            - Verify Traffic

            Configuration: ISIS/IPv4/IPv6 Traffic

            Verification:
            - Verify Traffic Stats : Checks TGEN Traffic by comparing the values of RX/TX packet counts on the transmitted and received ports
            - Verify shut/no_shut bundle members while traffic flows

            Triggers: Move one member to one bundle for all interfaces

        """
        self.test_name = 'test_one_member_in_one_bundle_for_all_interfaces'
        error_list = []

        uut = ApData.R1
        peer_devices = [ApData.R2, ApData.R3]
        test_devices = [uut] + peer_devices
        members_lacp_mode = ApData.zap.get_testcase_configuration(
            self.test_name).get("member_lacp_mode")
        bundle_keywords = ApData.zap.get_testcase_configuration(
            self.test_name).get("bundle_keywords")
        isis_info = ApData.zap.get_testcase_configuration(
            self.test_name).get("isis_info")
        new_bundles_loss_duration_limit = ApData.zap.get_testcase_configuration(
            self.test_name).get("new_bundles_loss_duration_limit")
        base_bundles_loss_duration_limit = ApData.zap.get_testcase_configuration(
            self.test_name).get("base_bundles_loss_duration_limit")
        mtu = ApData.zap.get_testcase_configuration(self.test_name).get("mtu")
        peer_by_acls = BundleApBase.get_peer_by_acls()

        with pytest.allure.step("Start traffic"):
            BundleApBase.traffic_cleanup(ApData)
            ApData.tgn_obj.start_traffic(ApData.traffic_stream_list)
            Helper.sleep(15, msg='Waiting for traffic ...')

        with pytest.allure.step("Remove base isis configuration"):
            try:
                BundleApBase.configure_base_isis(
                    ApData.zap, connection_mode=ApData.mode, mode="unconfig")
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Remove all interfaces configuration except tgn and loopbacks"):
            try:
                interfaces_to_delete = {}
                for device in test_devices:
                    interfaces_to_delete[device] = [if_name for if_name, if_obj in ApData.zap.get_interfaces(by_name=True, group="base_setup",
                                                                                                        device=device, sub_interfaces=True).items()
                                                    if 'bundle' in if_name.lower() or if_obj.remote and if_obj.remote.type.lower() != 'tgn']
                BundleApBase.delete_interfaces(
                    interfaces_per_device=interfaces_to_delete)
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Get all interfaces from zap and sort for one member per bundle"):
            try:
                uut_interfaces = {if_name: if_obj for if_name, if_obj in ApData.zap.get_interfaces(device=uut, group="base_setup",
                                    by_name=True).items() if 'gi' in if_name.lower() and if_obj.remote and if_obj.remote.type.lower() != 'tgn'}
                sorted_new_interfaces = BundleApBase.get_sorted_interfaces_by_device_with_ip(uut_interfaces, device=uut, peer_devices=peer_devices,
                                                                                                                                **bundle_keywords)
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Set new bundles with one member each"):
            try:
                with ApData.topo.config(*test_devices, thread=True):
                    for device in test_devices:
                        for interface_tuple in sorted_new_interfaces[device]:
                            device.bundlemgr.add_bundle_interface(
                                device.bundlemgr.BundleInterface(**dict(interface_tuple._asdict())))
                            device.ifmgr.noshut(interface_tuple.member_name)
                            device.ifmgr.add_bundle_interface(
                                interface_tuple.member_name, bundle_id=interface_tuple.bundle_id, port_activity=members_lacp_mode)
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step(f"Set bundles mtu to {mtu}"):
            try:
                with ApData.topo.config(*test_devices, thread=True):
                    for device in test_devices:
                        interface_names = [
                            intf.interface_name for intf in sorted_new_interfaces[device]]
                        device.ifmgr.set_mtu(interface_names, mtu=mtu)
            except Exception as err:
                error_list.append(err)

        # Add acl config
        with ApData.topo.config(*[uut], thread=True):
            if self.configure_acl:
                for device in peer_devices:
                    peer_interface_names = [
                        intf.interface_name for intf in sorted_new_interfaces[device]]
                    for interface in peer_interface_names:
                        for acl in peer_by_acls[device]:
                            uut.acl.set_acl_to_interface(access_list_name=acl.acl_name, address_family=acl.address_family,
                                                            direction=acl.direction, interface=interface, mode='config')

        with pytest.allure.step("Get tgn connections and loopbacks"):
            try:
                tgn_loopback_interfaces = defaultdict(dict)
                for device in test_devices:
                    interfaces = {if_name: if_obj for if_name, if_obj in ApData.zap.get_interfaces(device=device,
                                    group="base_setup", by_name=True).items() if 'loopback' in if_name.lower() or if_obj.remote
                                    and if_obj.remote.type.lower() == 'tgn'}
                    tgn_loopback_interfaces[device] = interfaces
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Set isis for all existing tgns, loopbacks, and new bundles"):
            try:
                for device in test_devices:
                    isis_interfaces = [intf_obj.interface_name for intf_obj in sorted_new_interfaces[device]] + [
                        if_name for if_name in tgn_loopback_interfaces[device]]
                    device.isis.config_isis_instance(instance_name=isis_info['isis_instance'], net_id=isis_info[device.alias]['net_id'],
                                                        level=isis_info['level'], nsr=isis_info['nsr'], nsf=isis_info['nsf'],
                                                        af_name=isis_info['af_name'][0], metric_style=isis_info['metric_style'],
                                                        connected_route_is_presence=isis_info['redistribute_connected'])
                    device.isis.config_isis_instance(instance_name=isis_info['isis_instance'], net_id=isis_info[device.alias]['net_id'],
                                                        level=isis_info['level'], nsr=isis_info['nsr'], nsf=isis_info['nsf'],
                                                        af_name=isis_info['af_name'][1], metric_style=isis_info['metric_style'],
                                                        connected_route_is_presence=isis_info['redistribute_connected'])
                    device.isis.config_isis_interface(instance_name=isis_info['isis_instance'], interfaces=isis_interfaces,
                                                        level=isis_info['level'], hello_padding=isis_info['hello_padding'],
                                                        af_name=isis_info['af_name'][0], saf_name=isis_info['saf_name'],
                                                        metric=isis_info['metric'])
                    device.isis.config_isis_interface(instance_name=isis_info['isis_instance'], interfaces=isis_interfaces,
                                                        level=isis_info['level'], hello_padding=isis_info['hello_padding'],
                                                        af_name=isis_info['af_name'][1], saf_name=isis_info['saf_name'],
                                                        metric=isis_info['metric'])
            except Exception as err:
                error_list.append(err)
            BundleApBase.verify_isis_routes()

        with pytest.allure.step("Verify traffic"):
            try:
                Helper.sleep(15, msg='Waiting for traffic after trigger ...')
                ApData.tgn_obj.stop_traffic()
                # 118000ms-110500ms-need-need  # After acl addition, SF-D goes to 194305ms
                traffic_stats, _ = ApData.tgn_obj.verify_traffic(tolerance=100)
                BundleApBase.verify_traffic_loss_duration(
                    traffic_stats=traffic_stats, error_list=error_list, loss_duration_limit=new_bundles_loss_duration_limit)
            except Exception as err:
                error_list.append(err)
            finally:
                ApData.tgn_obj.clear_traffic_stats()

        #getting respose time to upload to violet dashboard for 1d mgbl scale
        if hasattr(ApData,"mgbl_enabled") and ApData.mgbl_enabled :
            intf_summary = ApData.R1.ifmgr.get_show_interfaces_summary()
            for each_intf_type in intf_summary:
                if each_intf_type.interface_type == 'ift_etherbundle':
                    total_up_bundles = int(each_intf_type.up)
                    total_bundles = int(each_intf_type.total)
                    break
            kpi_id = ["10028", "10029"]
            for kpi in kpi_id:
                ApData.data_to_push_to_db.setdefault(kpi, {})
            BundleApBase.get_resposnce_time_mgbl(ApData=ApData,device = ApData.R1,
                                                        kpi_id=kpi_id,
                                                        scale_qualified=str(total_up_bundles),
                                                        xpath=ApData.mgbl_config["bundle_brief_xpath"])

        if ApData.upload_to_xrvault:
            intf_summary = ApData.R1.ifmgr.get_show_interfaces_summary()
            for each_intf_type in intf_summary:
                if each_intf_type.interface_type == 'ift_etherbundle':
                    total_up_bundles = int(each_intf_type.up)
                    total_bundles = int(each_intf_type.total)
                    break
            log.banner(f'Total number of L3 Bundles configured in UUT-R1: {total_bundles}')
            log.banner(f'Total number of L3 Bundles UP in UUT-R1: {total_up_bundles}')

            # get LC info of one of the bundles - BE1
            intf_objects = ApData.R1.get_interfaces()
            nodes = ApData.R1.inventory.get_sysadmin_node_status()
            lc_location = str(BundleApBase.get_hw_locations_of_interface(interface=intf_objects['Bundle-Ether1'], device=ApData.R1))[2:-2]
            lc_pid = None
            for node in nodes:
                if node.location in lc_location:
                    lc_pid = node.card_type.upper()
                    break
            # call XR Vault method to push l3 bundles scale number
            log.banner("we have l3 bundles scaled on system ")
            log.banner("This scale number depends on the POD in which script runs")
            BundleApBase.push_data_to_vault(scale_id=10028, scale_category='interfaces', scale_sub_category='Bundle Interfaces',
                                            profile='Interface-Bundle scale system level', scale_per_npu='', scale_per_lc='',
                                            scale_per_system=str(total_up_bundles), lc_pid=lc_pid)
            BundleApBase.push_data_to_vault(scale_id=10029, scale_category='interfaces', scale_sub_category='Bundle L3 Interfaces',
                                            profile='Interface-L3 Bundle scale system level', scale_per_npu='', scale_per_lc='',
                                            scale_per_system=str(total_up_bundles), lc_pid=lc_pid)

        with pytest.allure.step("Run basic checks"):
            try:
                bundle_name_list = [
                    intf_obj.interface_name for intf_obj in sorted_new_interfaces[ApData.R1]]
                uut_interfaces_list = [
                    intf_obj.interface_name for device in peer_devices for intf_obj in sorted_new_interfaces[device]]
                self.basic_test.test_bundle_bringup(lacp='on', dynamic=True, bundle_name_list=bundle_name_list,
                                                    uut_interfaces_list=uut_interfaces_list, vlan=False,
                                                    dynamic_bundles=True)
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Verify acl"):
            try:
                BundleApBase.verify_acl(
                    configure_acl=self.configure_acl, verify_acl=self.verify_acl)
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Start traffic"):
            BundleApBase.traffic_cleanup(ApData)
            ApData.tgn_obj.start_traffic(ApData.traffic_stream_list)
            Helper.sleep(15, msg='Waiting for traffic ...')

        with pytest.allure.step("Remove isis for all existing tgns and new bundles"):
            try:
                for device in test_devices:
                    device.isis.config_isis_instance(
                        instance_name=isis_info['isis_instance'], unconfig=True)
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Remove new bundles with one member each configuration"):
            try:
                interfaces_to_delete = defaultdict(list)
                if ApData.verify_global_id_npu:
                    try:
                        interfaces_list = uut_interfaces
                        log.info(f'Getting the snapshot of global ids for the interfaces: {interfaces_list}')
                        global_id_snapshot = BundleApBase.get_global_id(uut, interfaces_list)
                    except Exception as err:
                        error_list.append(err)
                for device in test_devices:
                    for Interface in sorted_new_interfaces[device]:
                        interfaces_to_delete[device].extend(
                            [Interface.interface_name, Interface.member_name])
                BundleApBase.delete_interfaces(
                    interfaces_per_device=interfaces_to_delete)
            except Exception as err:
                error_list.append(err)

        if ApData.verify_global_id_npu:
            try:
                log.info(f"Getting the current values of global ids for the interfaces: {interfaces_list}")
                global_id_current = BundleApBase.get_global_id(uut, interfaces_list)
                BundleApBase.verify_global_id(uut, global_id_snapshot, global_id_current)
            except:
                log.info("Global id might or might not change")

        with pytest.allure.step("Set base interface configuration"):
            try:
                BundleApBase.configure_base_interfaces(ApData.zap,
                                                        connection_mode=ApData.mode,
                                                        configure_ipv4_address=ApData.configure_ipv4_address,
                                                        configure_ipv6_address=ApData.configure_ipv6_address)
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Set base isis configuration"):
            try:
                BundleApBase.configure_base_isis(
                    ApData.zap, connection_mode=ApData.mode)
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Set acl configuration"):
            try:
                if self.configure_acl:
                    BundleApBase.configure_base_acl()
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Set qos configuration on interface"):
            for platform, data in ApData.platforms.items():
                if (re.match(platform, ApData.R1.platform) and data.get('config_qos')) == True:
                    BundleApBase.bundle_qos_config_on_interfaces(ApData)

        with pytest.allure.step("Verify traffic"):
            try:
                Helper.sleep(15, msg='Waiting for traffic after trigger ...')
                ApData.tgn_obj.stop_traffic()
                # 111000ms-92800ms-need-need <- Before ACL config add, after SF-D - 106401ms
                traffic_stats, _ = ApData.tgn_obj.verify_traffic(tolerance=100)
            except Exception as err:
                error_list.append(err)
            finally:
                ApData.tgn_obj.clear_traffic_stats()

        with pytest.allure.step("Run basic checks"):
            try:
                self.basic_test.test_bundle_bringup()
            except Exception as err:
                error_list.append(err)

            try:
                self.basic_test.test_bundle_bringup_with_lacp()
            except Exception as err:
                error_list.append(err)

        with pytest.allure.step("Verify acl"):
            try:
                BundleApBase.verify_acl(
                    configure_acl=self.configure_acl, verify_acl=self.verify_acl)
            except Exception as err:
                error_list.append(err)

        if ApData.verify_global_id_npu:
            try:
                log.info(f"Getting the current values of global ids for the interfaces: {interfaces_list}")
                global_id_current = BundleApBase.get_global_id(ApData.R1, interfaces_list)
                BundleApBase.verify_global_id(ApData.R1, global_id_snapshot, global_id_current)
            except:
                log.info("Global id might or might not change")

        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('verify_qos')) == True:
                try:
                    BundleApBase.bundle_qos_verify(ApData, ApData.qos_tolerance)
                except Exception as err:
                    error_list.append(err)

        with pytest.allure.step("Checking for any errors"):
            if error_list:
                raise CafyException.CompositeError(error_list)

    @pytest.mark.parametrize('devices', [['R2']], ids=['R2 side only'])
    def test_add_remove_all_members_to_one_bundle(self, devices):
        """
            test_add_remove_all_members_to_one_bundle

            Add/remove all bundle members (up to weighted bundle limit of 64) to one bundle while traffic flows only on one bundle on each side

            This test verfies the following:
            - Verify Bundle members can be added/removed and traffic flows through bundle
            - Verify Traffic

            Configuration: ISIS/IPv4/IPv6 Traffic

            Verification:
            - Verify Traffic Stats : Checks TGEN Traffic by comparing the values of RX/TX packet counts on the transmitted and received ports
            - Verify add/remove bundle members while traffic flows

            Triggers: Add/Remove all members to one bundle

        """
        self.test_name = "test_add_remove_all_members_to_one_bundle"
        log.banner('In Testcase ' + self.test_name)
        upload_data_flag = False

        total_bundle_weight_max = ApData.zap.get_testcase_configuration(
            self.test_name).get("total_bundle_weight_max")
        max_bundle_member_count = ApData.zap.get_testcase_configuration(
            self.test_name).get("max_bundle_member_count")
        add_loss_duration_limit = ApData.zap.get_testcase_configuration(
            self.test_name).get("add_loss_duration_limit")
        remove_loss_duration_limit = ApData.zap.get_testcase_configuration(
            self.test_name).get("remove_loss_duration_limit")

        # Initialize composite error list to empty list
        error_list = []

        # Obtain Object Test Devices
        uut = ApData.R1
        device_handles = []
        for device in devices:
            device_handles.append(ApData.zap.get_device(device))

        # Account for non-impacted bundles on non-impacted device side
        non_impacted_device = None
        if len(device_handles) == 1:
            non_impacted_device = ApData.R3 if device_handles[0] is ApData.R2 else ApData.R2

        # Obtain all bundle members that can be moved to random bundle
        # and members to discard due to limits
        bundle_members_adjustment_data = BundleApBase.determine_max_members_to_add_to_bundle(device_handles, non_impacted_device,
                                                                                                total_bundle_weight_max=total_bundle_weight_max,
                                                                                                max_bundle_member_count=max_bundle_member_count)

        test_devices = device_handles + [uut]

        log.banner('In Testcase ' + self.test_name + ': Starting traffic')
        BundleApBase.traffic_cleanup(ApData)
        ApData.tgn_obj.start_traffic(ApData.traffic_stream_list)
        Helper.sleep(15, msg='Waiting for traffic ...')

        # Remove all other members and add what members that can be added to random bundle
        disregard_interfaces = set()
        uut_not_active_bundles = {if_name for if_name, _ in ApData.zap.get_interfaces(
            by_name=True, device=uut, group="base_setup").items() if 'bundle' in if_name.lower()}
        try:
            with ApData.topo.config(*test_devices, thread=True):
                for peer_device in device_handles:
                    other_members_obj = bundle_members_adjustment_data[peer_device]
                    other_members_to_add = other_members_obj['other_members_to_add']
                    peer_other_members_to_add_list = [
                        member.peer_member for member in other_members_to_add]
                    uut_other_members_to_add_list = [
                        member.uut_member for member in other_members_to_add]
                    other_members_not_added = other_members_obj['other_members_not_added']
                    peer_other_members_not_added_list = [
                        member.peer_member for member in other_members_not_added]
                    uut_other_members_not_added_list = [
                        member.uut_member for member in other_members_not_added]
                    random_bundle_id = other_members_obj['random_bundle_id']

                    if ApData.verify_global_id_npu:
                        try:
                            interfaces_list = uut_other_members_to_add_list
                            log.info(f"Getting the snapshot of global ids for the interfaces: {interfaces_list}")
                            global_id_snapshot = BundleApBase.get_global_id(uut, interfaces_list)
                        except Exception as err:
                            error_list.append(err)

                    # Remove all members from other bundles
                    peer_device.ifmgr.remove_bundle_interface(
                        peer_other_members_to_add_list)
                    peer_device.ifmgr.remove_bundle_interface(
                        peer_other_members_not_added_list)
                    uut.ifmgr.remove_bundle_interface(
                        uut_other_members_to_add_list)
                    uut.ifmgr.remove_bundle_interface(
                        uut_other_members_not_added_list)

                    if ApData.verify_global_id_npu:
                        try:
                            log.info(f"Getting the current values of global ids for the interfaces: {interfaces_list}")
                            global_id_current = BundleApBase.get_global_id(uut, interfaces_list)
                            BundleApBase.verify_global_id(uut, global_id_snapshot, global_id_current)
                        except Exception as err:
                            error_list.append(err)

                    # Add all members to be added to random bundle
                    peer_device.ifmgr.add_bundle_interface(
                        peer_other_members_to_add_list, random_bundle_id, port_activity='active')
                    uut.ifmgr.add_bundle_interface(
                        uut_other_members_to_add_list, random_bundle_id, port_activity='active')

                    if ApData.verify_global_id_npu:
                        try:
                            log.info(f"Getting the current values of global ids for the interfaces: {interfaces_list}")
                            global_id_current = BundleApBase.get_global_id(uut, interfaces_list)
                            BundleApBase.verify_global_id(uut, global_id_snapshot, global_id_current)
                        except Exception as err:
                            error_list.append(err)

                    # Note which interfaces and bundles should not be used for acl checks
                    disregard_interfaces.update(set(uut_other_members_not_added_list))
                    uut_not_active_bundles.remove(f'Bundle-Ether{random_bundle_id}')
        except Exception as err:
            log.error(err)
            error_list.append(err)

        try:
            Helper.sleep(15, msg='Waiting for traffic after trigger ...')
            ApData.tgn_obj.stop_traffic()
            traffic_stats, _ = ApData.tgn_obj.verify_traffic(
                tolerance=100)  # 351ms-356ms-1036ms-311ms
            if random_bundle_id == '3':
                BundleApBase.verify_traffic_loss_duration(
                traffic_stats=traffic_stats, error_list=error_list, loss_duration_limit=add_loss_duration_limit)
            else:
                BundleApBase.verify_traffic_loss_duration(
                traffic_stats=traffic_stats, error_list=error_list, loss_duration_limit=remove_loss_duration_limit)
        except Exception as err:
            error_list.append(err)
        finally:
            ApData.tgn_obj.clear_traffic_stats()

        random_bundle_data = ApData.R1.bundlemgr.get_bundle(bundle_id=random_bundle_id)
        members_in_random_bundle = random_bundle_data[0].local_links_configured
        # verify members in random bundle are in up state
        try:
            BundleApBase.check_verify_bundle_ether(test_devices, members_in_random_bundle, random_bundle_id , status='Up')
            upload_data_flag = True
        except Exception as err:
            log.info("all the members in the random bundle are not in up state")
            error_list.append(err)

        # Verify bundle status
        try:
            BundleApBase.check_active_bundle_status(
                bundle_members_adjustment_data['active_uut_bundles_only'])
        except Exception as err:
            log.error(err)
            error_list.append(err)

        #gettting response time for mbgl 1d scale
        if hasattr(ApData,"mgbl_enabled") and ApData.mgbl_enabled and upload_data_flag:
            kpi_id = ["10016"]
            for kpi in kpi_id:
                ApData.data_to_push_to_db.setdefault(kpi, {})
            bundle_name = bundle_members_adjustment_data['active_uut_bundles_only'][0]
            bundle_ether_obj = ApData.R1.bundlemgr.get_bundle(bundle_name[-1])
            number_of_members = str(len(bundle_ether_obj[0].port.keys()))
            BundleApBase.get_resposnce_time_mgbl(ApData=ApData,device = ApData.R1,
                                                        kpi_id=kpi_id,
                                                        scale_qualified=number_of_members,
                                                        xpath=ApData.mgbl_config["bundle_brief_xpath"])


        if ApData.upload_to_xrvault and upload_data_flag:
            # calling XR Vault only in 1st parameterized scenario
            # get LC info of BE, where member is moved to one single bundle
            intf_objects = ApData.R1.get_interfaces()
            nodes = ApData.R1.inventory.get_sysadmin_node_status()
            bundle_name = bundle_members_adjustment_data['active_uut_bundles_only'][0]
            # here lc_location can have 2 locations: example: {'0/1/cpu0', '0/0/cpu0'}, however we use any one location
            lc_locations = BundleApBase.get_hw_locations_of_interface(interface=intf_objects[bundle_name], device=ApData.R1)
            lc_pid = None
            for node in nodes:
                if node.location in lc_locations:
                    lc_pid = node.card_type.upper()
                    break

            # get member count
            bundle_ether_obj = ApData.R1.bundlemgr.get_bundle(bundle_name[-1])
            number_of_members = str(len(bundle_ether_obj[0].port.keys()))

            # call XR Vault method to push bundle member scale number
            log.banner(f'we have {number_of_members} members in bundle {bundle_name} in R1-UUT')
            BundleApBase.push_data_to_vault(scale_id=10016, scale_category='interfaces', scale_sub_category='Members/Bundle',
                                            profile='Interface-Bundle member scale', scale_per_npu='', scale_per_lc='',
                                            scale_per_system=number_of_members, lc_pid=str(lc_pid))

        # Obtain ping lists for only active bundles
        ping_ipv4, ping_ipv6 = BundleApBase.get_specific_bundle_ping_info(
            bundle_members_adjustment_data['active_uut_bundles_only'])

        try:
            log.info("Verify cross and self ping over bundles")
            BundleApBase.verify_ipv4_ipv6_ping(
                device_list=ApData.uut_list, ipv4=ping_ipv4, ipv6=ping_ipv6)
        except Exception as err:
            log.error(err)
            error_list.append(err)
        # Verify traffic
        try:
            BundleApBase.verify_isis_neighbors(retries=3)
            BundleApBase.verify_isis_routes()
            log.info("Verify traffic")
            traffic_stats = BundleApBase.verify_traffic_stats(
                traffic_stream_list=ApData.traffic_stream_list)
            traffic_list = []
            for traffic_stream in ApData.traffic_stream_list:
                if "mpls" in traffic_stream:
                    traffic_list.append("MPLS")
                if "ipv4" in traffic_stream:
                    traffic_list.append("IPV4_UNICAST")
                if "ipv6" in traffic_stream:
                    traffic_list.append("IPV6_UNICAST")
            if not ApData.skip_verify_accounting:
                BundleApBase.verify_check_interface_accounting(traffic=list(set(traffic_list)),
                                                            traffic_stats=traffic_stats[0],
                                                            traffic_stream_list=ApData.traffic_stream_list,
                                                            uut_interfaces_list=bundle_members_adjustment_data['active_uut_all_interfaces'])
        except Exception as err:
            log.error(err)
            error_list.append(err)

        try:
            # disregard_interfaces.update(uut_not_active_bundles)
            BundleApBase.verify_acl(disregard_interfaces=disregard_interfaces,
                                    configure_acl=self.configure_acl, verify_acl=self.verify_acl)
        except Exception as err:
            error_list.append(err)

        log.banner('In Testcase ' + self.test_name + ': Starting traffic')
        BundleApBase.traffic_cleanup(ApData)
        ApData.tgn_obj.start_traffic(ApData.traffic_stream_list)
        Helper.sleep(15, msg='Waiting for traffic ...')

        # Remove all other members and revert members back to original configuration
        try:
            with ApData.topo.config(*test_devices, thread=True):
                for peer_device in device_handles:
                    other_members_obj = bundle_members_adjustment_data[peer_device]
                    other_members_to_add = other_members_obj['other_members_to_add']
                    peer_other_members_to_add_list = [
                        member.peer_member for member in other_members_to_add]
                    uut_other_members_to_add_list = [
                        member.uut_member for member in other_members_to_add]
                    other_members_not_added = other_members_obj['other_members_not_added']

                    # Remove all members from random bundle
                    peer_device.ifmgr.remove_bundle_interface(
                        peer_other_members_to_add_list)
                    uut.ifmgr.remove_bundle_interface(
                        uut_other_members_to_add_list)

                    # Revert back to original bundle configuration
                    for member in other_members_to_add + other_members_not_added:
                        peer_device.ifmgr.add_bundle_interface([member.peer_member],
                                                                member.peer_bundle_id,
                                                                port_activity='active')
                        uut.ifmgr.add_bundle_interface([member.uut_member],
                                                        member.uut_bundle_id,
                                                        port_activity='active')

        except Exception as err:
            log.error(err)
            error_list.append(err)

        try:
            Helper.sleep(15, msg='Waiting for traffic after trigger ...')
            ApData.tgn_obj.stop_traffic()
            traffic_stats, _ = ApData.tgn_obj.verify_traffic(
                tolerance=100)  # 1587ms-441ms-543ms-1545ms
        except Exception as err:
            error_list.append(err)
        finally:
            ApData.tgn_obj.clear_traffic_stats()

        # Verify all bundles are up and traffic
        try:
            self.basic_test.test_bundle_bringup()
        except Exception as err:
            error_list.append(err)

        # Verify all bundles with lacp are up and traffic
        try:
            self.basic_test.test_bundle_bringup_with_lacp()
        except Exception as err:
            error_list.append(err)

        try:
            BundleApBase.verify_acl(
                configure_acl=self.configure_acl, verify_acl=self.verify_acl)
        except Exception as err:
            error_list.append(err)

        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('verify_qos')) == True:
                try:
                    BundleApBase.bundle_qos_verify(ApData, ApData.qos_tolerance)
                except Exception as err:
                    error_list.append(err)

        if error_list:
            raise CafyException.CompositeError(error_list)

    @classmethod
    def teardown_class(self):
        """
            Teardown method for cleaning up configurations after test execution.

            This method performs the following cleanup tasks:
            1. Removes ACL configurations if `configure_acl` is set.
            2. Unconfigures Segment Routing (SR) and IS-IS configurations for each address family (AF)
            if the platform supports SR configuration.
            3. Unconfigures SR L2 adjacency SID and bundle SR configurations.
            4. Deletes base IS-IS configurations and interfaces.
            5. Unconfigures multicast settings if the platform supports multicast configuration.
            6. Removes QoS policy maps and deletes class maps if the platform supports QoS configuration.
            7. Unconfigures NetFlow settings if the platform supports NetFlow configuration.

        """
        if self.configure_acl:
            BundleApBase.configure_base_acl(config=False)
        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('config_sr')) == True:
                for af_name in self.af_name_list:
                    ApData.R1.isis.set_isis_instance_with_sr(instance_name=ApData.zap.get_feature_configuration(
                        "isis/R1/instance")[0]['instance_name'], af_name=af_name, bundle_member_adj_sid=True, unconfig=True)
                    ApData.R1.isis.set_isis_instance_with_sr(instance_name=ApData.zap.get_feature_configuration(
                        "isis/R1/instance")[0]['instance_name'], af_name=af_name, mpls=True, unconfig=True)
                ApData.R1.sr.config_sr_l2_adj_sid(unconfig=True)
                BundleApBase.bundle_sr_config_interface(
                    af='ipv4', prefix_sid_type="absolute", prefix_sid_value=16000, unconfig=True)
        BundleApBase.configure_base_isis(
            ApData.zap, connection_mode=ApData.mode, mode="unconfig")
        BundleApBase.delete_interfaces()
        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('config_multicast')) == True:
                BundleApBase.bundle_multicast_unconfig(ApData)
        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('config_qos')) == True:
                ApData.policy_map_obj.set_policymap_unconfig(
                    policymap="pmap_bundle_ingress")
                ApData.policy_map_obj.set_policymap_unconfig(
                    policymap="pmap_bundle_egress")
                for cmap in ApData.classmap_list:
                    ApData.class_map_obj.configure_classmap(
                        classmap_name=cmap, classmap_type='qos', match_type="any", mode="delete")
        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('config_netflow')) == True:
                BundleApBase.bundle_netflow_config(ApData, unconfig=True)

@pytest.mark.Feature("BundleLacp")
class TestBundleWithL3SubIfs(BasicBundleChecks,BundleApBase):
    """
        TestBundleWithL3SubIfs
    """

    @classmethod
    def setup_class(self):
        """
            Setup section for L3 Bundle Sub-interface scale testcases

            STEPS:
            1. Do basic bring up & verify traffic is fine
            2. Disconnect default tgen file & connect to scale tgen file
            3. Configure scaled Interfaces
            4. Configure static routing
            5. Verify traffic
            :return: None
        """
        self.unconfig_hqos=False
        BundleApBase.configure_base_interfaces(ApData.zap,
                                                connection_mode=ApData.mode,
                                                configure_ipv4_address=ApData.configure_ipv4_address,
                                                configure_ipv6_address=ApData.configure_ipv6_address)
        self.basic_test = TestBundlemgrBasicChecks()
        l3_scale_dict = ApData.zap.testcase_configuration.get('test_bundle_with_L3_subifs_scale')
        self.r1_r2_bundle_id = l3_scale_dict.get("bundle_id")
        self.bundle_scale = l3_scale_dict.get("bundle_vlan_scale")
        # config vlan scales for BE3 & BE5
        dut_device_handles = [ApData.R1, ApData.R2, ApData.R3]
        dut_device_handles[0].connect()

        # check if second vlan is supported
        for platform, data in ApData.platforms.items():
            if platform.upper() in ApData.R1.platform.upper():
                second_vlan_supported = data.get('second_vlan_supported')

        # config bundle vlan scale
        ApData.R1.intfs = ApData.zap.get_interfaces(device=ApData.R1, group="l3_scale")
        ApData.R2.intfs = ApData.zap.get_interfaces(device=ApData.R2, group="l3_scale")
        ApData.R3.intfs = ApData.zap.get_interfaces(device=ApData.R3, group="l3_scale")

        #if second vlan is not supported ,Modify interface configuration by deleting second vlan info
        if  not second_vlan_supported:
            for device in [ApData.R1,ApData.R2,ApData.R3]:
                for interface in device.intfs.values():
                    for vlan in interface.vlans.values():
                        if 'second_dot1q' in vlan.encapsulation:
                            vlan.encapsulation['dot1q'] = vlan.encapsulation['second_dot1q']
                            del vlan.encapsulation['second_dot1q']


        # dot1q vlan range is 4094
        if int(self.bundle_scale) > 4000:
            if second_vlan_supported:
                for each_vlan in ApData.R1.intfs['Bundle-Ether131'].vlans:
                    if int(each_vlan) > 4000:
                        ApData.R1.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['dot1q'] = int(
                            ApData.R1.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['dot1q'])+1
                        ApData.R1.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['second_dot1q'] = int(
                            ApData.R1.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['second_dot1q'])-4000
                for each_vlan in ApData.R3.intfs['Bundle-Ether131'].vlans:
                    if int(each_vlan) > 4000:
                        ApData.R3.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['dot1q'] = int(
                            ApData.R3.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['dot1q'])+1
                        ApData.R3.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['second_dot1q'] = int(
                            ApData.R3.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['second_dot1q'])-4000
            else:
                #With single vlan config only 4094 is max possible scale config to check, so remove all vlans > 4090
                for device in [ApData.R1,ApData.R3]:
                    for id in range(4091, int(self.bundle_scale)+1):
                        device.intfs['Bundle-Ether131'].vlans.pop(f'{id}', None)
                for each_vlan in ApData.R1.intfs['Bundle-Ether131'].vlans:
                    ApData.R1.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['dot1q'] = int(
                        ApData.R1.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['dot1q'])
                for each_vlan in ApData.R3.intfs['Bundle-Ether131'].vlans:
                    ApData.R3.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['dot1q'] = int(
                        ApData.R3.intfs['Bundle-Ether131'].vlans[each_vlan].encapsulation['dot1q'])





        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('hw_module_permit_stats','False')) == True:
                if "hqos-enable" in ApData.r1_run_conf_hw_module:
                    # remove 8 - BE131 sub interfaces from R1 and R3
                    # why we do this - bundle main is also accounted when HQoS in enabled
                    # BE1-6,121,131 - so total - 8 bundle main interface exists in system
                    log.info('removing extra 8 sub-interfaces, as box is enabled with HQOS')
                    extra_be131_vlans =  [ str(id) for id in range(int(self.bundle_scale-7), int(self.bundle_scale)+1)]
                    for vlan_id in extra_be131_vlans:
                        del ApData.R1.intfs['Bundle-Ether131'].vlans[vlan_id]
                        del ApData.R3.intfs['Bundle-Ether131'].vlans[vlan_id]

        if not ApData.mgbl_enabled:
            with ApData.topo.config(ApData.R1, thread=True):
                ApData.zap.configure_interfaces(interfaces=ApData.R1.intfs,
                                        ifmgr=ApData.R1.ifmgr,configure_ipv4_address=ApData.configure_ipv4_address,
                                        configure_ipv6_address=ApData.configure_ipv6_address,
                                        skip_speed_change=True)
            with ApData.topo.config(ApData.R2, thread=True):
                ApData.zap.configure_interfaces(interfaces=ApData.R2.intfs,
                                        ifmgr=ApData.R2.ifmgr,
                                        configure_ipv4_address=ApData.configure_ipv4_address,
                                        configure_ipv6_address=ApData.configure_ipv6_address,
                                        skip_speed_change=True)
            with ApData.topo.config(ApData.R3, thread=True):
                ApData.zap.configure_interfaces(interfaces=ApData.R3.intfs,
                                        ifmgr=ApData.R3.ifmgr,
                                        configure_ipv4_address=ApData.configure_ipv4_address,
                                        configure_ipv6_address=ApData.configure_ipv6_address,
                                        skip_speed_change=True)
        else:
            BundleApBase.configure_interfaces_mgbl(dev_obj=ApData.R1, interfaces=ApData.R1.intfs, scale_trim=False)
            BundleApBase.configure_interfaces_mgbl(dev_obj=ApData.R2, interfaces=ApData.R2.intfs, scale_trim=False)
            BundleApBase.configure_interfaces_mgbl(dev_obj=ApData.R3, interfaces=ApData.R3.intfs, scale_trim=False)
            with pytest.allure.step("Unshutting the interfaces"):
                for dut in dut_device_handles:
                    dut.ifmgr = IfMgr(device=dut, mode=ApData.mode)
                    dut.ifmgr.noshut_all()

        with pytest.allure.step("Disconnect the default xml"):
            # Disconnect default TGN file
            ApData.tgn_obj.tgn_disconnect()

        with pytest.allure.step("Connecting tgen using scale xml"):
            # Loading scale TGN file and start protocols
            ApData.zap.load_tgn_config_file(
                    ApData.tgn_obj, ApData.tgn_bundle_l3_scale, ApData.port_list)
            ApData.tgn_obj.start_all_protocols()

        self.r1_r2_bundle_members = BundleApBase.get_bundle_members(ApData.R1, self.r1_r2_bundle_id)
        self.r1_r2_bundle_name = "Bundle-Ether" + str(self.r1_r2_bundle_id)
        self.dut_device_handles = [ApData.R1, ApData.R2, ApData.R3]
        ApData.Static_R1 = IpStatic(device=self.dut_device_handles[0], name='static_R1', mode=ApData.mode)
        ApData.Static_R2 = IpStatic(device=self.dut_device_handles[1], name='static_R2', mode=ApData.mode)
        ApData.Static_R3 = IpStatic(device=self.dut_device_handles[2], name='static_R3', mode=ApData.mode)

        # Setting static route max path to 40k for v4 & v6
        with ApData.topo.config(ApData.R1, ApData.R2, ApData.R3, thread=True):
            ApData.Static_R1.set_maximum_path(maximum_path=40000)
            ApData.Static_R2.set_maximum_path(maximum_path=40000)
            ApData.Static_R3.set_maximum_path(maximum_path=40000)
            ApData.Static_R1.set_maximum_path(maximum_path=40000, ip_version='ipv6')
            ApData.Static_R2.set_maximum_path(maximum_path=40000, ip_version='ipv6')
            ApData.Static_R3.set_maximum_path(maximum_path=40000, ip_version='ipv6')

        # set static route
        with ApData.topo.config(ApData.R1, ApData.R2, ApData.R3, thread=True):
            ApData.zap.configure_static_routes(static_instance_list=[ApData.Static_R1])
            ApData.zap.configure_static_routes(static_instance_list=[ApData.Static_R2])
            ApData.zap.configure_static_routes(static_instance_list=[ApData.Static_R3])

        # display interfaces summary
        ApData.R1.ifmgr.get_show_interfaces_summary()
        ApData.R2.ifmgr.get_show_interfaces_summary()
        ApData.R3.ifmgr.get_show_interfaces_summary()

        # display route - v4 & v6 summary
        with ApData.topo.config(*dut_device_handles, thread=True):
            for dut in dut_device_handles:
                dut.route.get_ipv4_route_summary()
                dut.route.get_ipv6_route_summary()

        # start streams
        BundleApBase.traffic_cleanup(ApData)
        ApData.tgn_obj.start_arp()
        Helper.sleep(5, msg='Waiting for traffic....')
        if(self.bundle_scale == 7990):
            tgn_streams = ApData.l3_scale_8k_traffic_streams
        elif(self.bundle_scale == 1628):
            tgn_streams = ApData.l3_scale_1638_traffic_streams
        else:
            tgn_streams = ApData.l3_scale_1k_traffic_streams
        ApData.tgn_obj.start_traffic(tgn_streams)
        Helper.sleep(25, msg='Waiting for traffic ...')
        BundleApBase.traffic_cleanup(ApData)

        # restart traffic
        ApData.tgn_obj.start_traffic(tgn_streams)
        Helper.sleep(50, msg='Waiting for traffic ...')

        #stop and check©
        ApData.tgn_obj.stop_traffic()
        traffic_stats, _ = ApData.tgn_obj.verify_traffic(traffic_items=tgn_streams, tolerance=100)

        Helper.sleep(10, msg='sleep for 10 sec')
        ApData.tgn_obj.start_traffic(tgn_streams)
        Helper.sleep(15, msg='Waiting for traffic ...')
        ApData.tgn_obj.stop_traffic()
        traffic_stats, _ = ApData.tgn_obj.verify_traffic(traffic_items=tgn_streams, tolerance=100)

    @classmethod
    def teardown_class(self):
        """
            Teardown method for cleaning up the test environment after executing the test cases.

            This method performs the following actions:
            1. Unconfigures static routes for the test devices (R1, R2, R3) in both IPv4 and IPv6 modes.
            2. Resets the maximum path configuration for static routes on the test devices.
            3. Unconfigures bundle VLAN scale by retrieving and unconfiguring interfaces associated with the "l3_scale" group.
            4. Deletes any stale traffic generator (TGEN) sessions and reloads the default TGEN configuration file.
            5. Starts all TGEN protocols after reloading the configuration.
            6. Unconfigures interfaces on the test devices (R1, R2, R3) including IPv4 and IPv6 addresses, while skipping speed changes.
            7. Deletes all bundle interfaces and logical interfaces of type 'Bundle-Ether' on the test devices.
            8. Optionally unconfigures hierarchical QoS (HQoS) on R1 and triggers a reload of all cards, followed by a stabilization wait period.
        """
        test_devices = [ApData.R1, ApData.R2, ApData.R3]
        with ApData.topo.config(ApData.R1, ApData.R2, ApData.R3, thread=True):
            ApData.zap.configure_static_routes(static_instance_list=[ApData.Static_R1], config_mode="unconfig")
            ApData.zap.configure_static_routes(static_instance_list=[ApData.Static_R2], config_mode="unconfig")
            ApData.zap.configure_static_routes(static_instance_list=[ApData.Static_R3], config_mode="unconfig")

        with ApData.topo.config(ApData.R1, ApData.R2, ApData.R3, thread=True):
            ApData.Static_R1.set_maximum_path(maximum_path=40000, unconfig = True)
            ApData.Static_R2.set_maximum_path(maximum_path=40000, unconfig = True)
            ApData.Static_R3.set_maximum_path(maximum_path=40000, unconfig = True)
            ApData.Static_R1.set_maximum_path(maximum_path=40000, ip_version='ipv6', unconfig = True)
            ApData.Static_R2.set_maximum_path(maximum_path=40000, ip_version='ipv6', unconfig = True)
            ApData.Static_R3.set_maximum_path(maximum_path=40000, ip_version='ipv6', unconfig = True)

        # unconfig bundle vlan scale
        ApData.R1.intfs = ApData.zap.get_interfaces(device=ApData.R1, group="l3_scale")
        ApData.R2.intfs = ApData.zap.get_interfaces(device=ApData.R2, group="l3_scale")
        ApData.R3.intfs = ApData.zap.get_interfaces(device=ApData.R3, group="l3_scale")

        #deleting stale tgen session
        ApData.tgn_obj.delete_session()
        #loading back the default tgen file
        ApData.zap.load_tgn_config_file(
            ApData.tgn_obj, ApData.tgn_config_file, ApData.port_list)
        ApData.tgn_obj.start_all_protocols()

        with ApData.topo.config(ApData.R1, thread=True):
            ApData.zap.configure_interfaces(interfaces=ApData.R1.intfs,ifmgr=ApData.R1.ifmgr,unconfig=True,
                                            configure_ipv4_address=ApData.configure_ipv4_address,
                                            configure_ipv6_address=ApData.configure_ipv6_address,skip_speed_change=True)
        with ApData.topo.config(ApData.R2, thread=True):
            ApData.zap.configure_interfaces(interfaces=ApData.R2.intfs,ifmgr=ApData.R2.ifmgr,unconfig=True,
                                            configure_ipv4_address=ApData.configure_ipv4_address,
                                            configure_ipv6_address=ApData.configure_ipv6_address,skip_speed_change=True)
        with ApData.topo.config(ApData.R3, thread=True):
            ApData.zap.configure_interfaces(interfaces=ApData.R3.intfs,ifmgr=ApData.R3.ifmgr,unconfig=True,
                                            configure_ipv4_address=ApData.configure_ipv4_address,
                                            configure_ipv6_address=ApData.configure_ipv6_address,skip_speed_change=True)

        BundleApBase.delete_interfaces()
        for device in test_devices:
            intf_obj = device.ifmgr.get_interfaces(management=False)
            device.ifmgr.delete_interface(intf_obj, logical_interface_type='Bundle-Ether')

        if self.unconfig_hqos:
            log.banner('unconfiguring hqos')
            ApData.R1.qos_hw_obj.set_hierarchical_qos_disable()
            router_reload_trigger = ApData.R1.event.ReloadAllCards(inv_obj=ApData.R1.inventory)
            router_reload_trigger.run()
            Helper.sleep(120,'Wait for UUT to stabilise after reload')

    def test_l3scale_interface_accounting(self):
        """
            test_l3scale_interface_accounting

            Test L3 Bundle sub-interface scale class

            This test verifies the following:
            - Verify 1024 bundle l3 sub-interfaces are able to configure on given XR router
            - Verify upto 8k bundle l3 sub-interfaces if we change numbers in input file
            - Verify data traffic IPv4 and IPv6 on configured bundle l3 sub-interfaces

            Configuration: L3 Bundle sub-interfaces, for asr9k 8k interfaces, for rest 1024.

            Verification: all interfaces are getting created or not

            Triggers: None
        """

        l3_scale_dict = ApData.zap.testcase_configuration.get('test_bundle_with_L3_subifs_scale')
        bundle_scale = l3_scale_dict.get("bundle_vlan_scale")
        general_acceptable_loss = ApData.zap.get_testcase_configuration('test_bundle_with_L3_subifs_scale').get("general_acceptable_loss")
        for platform, data in ApData.platforms.items():
            if platform.upper() in ApData.R1.platform.upper():
                second_vlan_supported = data.get('second_vlan_supported')

        if not second_vlan_supported and (int(bundle_scale) > 4090):
            #As we already have BE3.100 to BE3.109 already configured as part common setup,
            # Trimmed our scale to 4090 as part of single vlan max scaling.
            total_vlans = 4090 + 10
        else:
            total_vlans = int(bundle_scale) + 10 # as we already have BE3.100 to BE3.109 already configured as part common setup
        exp_intf_sum = ApData.R1.ifmgr.ShowInterfacesSummary(interface_type='ift_vlan_subif', total=total_vlans, up=total_vlans)
        error_list = []

        #gettting response time for mbgl 1d scale
        if hasattr(ApData,"mgbl_enabled") and ApData.mgbl_enabled :
            kpi_id = ["10025", "10024", "10031"]
            for kpi in kpi_id:
                ApData.data_to_push_to_db.setdefault(kpi, {})
            BundleApBase.get_resposnce_time_mgbl(ApData=ApData,device = ApData.R1,
                                                        kpi_id=kpi_id,
                                                        scale_qualified=exp_intf_sum.total,
                                                        xpath=ApData.mgbl_config["bundle_brief_xpath"])
        # verify scale interface nummbers
        ApData.R1.ifmgr.verify_show_interfaces_summary(exp_intf_sum, retries=20)

        if ApData.upload_to_xrvault:
            # get LC info of BE131, where bundle l3 sub-interfaces is scaled
            intf_objects = ApData.R1.get_interfaces()
            nodes = ApData.R1.inventory.get_sysadmin_node_status()
            lc_location = str(BundleApBase.get_hw_locations_of_interface(interface=intf_objects['Bundle-Ether131'], device=ApData.R1))[2:-2]
            lc_pid = None
            for node in nodes:
                if node.location in lc_location:
                    lc_pid = node.card_type.upper()
                    break

            # call XR Vault method to push bundle l3 sub-interface scale number
            # check HQoS mode configured or not
            log.banner("we have bundle l3 sub-interfaces scaled on Bundle BE131, which has only 1 member in it")
            log.banner("scale numbers are applicable for per bundle, per NP/NPU, per LC and per system - all are same")
            BundleApBase.push_data_to_vault(scale_id=10031, scale_category='interfaces', scale_sub_category='L3 VLAN Sub-interface per Bundle',
                                            profile='L3 VLAN Sub-interface per Bundle', scale_per_npu=exp_intf_sum.total,
                                            scale_per_lc=exp_intf_sum.total, scale_per_system=exp_intf_sum.total, lc_pid=lc_pid)
            if "hqos-enable" in ApData.r1_run_conf_hw_module:
                BundleApBase.push_data_to_vault(scale_id=10025, scale_category='interfaces',
                                                scale_sub_category='L3 subinterfaces on bundle(s) (HQoS mode)',
                                                profile='Interface-Bundle L3 sub-interface scale with HQoS enabled',
                                                scale_per_npu=exp_intf_sum.total, scale_per_lc=exp_intf_sum.total,
                                                scale_per_system=exp_intf_sum.total, lc_pid=lc_pid)
            else:
                BundleApBase.push_data_to_vault(scale_id=10024, scale_category='interfaces',
                                                scale_sub_category='L3 subinterfaces on bundle(s) (non-HQoS mode)',
                                                profile='Interface-Bundle L3 sub-interface scale', scale_per_npu=exp_intf_sum.total,
                                                scale_per_lc=exp_intf_sum.total, scale_per_system=exp_intf_sum.total, lc_pid=lc_pid)

        # set traffic stream list based on scale number
        if(bundle_scale == 7990):
            tgn_streams = ApData.l3_scale_8k_traffic_streams
        elif(bundle_scale == 1628):
            tgn_streams = ApData.l3_scale_1638_traffic_streams
        else:
            tgn_streams = ApData.l3_scale_1k_traffic_streams

        # cleanup and start arp, traffic and stop traffic
        BundleApBase.traffic_cleanup(ApData)
        Helper.sleep(60, msg='Waiting for stats cleanup as we have scale setup...')
        ApData.tgn_obj.start_arp()
        Helper.sleep(5, msg='Waiting for traffic....')
        ApData.tgn_obj.start_arp_on_streams()
        Helper.sleep(5, msg='Waiting for traffic....')
        ApData.tgn_obj.start_traffic(tgn_streams)
        Helper.sleep(60, msg='Waiting for traffic ...')
        ApData.tgn_obj.stop_traffic()
        traffic_stats, _ = ApData.tgn_obj.verify_traffic(traffic_items=tgn_streams, tolerance=100)
        Helper.sleep(50, msg='Waiting for stats to settledown ...')
        BundleApBase.verify_traffic_loss_duration(traffic_stats=traffic_stats,error_list=error_list,loss_duration_limit=int(general_acceptable_loss))

        if error_list:
            raise CafyException.CafyBaseException(error_list)
        # just to display accounting stats
        ApData.R1.ifmgr.get_interface_accounting()

    def test_l3scale_interface_accounting_hqos(self):
        """
            test_l3scale_interface_accounting_hqos

            Test L3 Bundle sub-interface scale class with HQOS

            This test verifies the following:
            - Verify 1024 bundle l3 sub-interfaces are able to configure on given XR router with HQOS enabled
            - Verify upto 8k bundle l3 sub-interfaces if we change numbers in input file
            - Verify data traffic IPv4 and IPv6 on configured bundle l3 sub-interfaces

            Configuration: L3 Bundle sub-interfaces, for asr9k 8k interfaces, for rest 1024.

            Verification: all interfaces are getting created or not

            Triggers: None
        """
        self.unconfig_hqos=True
        hqos_tc_applicable = False
        for platform, data in ApData.platforms.items():
            if (re.match(platform, ApData.R1.platform) and data.get('hw_module_permit_stats','False')) == True:
                hqos_tc_applicable = True
        if not hqos_tc_applicable:
            pytest.skip('HQOS testcase is not applicable in this platform, so skipping this testcase')

        l3_scale_dict = ApData.zap.testcase_configuration.get('test_bundle_with_L3_subifs_scale')
        bundle_scale = l3_scale_dict.get("bundle_vlan_scale")

        # as of now only NCS5500 is platform for HQoS
        if ("hqos-enable" not in ApData.r1_run_conf_hw_module) or ("bundle-scale" not in ApData.r1_run_conf_hw_module):
            log.banner('setting HQoS and bundle-scale hw-module profile clis and reloading system')
            # remove 8 - BE131 sub interfaces from R1 and R3
            # why we do this - bundle main is also accounted when HQoS in enabled
            # BE1-6,121,131 - so total - 8 bundle main interface exists in system
            extra_be131_vlans =  [ "Bundle-Ether131" + "." + str(id) for id in range(int(bundle_scale)-7, int(bundle_scale)+1)]
            log.info('in HQOS mode, bundle main intf is also counted, so removing 8 bundle l3-sub intfs configured')
            with ApData.topo.config(ApData.R1, ApData.R3, thread=True):
                ApData.R1.ifmgr.delete_interface(interfaces=extra_be131_vlans)
                ApData.R3.ifmgr.delete_interface(interfaces=extra_be131_vlans)
                ApData.R1.qos_hw_obj.set_hierarchical_qos_enable()
                ApData.R1.qos_hw_obj.set_bundle_scale(max_bundle='1024', enable=True)
                router_reload_trigger = ApData.R1.event.ReloadAllCards(inv_obj=ApData.R1.inventory)
                router_reload_trigger.run()
                Helper.sleep(120,'Wait for UUT to stabilise after reload')
        else:
            log.banner('HQoS and bundle-scale hw-module profile clis are already configured on system')

        total_vlans = int(bundle_scale)+10-8 # as we already have BE3.100 to BE3.109 already configured as part common setup
        # 8 main interfaces will be considered in scale calculation.
        exp_intf_sum = ApData.R1.ifmgr.ShowInterfacesSummary(interface_type='ift_vlan_subif', total=total_vlans, up=total_vlans)

        #gettting response time for mbgl 1d scale
        if hasattr(ApData,"mgbl_enabled") and ApData.mgbl_enabled :
            kpi_id = ["10031", "10025"]
            for kpi in kpi_id:
                ApData.data_to_push_to_db.setdefault(kpi, {})
            BundleApBase.get_resposnce_time_mgbl(ApData=ApData,device = ApData.R1,
                                                        kpi_id=kpi_id,
                                                        scale_qualified=exp_intf_sum.total,
                                                        xpath=ApData.mgbl_config["bundle_brief_xpath"])

        # verify scale interface nummbers
        ApData.R1.ifmgr.verify_show_interfaces_summary(exp_intf_sum, retries=20)

        if ApData.upload_to_xrvault:
            # get LC info of BE131, where bundle l3 sub-interfaces is scaled
            intf_objects = ApData.R1.get_interfaces()
            nodes = ApData.R1.inventory.get_sysadmin_node_status()
            lc_location = str(BundleApBase.get_hw_locations_of_interface(interface=intf_objects['Bundle-Ether131'], device=ApData.R1))[2:-2]
            lc_pid = None
            for node in nodes:
                if node.location in lc_location:
                    lc_pid = node.card_type.upper()
                    break

            # call XR Vault method to push bundle l3 sub-interface scale number
            # check HQoS mode configured or not
            log.banner("we have bundle l3 sub-interfaces scaled on Bundle BE131, which has only 1 member in it")
            log.banner("scale numbers are applicable for per bundle, per NP/NPU, per LC and per system - all are same")
            BundleApBase.push_data_to_vault(scale_id=10031, scale_category='interfaces', scale_sub_category='L3 VLAN Sub-interface per Bundle',
                                            profile='L3 VLAN Sub-interface per Bundle', scale_per_npu=exp_intf_sum.total,
                                            scale_per_lc=exp_intf_sum.total, scale_per_system=exp_intf_sum.total, lc_pid=lc_pid)
            BundleApBase.push_data_to_vault(scale_id=10025, scale_category='interfaces',
                                            scale_sub_category='L3 subinterfaces on bundle(s) (HQoS mode)',
                                            profile='Interface-Bundle L3 sub-interface scale with HQoS enabled',
                                            scale_per_npu=exp_intf_sum.total, scale_per_lc=exp_intf_sum.total,
                                            scale_per_system=exp_intf_sum.total, lc_pid=lc_pid)

        # set traffic stream list based on scale number
        if(bundle_scale == 7990):
            tgn_streams = ApData.l3_scale_8k_traffic_streams
        elif(bundle_scale == 1628):
            tgn_streams = ApData.l3_scale_1638_traffic_streams
        else:
            tgn_streams = ApData.l3_scale_1k_traffic_streams

        # cleanup and start arp, traffic and stop traffic
        BundleApBase.traffic_cleanup(ApData)
        Helper.sleep(60, msg='Waiting for stats cleanup as we have scale setup...')
        ApData.tgn_obj.start_arp()
        Helper.sleep(5, msg='Waiting for traffic....')
        ApData.tgn_obj.start_traffic(tgn_streams)
        Helper.sleep(60, msg='Waiting for traffic ...')
        ApData.tgn_obj.stop_traffic()
        traffic_stats, _ = ApData.tgn_obj.verify_traffic(traffic_items=tgn_streams, tolerance=100)
        Helper.sleep(50, msg='Waiting for stats to settledown ...')

        # just to display accounting stats
        ApData.R1.ifmgr.get_interface_accounting()

        # unconfig hqos
        log.banner('unconfiguring hqos')
        ApData.R1.qos_hw_obj.set_hierarchical_qos_disable()
        router_reload_trigger = ApData.R1.event.ReloadAllCards(inv_obj=ApData.R1.inventory)
        router_reload_trigger.run()
        Helper.sleep(120,'Wait for UUT to stabilise after reload')

        self.unconfig_hqos=False

