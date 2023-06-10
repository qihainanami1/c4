package org.onosproject.ngsdn.tutorial;

import jdk.jshell.execution.Util;
import org.apache.commons.collections.bag.HashBag;
import org.onlab.packet.IPv6;
import org.onlab.packet.MacAddress;
import org.onosproject.cli.net.AddHostToHostIntentCommand;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.onosproject.ngsdn.tutorial.AppConstants.INITIAL_SETUP_DELAY;

@Component(immediate = true,
        service = {GroupService.class},
        enabled = true)
public class GroupTableComponent implements GroupService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private org.onosproject.net.group.GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    private ApplicationId appId;

    // 3 fixed GROUP_ID of almost 3 subnet(2-layer broadcast field)
    private static final int SUBNET_GROUP_ID_1 = 114;
    private static final int SUBNET_GROUP_ID_2 = 115;
    private static final int SUBNET_GROUP_ID_3 = 116;


    ConcurrentHashMap<String, Integer> groupNameIndexMap = new ConcurrentHashMap<>();
    ConcurrentHashMap<String, GroupDescription> groupDescriptionMap = new ConcurrentHashMap<>();
    ConcurrentHashMap<String, Collection<PortNumber>> groupPortNumbersMap = new ConcurrentHashMap<>();

    @Override
    public Set<Host> getGroupInfo(String gname) {
        GroupDescription groupDescription = groupDescriptionMap.get(gname);
        DeviceId deviceId = groupDescription.deviceId();
        Collection<PortNumber> portNumbers = groupPortNumbersMap.get(gname);
        Set<Host> ret = new HashSet<>();
        for (PortNumber portNumber : portNumbers) {
            ConnectPoint connectPoint = new ConnectPoint(deviceId, portNumber);
            Set<Host> hosts = hostService.getConnectedHosts(connectPoint);
            ret.addAll(hosts);
        }
        return ret;
    }

    @Activate
    protected void activate() {
        groupNameIndexMap.put("group1", SUBNET_GROUP_ID_1);
        groupNameIndexMap.put("group2", SUBNET_GROUP_ID_2);
        groupNameIndexMap.put("group3", SUBNET_GROUP_ID_3);
        appId = coreService.registerApplication("org.onosproject.ngsdn-tutorial");

        // Register listeners to be informed about device and host events.
        // TODO: detect when a port of device change, and modify multicast strategy
        // deviceService.addListener(deviceListener);
        // TODO: detect when a user verified by login, and a host add event issue
        // hostService.addListener(hostListener);

        // mapIpv6DstAddrToMulticast(DeviceId.deviceId("device:leaf2"));

    }

    @Override
    public void insertNewPortNumber(DeviceId deviceId, String groupName, PortNumber newPort) {
        // if exists, group it first
        GroupDescription groupDesc = groupDescriptionMap.get(groupName);
        Collection<PortNumber> portNumbers = new HashSet<>();

        if (groupDesc != null) {
            portNumbers = groupPortNumbersMap.get(groupName);
            groupService.removeGroup(deviceId, groupDesc.appCookie(), appId);
        }

        portNumbers.add(newPort);
        // log.error("{}, {}, {}", deviceId, groupName, newPort);
        final GroupDescription multicastGroup = Utils.buildMulticastGroup(
                appId, deviceId, groupNameIndexMap.get(groupName), portNumbers);

        groupDescriptionMap.put(groupName, multicastGroup);
        groupPortNumbersMap.put(groupName, portNumbers);

        groupService.addGroup(multicastGroup);
    }

    @Override
    public void removePortNumber(DeviceId deviceId, String groupName, PortNumber newPort) {
        // if exists, group it first
        GroupDescription groupDesc = groupDescriptionMap.get(groupName);
        Collection<PortNumber> portNumbers = new HashSet<>();

        if (groupDesc != null) {
            portNumbers = groupPortNumbersMap.get(groupName);
            groupService.removeGroup(deviceId, groupDesc.appCookie(), appId);
        }

        portNumbers.remove(newPort);

        final GroupDescription multicastGroup = Utils.buildMulticastGroup(
                appId, deviceId, groupNameIndexMap.get(groupName), portNumbers);

        groupDescriptionMap.put(groupName, multicastGroup);
        groupPortNumbersMap.put(groupName, portNumbers);
        groupService.addGroup(multicastGroup);

    }

    @Override
    public void removeGroup(String deviceId, String groupName) {
        GroupDescription groupDesc = groupDescriptionMap.get(groupName);
        if (groupDesc == null) {
            return;
        }
        groupService.removeGroup(DeviceId.deviceId(deviceId), groupDesc.appCookie(), appId);

        groupDescriptionMap.remove(groupName);
        groupPortNumbersMap.remove(groupName);
    }

    boolean identityAuth(String username, String passwd) {
        // mock
        return true;
    }

    @Override
    // assume h3 and h4 for broadcast domain Group1
    public void addHostToGroup(String hostname, String groupName) {
        HostId hostId = Utils.map(hostname);
        Host host = hostService.getHost(hostId);

        // get host location(device-port connect to this host directly)
        HostLocation location = host.location();

        insertNewPortNumber(location.deviceId(), groupName, location.port());
    }

    @Override
    public void removeHostInGroup(String hostname, String groupName) {
        HostId hostId = Utils.map(hostname);
        Host host = hostService.getHost(hostId);

        // get host location(device-port connect to this host directly)
        HostLocation location = host.location();

        removePortNumber(location.deviceId(), groupName, location.port());
    }

    // TODO: SRv6 multicast
    // create a p4-table, mapping a ipv6_dst_addr to a mcast_grp before 3-layer v6 forward

    @Deprecated
    private void mapIpv6DstAddrToMulticast(DeviceId deviceId) {
        // Action: set multicast group id

        String ipv6Address = "2001:f:f::1";
        String[] addressBlocks = ipv6Address.split(":");
        byte[] byteArray = new byte[16];

        int byteArrayIndex = 0;
        for (String block : addressBlocks) {
            block = (block.length() < 4 ? "0000" + block : block);
            byteArray[byteArrayIndex++] = (byte) Integer.parseInt(block.substring(0, 2), 16);
            byteArray[byteArrayIndex++] = (byte) Integer.parseInt(block.substring(2, 4), 16);
        }

        final PiCriterion ipv6BroadcastCriterion = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("hdr.ipv6.dst_addr"),
                        byteArray
                )
                .build();

        final PiAction setMcastGroupAction = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.set_multicast_group"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("gid"),
                        SUBNET_GROUP_ID_1))
                .build();

        String tableId = "IngressPipeImpl.ipv6_multicast_table";
        final FlowRule rule = Utils.buildFlowRule(
                deviceId, appId, tableId, ipv6BroadcastCriterion
                , setMcastGroupAction);


        flowRuleService.applyFlowRules(rule);
    }

    @Deactivate
    protected void deactivate() {
//        deviceService.removeListener(deviceListener);
//        hostService.removeListener(hostListener);

        log.info("Stopped");
    }

}
