/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.ngsdn.tutorial;

import com.google.common.collect.Lists;
import org.onlab.packet.Ip6Address;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleOperations;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.google.common.collect.Streams.stream;
import static org.onosproject.net.device.DeviceEvent.Type.PORT_UPDATED;
import static org.onosproject.ngsdn.tutorial.AppConstants.INITIAL_SETUP_DELAY;

/**
 * Application which handles SRv6 segment routing.
 */
@Component(
        immediate = true,
        service = {Srv6InsertComponentService.class},
        enabled = true

)
public class Srv6InsertComponent implements Srv6InsertComponentService {

    private static final Logger log = LoggerFactory.getLogger(Srv6InsertComponent.class);
    private ApplicationId appId;

    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    FlowRuleService flowRuleService;
    private List<List<String>> listOfSegments = new ArrayList<>();
    private Integer currentSegment;
    @Activate
    protected void activate() {
        // srv6-insert device:leaf1 3:201:2:: 3:102:2:: 2001:f:f::1
        List<String> segments1 = new ArrayList<>();
        segments1.add("3:201:2::"); // spine1
        segments1.add("3:102:2::"); // leaf2
        segments1.add("2001:f:f::1"); // group ipv6 address
        listOfSegments.add(segments1);
        currentSegment = 0;

        List<String> segments2 = new ArrayList<>();
        segments2.add("3:202:2::"); // spine2
        segments2.add("3:102:2::"); // leaf2
        segments2.add("2001:f:f::1"); // group ipv6 address

        listOfSegments.add(segments2);

        createMockSRV6Rule();
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {

        log.info("Stopped");
    }

    /**
     * Insert a SRv6 transit insert policy that will inject an SRv6 header for
     * packets destined to destIp.
     *
     * @param deviceId     device ID
     * @param destIp       target IP address for the SRv6 policy
     * @param prefixLength prefix length for the target IP
     * @param segmentList  list of SRv6 SIDs that make up the path
     */
    public void insertSrv6InsertRule(DeviceId deviceId, Ip6Address destIp, int prefixLength,
                                     List<Ip6Address> segmentList) {
        if (segmentList.size() < 2 || segmentList.size() > 3) {
            throw new RuntimeException("List of " + segmentList.size() + " segments is not supported");
        }

        String tableId = "IngressPipeImpl.srv6_transit";

        PiCriterion match = PiCriterion.builder()
                .matchLpm(PiMatchFieldId.of("hdr.ipv6.dst_addr"), destIp.toOctets(), prefixLength)
                .build();

        List<PiActionParam> actionParams = Lists.newArrayList();

        for (int i = 0; i < segmentList.size(); i++) {
            PiActionParamId paramId = PiActionParamId.of("s" + (i + 1));
            PiActionParam param = new PiActionParam(paramId, segmentList.get(i).toOctets());
            actionParams.add(param);
        }

        PiAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.srv6_t_insert_" + segmentList.size()))
                .withParameters(actionParams)
                .build();
        // ---- END SOLUTION ----

        final FlowRule rule = Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);

        flowRuleService.applyFlowRules(rule);
    }

    /**
     * Remove all SRv6 transit insert polices for the specified device.
     *
     * @param deviceId device ID
     */
    public void clearSrv6InsertRules(DeviceId deviceId) {
        String tableId = "IngressPipeImpl.srv6_transit";

        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
        stream(flowRuleService.getFlowEntries(deviceId))
                .filter(fe -> fe.appId() == appId.id())
                .filter(fe -> fe.table().equals(PiTableId.of(tableId)))
                .forEach(ops::remove);
        flowRuleService.apply(ops.build());
    }

    @Override
    public void mockUpdateECMPPath() {
        log.info("port is disabled, changing srv6 path");
        // update port stat to disabled
        currentSegment = (currentSegment == 0) ? 1 : 0;
        createMockSRV6Rule();
    }

    public void createMockSRV6Rule() {
        List<Ip6Address> sids = listOfSegments.get(currentSegment).stream()
                .map(Ip6Address::valueOf)
                .collect(Collectors.toList());
        Ip6Address destIp = sids.get(sids.size() - 1);
        clearSrv6InsertRules(DeviceId.deviceId("device:leaf1"));
        insertSrv6InsertRule(DeviceId.deviceId("device:leaf1"), destIp, 128, sids);
    }

}