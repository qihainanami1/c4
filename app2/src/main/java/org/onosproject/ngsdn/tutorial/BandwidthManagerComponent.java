package org.onosproject.ngsdn.tutorial;

import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.meter.DefaultMeter;
import org.onosproject.net.meter.DefaultMeterRequest;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.packet.*;
import org.onosproject.net.pi.model.*;
import org.onosproject.net.pi.runtime.*;
import org.onosproject.net.statistic.StatisticService;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.lang.String.format;

@SuppressWarnings("all")
@Component(immediate = true,
        service = {BandwidthManagerService.class},
        enabled = true
)
public class BandwidthManagerComponent implements BandwidthManagerService{
    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MeterService meterService;
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
    protected ComponentConfigService cfgService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StatisticService statisticService;
    private ApplicationId appId;
    
    private ConcurrentHashMap<Integer, PiMeterCellId> meters = new ConcurrentHashMap<>();
    private ConcurrentHashMap<Integer, List<FlowTuple>> slices = new ConcurrentHashMap<>();

    private static final String ALERT_MESSAGE = "IngressPipeImpl.alert_msg_meter";
    private static final String VIDEO_UDP_STREAM = "IngressPipeImpl.video_udp_meter";
    private static final String OTHER_STREAM = "IngressPipeImpl.other_stream";
    
    private static final Integer ALERT_MESSAGE_SLICEID = 0;
    private static final Integer VIDEO_UDP_SLICEID = 1;
    private static final Integer OTHER_STREAM_SLICEID = 2;

    private static Integer indirectMeterIndex = 0;
    private static Integer _sliceID = 0;
    
    // 10Gbps
    private static Integer bandwidthCapacity = 10 * 1024 * 1024 * 1024 / 8; // Bps
    private static ConcurrentHashMap<ConnectPoint, Integer> availableBw;

    private PiMeterBand buildPiMeterBand(long cir, long cburst) {
        return new PiMeterBand(cir, cburst);
    }

    private PiMeterCellConfig buildMeterConfig(String meterID, int index, long cir, long cburst) {
        PiMeterCellId piMeterCellId = PiMeterCellId.ofIndirect(PiMeterId.of(meterID), indirectMeterIndex++);
        meters.put(_sliceID, piMeterCellId);
        slices.put(_sliceID, new ArrayList<>());
        _sliceID++;
        return PiMeterCellConfig.builder().withMeterCellId(piMeterCellId).withMeterBand(buildPiMeterBand(cir, cburst)).build();
    }

    @Override
    public FlowTuple addFlowToSlice(int sliceID, FlowTuple flowTuple) {
        if (slices.get(sliceID) == null) {
            slices.get(OTHER_STREAM_SLICEID).add(flowTuple);
        }
        slices.get(sliceID).add(flowTuple);
        return flowTuple;
    }

    public void sendQoSRuleToSlice(DeviceId deviceId, int sliceID, long bw) {
        final String classifyTableName = "IngressPipeImpl.m_classify";
        final String colorTableName = "IngressPipeImpl.m_read";
        final String filterTableName = "IngressPipeImpl.m_filter";
        for (FlowTuple flowTuple : slices.get(sliceID)) {
            final PiCriterion classifyCritertion = PiCriterion.builder()
                    .matchExact(PiMatchFieldId.of("hdr.ipv6.src_addr"), flowTuple.srcAddr)
                    .matchExact(PiMatchFieldId.of("hdr.ipv6.dst_addr"), flowTuple.dstAddr)
                    .matchExact(PiMatchFieldId.of("local_metadata.l4_src_port"), flowTuple.srcPort)
                    .matchExact(PiMatchFieldId.of("local_metadata.l4_dst_port"), flowTuple.dstPort)
                    .matchExact(PiMatchFieldId.of("hdr.ipv6.next_hdr"), flowTuple.getNextHdr())
                    .build();
            PiAction classifyAction = PiAction.builder()
                    .withId(PiActionId.of("IngressPipeImpl.set_slice_id"))
                    .withParameter(new PiActionParam(
                            PiActionParamId.of("slice_id"), sliceID
                    )).build();

            FlowRule classifyRule = Utils.buildFlowRule(deviceId, appId, classifyTableName, classifyCritertion, classifyAction);
            flowRuleService.applyFlowRules(classifyRule);
        }
        // submit meter table for m_read
        meterService.submit(DefaultMeterRequest.builder().forDevice(deviceId).fromApp(appId).add());

    }

    // mapping p4PacketIn to ONOS packet_in
    public InboundPacket mapInboundPacket(PiPacketOperation packetIn, DeviceId deviceId)
            throws PiPipelineInterpreter.PiInterpreterException {

        final String inportMetadataName = "ingress_port";
        // 0=GREEN, 1=YELLOW, 2=RED
        final String colorMetadataName = "meta_tag";
        final String priorityMetadataName = "priority";
        final String sliceMetadataName = "slice_id";
        Optional<PiPacketMetadata> inportMetadata = packetIn.metadatas()
                .stream()
                .filter(meta -> meta.id().id().equals(inportMetadataName))
                .findFirst();

        if (!inportMetadata.isPresent()) {
            throw new PiPipelineInterpreter.PiInterpreterException(format(
                    "Missing metadata '%s' in packet-in received from '%s': %s",
                    inportMetadataName, deviceId, packetIn));
        }

        Optional<PiPacketMetadata> colorMetadata = packetIn.metadatas()
                .stream()
                .filter(meta -> meta.id().id().equals(colorMetadataName))
                .findFirst();

        Optional<PiPacketMetadata> priorityMetadata = packetIn.metadatas()
                .stream()
                .filter(meta -> meta.id().id().equals(priorityMetadataName))
                .findFirst();
        Optional<PiPacketMetadata> sliceMetadata = packetIn.metadatas()
                .stream()
                .filter(meta -> meta.id().id().equals(sliceMetadataName))
                .findFirst();

        final byte[] payloadBytes = packetIn.data().asArray();
        final ByteBuffer rawData = ByteBuffer.wrap(payloadBytes);
        final Ethernet ethPkt;
        try {
            ethPkt = Ethernet.deserializer().deserialize(
                    payloadBytes, 0, packetIn.data().size());
        } catch (DeserializationException dex) {
            throw new PiPipelineInterpreter.PiInterpreterException(dex.getMessage());
        }

        final ImmutableByteSequence portBytes = inportMetadata.get().value();
        final short portNum = portBytes.asReadOnlyBuffer().getShort();
        final ConnectPoint receivedFrom = new ConnectPoint(
                deviceId, PortNumber.portNumber(portNum));
        return new DefaultInboundPacket(receivedFrom, ethPkt, rawData);
    }

    @Override
    public FlowTuple deleteFlowInSlice(int sliceId, FlowTuple flowTuple) {
        if (slices.get(sliceId) == null) {
            slices.get(OTHER_STREAM_SLICEID).remove(flowTuple);
        }
        slices.get(sliceId).remove(flowTuple);
        return flowTuple;
    }

    @Override
    public void deleteSlices(int sliceId) {
        slices.remove(sliceId);
    }

    @Override
    public List<FlowTuple> getSlice(int sliceId) {
        return slices.get(sliceId);
    }

    public class BandwidthManager implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Object inboundPacket = context.inPacket();
            try {
                InboundPacket packet = mapInboundPacket((PiPacketOperation) inboundPacket, DeviceId.deviceId("device:leaf1"));

            } catch (PiPipelineInterpreter.PiInterpreterException e) {
                e.printStackTrace();
            }
        }
    }
    @Activate
    protected void activate() {

        log.info("starting bandwidth manager");
        appId = coreService.registerApplication("org.onosproject.ngsdn-tutorial");
        log.info("{} start working...", appId.id());
    }
}
