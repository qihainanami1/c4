package org.onosproject.ngsdn.tutorial;

import com.google.common.hash.HashFunction;
import org.apache.commons.lang.BitField;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.*;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.net.statistic.StatisticService;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

@Component(immediate = true,
        service = {LossRadarService.class},
        enabled = true
)
public class LossRadarCollectorComponent implements LossRadarService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;
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

    private LossCollector lossCollector;
    private ApplicationId appId;

    private static final int NUM_PORTS = 2;
    private static final int NUM_BATCHES = 2;

    private static final int REGISTER_SIZE_TOTAL = 6144;
    private static final int REGISTER_BATCH_SIZE = REGISTER_SIZE_TOTAL / NUM_BATCHES;
    private static final int REGISTER_PORT_SIZE = REGISTER_BATCH_SIZE / NUM_PORTS;
    private static final int LOSS_TYPE = 0x1234;

    private final static int[] crc32_polinomials = {0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7,
            0xEB31D82E, 0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C,
            0x32583499, 0x992C1A4C};

    public static ByteBuffer extractByteBuffer(ByteBuffer srcBuffer) {
        ByteBuffer newBuffer = ByteBuffer.allocate(srcBuffer.remaining() - 16);
        srcBuffer.position(16);
        newBuffer.put(srcBuffer.slice());
        newBuffer.rewind();
        return newBuffer;
    }

    public static class Crc32HashFunction {

        // invertible hash function equivalent to P4
        public int bitByBitFast(int[] flowStream) {
            return P4Hash(flowStream);
        }

        public int P4Hash(int[] flowStream) {
            // according to which P4Hash implementations
            return 0;
        }
    }

    @Override
    public Set<String> decodeMeterPair() {
        try {
            return decodeMeterPair0(new HashMap<>(), new HashMap<>(), new Crc32HashFunction[3]);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Set<String> decodeMeterPair0(Map<String, int[]> umRegisters, Map<String, int[]> dmRegisters, Crc32HashFunction[] hashes) throws UnknownHostException {
        Set<String> droppedPackets = new HashSet<>();
        int[] umCounter = umRegisters.get("IngressPipeImpl.um_counter");
        int[] umIpSrc = umRegisters.get("IngressPipeImpl.um_ip_src");
        int[] umIpDst = umRegisters.get("IngressPipeImpl.um_ip_dst");
        int[] umPortsProtoId = umRegisters.get("IngressPipeImpl.um_ports_proto");
        int[] dmCounter = dmRegisters.get("IngressPipeImpl.dm_counter");
        int[] dmIpSrc = dmRegisters.get("IngressPipeImpl.dm_ip_src");
        int[] dmIpDst = dmRegisters.get("IngressPipeImpl.dm_ip_dst");
        int[] dmPortsProtoId = dmRegisters.get("IngressPipeImpl.dm_ports_proto");
        while (Arrays.stream(umCounter).min().getAsInt() == 1) {
            int i = -1;
            for (int j = 0; j < umCounter.length; j++) {
                if (umCounter[j] == 1) {
                    umCounter[j]--;
                    dmCounter[j]--;

                    i = j;
                    break;
                }
            }
            if (i == -1) {
                break;
            }

            int tmpSrc = umIpSrc[i] ^ dmIpSrc[i];
            int tmpDst = umIpDst[i] ^ dmIpDst[i];
            String src = decodeIpAddress(tmpSrc);
            String dst = decodeIpAddress(tmpDst);
            // 48B misc(src_port, dst_port, next_hdr)
            long misc = umPortsProtoId[i] ^ dmPortsProtoId[i];
            long proto = (misc >> 16) & 0xff;
            long dstPort = (misc >> 24) & 0xffff;
            long srcPort = (misc >> 40) & 0xffff;

            int[] flowStream = buildFlowBytestream(src, dst, srcPort, dstPort, proto);
            int index0 = hashes[0].bitByBitFast(flowStream) % REGISTER_PORT_SIZE;
            int index1 = hashes[1].bitByBitFast(flowStream) % REGISTER_PORT_SIZE;
            int index2 = hashes[2].bitByBitFast(flowStream) % REGISTER_PORT_SIZE;

            umIpSrc[index0] ^= tmpSrc;
            umIpSrc[index1] ^= tmpSrc;
            umIpSrc[index2] ^= tmpSrc;

            umIpDst[index0] ^= tmpDst;
            umIpDst[index1] ^= tmpDst;
            umIpDst[index2] ^= tmpDst;

            umPortsProtoId[index0] ^= misc;
            umPortsProtoId[index1] ^= misc;
            umPortsProtoId[index2] ^= misc;

            if (dmCounter[index0] < 0 || dmCounter[index1] < 0 || dmCounter[index2] < 0) {
                break;
            }
            dmCounter[index0]--;
            dmCounter[index1]--;
            dmCounter[index2]--;

            droppedPackets.add(buildFlowString(src, dst, (int) srcPort, ((int) dstPort), ((int) proto)));
        }

        return droppedPackets;
    }

    private String decodeIpAddress(int addr) {
        byte[] bytes = ByteBuffer.allocate(4).putInt(addr).array();
        return String.format("%d.%d.%d.%d", bytes[0] & 0xff, bytes[1] & 0xff, bytes[2] & 0xff, bytes[3] & 0xff);
    }

    /*
    5-tuple 
    ipv6_src = 128b
    ipv6_dst = 128b
    src_port = 16b
    dst_port = 16b
    next_hdr = 16b
    
    cache friendly: cache 16b = 320b = 40B
     */
    private int[] buildFlowBytestream(String src, String dst, long srcPort, long dstPort, long proto) throws UnknownHostException {
        byte[] srcBytes = Inet6Address.getByName(src).getAddress();
        byte[] dstBytes = Inet6Address.getByName(dst).getAddress();
        ByteBuffer buffer = ByteBuffer.allocate(40);
        buffer.put(srcBytes);
        buffer.put(dstBytes);
        buffer.putShort(((short) srcPort));
        buffer.putShort(((short) dstPort));
        buffer.put((byte) proto);
        byte[] padding = new byte[2];
        buffer.put(padding);

        return toBits(buffer.array());
    }

    private String buildFlowString(String src, String dst, int srcPort, int dstPort, int proto) {
        return String.format("%s;%d;%s;%d;%d", src, srcPort, dst, dstPort, proto);
    }

    private int[] toBits(byte[] bytes) {
        int[] bits = new int[bytes.length * 8];
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            for (int j = 0; j < 8; j++) {
                bits[i * 8 + j] = (b & (1 << (7 - j))) == 0 ? 0 : 1;
            }
        }
        return bits;
    }


    public class LossCollector implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }
            InboundPacket pkt = context.inPacket();
            ByteBuffer rawData = pkt.unparsed();
            Ethernet packet = pkt.parsed();

            ByteBuffer unparsed = pkt.unparsed();
            // cpu_in(16bit) = 2B
            // ethernet(48+48+16) = 14B
            // ipv6(320bit) = 40B next_hdr 6B
            // loss = 1bit + 7bit + 8bit

            short ipv6NextHdr = unparsed.getShort(22);
            if (ipv6NextHdr == LOSS_TYPE) {
                byte[] cpuInHeader = new byte[2];
                rawData.get(cpuInHeader);
                byte[] etherHeader = new byte[14];
                rawData.get(etherHeader);
                byte[] ipv6Hdr = new byte[40];
                rawData.get(ipv6Hdr);
                byte[] lossHdr = new byte[2];
                rawData.get(lossHdr);
                int batch_id = (lossHdr[0] & 0x80) >> 7;

                int inPort = ((cpuInHeader[0] & 0xFF) << 1) | ((cpuInHeader[1] >> 7) & 0x01);
                int next_hdr = lossHdr[1];

                int start = (batch_id * REGISTER_BATCH_SIZE) + ((inPort - 1) * REGISTER_PORT_SIZE);
                int end = start + REGISTER_PORT_SIZE;

                context.block();
            }
        }


        @Activate
        protected void activate() {
            log.info("starting loss collecting");
            appId = coreService.registerApplication("org.onosproject.ngsdn-tutorial");
            lossCollector = new LossCollector();
            packetService.addProcessor(lossCollector, PacketProcessor.advisor(1));
            log.info("{} start working...", appId.id());
        }

        @Deactivate
        protected void deactivate() {
            log.info("{} closing...", appId.id());

            packetService.removeProcessor(lossCollector);
        }

    }
}
