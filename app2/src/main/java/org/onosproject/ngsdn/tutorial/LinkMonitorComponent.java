/*
 * Copyright 2022-present Open Networking Foundation
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


import org.onlab.packet.DeserializationException;
import org.onlab.packet.MacAddress;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.link.LinkStore;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiPacketOperation;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.net.statistic.Load;
import org.onosproject.net.statistic.StatisticService;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.onosproject.p4runtime.api.P4RuntimeClient;
import org.onosproject.p4runtime.api.P4RuntimeController;
import org.onosproject.p4runtime.api.P4RuntimeStreamClient;
import org.onosproject.p4runtime.api.P4RuntimeWriteClient;
import org.onosproject.store.primitives.DefaultDistributedLock;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Dictionary;
import java.util.Properties;

import static org.onlab.util.Tools.get;
import static org.onosproject.ngsdn.tutorial.AppConstants.APP_NAME;

import org.onlab.packet.Ethernet;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.*;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;

@Component(immediate = true,
        service = {DelayService.class},
        enabled = true
)
public class LinkMonitorComponent implements DelayService {


    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final String PROBE_SPILT = ";";

    private static final short PROBE_ETH = 0x0812;

    private static final String PROBE_SRC = "12:34:56:78:9a:bc";

    // in l2_ternary_table, macAddr 33:33:xx:xx:xx:xx is mapping to mcast_grp
    // it will send to all port exclude egress_in i,e:CPU_PORT
    private static final String PROBE_DST = "12:34:56:78:9a:bc";

    private final int probeInternal = 4000;

    private final int latencyAverageSize = 5;
    private final int calculateInternal = 4000;


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private PiPipeconfService pipeconfService;

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
    private ExecutorService probeWorker;
    private ScheduledExecutorService pathWorker = Executors.newScheduledThreadPool(1);

    private ApplicationId appId;

    private final Map<Link, List<Integer>> linkLatencies = new ConcurrentHashMap<>();

    private final Map<Link, Integer> initLinklatencies = new ConcurrentHashMap<>();
    private final Map<DeviceId, Integer> controlLinkLatencies = new ConcurrentHashMap<>();

    LinkQualifyProbeTask probeTask;
    CalculateLatencyTask calculateTask;

    LinkProbeReceiver linkProbeReceiver;

    public void requestPushPacket() {

        TrafficSelector selector = DefaultTrafficSelector.builder().matchEthType(PROBE_ETH).build();
        packetService.requestPackets(selector, PacketPriority.HIGH, appId);
    }

    public void cancelPushPacket() {
        TrafficSelector selector = DefaultTrafficSelector.builder().matchEthType(PROBE_ETH).build();
        packetService.cancelPackets(selector, PacketPriority.HIGH, appId);
    }

    public Integer getLinkDelay(Link link) {
        Integer average = 0;
        List<Integer> records = linkLatencies.get(link);
        for (Integer record : records) {
            average += record;
        }
        return average / latencyAverageSize;
    }

    //
//
//    // 获取所有链路时延
    public Map<Link, Integer> getAllLinkDelays() {
        Map<Link, Integer> averageResult = new HashMap<>();
        linkLatencies.forEach(
                (link, records) -> {
                    int sum = 0;
                    for (int record : records) sum += record;
                    // 求平均值
                    averageResult.put(link, sum / latencyAverageSize);
                }
        );
        return averageResult;
    }

    public class LinkQualifyProbeTask implements Runnable {
        private boolean toRun = true;

        public void shutdown() {
            toRun = false;
        }


        @Override
        @SuppressWarnings("beta")
        public void run() {
            // 间隔一段时间就执行一次 时延探测任务
            while (toRun) {
                log.debug("send packet out to data plane network");
                // 遍历所有 可用设备
                for (Device device : deviceService.getAvailableDevices()) {
                    DeviceId deviceId = device.id();

                    final PiCriterion aclCriterion = PiCriterion.builder()
                            .matchTernary(
                                    PiMatchFieldId.of("hdr.ethernet.ether_type"),
                                    0x0812,
                                    16)
                            .build();

                    final PiAction aclAction = PiAction.builder()
                            .withId(PiActionId.of("IngressPipeImpl.clone_to_cpu"))
                            .build();
                    final FlowRule rule4 = Utils.buildFlowRule(
                            deviceId, appId, "IngressPipeImpl.acl_table",
                            aclCriterion, aclAction);
                    flowRuleService.applyFlowRules(rule4);
                    // 构造两个treatment对象，treatment用于指导一个流表的action，也就是收到了流表后，openflow switch的行为

                    // 收到这个流表的交换机，将发起广播报文
                    TrafficTreatment treatmentAll =
                            DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(233)).build();

                    // 收到这个流表的交换机，将把报文转发给控制器
                    TrafficTreatment treatmentController =
                            DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(255)).build();

                    // 构造PDU，并封装为以太网帧。注意，以太网帧为SDN网络里传输的基本单位。
                    Ethernet ethernet = new Ethernet();
                    ethernet.setSourceMACAddress(PROBE_SRC); // 源MAC无意义，随便设置就行
                    ethernet.setDestinationMACAddress(PROBE_DST); // 广播包
                    ethernet.setEtherType(PROBE_ETH); // 我们随机生成的一个代表广播包类型的16位数字。

                    PDU payload = new PDU(deviceId.toString(), System.currentTimeMillis());
                    ethernet.setPayload(payload);

                    DefaultOutboundPacket packetAll = new DefaultOutboundPacket(deviceId, treatmentAll, ByteBuffer.wrap(ethernet.serialize()));
                    // System.out.println("send packetAll ==> " + packetAll);
                    packetService.emit(packetAll);


                    payload = new PDU(deviceId.toString(), System.currentTimeMillis());
                    ethernet.setPayload(payload);

                    DefaultOutboundPacket packet = new DefaultOutboundPacket(deviceId, treatmentController, ByteBuffer.wrap(ethernet.serialize()));
                    // System.out.println("send packetController ==> " + packet);
                    packetService.emit(packet);


                    // method "packetOut()" of this object for send packet_out to switch
                    // can handle a PiPacketOperation obj
                    // util/p4rt-sh --grpc-addr localhost:50001 --config
                    // p4src/build/p4info.txt,p4src/build/bmv2.json --election-id 0,1

                    // for packet_in, can also mapping to a PiPacketOperation
                    // we can put metadata in PiPacketOperation Object to get another critical info
                    // TODO: how to send PiPacketOperation to data plane
                    // TODO: how to mapping PortNumber.ALL to p4 object
                    // TODO: maybe P4RuntimeController can indicate metadata(include multicast grp)

                    // TODO: don't be confused by p4runtime
                    // TODO: p4runtime is a grpc indeed, so send this PiPacketOperation is send a grpc
                    // TODO: by using "usage", we find P4RuntimeStreamClient can receive a PiPacketOperation as params
                }

                try {
                    Thread.sleep(probeInternal);
                } catch (InterruptedException e) {
                    break;
                }
            }
            log.info("数据报文探测停止~~");
        }

    }

    public static ByteBuffer extractByteBuffer(ByteBuffer srcBuffer) {
        ByteBuffer newBuffer = ByteBuffer.allocate(srcBuffer.remaining() - 16);
        srcBuffer.position(16);
        newBuffer.put(srcBuffer.slice());
        newBuffer.rewind();
        return newBuffer;
    }

    public class LinkProbeReceiver implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            long now = System.currentTimeMillis();

            if (context.isHandled()) {
                return;
            }
            InboundPacket pkt = context.inPacket();
            ByteBuffer rawData = pkt.unparsed();
            Ethernet packet = pkt.parsed();
            // log.debug("recvData:" + String.valueOf(packet.getPayload()));
            // log.debug("etherTYpe" + packet.getEtherType());

            // pre-handle a packet_in generated by p4!
            // notice: P4 handle packet_in by adding a header cpu_in, which can't be recognized by onos

            // if not equal 255
            // which mean the packet_in isn't directly send back to controller
            // but by p4 wrap it a cpu_in then send back

            // TODO:
            // we can parse ByteBuffer which format [16bit-cpu_in] [48bit-srcAddr] [48bit-dstAddr] [16bit-etherType]
            // as Buffer[14:15] we need to read from

            @Deprecated
            ByteBuffer unparsed = pkt.unparsed();
            short etherType = unparsed.getShort(14);// getByteBuffer[14], get 2 bytes as a short
            if (etherType == 0x0812) {

                // 9bit ingress_port (PortNumber)
                // 7bit padding
                // amend it
                // packet_in by amending
                byte[] cpuInHeader = new byte[2];
                // read 16 bits
                // FUCK: cpu_in header is 16bits not 16bytes
                rawData.get(cpuInHeader);
                System.out.println("get cpuInHeader ==> " + Arrays.toString(cpuInHeader));
                // 解析 cpu_in 头部获取 in_port
                int inPort = ((cpuInHeader[0] & 0xFF) << 1) | ((cpuInHeader[1] >> 7) & 0x01);


                // 读取数据帧部分
                byte[] ethernetFrame = new byte[rawData.remaining()];
                rawData.get(ethernetFrame);
                // System.out.println("parsing...: "+ Arrays.toString(ethernetFrame));
                try {
                    packet = Ethernet.deserializer().deserialize(
                            ethernetFrame, 0, ethernetFrame.length
                    );
                } catch (DeserializationException e) {
                    e.printStackTrace();
                }
                System.out.println("get BiasPacket_in: ==> " + packet + ", and in_port=" + pkt.receivedFrom().port());
                System.out.println("from where ==> " + pkt.receivedFrom() + " and payload is : " + new String(packet.getPayload().serialize(), StandardCharsets.US_ASCII));

                if (packet.getEtherType() == PROBE_ETH) {
                }
            } else {
                // System.out.println("get packet_in: ==> " + pkt + ", and in_port=" + pkt.receivedFrom().port());
                // System.out.println("from where ==> " + pkt.receivedFrom() +  " and payload is : " + new String(packet.getPayload().serialize(), StandardCharsets.US_ASCII));
            }


            if (packet.getEtherType() == PROBE_ETH) {
                byte[] serialize = packet.getPayload().serialize();
                // TODO: parse more info that p4 collected
                String[] data = new String(serialize).split(PROBE_SPILT);
                DeviceId probeSrc = DeviceId.deviceId(data[0]);
                long before = Long.parseLong(data[1]);

                if (pkt.receivedFrom().port().equals(PortNumber.portNumber(255))) {
                    // get packet_in's ingress_port metadata
                    log.debug("round trip from device:{} to controller, delay:{}", probeSrc, (int) (now - before));
                    controlLinkLatencies.put(probeSrc, (int) (now - before));
                } else {
                    // in p4, receivedFrom is the same !!

                    Set<Link> links = linkService.getIngressLinks(context.inPacket().receivedFrom());
                    if (links.isEmpty()) {
                        log.warn("packet loss :: {}", context.inPacket().receivedFrom());
                        // packet drop !!
                        // if a link can't be detected, meaning probe packet is loss !
                        log.debug("probe packet losing!");
                        // return;
                    }
                    for (Link link : links) {
                        if (link.src().deviceId().equals(probeSrc)) {
                            // 更新链路时延
                            log.debug("{}->{}, delay:{}", link.src(), link.dst(), (int) (now - before));
                            initLinklatencies.put(link, (int) (now - before));
                        }
                    }
                }
            }
            // 不传给pipeline的下一个processor了，直接结束对packet in的处理
            context.block();
        }
    }

    public class CalculateLatencyTask implements Runnable {

        private boolean toRun = true;

        public void shutdown() {
            toRun = false;
        }

        @Override
        public void run() {
            while (toRun) {
                initLinklatencies.forEach(
                        (link, record) -> {
                            // 时延计算
                            // 我们先算出从 控制器分别到link的源设备和目标设备的链路时延
                            // 由于广撒网的时候计算一次时间，(controller -- packet out -- device)
                            // 然后device根据流表向所有结点转发数据(包括交换机结点) [device -- packet in -- controller]又计算一次
                            // 因此我们记录的是一个来回的时间，我们要把时间除2、如果链路没有记录，则按照0算

                            // 从srcDevice到controller的时延
                            record -= controlLinkLatencies.getOrDefault(link.src().deviceId(), 0) / 2;
                            // 从dstDevice到controller的时延
                            record -= controlLinkLatencies.getOrDefault(link.dst().deviceId(), 0) / 2;

                            List<Integer> records;
                            if (linkLatencies.get(link) == null) {
                                records = new ArrayList<>();
                                linkLatencies.put(link, records);
                            } else {
                                records = linkLatencies.get(link);
                            }

                            // 是否需要LRU
                            if (records.size() >= latencyAverageSize) {
                                records.remove(0);
                            }
                            // 加入这次时延，如果为负数，说明计算有误，为0
                            records.add(record < 0 ? 0 : record);
                        }
                );
                // 每隔一段时间计算一次
                try {
                    Thread.sleep(calculateInternal);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }
    }

    @Override
    public HostId map(String hostAlias) {
        String PREFIX = "00:00:00:00:00:";
        String SUFFIX = "/None";
        if (hostAlias.length() == 2) {
            char c = hostAlias.toCharArray()[1];
            return HostId.hostId(PREFIX + c + '0' + SUFFIX);
        } else {
            String s = hostAlias.substring(1);
            return HostId.hostId(PREFIX + s + SUFFIX);
        }
    }

    private Map<Link, Integer> linkDelays;

//    private void getAllECMPPath() {
//        HostId h2 = map("h2");
//        Host src = hostService.getHost(h2);
//        Host dst = hostService.getHost(map("h3"));
//        getAllECMPPath(src, dst);
//    }


    // get all equal-cost paths between host h1 and host h2
    public void calculateAllECMPPath(Host src, Host dst) {
        linkDelays = getAllLinkDelays();
        if (linkDelays.isEmpty()) {
            return;
        }
        Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(), src.location().deviceId(), dst.location().deviceId());
        Path priorityPath = null;
        Integer minLatency = Integer.MAX_VALUE;
        // how many equal cost multi path
        Integer[] mpLatencies = new Integer[paths.size()];
        int index = 0;
        for (Path path : paths) {
            List<Link> links = path.links();
            Integer latency = 0;
            for (Link link : links) {
                // notice: if src and dst is reverse, our code should also effect !!
                latency += getFromLinkDelays(link);
                ConnectPoint srcCp = link.src();
                PortStatistics portStat = deviceService.getDeltaStatisticsForPort(srcCp.deviceId(), srcCp.port());
//                Load load = statisticService.load(link);
//                log.error("link {}<->{} => load :{}", link.src().deviceId(), link.dst().deviceId(), portStat);
//                log.error("throughput: {}Kbps", portStat.bytesSent() * 8 / 5 / 1024);
            }
            mpLatencies[index++] = latency;
            if (latency < minLatency) {
                priorityPath = path;
            }
        }
//        log.error("{} : {}", priorityPath, Arrays.toString(mpLatencies));
        log.error("{}", Arrays.toString(mpLatencies));
    }

    // get all equal-cost paths between host h1 and host h2
    @Override
    public Map<Path, Integer> getAllECMPPath(HostId srcId, HostId dstId) {

        Host src = hostService.getHost(srcId);
        Host dst = hostService.getHost(dstId);
        linkDelays = getAllLinkDelays();
        if (linkDelays.isEmpty()) {
            return null;
        }
        Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(), src.location().deviceId(), dst.location().deviceId());
        Path priorityPath = null;
        Integer minLatency = Integer.MAX_VALUE;
        Map<Path, Integer> res = new HashMap<>();
        // how many equal cost multi path
        Integer[] mpLatencies = new Integer[paths.size()];
        int index = 0;
        for (Path path : paths) {
            List<Link> links = path.links();
            Integer latency = 0;
            for (Link link : links) {
                // notice: if src and dst is reverse, our code should also effect !!
                latency += getFromLinkDelays(link);
                ConnectPoint srcCp = link.src();
//                Load load = statisticService.load(link);
//                log.error("link {}<->{} => load :{}", link.src().deviceId(), link.dst().deviceId(), portStat);
//                log.error("throughput: {}Kbps", portStat.bytesSent() * 8 / 5 / 1024);
            }
            res.put(path, latency);
            mpLatencies[index++] = latency;
            if (latency < minLatency) {
                priorityPath = path;
            }
        }
//        log.error("{} : {}", priorityPath, Arrays.toString(mpLatencies));
        return res;
    }


    @Override
    public Integer getFromLinkDelays(Link link) {
        Integer ret = linkDelays.get(link);

        if (ret == null) {
            // if ret == null, try to reverse the link
            DeviceId srcDeviceId = link.src().deviceId();
            DeviceId dstDeviceId = link.dst().deviceId();
            PortNumber srcPort = link.src().port();
            PortNumber dstPort = link.dst().port();

            ConnectPoint srcConnectPoint = new ConnectPoint(dstDeviceId, dstPort);
            ConnectPoint dstConnectPoint = new ConnectPoint(srcDeviceId, srcPort);

            Link newLink = DefaultLink.builder()
                    .providerId(link.providerId())
                    .src(srcConnectPoint)
                    .dst(dstConnectPoint)
                    .state(link.state())
                    .type(link.type())
                    .isExpected(link.isExpected())
                    .build();
            ret = linkDelays.get(newLink);
        }

        // if ret still null, we regard it as "non-access", and delay is indefinite
        return ret == null ? 10000000 : ret;
    }

    @Override
    public Integer getFromLinkDelays(String s1, String s2) {
        Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(), DeviceId.deviceId(s1), DeviceId.deviceId(s2));
        if (paths.size() != 1) {
            return -1;
        }
        List<Path> l = new ArrayList<>(paths);
        Path p = l.get(0);
        List<Link> links = p.links();
        if (links.size() != 1) {
            return -1;
        }
        return getFromLinkDelays(links.get(0));
    }

    @Activate
    protected void activate() {
        log.info("starting link monitor...");

        appId = coreService.registerApplication("org.onosproject.ngsdn-tutorial");

        linkProbeReceiver = new LinkProbeReceiver();
        packetService.addProcessor(linkProbeReceiver, PacketProcessor.advisor(1));

        // we want that ether_type = 0x0812 should match
        // but using ONOS RuleRole seems no use ...
        // use PiUtils to insert acl_table !
        requestPushPacket();
        probeTask = new LinkQualifyProbeTask();
        calculateTask = new CalculateLatencyTask();
        probeWorker = Executors.newCachedThreadPool();
        probeWorker.submit(probeTask);
        probeWorker.submit(calculateTask);

//        pathWorker.scheduleAtFixedRate(this::getAllECMPPath, 0, 5, TimeUnit.SECONDS);

        log.info("{} start working...", appId.id());
    }

    @Deactivate
    protected void deactivate() {
        log.info("{} closing...", appId.id());
        probeTask.shutdown();
        calculateTask.shutdown();

        probeWorker.shutdown();
        pathWorker.shutdown();

        try {
            log.info("waiting pool to shutdown");
            probeWorker.awaitTermination(3, TimeUnit.SECONDS);
            log.info("shutdown successfully");
        } catch (InterruptedException e) {
            e.printStackTrace();
            log.warn("something wrong occur in closing...");
        }

        cancelPushPacket();

        packetService.removeProcessor(linkProbeReceiver);
        log.info("应用关闭...");
    }

}
