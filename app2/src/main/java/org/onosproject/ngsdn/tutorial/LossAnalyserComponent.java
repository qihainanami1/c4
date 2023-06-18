package org.onosproject.ngsdn.tutorial;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;


@Component(immediate = true,
        service = {LossAnalyserService.class},
        enabled = true
)
public class LossAnalyserComponent {


    private final Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkMonitorComponent linkMonitorComponent;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LossRadarCollectorComponent lossRadarCollectorComponent;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);


    @Activate
    protected void activate() {
        log.info("starting link monitor...");
        appId = coreService.registerApplication("org.onosproject.ngsdn-tutorial");
        log.info("{} start working...", appId.id());

        executor.scheduleAtFixedRate(() -> {

        }, 0, 10, TimeUnit.MILLISECONDS);
    }



    private FlowTuple parseString(String flow) {
        String[] split = flow.split(";");
        return new FlowTuple(split[0].getBytes(StandardCharsets.UTF_8),
                split[2].getBytes(StandardCharsets.UTF_8),
                split[1].getBytes(StandardCharsets.UTF_8),
                split[3].getBytes(StandardCharsets.UTF_8),
                split[4].getBytes(StandardCharsets.UTF_8));

    }

    // 10ms
    private static final int ANALYSE_PERIOD = 10;
    // tcp-only
    private static final int BURST_THRESHOLD = 10;

    public enum LossType {
        CONGESTION,
        BLACK_HOLES,
        RANDOM_DROPS,
        LOOP,
        UNKNOWN
    }
    public LossType analyse() {
        return LossType.UNKNOWN;
    }
}
