package org.onosproject.ngsdn.tutorial;

import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.onosproject.ngsdn.tutorial.AppConstants.INITIAL_SETUP_DELAY;

@Component(
        immediate = true,
        enabled = false
)
public class PathSelectorComponent {
    private final Logger log = LoggerFactory.getLogger(getClass());

    // choose host h1 -> host h2's equal cost multi path
    // and using srv6 to device which cost is the lowest
    private ApplicationId appId;

    //--------------------------------------------------------------------------
    // ONOS CORE SERVICE BINDING
    //
    // These variables are set by the Karaf runtime environment before calling
    // the activate() method.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService configService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private TopologyService topologyService;

    //    @Reference(cardinality = ReferenceCardinality.MANDATORY, policyOption = ReferencePolicyOption.GREEDY)
//    private LinkMonitorComponent linkMonitorComponent;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LinkMonitorComponent linkMonitorComponent;
    // after some delay to get this, otherwise will cause NPE
    private Map<Link, Integer> linkDelays;

    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().

    //--------------------------------------------------------------------------

    private ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);

    private static String PREFIX = "00:00:00:00:00:";
    private static String SUFFIX = "/None";

    private HostId map(String hostAlias) {
        if (hostAlias.length() == 2) {
            char c = hostAlias.toCharArray()[1];
            return HostId.hostId(PREFIX + c + '0' + SUFFIX);
        } else {
            String s = hostAlias.substring(1);
            return HostId.hostId(PREFIX + s + SUFFIX);
        }
    }

    @Activate
    protected void activate() throws InterruptedException {
        appId = mainComponent.getAppId();

        // delay 10s to get linkDelays
        executor.scheduleAtFixedRate(this::getAllECMPPath, 10, 1, TimeUnit.SECONDS);
        log.info("ECMP Path selector Started");
    }


    private void getAllECMPPath() {

        HostId h2 = map("h2");
        Host src = hostService.getHost(h2);
        Host dst = hostService.getHost(map("h3"));
        linkDelays = linkMonitorComponent.getAllLinkDelays();
        getAllECMPPath(src, dst);
    }

    @Deactivate
    protected void deactivate() {
//        deviceService.removeListener(deviceListener);
//        hostService.removeListener(hostListener);

        log.info("Stopped");
    }


    // get all equal-cost paths between host h1 and host h2
    private void getAllECMPPath(Host src, Host dst) {
        log.error("?? fanbingle ??");
        log.error("{}", linkDelays);
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
                latency += linkDelays.get(link);
            }
            mpLatencies[index++] = latency;
            if (latency < minLatency) {
                priorityPath = path;
            }
        }
        log.error("{} : {}", priorityPath, Arrays.toString(mpLatencies));
    }
}
