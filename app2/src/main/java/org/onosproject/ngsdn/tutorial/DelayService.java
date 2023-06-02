package org.onosproject.ngsdn.tutorial;

import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;

import java.util.Map;

public interface DelayService {

    Integer getLinkDelay(Link link);

    Map<Link, Integer> getAllLinkDelays();

    Map<Path, Integer> getAllECMPPath(HostId src, HostId dst);

    HostId map(String hostAlias);

    Integer getFromLinkDelays(Link link);

    Integer getFromLinkDelays(String swID1, String swID2);
}
