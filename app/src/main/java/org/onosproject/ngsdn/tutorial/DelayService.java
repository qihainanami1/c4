package org.onosproject.ngsdn.tutorial;

import org.onosproject.net.Link;

import java.util.Map;

public interface DelayService {

    Integer getLinkDelay(Link link);

    Map<Link, Integer> getAllLinkDelays();

}
