/*
 * Copyright 2023-present Open Networking Foundation
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

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.net.Link;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.onosproject.rest.AbstractWebResource;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Map;

/**
 * Sample web resource.
 */
@Path("v1")
public class AppWebResource extends AbstractWebResource {

    DelayService delayService = getService(DelayService.class);

    /**
     * Get hello world greeting.
     *
     * @return 200 OK
     */
    @GET
    @Path("")
    public Response getGreeting() {
        ObjectNode node = mapper().createObjectNode().put("description", "A restful endpoint about link latency...");
        return ok(node).build();
    }

    @GET
    @Path("/link/all")
    public Response getDelay() {
        ObjectNode node = mapper().createObjectNode();
        Map<Link, Integer> delays = delayService.getAllLinkDelays();
        for (Map.Entry<Link, Integer> entry : delays.entrySet()) {
            Link aLink = entry.getKey();
            String link = aLink.src() + "->" + aLink.dst();
            node.put(link, entry.getValue());
        }
        return ok(node).build();
    }

    @GET
    @Path("/link/host/{h1}/{h2}")
    public Response getDelayOfLinkByHostId(
            @PathParam("h1") String h1,
            @PathParam("h2") String h2
    ) {
        ObjectNode node = mapper().createObjectNode();

        Map<org.onosproject.net.Path ,Integer> res = delayService.getAllECMPPath(Utils.map(h1), Utils.map(h2));
        for (Map.Entry<org.onosproject.net.Path, Integer> entry : res.entrySet()) {
            node.put(String.valueOf(entry.getKey()), entry.getValue());
        }
        return ok(node).build();
    }

    @GET
    @Path("/link/sw/{s1}/{s2}")
    public Response getDelayOfLinkBySwIDNoOrder(
            @PathParam("s1") String switchId1,
            @PathParam("s2") String switchId2
    ) {
        ObjectNode node = mapper().createObjectNode();
        Integer res = delayService.getFromLinkDelays(switchId1, switchId2);
        if (res == -1) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"please ensure only a single link!\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } else {
            node.put("delay", res);
            return ok(node).build();
        }
    }

}
