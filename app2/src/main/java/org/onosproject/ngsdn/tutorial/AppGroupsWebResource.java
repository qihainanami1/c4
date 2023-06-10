package org.onosproject.ngsdn.tutorial;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.rest.AbstractWebResource;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Path("group/")
public class AppGroupsWebResource extends AbstractWebResource {


    @GET
    @Path("")
    public Response getGreeting() {
        ObjectNode node = mapper().createObjectNode().put("description", "A restful endpoint about group management...");
        return ok(node).build();
    }

    GroupService groupService = getService(GroupService.class);


    @GET
    @Path("{gname}")
    public Response getGroupInfo(
            @PathParam("gname") String gname
    ) {
        ObjectNode node = mapper().createObjectNode();

        Set<Host> groupInfo = groupService.getGroupInfo(gname);
        List<HostId> collect = groupInfo.stream().map(Host::id).collect(Collectors.toList());
        List<String> res = collect.stream().map(HostId::toString).collect(Collectors.toList());
        String jsonArr = null;
        try {
            jsonArr = new ObjectMapper().writeValueAsString(res);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        node.put(gname, jsonArr);
        return ok(node).build();
    }

    @POST
    @Path("add/port/{deviceID}/{gname}/{portNum}")
    public Response addPortToGroup(
            @PathParam("deviceID") String deviceID,
            @PathParam("gname") String gname,
            @PathParam("portNum") String portNum
    ) {
        groupService.insertNewPortNumber(DeviceId.deviceId(deviceID), gname, PortNumber.portNumber(portNum));
        return Response.status(Response.Status.OK)
                .entity("{\"success\":\"insert into group:" + gname + ", portNum: " + portNum + " \"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    @POST
    @Path("delete/port/{deviceID}/{gname}/{portNum}")
    public Response delPortInGroup(
            @PathParam("deviceID") String deviceID,
            @PathParam("gname") String gname,
            @PathParam("portNum") String portNum
    ) {
        groupService.removePortNumber(DeviceId.deviceId(deviceID), gname, PortNumber.portNumber(portNum));
        return Response.status(Response.Status.NO_CONTENT)
                .entity("{\"success\":\"remove into group:" + gname + ", portNum: " + portNum + " \"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }


    @DELETE
    @Path("delete/{deviceID}/{gname}")
    public Response deleteGroup(
            @PathParam("deviceID") String deviceID,
            @PathParam("gname") String gname
    ) {
        groupService.removeGroup(deviceID, gname);
        return Response.status(Response.Status.NO_CONTENT)
                .entity("{\"success\":\"group:" + gname + " is deleted \"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }


    @POST
    @Path("add/host/{gname}/{hostID}")
    public Response addHostToGroup(
            @PathParam("gname") String gname,
            @PathParam("hostID") String hostID
    ) {
        groupService.addHostToGroup(hostID, gname);
        return Response.status(Response.Status.OK)
                .entity("{\"success\":\"add host:" + hostID + " into group:" + gname + "\"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    @POST
    @Path("delete/host/{gname}/{hostID}")
    public Response delHostInGroup(
            @PathParam("gname") String gname,
            @PathParam("hostID") String hostID
    ) {
        groupService.removeHostInGroup(hostID, gname);
        return Response.status(Response.Status.NO_CONTENT)
                .entity("{\"success\":\"remove host:" + hostID + " into group:" + gname + "\"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }




}
