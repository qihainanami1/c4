package org.onosproject.ngsdn.tutorial;

import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/port")
public class AppMockECMPWebResource extends AbstractWebResource {

    private final Logger log = LoggerFactory.getLogger(getClass());

    Srv6InsertComponentService srv6InsertComponent = getService(Srv6InsertComponentService.class);

    @Path("/disable/{deviceID}/{portID}")
    public Response mockDisablePort(
            @PathParam("deviceID") String deviceID,
            @PathParam("portID") Integer portID
    ) {
        log.info("disable port: {}/{}", deviceID, portID);
        srv6InsertComponent.mockUpdateECMPPath();
        return Response.status(Response.Status.OK)
                .entity("{\"success\": \"port disabled, and change to another path\"}")
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Path("/enable/{deviceID}/{portID}")
    public Response mockEnablePort(
            @PathParam("deviceID") String deviceID,
            @PathParam("portID") Integer portID
    ) {
        log.info("disable port: {}/{}", deviceID, portID);
        return Response.status(Response.Status.OK)
                .entity("{\"success\": \"port enable, and no need to change another path\"}")
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }
}
