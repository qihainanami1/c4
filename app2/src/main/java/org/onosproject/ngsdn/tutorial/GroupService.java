package org.onosproject.ngsdn.tutorial;

import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.PortNumber;

import java.util.Set;

public interface GroupService {
    void insertNewPortNumber(DeviceId deviceId, String groupName, PortNumber newPort);

    void removeGroup(String deviceId, String groupName);

    void addHostToGroup(String hostname, String groupName);

    void removeHostInGroup(String hostname, String groupName);

    void removePortNumber(DeviceId deviceId, String groupName, PortNumber newPort);

    Set<Host> getGroupInfo(String gname);

    void mockUpdateECMPPath();
}
