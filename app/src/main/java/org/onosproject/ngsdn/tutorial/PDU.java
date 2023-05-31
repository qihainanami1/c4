package org.onosproject.ngsdn.tutorial;


import org.onlab.packet.BasePacket;

import java.nio.charset.StandardCharsets;

public class PDU extends BasePacket {
    private String deviceId;
    private Long date;

    public PDU(String deviceId, Long date) {
        this.deviceId = deviceId;
        this.date = date;
    }

    @Override
    public byte[] serialize() {
        return this.toString().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return deviceId + ";" + date;
    }

}

