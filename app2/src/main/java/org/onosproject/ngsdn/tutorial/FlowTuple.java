package org.onosproject.ngsdn.tutorial;

import java.util.Arrays;

public class FlowTuple {
    byte[] srcAddr;
    byte[] dstAddr;
    byte[] srcPort;
    byte[] dstPort;
    byte[] nextHdr;

    public FlowTuple(byte[] srcAddr, byte[] dstAddr, byte[] srcPort, byte[] dstPort, byte[] nextHdr) {
        this.srcAddr = srcAddr;
        this.dstAddr = dstAddr;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.nextHdr = nextHdr;
    }

    public byte[] getSrcAddr() {
        return srcAddr;
    }

    public void setSrcAddr(byte[] srcAddr) {
        this.srcAddr = srcAddr;
    }

    public byte[] getDstAddr() {
        return dstAddr;
    }

    public void setDstAddr(byte[] dstAddr) {
        this.dstAddr = dstAddr;
    }

    public byte[] getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(byte[] srcPort) {
        this.srcPort = srcPort;
    }

    public byte[] getDstPort() {
        return dstPort;
    }

    public void setDstPort(byte[] dstPort) {
        this.dstPort = dstPort;
    }

    public byte[] getNextHdr() {
        return nextHdr;
    }

    public void setNextHdr(byte[] nextHdr) {
        this.nextHdr = nextHdr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FlowTuple flowTuple = (FlowTuple) o;
        return Arrays.equals(srcAddr, flowTuple.srcAddr) && Arrays.equals(dstAddr, flowTuple.dstAddr) && Arrays.equals(srcPort, flowTuple.srcPort) && Arrays.equals(dstPort, flowTuple.dstPort) && Arrays.equals(nextHdr, flowTuple.nextHdr);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(srcAddr);
        result = 31 * result + Arrays.hashCode(dstAddr);
        result = 31 * result + Arrays.hashCode(srcPort);
        result = 31 * result + Arrays.hashCode(dstPort);
        result = 31 * result + Arrays.hashCode(nextHdr);
        return result;
    }
}
