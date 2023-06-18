package org.onosproject.ngsdn.tutorial;

import java.util.List;

public interface BandwidthManagerService {
    FlowTuple addFlowToSlice(int sliceID, FlowTuple flowTuple);
    FlowTuple deleteFlowInSlice(int sliceId, FlowTuple flowTuple);
    void deleteSlices(int sliceId);
    List<FlowTuple> getSlice(int sliceId);
}
