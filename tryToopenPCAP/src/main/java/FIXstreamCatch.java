import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

import java.util.ArrayList;
import java.util.HashMap;

public  class FIXstreamCatch {

    public String getPortEqualler() {
        return portEqualler;
    }

    public void setPortEqualler(String portEqualler) {
        this.portEqualler = portEqualler;
    }

    private String portEqualler;

    public FIXstreamCatch() {

    }

    public ArrayList<Packet> pcapSortedByTCPpORT(ArrayList<Packet> tcpPackets)
    {
        ArrayList<Packet> tcpPacketsByPort = new ArrayList<>();
        for(int i =0;i< tcpPackets.size();i++)
        {
            if(tcpPackets.get(i).get(TcpPacket.class).getHeader().getSrcPort().toString().replace( " (unknown)", "").equals(portEqualler)||
                    tcpPackets.get(i).get(TcpPacket.class).getHeader().getDstPort().toString().replace( " (unknown)", "").equals(portEqualler) )
            {
                tcpPacketsByPort.add(tcpPackets.get(i));
            }
        }
        return  tcpPacketsByPort;
    }

    public ArrayList<Packet> pcapSorterByTcp(PcapHandle pcapHandle) throws NotOpenException {
        ArrayList<Packet> packets = new ArrayList<>();
        Packet packet = pcapHandle.getNextPacket();
        while(packet != null)
        {
            if (packet.contains(TcpPacket.class))
            {
                packets.add(packet);
            }
            packet = pcapHandle.getNextPacket();
        }

        return packets;
    }

    public ArrayList<Packet> pcapSorterBySyn(ArrayList<Packet> packets)
    {
        ArrayList<Packet> tcpPackets = new ArrayList<>();
        for (int i =0; i< packets.size(); i++)
        {
            if (packets.get(i).get(TcpPacket.class).getHeader().getSyn() && packets.get(i).get(TcpPacket.class).getHeader().getSequenceNumber() == 0)

            {
                tcpPackets.add(packets.get(i));
            }
        }
        return  tcpPackets;
    }


}
