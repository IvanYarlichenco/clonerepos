import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.Scanner;

public class Main  extends FIXstreamCatch{

    public static void main(String[] args) throws Exception {

        PcapHandle pcapHandle = Pcaps.openOffline("newDump.pcap");

        Scanner myObj = new Scanner(System.in);
        System.out.println("Enter Server port(9877): ");
        final String servPort = myObj.nextLine();

        FIXstreamCatch fsx = new FIXstreamCatch();
        fsx.setPortEqualler(servPort);
        ArrayList<Packet> tcpPackets;
        tcpPackets = fsx.pcapSortedByTCPpORT(fsx.pcapSorterByTcp(pcapHandle));

            for (int i = 0;i< tcpPackets.size();i++)
            {
                System.out.println(tcpPackets.get(i));
            }
    }


}

