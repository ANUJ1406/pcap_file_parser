package com.inspireprojects.readpcap2;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import java.io.FileNotFoundException;
import java.io.IOException;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button b1;
        b1 = (Button) findViewById(R.id.read);
        b1.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Pcap pcap = null;
                try {
                    pcap = Pcap.openStream(getResources().openRawResource(R.raw.smallflows));
                    pcap.loop(new PacketHandler() {
                        @Override
                        public boolean nextPacket(Packet packet) throws IOException {
                           if (packet.hasProtocol(Protocol.TCP)) {
                                TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                                Buffer buffer = tcpPacket.getPayload();
								//just below two lines tells you how to read the information of packet......to be entered in an excel file
                                Toast.makeText(getApplicationContext(),"TCP\n"+"Source_Ip: "+tcpPacket.getParentPacket().getSourceIP()+"\nDestination_Ip: "+
                                        tcpPacket.getParentPacket().getDestinationIP()+"\nDestination_Port:"+tcpPacket.getDestinationPort(),Toast.LENGTH_LONG).show();
                                if (buffer != null) {
                                    System.out.println("TCP: " + buffer);
                                }
                                //else
                                   // Toast.makeText(getApplicationContext(),"BUFFER NULL",Toast.LENGTH_LONG).show();
                           } else if (packet.hasProtocol(Protocol.UDP)) {

                                UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                                Buffer buffer = udpPacket.getPayload();
								//just below two lines tells you how to read the information of packet......to be entered in an excel file
                               Toast.makeText(getApplicationContext(),"UDP\n"+"Source_Ip: "+udpPacket.getParentPacket().getSourceIP()+"\nDestination_Ip: "+
                                       udpPacket.getParentPacket().getDestinationIP()+"\nDestination_Port:"+udpPacket.getDestinationPort(),Toast.LENGTH_LONG).show();
                               if (buffer != null) {
                                    System.out.println("UDP: " + buffer);
                                }
                               //else
                                 //  Toast.makeText(getApplicationContext(),"BUFFER NULL",Toast.LENGTH_LONG).show();
                           }
                            else
                            {

                            }
                            return true;
                        }
                    });
                } catch (IOException ex) {
                    System.out.println(ex.getMessage());
                    Toast.makeText(getApplicationContext(),"ERROR",Toast.LENGTH_LONG).show();
                }
            }
        });
    }
}
