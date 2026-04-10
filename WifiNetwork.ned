import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.WirelessHost;
import inet.node.wireless.AccessPoint;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;

network IoTNetwork
{
    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=50,50");
        }

        // --- MEDIUM RADIO SÉPARÉ PAR MAISON ---
        radioMediumA: Ieee80211ScalarRadioMedium {
            @display("p=250,50");
        }
        radioMediumB: Ieee80211ScalarRadioMedium {
            @display("p=450,50");
        }

        // --- MAISON A (France) ---
        apA: AccessPoint {
            @display("p=250,200;i=device/accesspoint");
        }
        cameraA: WirelessHost {
            @display("p=150,100;i=block/circle");
        }
        phoneA: WirelessHost {
            @display("p=150,200;i=device/cellphone");
        }
        watchA: WirelessHost {
            @display("p=150,300;i=device/clock");
        }

        // --- MAISON B (USA) ---
        apB: AccessPoint {
            @display("p=450,200;i=device/accesspoint");
        }
        cameraB: WirelessHost {
            @display("p=550,100;i=block/circle");
        }
        phoneB: WirelessHost {
            @display("p=550,200;i=device/cellphone");
        }
        watchB: WirelessHost {
            @display("p=550,300;i=device/clock");
        }

    connections:
        // Lien intercontinental France <--> USA (câble sous-marin simulé)
        apA.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apB.ethg++;
}
