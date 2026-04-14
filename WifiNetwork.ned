import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.WirelessHost;
import inet.node.wireless.AccessPoint;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;

network IoTNetwork
{
    submodules:
        configurator: Ipv4NetworkConfigurator { @display("p=50,50"); }

        radioMediumA: Ieee80211ScalarRadioMedium { @display("p=150,50"); }
        radioMediumB: Ieee80211ScalarRadioMedium { @display("p=450,50"); }
        radioMediumC: Ieee80211ScalarRadioMedium { @display("p=750,50"); }
        radioMediumD: Ieee80211ScalarRadioMedium { @display("p=1050,50"); }
        radioMediumE: Ieee80211ScalarRadioMedium { @display("p=150,50"); }
        radioMediumF: Ieee80211ScalarRadioMedium { @display("p=450,50"); }
        radioMediumG: Ieee80211ScalarRadioMedium { @display("p=750,50"); }
        radioMediumH: Ieee80211ScalarRadioMedium { @display("p=1050,50"); }
        radioMediumI: Ieee80211ScalarRadioMedium { @display("p=150,50"); }
        radioMediumJ: Ieee80211ScalarRadioMedium { @display("p=450,50"); }

        apA: AccessPoint { @display("p=150,150;i=device/accesspoint"); }
        cameraA[1]: WirelessHost { @display("i=block/circle"); }
        phoneA[2]: WirelessHost { @display("i=device/cellphone"); }
        watchA[2]: WirelessHost { @display("i=device/clock"); }

        apB: AccessPoint { @display("p=450,150;i=device/accesspoint"); }
        cameraB[2]: WirelessHost { @display("i=block/circle"); }
        phoneB[1]: WirelessHost { @display("i=device/cellphone"); }
        watchB[2]: WirelessHost { @display("i=device/clock"); }

        apC: AccessPoint { @display("p=750,150;i=device/accesspoint"); }
        cameraC[2]: WirelessHost { @display("i=block/circle"); }
        phoneC[2]: WirelessHost { @display("i=device/cellphone"); }
        watchC[1]: WirelessHost { @display("i=device/clock"); }

        apD: AccessPoint { @display("p=1050,150;i=device/accesspoint"); }
        cameraD[3]: WirelessHost { @display("i=block/circle"); }
        phoneD[1]: WirelessHost { @display("i=device/cellphone"); }
        watchD[1]: WirelessHost { @display("i=device/clock"); }

        apE: AccessPoint { @display("p=150,450;i=device/accesspoint"); }
        cameraE[1]: WirelessHost { @display("i=block/circle"); }
        phoneE[2]: WirelessHost { @display("i=device/cellphone"); }
        watchE[2]: WirelessHost { @display("i=device/clock"); }

        apF: AccessPoint { @display("p=450,450;i=device/accesspoint"); }
        cameraF[2]: WirelessHost { @display("i=block/circle"); }
        phoneF[2]: WirelessHost { @display("i=device/cellphone"); }
        watchF[1]: WirelessHost { @display("i=device/clock"); }

        apG: AccessPoint { @display("p=750,450;i=device/accesspoint"); }
        cameraG[1]: WirelessHost { @display("i=block/circle"); }
        phoneG[4]: WirelessHost { @display("i=device/cellphone"); }

        apH: AccessPoint { @display("p=1050,450;i=device/accesspoint"); }
        cameraH[1]: WirelessHost { @display("i=block/circle"); }
        phoneH[2]: WirelessHost { @display("i=device/cellphone"); }
        watchH[2]: WirelessHost { @display("i=device/clock"); }

        apI: AccessPoint { @display("p=150,750;i=device/accesspoint"); }
        cameraI[1]: WirelessHost { @display("i=block/circle"); }
        phoneI[3]: WirelessHost { @display("i=device/cellphone"); }
        watchI[1]: WirelessHost { @display("i=device/clock"); }

        apJ: AccessPoint { @display("p=450,750;i=device/accesspoint"); }
        cameraJ[1]: WirelessHost { @display("i=block/circle"); }
        phoneJ[1]: WirelessHost { @display("i=device/cellphone"); }
        watchJ[3]: WirelessHost { @display("i=device/clock"); }

    connections:
        apA.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apB.ethg++;
        apA.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apC.ethg++;
        apA.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apD.ethg++;
        apA.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apE.ethg++;
        apA.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apF.ethg++;
        apA.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apG.ethg++;
        apA.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apH.ethg++;
        apA.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apI.ethg++;
        apA.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apJ.ethg++;
        apB.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apC.ethg++;
        apB.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apD.ethg++;
        apB.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apE.ethg++;
        apB.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apF.ethg++;
        apB.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apG.ethg++;
        apB.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apH.ethg++;
        apB.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apI.ethg++;
        apB.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apJ.ethg++;
        apC.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apD.ethg++;
        apC.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apE.ethg++;
        apC.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apF.ethg++;
        apC.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apG.ethg++;
        apC.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apH.ethg++;
        apC.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apI.ethg++;
        apC.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apJ.ethg++;
        apD.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apE.ethg++;
        apD.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apF.ethg++;
        apD.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apG.ethg++;
        apD.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apH.ethg++;
        apD.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apI.ethg++;
        apD.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apJ.ethg++;
        apE.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apF.ethg++;
        apE.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apG.ethg++;
        apE.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apH.ethg++;
        apE.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apI.ethg++;
        apE.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apJ.ethg++;
        apF.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apG.ethg++;
        apF.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apH.ethg++;
        apF.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apI.ethg++;
        apF.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apJ.ethg++;
        apG.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apH.ethg++;
        apG.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apI.ethg++;
        apG.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apJ.ethg++;
        apH.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apI.ethg++;
        apH.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apJ.ethg++;
        apI.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> apJ.ethg++;
}