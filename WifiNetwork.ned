import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.aodv.AodvRouter;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;

// Module IoT avec PUF integre
module IoTNode extends AodvRouter
{
    submodules:
        puf: PufModule {
            @display("p=100,200");
        }
        pufAuthApp: PufAuthApp {
            @display("p=100,300");
        }
}

network IoTNetwork
{
    submodules:
        configurator: Ipv4NetworkConfigurator { @display("p=50,50"); }
        radioMedium: Ieee80211ScalarRadioMedium { @display("p=200,50"); }

        cameraA[1]: IoTNode { @display("i=block/circle"); }
        phoneA[3]: IoTNode { @display("i=device/cellphone"); }
        watchA[1]: IoTNode { @display("i=device/clock"); }
        cameraB[4]: IoTNode { @display("i=block/circle"); }
        watchB[1]: IoTNode { @display("i=device/clock"); }
        cameraC[3]: IoTNode { @display("i=block/circle"); }
        phoneC[2]: IoTNode { @display("i=device/cellphone"); }
        cameraD[3]: IoTNode { @display("i=block/circle"); }
        phoneD[1]: IoTNode { @display("i=device/cellphone"); }
        watchD[1]: IoTNode { @display("i=device/clock"); }
        cameraE[1]: IoTNode { @display("i=block/circle"); }
        phoneE[2]: IoTNode { @display("i=device/cellphone"); }
        watchE[2]: IoTNode { @display("i=device/clock"); }
        phoneF[3]: IoTNode { @display("i=device/cellphone"); }
        watchF[2]: IoTNode { @display("i=device/clock"); }
        cameraG[1]: IoTNode { @display("i=block/circle"); }
        phoneG[3]: IoTNode { @display("i=device/cellphone"); }
        watchG[1]: IoTNode { @display("i=device/clock"); }
        cameraH[2]: IoTNode { @display("i=block/circle"); }
        phoneH[2]: IoTNode { @display("i=device/cellphone"); }
        watchH[1]: IoTNode { @display("i=device/clock"); }
        cameraI[3]: IoTNode { @display("i=block/circle"); }
        phoneI[2]: IoTNode { @display("i=device/cellphone"); }
        cameraJ[2]: IoTNode { @display("i=block/circle"); }
        phoneJ[3]: IoTNode { @display("i=device/cellphone"); }

    connections allowunconnected:
}