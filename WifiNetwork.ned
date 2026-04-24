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

        cameraA[2]: IoTNode { @display("i=block/circle"); }
        phoneA[2]: IoTNode { @display("i=device/cellphone"); }
        watchA[1]: IoTNode { @display("i=device/clock"); }
        cameraB[3]: IoTNode { @display("i=block/circle"); }
        watchB[2]: IoTNode { @display("i=device/clock"); }
        phoneC[2]: IoTNode { @display("i=device/cellphone"); }
        watchC[3]: IoTNode { @display("i=device/clock"); }
        cameraD[1]: IoTNode { @display("i=block/circle"); }
        phoneD[3]: IoTNode { @display("i=device/cellphone"); }
        watchD[1]: IoTNode { @display("i=device/clock"); }
        cameraE[2]: IoTNode { @display("i=block/circle"); }
        phoneE[2]: IoTNode { @display("i=device/cellphone"); }
        watchE[1]: IoTNode { @display("i=device/clock"); }
        phoneF[1]: IoTNode { @display("i=device/cellphone"); }
        watchF[4]: IoTNode { @display("i=device/clock"); }
        cameraG[2]: IoTNode { @display("i=block/circle"); }
        phoneG[2]: IoTNode { @display("i=device/cellphone"); }
        watchG[1]: IoTNode { @display("i=device/clock"); }
        cameraH[1]: IoTNode { @display("i=block/circle"); }
        watchH[4]: IoTNode { @display("i=device/clock"); }
        cameraI[3]: IoTNode { @display("i=block/circle"); }
        phoneI[1]: IoTNode { @display("i=device/cellphone"); }
        watchI[1]: IoTNode { @display("i=device/clock"); }
        cameraJ[2]: IoTNode { @display("i=block/circle"); }
        watchJ[3]: IoTNode { @display("i=device/clock"); }

    connections allowunconnected:
}