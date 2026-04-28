import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.aodv.AodvRouter;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;

module IoTNode extends AodvRouter {
    submodules:
        puf: PufModule { @display("p=100,200"); }
        pufAuthApp: PufAuthApp { @display("p=100,300"); }
}

network IoTNetwork {
    submodules:
        configurator: Ipv4NetworkConfigurator { @display("p=50,50"); }
        radioMedium: Ieee80211ScalarRadioMedium { @display("p=200,50"); }

        cameraA[2]: IoTNode { @display("i=block/circle"); }
        watchA[3]: IoTNode { @display("i=device/clock"); }
        cameraB[1]: IoTNode { @display("i=block/circle"); }
        phoneB[1]: IoTNode { @display("i=device/cellphone"); }
        watchB[3]: IoTNode { @display("i=device/clock"); }
        phoneC[3]: IoTNode { @display("i=device/cellphone"); }
        watchC[2]: IoTNode { @display("i=device/clock"); }
        cameraD[2]: IoTNode { @display("i=block/circle"); }
        phoneD[2]: IoTNode { @display("i=device/cellphone"); }
        watchD[1]: IoTNode { @display("i=device/clock"); }
        cameraE[3]: IoTNode { @display("i=block/circle"); }
        phoneE[2]: IoTNode { @display("i=device/cellphone"); }
        cameraF[2]: IoTNode { @display("i=block/circle"); }
        phoneF[1]: IoTNode { @display("i=device/cellphone"); }
        watchF[2]: IoTNode { @display("i=device/clock"); }

    connections allowunconnected:
}