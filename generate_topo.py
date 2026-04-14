import random, math, json

# ============================================================
# VARIABLES GLOBALES — modifie uniquement ici
# ============================================================
NB_PAN           = 10
NB_OBJECTS_TOTAL = 50
TYPES_OBJETS     = ["camera", "phone", "watch"]
AREA_X, AREA_Y   = 1200, 900
NED_FILE         = "WifiNetwork.ned"
INI_FILE         = "omnetpp.ini"
GRAPH_FILE       = "social_graph.json"
# ============================================================

random.seed()

def label(pan_id):
    return chr(ord('A') + pan_id)

def place_aps(n, area_x, area_y):
    cols = math.ceil(math.sqrt(n))
    rows = math.ceil(n / cols)
    positions = []
    for i in range(n):
        col = i % cols
        row = i // cols
        x = int((col + 0.5) * area_x / cols)
        y = int((row + 0.5) * area_y / rows)
        positions.append((x, y))
    return positions[:n]

def pos_autour(cx, cy, r=120):
    a = random.uniform(0, 2 * math.pi)
    d = random.uniform(40, r)
    return int(cx + d * math.cos(a)), int(cy + d * math.sin(a))

ap_positions = place_aps(NB_PAN, AREA_X, AREA_Y)

objets_par_pan = {i: [] for i in range(NB_PAN)}
for k in range(NB_OBJECTS_TOTAL):
    objets_par_pan[k % NB_PAN].append(random.choice(TYPES_OBJETS))

comptage = {}
for pan_id in range(NB_PAN):
    comptage[pan_id] = {t: objets_par_pan[pan_id].count(t) for t in TYPES_OBJETS}

print("=== Topologie generee ===")
for pan_id in range(NB_PAN):
    print(f"  PAN {label(pan_id)} : {comptage[pan_id]}")
print(f"  Total : {NB_OBJECTS_TOTAL} objets dans {NB_PAN} PANs")

# ============================================================
# NED
# ============================================================
icons = {"camera": "block/circle", "phone": "device/cellphone", "watch": "device/clock"}
ned = []
ned.append("import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;")
ned.append("import inet.node.inet.WirelessHost;")
ned.append("import inet.node.wireless.AccessPoint;")
ned.append("import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;")
ned.append("")
ned.append("network IoTNetwork")
ned.append("{")
ned.append("    submodules:")
ned.append('        configurator: Ipv4NetworkConfigurator { @display("p=50,50"); }')
ned.append("")
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    x = ap_positions[pan_id][0]
    ned.append('        radioMedium' + Lp + ': Ieee80211ScalarRadioMedium { @display("p=' + str(x) + ',50"); }')
ned.append("")
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    x, y = ap_positions[pan_id]
    ned.append('        ap' + Lp + ': AccessPoint { @display("p=' + str(x) + ',' + str(y) + ';i=device/accesspoint"); }')
    for t in TYPES_OBJETS:
        n = comptage[pan_id][t]
        if n > 0:
            ned.append('        ' + t + Lp + '[' + str(n) + ']: WirelessHost { @display("i=' + icons[t] + '"); }')
    ned.append("")
ned.append("    connections:")
for i in range(NB_PAN):
    for j in range(i+1, NB_PAN):
        Li, Lj = label(i), label(j)
        ned.append('        ap' + Li + '.ethg++ <--> { datarate = 100Mbps; delay = 150ms; } <--> ap' + Lj + '.ethg++;')
ned.append("}")

with open(NED_FILE, "w") as f:
    f.write("\n".join(ned))

# ============================================================
# INI
# ============================================================
L = []
L.append("[General]")
L.append("network = IoTNetwork")
L.append("sim-time-limit = 100s")
L.append("")
L.append("**.constraintAreaMinX = 0m")
L.append("**.constraintAreaMinY = 0m")
L.append("**.constraintAreaMinZ = 0m")
L.append(f"**.constraintAreaMaxX = {AREA_X}m")
L.append(f"**.constraintAreaMaxY = {AREA_Y}m")
L.append("**.constraintAreaMaxZ = 0m")
L.append("")
L.append("*.configurator.addStaticRoutes = true")
L.append("*.configurator.addDefaultRoutes = true")
L.append('*.configurator.config = xmldoc("config.xml")')
L.append("")
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    L.append('*.ap' + Lp + '.wlan[*].radio.radioMediumModule = "radioMedium' + Lp + '"')
    for t in TYPES_OBJETS:
        if comptage[pan_id][t] > 0:
            L.append('*.' + t + Lp + '[*].wlan[*].radio.radioMediumModule = "radioMedium' + Lp + '"')
L.append("")
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        if comptage[pan_id][t] > 0:
            L.append('*.' + t + Lp + '[*].wlan[*].mgmt.typename = "Ieee80211MgmtSta"')
            L.append('*.' + t + Lp + '[*].wlan[*].agent.typename = "Ieee80211AgentSta"')
    L.append('*.ap' + Lp + '.wlan[*].mgmt.typename = "Ieee80211MgmtAp"')
    L.append('*.ap' + Lp + '.wlan[*].agent.typename = ""')
L.append("")
L.append("**.wlan[*].radio.transmitter.power = 20mW")
L.append("**.wlan[*].bitrate = 11Mbps")
L.append("")
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    L.append('*.ap' + Lp + '.mobility.initialX = ' + str(ap_positions[pan_id][0]) + 'm')
    L.append('*.ap' + Lp + '.mobility.initialY = ' + str(ap_positions[pan_id][1]) + 'm')
    L.append('*.ap' + Lp + '.mobility.initialZ = 0m')
L.append("")
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        for i in range(comptage[pan_id][t]):
            x, y = pos_autour(*ap_positions[pan_id])
            L.append('*.' + t + Lp + '[' + str(i) + '].mobility.initialX = ' + str(x) + 'm')
            L.append('*.' + t + Lp + '[' + str(i) + '].mobility.initialY = ' + str(y) + 'm')
            L.append('*.' + t + Lp + '[' + str(i) + '].mobility.initialZ = 0m')
L.append("")
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        L.append('*.' + t + Lp + '[*].numApps = 0')

with open(INI_FILE, "w") as f:
    f.write("\n".join(L))

# ============================================================
# SOCIAL GRAPH
# ============================================================
social_graph = {}

# Construction des listes par type (pour OOR)
objets_par_type = {"camera": [], "phone": [], "watch": []}
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        for i in range(comptage[pan_id][t]):
            objets_par_type[t].append(t + Lp + '[' + str(i) + ']')

# Construction du graphe
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        for i in range(comptage[pan_id][t]):
            name = t + Lp + '[' + str(i) + ']'

            # SOR : tous les objets du même PAN (sauf soi-même)
            sor = [
                t2 + Lp + '[' + str(j) + ']'
                for t2 in TYPES_OBJETS
                for j in range(comptage[pan_id][t2])
                if t2 + Lp + '[' + str(j) + ']' != name
            ]

            # OOR : même type, PANs différents
            oor = [obj for obj in objets_par_type[t] if obj != name and Lp not in obj]

            social_graph[name] = {
                "owner": "user" + Lp,
                "type": t,
                "location": "maison" + Lp,
                "trust_score": round(random.uniform(0.6, 1.0), 2),
                "friends": sor + oor,
                "relations": {
                    "POR":   "user" + Lp,
                    "C-LOR": "maison" + Lp,
                    "SOR":   sor,
                    "OOR":   oor
                }
            }

with open(GRAPH_FILE, "w") as f:
    json.dump(social_graph, f, indent=4)

print("OK : " + NED_FILE + ", " + INI_FILE + ", " + GRAPH_FILE + " generés avec OOR !")
