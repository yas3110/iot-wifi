import random, math, json, hashlib

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
CONFIG_FILE      = "config.xml"
NB_CRP_SOR       = 1
NB_CRP_OOR       = 3
PUF_AUTH_PORT    = 4999
# Démarre après convergence AODV (~8s) pour éviter les échecs réseau
PUF_START_TIME   = 8
# Intervalle réduit à 2s pour plus de cycles d'auth et d'enrôlement
PUF_INTERVAL     = 2
# ============================================================

random.seed()

def label(pan_id):
    return chr(ord("A") + pan_id)

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

def puf_enroll(node_id, num_crp=5):
    puf_seed = abs(hash(node_id + "puf_secret")) % (10**9)
    seed_challenge = hashlib.sha256(
        f"{node_id}{puf_seed}OWN_SEED".encode()
    ).hexdigest()

    crp_db = {}
    current = seed_challenge
    for i in range(num_crp):
        response = hashlib.sha256(
            f"{current}{puf_seed}PUF_RESPONSE".encode()
        ).hexdigest()[:16]
        crp_db[current] = response
        current = hashlib.sha256(f"{current}DERIVE".encode()).hexdigest()

    return {
        "seed_challenge": seed_challenge,
        "seed_response":  crp_db[seed_challenge],
        "crp_db":         crp_db
    }

# ============================================================
# TOPOLOGIE
# ============================================================
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
ned.append("import inet.node.aodv.AodvRouter;")
ned.append("import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;")
ned.append("")
ned.append("// Module IoT avec PUF integre")
ned.append("module IoTNode extends AodvRouter")
ned.append("{")
ned.append("    submodules:")
ned.append("        puf: PufModule {")
ned.append('            @display("p=100,200");')
ned.append("        }")
ned.append("        pufAuthApp: PufAuthApp {")
ned.append('            @display("p=100,300");')
ned.append("        }")
ned.append("}")
ned.append("")
ned.append("network IoTNetwork")
ned.append("{")
ned.append("    submodules:")
ned.append('        configurator: Ipv4NetworkConfigurator { @display("p=50,50"); }')
ned.append('        radioMedium: Ieee80211ScalarRadioMedium { @display("p=200,50"); }')
ned.append("")
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        n = comptage[pan_id][t]
        if n > 0:
            ned.append(f'        {t}{Lp}[{n}]: IoTNode {{ @display("i={icons[t]}"); }}')
ned.append("")
ned.append("    connections allowunconnected:")
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
L.append(f"ned-path = ./:/home/ubuntuy/omnetpp-6.0.3/samples/inet4.5/src")
L.append("")
L.append("**.constraintAreaMinX = 0m")
L.append("**.constraintAreaMinY = 0m")
L.append("**.constraintAreaMinZ = 0m")
L.append(f"**.constraintAreaMaxX = {AREA_X}m")
L.append(f"**.constraintAreaMaxY = {AREA_Y}m")
L.append("**.constraintAreaMaxZ = 0m")
L.append("")
L.append("*.configurator.addStaticRoutes = false")
L.append("*.configurator.addDefaultRoutes = false")
L.append("*.configurator.addSubnetRoutes = false")
L.append('*.configurator.config = xmldoc("config.xml")')
L.append("")
L.append('**.wlan[*].radio.radioMediumModule = "radioMedium"')
L.append("")
L.append("**.wlan[*].radio.transmitter.power = 20mW")
L.append("**.wlan[*].bitrate = 11Mbps")
L.append("")
L.append("# --- Parametres AODV — convergence rapide ---")
L.append("**.aodv.activeRouteTimeout = 3s")
L.append("**.aodv.deletePeriod = 5s")
# helloInterval réduit pour découvrir les voisins plus vite
L.append("**.aodv.helloInterval = 0.5s")
L.append("**.aodv.allowedHelloLoss = 2")
# Plus de tentatives RREQ pour trouver les routes longues
L.append("**.aodv.rreqRetries = 3")
L.append("**.aodv.rreqRatelimit = 10")
# TTL plus grand dès le départ pour couvrir les nœuds distants
L.append("**.aodv.ttlStart = 2")
L.append("**.aodv.ttlIncrement = 2")
L.append("**.aodv.ttlThreshold = 7")
# Jitter réduit pour des échanges plus réactifs
L.append("**.aodv.jitterPar = 0.005s")
L.append("**.aodv.displayBubbles = true")
L.append("")
L.append("# --- PUF Auth App ---")
L.append(f"**.pufAuthApp.authStartTime = {PUF_START_TIME}s")
L.append(f"**.pufAuthApp.authInterval = {PUF_INTERVAL}s")
L.append("**.pufAuthApp.cmdenv-log-level = trace")
L.append("")
L.append("# --- Positions initiales ---")
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        for i in range(comptage[pan_id][t]):
            x, y = pos_autour(*ap_positions[pan_id])
            L.append(f"*.{t}{Lp}[{i}].mobility.initialX = {x}m")
            L.append(f"*.{t}{Lp}[{i}].mobility.initialY = {y}m")
            L.append(f"*.{t}{Lp}[{i}].mobility.initialZ = 0m")
L.append("")
L.append("# --- Mobilite ---")
L.append('**.camera*[*].mobility.typename = "StationaryMobility"')
L.append('**.watch*[*].mobility.typename = "StationaryMobility"')
L.append("")
L.append('**.phone*[*].mobility.typename = "RandomWaypointMobility"')
L.append("**.phone*[*].mobility.speed = uniform(0.5mps, 2mps)")
L.append("**.phone*[*].mobility.waitTime = uniform(1s, 5s)")
L.append("")

# Paires UDP inter-PAN
paires = []
used_src = set()
used_dst = set()
for pan_src in range(NB_PAN):
    Lsrc = label(pan_src)
    if comptage[pan_src]["phone"] > 0:
        for pan_dst in range(NB_PAN):
            Ldst = label(pan_dst)
            if pan_dst != pan_src and comptage[pan_dst]["camera"] > 0:
                src = f"phone{Lsrc}[0]"
                dst = f"camera{Ldst}[0]"
                if src not in used_src and dst not in used_dst:
                    paires.append((src, dst))
                    used_src.add(src)
                    used_dst.add(dst)
                if len(paires) >= 3:
                    break
    if len(paires) >= 3:
        break

L.append("# --- Applications UDP ---")
# startTime=10s : après convergence AODV et premier cycle PUF auth
L.append("# startTime=10s : apres convergence AODV et premier cycle PUF auth")
PORT = 5000
for idx, (src, dst) in enumerate(paires):
    port = PORT + idx
    L.append(f"*.{src}.numApps = 1")
    L.append(f'*.{src}.app[0].typename = "UdpBasicApp"')
    L.append(f'*.{src}.app[0].destAddresses = "{dst}"')
    L.append(f"*.{src}.app[0].destPort = {port}")
    L.append(f"*.{src}.app[0].messageLength = 512B")
    L.append(f"*.{src}.app[0].sendInterval = 2s")
    L.append(f"*.{src}.app[0].startTime = 10s")
    L.append(f"*.{dst}.numApps = 1")
    L.append(f'*.{dst}.app[0].typename = "UdpSink"')
    L.append(f"*.{dst}.app[0].localPort = {port}")
    L.append("")

L.append("# --- numApps=0 pour les autres noeuds ---")
src_set = {p[0] for p in paires}
dst_set = {p[1] for p in paires}
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        for i in range(comptage[pan_id][t]):
            node = f"{t}{Lp}[{i}]"
            if node not in src_set and node not in dst_set:
                L.append(f"*.{node}.numApps = 0")

with open(INI_FILE, "w") as f:
    f.write("\n".join(L))

# ============================================================
# CONFIG XML
# ============================================================
xml_lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    "<config>",
    '    <interface hosts="**" address="10.0.x.x" netmask="255.255.0.0"/>',
    "</config>"
]
with open(CONFIG_FILE, "w") as f:
    f.write("\n".join(xml_lines))

# ============================================================
# SOCIAL GRAPH
# ============================================================
objets_par_type = {"camera": [], "phone": [], "watch": []}
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        for i in range(comptage[pan_id][t]):
            objets_par_type[t].append(f"{t}{Lp}[{i}]")

all_enroll_data = {}
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        for i in range(comptage[pan_id][t]):
            name = f"{t}{Lp}[{i}]"
            all_enroll_data[name] = puf_enroll(name, num_crp=15)

social_graph = {}
for pan_id in range(NB_PAN):
    Lp = label(pan_id)
    for t in TYPES_OBJETS:
        for i in range(comptage[pan_id][t]):
            name = f"{t}{Lp}[{i}]"

            sor = [
                f"{t2}{Lp}[{j}]"
                for t2 in TYPES_OBJETS
                for j in range(comptage[pan_id][t2])
                if f"{t2}{Lp}[{j}]" != name
            ]
            oor = [
                obj for obj in objets_par_type[t]
                if obj != name and Lp not in obj
            ]
            relations = {
                "POR":   f"user{Lp}",
                "C-LOR": f"maison{Lp}",
                "SOR":   sor,
                "OOR":   oor
            }

            # Trust initial élevé (0.7-1.0) pour éviter les blocages prématurés
            # pendant la phase de convergence AODV
            base_trust = round(random.uniform(0.7, 1.0), 2)

            fingerprint = {
                "battery":    round(random.uniform(0.6, 1.0), 2),
                "reputation": round(random.uniform(0.5, 1.0), 2),
                "services":   random.randint(1, 5),
                "uptime":     round(random.uniform(0.7, 1.0), 2)
            }

            my_enroll = all_enroll_data[name]

            known_crp_dbs_node = {}
            for peer in sor + oor:
                peer_enroll = all_enroll_data[peer]
                known_crp_dbs_node[peer] = {
                    "seed_challenge": peer_enroll["seed_challenge"],
                    "seed_response":  peer_enroll["seed_response"],
                    "crp_db": peer_enroll["crp_db"]
                }

            social_graph[name] = {
                "owner":       f"user{Lp}",
                "type":        t,
                "location":    f"maison{Lp}",
                "fingerprint": fingerprint,
                "puf": {
                    "enrolled":        True,
                    "enrolledBy":      f"user{Lp}",
                    "seed_challenge":  my_enroll["seed_challenge"],
                    "seed_response":   my_enroll["seed_response"],
                    "crp_db":          my_enroll["crp_db"],
                    "auth_rules": {
                        "SOR":     {"level": "light", "nb_crp_required": NB_CRP_SOR},
                        "OOR":     {"level": "full",  "nb_crp_required": NB_CRP_OOR},
                        "AD_HOC":  {"level": "medium","nb_crp_required": 2},
                        "unknown": {"level": "none",  "nb_crp_required": 0}
                    }
                },
                "known_crp_dbs": known_crp_dbs_node,
                "trust_score":   base_trust,
                # Règles de mise à jour du trust :
                # - seuil de blocage abaissé à 0.2 pour tolérer plus d'échecs AODV
                # - pénalité réduite à -0.10 (au lieu de -0.20)
                "trust_update_rules": {
                    "puf_success":     +0.05,
                    "puf_failure":     -0.10,
                    "max":              1.0,
                    "min":              0.0,
                    "threshold_block":  0.2
                },
                "friends":   sor + oor,
                "relations": relations
            }

with open(GRAPH_FILE, "w") as f:
    json.dump(social_graph, f, indent=4)

print(f"\nOK : {NED_FILE}, {INI_FILE}, {CONFIG_FILE}, {GRAPH_FILE} generes !")
print(f"  -> IoTNode = AodvRouter + PufModule + PufAuthApp")
print(f"  -> {len(paires)} flux UDP inter-PAN :")
for src, dst in paires:
    print(f"     {src} -> {dst}")
print(f"  -> SOR : auth legere ({NB_CRP_SOR} CRP) | OOR : auth complete ({NB_CRP_OOR} CRP)")
print(f"  -> PUF demarre a t={PUF_START_TIME}s, cycle toutes les {PUF_INTERVAL}s")
print(f"  -> AODV helloInterval=0.5s, rreqRetries=3, ttlStart=2")
print(f"  -> Trust initial: 0.7-1.0, penalite: -0.10, seuil blocage: 0.2")