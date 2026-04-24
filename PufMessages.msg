// Round 1 : A → B  (initiation)
message DarpaRound1
{
    string senderId;
    string targetId;
    string nonce_A;       // N_A : 256 bits en hex
    string serviceCard;   // S_A : fingerprint de A
    string challenge;     // C_iA : challenge pour le PUF de B
    string bitMask;       // P_iA : masque bits instables
}

// Round 2 : B → A  (contre-challenge + preuve PUF de B)
message DarpaRound2
{
    string senderId;
    string targetId;
    string nonce_A;           // N_A recopié
    string nonce_B;           // N_B frais
    string serviceCard;       // S_B
    string challenge;         // C_iB : challenge pour le PUF de A
    string bitMask;           // P_iB
    string encryptedResponse; // E_iB = Encrypt(K_temp, R_iB_trunc)
    string proofBA;           // R_iA_seen_by_B = trunc(PUF_B(C_iA), P_iA)
}

// Round 3 : A → B  (preuve PUF de A + token)
message DarpaRound3
{
    string senderId;
    string targetId;
    string encryptedResponse; // E_iA = Encrypt(K_temp, R_iA_trunc)
    string proofAB;           // R_iB_seen_by_A = trunc(PUF_A(C_iB), P_iB)
    string tokenA;            // tok_A = MAC(K_AB, N_A||N_B||id_A)
}

// Round 4 : B → A  (confirmation mutuelle)
message DarpaRound4
{
    string senderId;
    string targetId;
    string tokenB;            // tok_B = MAC(K_AB, N_B||N_A||id_B)
}

// ================================================================
// ÉVOLUTION 2 : Messages d'enrôlement Ad Hoc (sans TTP)
// ================================================================

// EnrollRequest : A → B  (A inconnu de B, initie l'enrôlement)
// A envoie sa clé publique DH éphémère
message EnrollRequest
{
    string senderId;      // identifiant de A
    string targetId;      // identifiant de B
    string dhPublic;      // pub_A = SHA256(priv_A || "DH_PUB" || targetId)
    string serviceCard;   // fingerprint de A (pour décision d'acceptation)
}

// EnrollReply : B → A  (B accepte et envoie sa clé publique DH + premier CRP)
message EnrollReply
{
    string senderId;          // identifiant de B
    string targetId;          // identifiant de A
    string dhPublic;          // pub_B
    string serviceCard;       // fingerprint de B
    string initialChallenge;  // C_0 : premier challenge de la chaîne (pour le PUF de A)
    string initialResponse;   // R_0 : réponse attendue (chiffrée avec secret partagé)
}

// EnrollConfirm : A → B  (A confirme la réception et prouve son PUF)
message EnrollConfirm
{
    string senderId;      // identifiant de A
    string targetId;      // identifiant de B
    string pufProof;      // PUF_A(initialChallenge) — prouve l'identité physique de A
    string mac;           // MAC(sharedSecret, senderId||targetId||pufProof)
}
