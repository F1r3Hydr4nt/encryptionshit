#include "AES.h"
#include <iostream>
AES::AES(int keyLen)
{
  this->Nb = 4;
  switch (keyLen)
  {
  case 128:
    this->Nk = 4;
    this->Nr = 10;
    break;
  case 192:
    this->Nk = 6;
    this->Nr = 12;
    break;
  case 256:
    this->Nk = 8;
    this->Nr = 14;
    break;
  default:
    throw "Incorrect key length";
  }

  blockBytesLen = 4 * this->Nb * sizeof(unsigned char);
}

unsigned char * AES::EncryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    EncryptBlock(alignIn + i, out + i, key);
  }
  
  delete[] alignIn;
  
  return out;
}

unsigned char * AES::DecryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    DecryptBlock(alignIn + i, out + i, key);
  }
  
  delete[] alignIn;
  
  return out;
}


unsigned char *AES::EncryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    XorBlocks(block, alignIn + i, block, blockBytesLen);
    EncryptBlock(block, out + i, key);
  }
  
  delete[] block;
  delete[] alignIn;

  return out;
}

unsigned char *AES::DecryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    DecryptBlock(alignIn + i, out + i, key);
    XorBlocks(block, out + i, out + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] alignIn;

  return out;
}

unsigned char *AES::EncryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    EncryptBlock(block, encryptedBlock, key);
    XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, out + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] encryptedBlock;
  delete[] alignIn;

  return out;
}

unsigned char *AES::DecryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    EncryptBlock(block, encryptedBlock, key);
    XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, alignIn + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] encryptedBlock;
  delete[] alignIn;

  return out;
}
/*
    if (!args.mdc) {
        // Symmetrically Encrypted Data Packet (Tag 9)
        Packet::Tag9 tag9;
        tag9.set_encrypted_data(use_OpenPGP_CFB_encrypt(args.sym, Packet::SYMMETRICALLY_ENCRYPTED_DATA, to_encrypt, session_key, prefix));
        encrypted = std::make_shared <Packet::Tag9> (tag9);
    }
    else{
        // Modification Detection Code Packet (Tag 19)
        Packet::Tag19 tag19;
        tag19.set_hash(Hash::use(Hash::ID::SHA1, prefix + to_encrypt + "\xd3\x14"));

        // Sym. Encrypted Integrity Protected Data Packet (Tag 18)
        // encrypt(compressed(literal_data_packet(plain text)) + MDC SHA1(20 octets))
        Packet::Tag18 tag18;
        tag18.set_protected_data(use_OpenPGP_CFB_encrypt(args.sym, Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA, to_encrypt + tag19.write(), session_key, prefix));
        encrypted = std::make_shared <Packet::Tag18> (tag18);
    }
*/
// Above we see that MDC can be turned on or off
// If it is turned on the prefix + the data is to be hashed and appended to the data before encryption

uint8_t SYMMETRICALLY_ENCRYPTED_DATA             = 9;
uint8_t SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA   = 18;

unsigned char *AES::OpenPGP_EncryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen, string prefix, bool useMDC)
{
    const std::size_t BS = 16;

    if (prefix.size() < (BS + 2)) {
        //throw std::runtime_error("Error: Given prefix too short.");
    }
    else if (prefix.size() > (BS + 2)) {
        prefix = prefix.substr(0, BS + 2);    // reduce prefix
    }

  //    1. The feedback register (FR) is set to the IV, which is all zeros.
    //std::string FR(BS, 0);
    unsigned char * FR;
    memcpy(FR,iv,BS);
    //memcpy(fr, iv, sizeof(iv));

    //    2. FR is encrypted to produce FRE (FR Encrypted). This is the encryption of an all-zero value.
    //std::string FRE = crypt -> encrypt(FR);
    unsigned char * FRE;
    //unsigned char *fre = new unsigned char[blockBytesLen];
    EncryptBlock(FR, FRE, key);

   /*3.  FRE is xored with the first BS octets of random data prefixed to
       the plaintext to produce C[1] through C[BS], the first BS octets
       of ciphertext. */
    //FRE = xor_strings(FRE, prefix);
    //std::string C = FRE;
    unsigned char *fre_xored = new unsigned char[blockBytesLen];
    XorBlocks(FRE, (unsigned char*)prefix.c_str(), fre_xored, blockBytesLen);

   /*return fre_xored;
    //    3. FRE is xored with the first BS octets of random data prefixed to the plaintext to produce C[1] through C[BS], the first BS octets of ciphertext.
    FRE = xor_strings(FRE, prefix); */
    
    //std::string C = FRE;
    unsigned char * C;
    memcpy(C,fre_xored,sizeof(fre_xored));

    //    4. FR is loaded with C[1] through C[BS].
    //FR = C;
    memcpy(FR,C,sizeof(C));

    //    5. FR is encrypted to produce FRE, the encryption of the first BS octets of ciphertext.
    //FRE = crypt -> encrypt(FR);
    EncryptBlock(FR, FRE, key);

    // MDC here
    uint8_t packet;
    if(useMDC)
        packet = SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA;
    else packet = SYMMETRICALLY_ENCRYPTED_DATA;

    if (packet == SYMMETRICALLY_ENCRYPTED_DATA) {                    // resynchronization
        /*//    6. The left two octets of FRE get xored with the next two octets of data that were prefixed to the plaintext. This produces C[BS+1] and C[BS+2], the next two octets of ciphertext.
        C += xor_strings(FRE.substr(0, 2), prefix.substr(BS - 2, 2));

        //    7. (The resynchronization step) FR is loaded with C[3] through C[BS+2].
        FR = C.substr(2, BS);

        //    8. FR is encrypted to produce FRE.
        FRE = crypt -> encrypt(FR);

        //    9. FRE is xored with the first BS octets of the given plaintext, now that we have finished encrypting the BS+2 octets of prefixed data. This produces C[BS+3] through C[BS+(BS+2)], the next BS octets of ciphertext.
        C += xor_strings(FRE, data.substr(0, BS));*/
    }//         constexpr uint8_t SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA   = 18;
    else if (packet == SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA) {     // no resynchronization
        // 5.13. Sym. Encrypted Integrity Protected Data Packet (Tag 18)
        //
        //    Unlike the Symmetrically Encrypted Data Packet, no
        //    special CFB resynchronization is done after encrypting this prefix
        //    data.

        // Second block of ciphertext is the 2 repeated octets + the first BS - 2 octets of the plaintext
        //C += xor_strings(FRE, prefix.substr(BS - 2, 2) + data.substr(0, BS - 2));

    }
    else{
        //throw std::runtime_error("Error: Bad Packet Type");
    }
    // Normal CFB encryption for reference:
    /*
    
    const std::size_t BS = crypt -> blocksize() >> 3;
    std::string::size_type x = 0;
    while (out.size() < data.size()) {
        IV = xor_strings(crypt -> encrypt(IV), data.substr(x, BS));
        out += IV;
        x += BS;
    }
    return out;
    */
/* Taking this out for the time being

    std::string::size_type x = BS - ((packet == SYMMETRICALLY_ENCRYPTED_DATA)?0:2);
    while (x < data.size()) {
        //    10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for an 8-octet block).
        FR = C.substr(x + 2, BS);

        //    11. FR is encrypted to produce FRE.
        FRE = crypt -> encrypt(FR);

        //    12. FRE is xored with the next BS octets of plaintext, to produce the next BS octets of ciphertext. These are loaded into FR, and the process is repeated until the plaintext is used up.
        C += xor_strings(FRE, data.substr(x, BS));

        x += BS;
    }
 */
    return C;
}
//std::string sName(reinterpret_cast<char*>(name));

/*unsigned char* substr_uchar(unsigned char * in, int start, int length){
        unsigned char subbuff[length];
        memcpy( subbuff, &in[start], length );
        subbuff[length] = '\0';
        return (unsigned char*)subbuff;
}*/


/*
unsigned char *AES::OpenPGP_DecryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen, bool useMDC)
{
   const std::size_t BS = 16;   // perhaps should be * 2 as 2 hex chars = 1 char in a string

    //    1. The feedback register (FR) is set to the IV, which is all zeros.
    //std::string FR(BS, 0);
    unsigned char * FR;
    memcpy(FR,iv,BS);

    //    2. FR is encrypted to produce FRE (FR Encrypted). This is the encryption of an all-zero value.
    //std::string FRE = crypt -> encrypt(FR);
    unsigned char * FRE;
    //unsigned char *fre = new unsigned char[blockBytesLen];
    EncryptBlock(FR, FRE, key);

    //    4. FR is loaded with C[1] through C[BS].
    //FR = data.substr(0, BS);
    memcpy(FR,in,BS);

    //    3. FRE is xored with the first BS octets of random data prefixed to the plaintext to produce C[1] through C[BS], the first BS octets of ciphertext.
    //std::string prefix = xor_strings(FRE, FR);
    unsigned char *prefix = new unsigned char[blockBytesLen];
    XorBlocks(FRE, FR, prefix, blockBytesLen);

    string prefixString(reinterpret_cast<char*>(prefix));

    //    5. FR is encrypted to produce FRE, the encryption of the first BS octets of ciphertext.
    //FRE = crypt -> encrypt(FR); // encryption of ciphertext
    EncryptBlock(FR, FRE, key);
    

    //    6. The left two octets of FRE get xored with the next two octets of data that were prefixed to the plaintext. This produces C[BS+1] and C[BS+2], the next two octets of ciphertext.
    //if (prefix.substr(BS - 2, 2) != xor_strings(FRE.substr(0, 2), data.substr(BS, 2))) {
    //    throw std::runtime_error("Error: Bad OpenPGP_CFB check value.");
    //}

    // MDC here
    uint8_t packet;
    if(useMDC)
        packet = SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA;
    else packet = SYMMETRICALLY_ENCRYPTED_DATA;
    std::string P = "";
    std::string::size_type x = (packet == SYMMETRICALLY_ENCRYPTED_DATA)?2:0;

    while ((x + BS) < inLen){//data.size()) {
        unsigned char* substr = substr_uchar(in, x, BS);
        //P += xor_strings(FRE, substr);
        unsigned char* p;
        XorBlocks(FRE, substr, p, blockBytesLen);
        
        //DecryptBlock(alignIn + i, out + i, key);
        //XorBlocks(block, out + i, out + i, blockBytesLen);
        //FRE = crypt -> encrypt(substr);
        EncryptBlock(substr, FRE, key);
        x += BS;
    }
    //P += xor_strings(FRE, data.substr(x, BS));
    unsigned char* p;
    XorBlocks(FRE, substr_uchar(in, x, BS), p, blockBytesLen);

    P = P.substr(BS, P.size() - BS);

    return prefix + ((packet == SYMMETRICALLY_ENCRYPTED_DATA)?prefixString.substr(BS - 2, 2):std::string("")) + P;   // only add prefix 2 octets when resyncing - already shows up without resync
}*/
/*
std::string OpenPGP_CFB_encrypt(const SymAlg::Ptr & crypt, const uint8_t packet, const std::string & data, std::string prefix) {
    const std::size_t BS = 16;

    if (prefix.size() < (BS + 2)) {
        throw std::runtime_error("Error: Given prefix too short.");
    }
    else if (prefix.size() > (BS + 2)) {
        prefix = prefix.substr(0, BS + 2);    // reduce prefix
    }

    // 13.9. OpenPGP CFB Mode
    //
    //    OpenPGP does symmetric encryption using a variant of Cipher Feedback
    //    mode (CFB mode). This section describes the procedure it uses in
    //    detail. This mode is what is used for Symmetrically Encrypted Data
    //    Packets; the mechanism used for encrypting secret-key material is
    //    similar, and is described in the sections above.
    //
    //    In the description below, the value BS is the block size in octets of
    //    the cipher. Most ciphers have a block size of 8 octets. The AES and
    //    Twofish have a block size of 16 octets. Also note that the
    //    description below assumes that the IV and CFB arrays start with an
    //    index of 1 (unlike the C language, which assumes arrays start with a
    //    zero index).
    //
    //    OpenPGP CFB mode uses an initialization vector (IV) of all zeros, and
    //    prefixes the plaintext with BS+2 octets of random data, such that
    //    octets BS+1 and BS+2 match octets BS-1 and BS. It does a CFB
    //    resynchronization after encrypting those BS+2 octets.
    //
    //    Thus, for an algorithm that has a block size of 8 octets (64 bits),
    //    the IV is 10 octets long and ocets 7 and 8 of the IV are the same as
    //    octets 9 and 10. For an algorithm with a block size of 16 octets
    //    (128 bits), the IV is 18 octets long, and octets 17 and 18 replicate
    //    octets 15 and 16. Those extra two octets are an easy check for a
    //    correct key.
    //
    //    Step by step, here is the procedure:

    //    1. The feedback register (FR) is set to the IV, which is all zeros.
    std::string FR(BS, 0);

    //    2. FR is encrypted to produce FRE (FR Encrypted). This is the encryption of an all-zero value.
    std::string FRE = crypt -> encrypt(FR);

    //    3. FRE is xored with the first BS octets of random data prefixed to the plaintext to produce C[1] through C[BS], the first BS octets of ciphertext.
    FRE = xor_strings(FRE, prefix);
    std::string C = FRE;

    //    4. FR is loaded with C[1] through C[BS].
    FR = C;

    //    5. FR is encrypted to produce FRE, the encryption of the first BS octets of ciphertext.
    FRE = crypt -> encrypt(FR);

    if (packet == Packet::SYMMETRICALLY_ENCRYPTED_DATA) {                    // resynchronization
        //    6. The left two octets of FRE get xored with the next two octets of data that were prefixed to the plaintext. This produces C[BS+1] and C[BS+2], the next two octets of ciphertext.
        C += xor_strings(FRE.substr(0, 2), prefix.substr(BS - 2, 2));

        //    7. (The resynchronization step) FR is loaded with C[3] through C[BS+2].
        FR = C.substr(2, BS);

        //    8. FR is encrypted to produce FRE.
        FRE = crypt -> encrypt(FR);

        //    9. FRE is xored with the first BS octets of the given plaintext, now that we have finished encrypting the BS+2 octets of prefixed data. This produces C[BS+3] through C[BS+(BS+2)], the next BS octets of ciphertext.
        C += xor_strings(FRE, data.substr(0, BS));
    }
    else if (packet == Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA) {     // no resynchronization
        // 5.13. Sym. Encrypted Integrity Protected Data Packet (Tag 18)
        //
        //    Unlike the Symmetrically Encrypted Data Packet, no
        //    special CFB resynchronization is done after encrypting this prefix
        //    data.

        // Second block of ciphertext is the 2 repeated octets + the first BS - 2 octets of the plaintext
        C += xor_strings(FRE, prefix.substr(BS - 2, 2) + data.substr(0, BS - 2));
    }
    else{
        throw std::runtime_error("Error: Bad Packet Type");
    }

    std::string::size_type x = BS - ((packet == Packet::SYMMETRICALLY_ENCRYPTED_DATA)?0:2);
    while (x < data.size()) {
        //    10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for an 8-octet block).
        FR = C.substr(x + 2, BS);

        //    11. FR is encrypted to produce FRE.
        FRE = crypt -> encrypt(FR);

        //    12. FRE is xored with the next BS octets of plaintext, to produce the next BS octets of ciphertext. These are loaded into FR, and the process is repeated until the plaintext is used up.
        C += xor_strings(FRE, data.substr(x, BS));

        x += BS;
    }

    return C;
}*/


// xor the contents of 2 strings, up to the last character of the shorter string
std::string xor_strings(const std::string & str1, const std::string & str2) {
    std::string::size_type end = std::min(str1.size(), str2.size());
    std::string out = str1.substr(0, end);
    for(std::string::size_type i = 0; i < end; i++) {
        out[i] ^= str2[i];
    }
    return out;
}

//string OpenPGP_CFB_decrypt(const SymAlg::Ptr & crypt, const uint8_t packet, const std::string & data) {
string AES::OpenPGP_CFB_decrypt(const uint8_t packet, const std::string & data, unsigned char* key) {
    cout<<reinterpret_cast<char*>((unsigned char*)key)<<endl;
    const std::size_t BS = 16;//crypt -> blocksize() >> 3;
    //cout<<"Data length: "<<data.size()<<endl;
    //cout<<"1"<<endl;
    //    1. The feedback register (FR) is set to the IV, which is all zeros.
    std::string FR(BS, 0);
    //cout<<"2: "<<FR.size()<<endl;

    //    2. FR is encrypted to produce FRE (FR Encrypted). This is the encryption of an all-zero value.
    unsigned char* fre = new unsigned char[blockBytesLen];
    EncryptBlock(reinterpret_cast<unsigned char*>(const_cast<char*>(FR.c_str())),fre,key);
    std::string FRE = reinterpret_cast<char*>((unsigned char*)fre);
    //cout<<"3: "<<FRE.size()<<endl;

    //    4. FR is loaded with C[1] through C[BS].
    FR = data.substr(0, BS);
    //cout<<"4: "<<FR.size()<<endl;

    //    3. FRE is xored with the first BS octets of random data prefixed to the plaintext to produce C[1] through C[BS], the first BS octets of ciphertext.
    std::string prefix = xor_strings(FRE, FR);
    //cout<<"5: "<<prefix.size()<<endl;
    //unsigned char *fre_xored = new unsigned char[blockBytesLen];
    //XorBlocks(reinterpret_cast<unsigned char*>(const_cast<char*>(FRE.c_str())), reinterpret_cast<unsigned char*>(const_cast<char*>(FR.c_str())), fre_xored, blockBytesLen);
    //prefix = reinterpret_cast<char*>((unsigned char*)fre_xored);

    //    5. FR is encrypted to produce FRE, the encryption of the first BS octets of ciphertext.
    //FRE = crypt -> encrypt(FR); // encryption of ciphertext 
    fre = new unsigned char[blockBytesLen];
    EncryptBlock(reinterpret_cast<unsigned char*>(const_cast<char*>(FR.c_str())),fre,key);
    FRE = reinterpret_cast<char*>((unsigned char*)fre);
    //cout<<"5"<<endl;
    //cout<<prefix.size()<<" "<<BS-2<<endl;
    //    6. The left two octets of FRE get xored with the next two octets of data that were prefixed to the plaintext. This produces C[BS+1] and C[BS+2], the next two octets of ciphertext.
    if (prefix.substr(BS - 2, 2) != xor_strings(FRE.substr(0, 2), data.substr(BS, 2))) {
        //throw std::runtime_error("Error: Bad OpenPGP_CFB check value.");
        return "";
    }
    //cout<<"6"<<endl;

    std::string P = "";
    std::string::size_type x = (packet == SYMMETRICALLY_ENCRYPTED_DATA)?2:0;
    while ((x + BS) < data.size()) {
        std::string substr = data.substr(x, BS);
        P += xor_strings(FRE, substr);
        //FRE = crypt -> encrypt(substr);
        fre = new unsigned char[blockBytesLen];
        EncryptBlock(reinterpret_cast<unsigned char*>(const_cast<char*>(FR.c_str())),fre,key);
        FRE = reinterpret_cast<char*>((unsigned char*)fre);
        x += BS;
    }
    P += xor_strings(FRE, data.substr(x, BS));
    P = P.substr(BS, P.size() - BS);

    return prefix + ((packet == 9)?prefix.substr(BS - 2, 2):std::string("")) + P;   // only add prefix 2 octets when resyncing - already shows up without resync
}
/*
std::string use_OpenPGP_CFB_encrypt(const uint8_t sym_alg, const uint8_t packet, const std::string & data, const std::string & key, const std::string & prefix) {
    if (!sym_alg) {
        return data;
    }

    const SymAlg::Ptr alg = Sym::setup(sym_alg, key);
    return OpenPGP_CFB_encrypt(alg, packet, data, prefix);
}

std::string use_OpenPGP_CFB_decrypt(const uint8_t sym_alg, const uint8_t packet, const std::string & data, const std::string & key) {
    if (!sym_alg) {
        return data;
    }

    const SymAlg::Ptr alg = Sym::setup(sym_alg, key);
    return OpenPGP_CFB_decrypt(alg, packet, data);
}*/
/* An Attack on CFB Mode Encryption As Used By OpenPGP

2.1  Standard CFB ModeWe describe the standard CFB mode of operation as described in ANSI X9.52 [1] and NIST Special
    Publication 800-38A [7]. We will assume that the block size of the underlying block cipher, the
    block size of the CFB mode and the size of the feedback variable are all b bytes, 
    since this is thecase for the variant used by OpenPGP. We are doing this simply for
    ease of explanation and notethat nothing in this paper depends upon this fact.
    Let EK(·) be encryption with the symmetric key K by the underlying block cipher. 
    Let ⊕ be bitwise exclusive-or. The plaintext message to be encrypted will be M= (M1, M2, . . . , Mn) 
    where each Mi is b bytes long. A random b-byte initialization vector IV is required in order to produce
    the ciphertextC= (C1, C2, . . . , Cn) as
        C1 = EK (IV) ⊕ M1
        C2 = EK (C1) ⊕ M2
        C3 = EK (C2) ⊕ M3
        ....
        Ci = EK (Ci-1) ⊕ Mi
        Cn = EK (Cn-1) ⊕ Mn


 */
/*
std::string normal_CFB_encrypt(const SymAlg::Ptr & crypt, const std::string & data, std::string IV) {
    std::string out = "";
    const std::size_t BS = crypt -> blocksize() >> 3;
    std::string::size_type x = 0;
    while (out.size() < data.size()) {
        IV = xor_strings(crypt -> encrypt(IV), data.substr(x, BS));
        out += IV;
        x += BS;
    }
    return out;
}

std::string normal_CFB_decrypt(const SymAlg::Ptr & crypt, const std::string & data, std::string IV) {
    std::string out = "";
    const std::size_t BS = crypt -> blocksize() >> 3;
    std::string::size_type x = 0;
    while (x < data.size()) {
        out += xor_strings(crypt -> encrypt(IV), data.substr(x, BS));
        IV = data.substr(x, BS);
        x += BS;
    }
    return out;
}

std::string use_normal_CFB_encrypt(const uint8_t sym_alg, const std::string & data, const std::string & key, const std::string & IV) {
    if (!sym_alg) {
        return data;
    }

    const SymAlg::Ptr alg = Sym::setup(sym_alg, key);
    return normal_CFB_encrypt(alg, data, IV);
}

std::string use_normal_CFB_decrypt(const uint8_t sym_alg, const std::string & data, const std::string & key, const std::string & IV) {
    if (!sym_alg) {
        return data;
    }

    const SymAlg::Ptr alg = Sym::setup(sym_alg, key);
    return normal_CFB_decrypt(alg, data, IV);
}
*/
unsigned char * AES::PaddingNulls(unsigned char in[], unsigned int inLen, unsigned int alignLen)
{
  unsigned char * alignIn = new unsigned char[alignLen];
  memcpy(alignIn, in, inLen);
  return alignIn;
}

unsigned int AES::GetPaddingLength(unsigned int len)
{
  return (len / blockBytesLen) * blockBytesLen;
}

void AES::EncryptBlock(unsigned char in[], unsigned char out[], unsigned  char key[])
{
  unsigned char *w = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, w);
  unsigned char **state = new unsigned char *[4];
  state[0] = new unsigned  char[4 * Nb];
  int i, j, round;
  for (i = 0; i < 4; i++)
  {
    state[i] = state[0] + Nb * i;
  }


  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, w);

  for (round = 1; round <= Nr - 1; round++)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, w + round * 4 * Nb);
  }

  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, w + Nr * 4 * Nb);

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
  delete[] w;
}

void AES::DecryptBlock(unsigned char in[], unsigned char out[], unsigned  char key[])
{
  unsigned char *w = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, w);
  unsigned char **state = new unsigned char *[4];
  state[0] = new unsigned  char[4 * Nb];
  int i, j, round;
  for (i = 0; i < 4; i++)
  {
    state[i] = state[0] + Nb * i;
  }


  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, w + Nr * 4 * Nb);

  for (round = Nr - 1; round >= 1; round--)
  {
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, w + round * 4 * Nb);
    InvMixColumns(state);
  }

  InvSubBytes(state);
  InvShiftRows(state);
  AddRoundKey(state, w);

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
  delete[] w;
}


void AES::SubBytes(unsigned char **state)
{
  int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      t = state[i][j];
      state[i][j] = sbox[t / 16][t % 16];
    }
  }

}

void AES::ShiftRow(unsigned char **state, int i, int n)    // shift row i on n positions
{
  unsigned char t;
  int k, j;
  for (k = 0; k < n; k++)
  {
    t = state[i][0];
    for (j = 0; j < Nb - 1; j++)
    {
      state[i][j] = state[i][j + 1];
    }
    state[i][Nb - 1] = t;
  }
}

void AES::ShiftRows(unsigned char **state)
{
  ShiftRow(state, 1, 1);
  ShiftRow(state, 2, 2);
  ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b)    // multiply on x
{
  unsigned char mask = 0x80, m = 0x1b;
  unsigned char high_bit = b & mask;
  b = b << 1;
  if (high_bit) {    // mod m(x)
    b = b ^ m;
  }
  return b;
}

unsigned char AES::mul_bytes(unsigned char a, unsigned char b)
{
  unsigned char c = 0, mask = 1, bit, d;
  int i, j;
  for (i = 0; i < 8; i++)
  {
    bit = b & mask;
    if (bit)
    {
      d = a;
      for (j = 0; j < i; j++)
      {    // multiply on x^i
        d = xtime(d);
      }
      c = c ^ d;    // xor to result
    }
    b = b >> 1;
  }
  return c;
}

void AES::MixColumns(unsigned char **state)
{
  unsigned char s[4], s1[4];
  int i, j;

  for (j = 0; j < Nb; j++)
  {
    for (i = 0; i < 4; i++)
    {
      s[i] = state[i][j];
    }

    s1[0] = mul_bytes(0x02, s[0]) ^ mul_bytes(0x03, s[1]) ^ s[2] ^ s[3];
    s1[1] = s[0] ^ mul_bytes(0x02, s[1]) ^ mul_bytes(0x03, s[2]) ^ s[3];
    s1[2] = s[0] ^ s[1] ^ mul_bytes(0x02, s[2]) ^ mul_bytes(0x03, s[3]);
    s1[3] = mul_bytes(0x03, s[0]) ^ s[1] ^ s[2] ^ mul_bytes(0x02, s[3]);
    for (i = 0; i < 4; i++)
    {
      state[i][j] = s1[i];
    }

  }

}

void AES::AddRoundKey(unsigned char **state, unsigned char *key)
{
  int i, j;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      state[i][j] = state[i][j] ^ key[i + 4 * j];
    }
  }
}

void AES::SubWord(unsigned char *a)
{
  int i;
  for (i = 0; i < 4; i++)
  {
    a[i] = sbox[a[i] / 16][a[i] % 16];
  }
}

void AES::RotWord(unsigned char *a)
{
  unsigned char c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

void AES::XorWords(unsigned char *a, unsigned char *b, unsigned char *c)
{
  int i;
  for (i = 0; i < 4; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}

void AES::Rcon(unsigned char * a, int n)
{
  int i;
  unsigned char c = 1;
  for (i = 0; i < n - 1; i++)
  {
    c = xtime(c);
  }

  a[0] = c;
  a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(unsigned char key[], unsigned char w[])
{
  unsigned char *temp = new unsigned char[4];
  unsigned char *rcon = new unsigned char[4];

  int i = 0;
  while (i < 4 * Nk)
  {
    w[i] = key[i];
    i++;
  }

  i = 4 * Nk;
  while (i < 4 * Nb * (Nr + 1))
  {
    temp[0] = w[i - 4 + 0];
    temp[1] = w[i - 4 + 1];
    temp[2] = w[i - 4 + 2];
    temp[3] = w[i - 4 + 3];

    if (i / 4 % Nk == 0)
    {
        RotWord(temp);
        SubWord(temp);
        Rcon(rcon, i / (Nk * 4));
      XorWords(temp, rcon, temp);
    }
    else if (Nk > 6 && i / 4 % Nk == 4)
    {
      SubWord(temp);
    }

    w[i + 0] = w[i - 4 * Nk] ^ temp[0];
    w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
    w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
    w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
    i += 4;
  }

  delete []rcon;
  delete []temp;

}


void AES::InvSubBytes(unsigned char **state)
{
  int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      t = state[i][j];
      state[i][j] = inv_sbox[t / 16][t % 16];
    }
  }
}

void AES::InvMixColumns(unsigned char **state)
{
  unsigned char s[4], s1[4];
  int i, j;

  for (j = 0; j < Nb; j++)
  {
    for (i = 0; i < 4; i++)
    {
      s[i] = state[i][j];
    }
    s1[0] = mul_bytes(0x0e, s[0]) ^ mul_bytes(0x0b, s[1]) ^ mul_bytes(0x0d, s[2]) ^ mul_bytes(0x09, s[3]);
    s1[1] = mul_bytes(0x09, s[0]) ^ mul_bytes(0x0e, s[1]) ^ mul_bytes(0x0b, s[2]) ^ mul_bytes(0x0d, s[3]);
    s1[2] = mul_bytes(0x0d, s[0]) ^ mul_bytes(0x09, s[1]) ^ mul_bytes(0x0e, s[2]) ^ mul_bytes(0x0b, s[3]);
    s1[3] = mul_bytes(0x0b, s[0]) ^ mul_bytes(0x0d, s[1]) ^ mul_bytes(0x09, s[2]) ^ mul_bytes(0x0e, s[3]);

    for (i = 0; i < 4; i++)
    {
      state[i][j] = s1[i];
    }
  }
}

void AES::InvShiftRows(unsigned char **state)
{
  ShiftRow(state, 1, Nb - 1);
  ShiftRow(state, 2, Nb - 2);
  ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len)
{
  for (unsigned int i = 0; i < len; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}





