#include <iostream>
#include "AES.h"
#include <cassert>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>
#include <iomanip>
using namespace std;



void Test128()
{
  AES aes(128);
  unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
  unsigned char right[] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };


  unsigned int len = 0;
  unsigned char *out = aes.EncryptECB(plain, 16 * sizeof(unsigned char), key, len);

  assert(!memcmp(right, out, 16 * sizeof(unsigned char)));
  cout << "Test 128 [OK]" << endl;
  delete[] out;
}


void Test192()
{
  AES aes(192);
  unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x011,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
  unsigned char right[] = {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };

  unsigned int len;
  unsigned char *out = aes.EncryptECB(plain, 16 * sizeof(unsigned char), key, len);
  assert(!memcmp(right, out, 16 * sizeof(unsigned char)));
  cout << "Test 192 [OK]" << endl;
  delete[] out;
}


void Test256()
{
  AES aes(256);
  unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x011,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
  unsigned char right[] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };

  unsigned int len = 0;
  unsigned char *out = aes.EncryptECB(plain, 16 * sizeof(unsigned char), key, len);
  assert(!memcmp(right, out, 16 * sizeof(unsigned char)));
  cout << "Test 256 [OK]" << endl;
  delete[] out;
}

void TestECB()
{
  AES aes(256);
  unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

  unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x011,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

  unsigned int len = 0;
  unsigned char *out = aes.EncryptECB(plain, 16 * sizeof(unsigned char), key, len);
  unsigned char *innew = aes.DecryptECB(out, 16 * sizeof(unsigned char), key, len);
  assert(!memcmp(innew, plain, 16 * sizeof(unsigned char)));
  cout << "Test ECB [OK]" << endl;
  delete[] out;
  delete[] innew;
}
inline string ByteToStr(const uint8_t &byte);
void TestCBC()
{
  AES aes(256);
  unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  unsigned char iv[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x011,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

  unsigned int len;
  unsigned char *out = aes.EncryptCBC(plain, 16 * sizeof(unsigned char), key, iv, len);
  unsigned char *innew = aes.DecryptCBC(out, 16 * sizeof(unsigned char), key, iv, len);
  assert(!memcmp(innew, plain, 16 * sizeof(unsigned char)));
  cout << "Test CBC [OK]" << endl;
  delete[] out;
  delete[] innew;
}

void TestCFB()
{
  AES aes(256);
  unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  unsigned char iv[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x011,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

  unsigned int len;
  unsigned char *out = aes.EncryptCFB(plain, 16 * sizeof(unsigned char), key, iv, len);
  unsigned char *innew = aes.DecryptCFB(out, 16 * sizeof(unsigned char), key, iv, len);
  assert(!memcmp(innew, plain, 16 * sizeof(unsigned char)));
  cout << "Test CFB [OK]" << endl;
  delete[] out;
  delete[] innew;
}

string clearHex = "377abcaf271c00044eff88984300000000000000620000000000000066975547e0003f003b5d002a1a0927641c878f5fb2ae3a9af8f38cccac022301129445b5bdc218fa7dcf97fa0c41a115ec119c99e0d2e3045a5a6fec0a5b1c4c4ad694b30000000104060001094300070b010001212101000c4000080a01202c403400000501190c000000000000000000000000111d0063006c0065006100720074006500780074002e007400780074000000140a010080173d827232d501150601002080a4810000";
string cipherCBCHex = "53616c7465645f5f0f1e1a1158af70edc9523a2484d2cd77350ee59c90004b89165e523723304567d740a356822d2618f8b24e697dd671302c41c1ecc1d24b25e907c8ed8235fe731f337adebfda5b9ff86c47450ffd0251cedf2088ad9770e81fe349de55f8d1c6fa40cc508005695a260017cbc0784399b8547886ff2d82eee89d2700c05ddcadb6cdba9213a274d929306bae455e28708ecb601845ef0c67df1e2bd3b63b6040b76b032cd70d879d58c1c3355d1271ba75f1eb5b4663c0ee3fd6ece8a1a74f85c608648d1f8b1245df3db7130909ac73fa820d651c4790e5";
string cipherCFBHex = "8c0d040903024a84b6211ffc779b34d2c03701161ccc1df35c4fffae3a9f66d43ddda2d74ac6fe1d9c69da03f4f563ae21413e22e3cbddfc9f381f4e45fe92eaa8a4fec74690580ea06849fef68921c6c8ba656582afd1e7cc6bd34509ae2a92170fefb5a2f91dd22f9e433ea2f9f8cd5de2b2ae25408d83a515d72f8496991d0bacbe23d1ed835ae0a8f7d15711040d54fa738f1f881900dbc2b4ca7685ff1b32e4eddbe0c2814e42363d137e1f931000f773a17e4e3a2d0775d3239cb496acef2e121e50f7b5aed4322af93fc40e79454a9ee424747f32351a93972b816bdd55513dd63f630ea8ede89654e73d2aec406e8290f8f6562ba7b823b80dee73516f3b2e047a5eaecef7";
// string cipherCFBHex = "8c 0d 04 09 03 02 4a84b6211ffc779 b34d2c03701161ccc1df35c4fffae3a9f66d43ddda2d74ac6fe1d9c69da03f4f563ae21413e22e3cbddfc9f381f4e45fe92eaa8a4fec74690580ea06849fef68921c6c8ba656582afd1e7cc6bd34509ae2a92170fefb5a2f91dd22f9e433ea2f9f8cd5de2b2ae25408d83a515d72f8496991d0bacbe23d1ed835ae0a8f7d15711040d54fa738f1f881900dbc2b4ca7685ff1b32e4eddbe0c2814e42363d137e1f931000f773a17e4e3a2d0775d3239cb496acef2e121e50f7b5aed4322af93fc40e79454a9ee424747f32351a93972b816bdd55513dd63f630ea8ede89654e73d2aec406e8290f8f6562ba7b823b80dee73516f3b2e047a5eaecef7";
// Salt bytes: [6:14]
/*  gpg --list-packets archivedcleartext.7z.gpg 
    gpg: AES256 encrypted data
    gpg: encrypted with 1 passphrase
    # off=0 ctb=8c tag=3 hlen=2 plen=13
    :symkey enc packet: version 4, cipher 9, s2k 3, hash 2
        salt 4A84B6211FFC779B, count 10240 (52)
    # off=15 ctb=d2 tag=18 hlen=3 plen=247 new-ctb
    :encrypted data packet:
        length: 247
        mdc_method: 2
    # off=37 ctb=a3 tag=8 hlen=1 plen=0 indeterminate
    :compressed packet: algo=1
    # off=39 ctb=ac tag=11 hlen=2 plen=223           
    :literal data packet:
        mode b (62), created 1562250274, name="archivedcleartext.7z",
        raw data: 197 bytes
     */

/*Old: Symmetric-Key Encrypted Session Key Packet(tag 3)(13 bytes)
        New version(4)
        Sym alg - AES with 256-bit key(sym 9)
        Iterated and salted string-to-key(s2k 3):
                Hash alg - SHA1(hash 2)
                Salt - 4a 84 b6 21 1f fc 77 9b 
                Count - 10240(coded count 52)
New: Symmetrically Encrypted and MDC Packet(tag 18)(247 bytes)
        Ver 1
        Encrypted data [sym alg is specified in sym-key encrypted session key]
                (plain text + MDC SHA1(20 bytes))
                 */

string cbcKeyHex = "8BBDFE671448FFBBA127DB71763D78AEF9A3BB55CDDB242544429DC062DDB38D";
string cbcIVHex = "E739E753DA3AD7977E936A7919C4FD34";
string cfbKeyHex = "ED72BFC9290576788991E9A0819002773929E6595C0D39FBAC3B929863970EBA";

typedef vector<uint8_t> bytes;
string BytesToStr(const bytes &in)
{
    bytes::const_iterator from = in.cbegin();
    bytes::const_iterator to = in.cend();
    ostringstream oss;
    for (; from != to; ++from)
       oss << hex << setw(2) << setfill('0') << showbase << static_cast<int>(*from);
    return oss.str();
}

string ByteToStr(const uint8_t &byte)
{
    ostringstream oss;
       oss << hex << setw(2) << setfill('0') << showbase << static_cast<int>(byte);
    return oss.str();
}

string hexStr(vector<uint8_t> data)
{
    ostringstream ss;
    ss << hex << setfill ('0');
    //if (use_uppercase)
    //    ss << uppercase;
    for(int i(0);i<data.size();++i){
        ss<<setw(2)<<static_cast<int>(data[i]);
        //if (insert_spaces && first != last)
        //    ss << " ";
    }
    return ss.str();
}

bytes HexToBytes(const string& hex){
	bytes bytes;
	
	for (unsigned int i = 0; i < hex.length(); i += 2){
		string byteString = hex.substr(i, 2);
		unsigned char byte = (char) strtol(byteString.c_str(), NULL, 16);
		bytes.push_back(byte);
	}
	
	return bytes;
}

void DecryptOpenSSLCBC(string cipherHex, string keyHex, string ivHex){
    bytes cipherBytes = HexToBytes(cipherHex);
    bytes keyBytes = HexToBytes(keyHex);
    bytes ivBytes = HexToBytes(ivHex);
     int saltLength = 16;
    //unsigned char *out = aes.EncryptCBC(plain, 16 * sizeof(unsigned char), key, iv, len);
    unsigned char *out[cipherBytes.size()-saltLength];
    //cout<<cipherBytes.size()<<endl;
    unsigned char *key[keyBytes.size()];
    unsigned char *iv[ivBytes.size()];
    //skip "Salted__" + 8 bytes*/
    for(int i = 0;i<cipherBytes.size()-saltLength;i++)
        out[i] = &cipherBytes[i+saltLength];
    for(int i = 0;i<keyBytes.size();i++)
        key[i] = &keyBytes[i];
    for(int i = 0;i<ivBytes.size();i++)
        iv[i] = &ivBytes[i];
    
    AES aes(256);
    unsigned int len;
    unsigned char *innew = aes.DecryptCBC(out[0], 16 * sizeof(unsigned char), key[0], iv[0], len);
    int i = 0;
    while(i<len){
        cout<<ByteToStr(*(innew+i))<<" ";
        i++;
    }cout<<endl;

    cout << "Decrypted CBC" << endl;
    delete[] innew;
}

void DecryptGPGCFB(string cipherHex, string keyHex, int s){
    bytes cipherBytes = HexToBytes(cipherHex);
    bytes keyBytes = HexToBytes(keyHex);
    
    int skipBytes = s;
    unsigned char *out = new unsigned char[cipherBytes.size()-skipBytes];
    unsigned char *key = new unsigned char[keyBytes.size()];
    //skip "Salted__" + 8 bytes*/
    for(int i = 0;i<cipherBytes.size()-skipBytes;i++){
        out[i] = cipherBytes[i+skipBytes];
        //cout<<"byte "<<cipherBytes[i+skipBytes];
    }
    for(int i = 0;i<keyBytes.size();i++)
        key[i] = keyBytes[i];
    //cout<<"Got here"<<endl;
    AES aes(256);
    //unsigned int len;
    //unsigned char iv[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    //cout<<"Got here 2 "<<strlen((char*)out)<<endl;//cipherBytes.size()-skipBytes<<endl;
    string temp = aes.OpenPGP_CFB_decrypt(18,reinterpret_cast<char*>((unsigned char*)out),key);
    if(temp==""){
        //std::cout<<"Error: Bad OpenPGP_CFB check value."<<std::endl;
        delete[] out;
        delete[] key;
        return;
    }
    //else cout<<"Success??"<<endl;
    unsigned char *innew = reinterpret_cast<unsigned char*>(const_cast<char*>(temp.c_str()));
    int i = 0;
    //cout<<"     : ";
    while(i<temp.size()){
        cout<<ByteToStr(*(innew+i))<<" ";
        i++;
    }cout<<endl;

    //cout << "Decrypted   CFB" << endl;
    delete[] out;
    delete[] key;
    delete[] innew;
    cout<<" got here hmmm "<<endl;
}

int main()
{
    Test128();
    Test192();
    Test256();
    TestECB();
    TestCBC();
    TestCFB();
    DecryptOpenSSLCBC(cipherCBCHex,cbcKeyHex,cbcIVHex);
    //AES aes(256);
    //cout<<"blockBytesLen: "<<aes.blockBytesLen<<endl;   //  blockBytesLen: 16
    //const std::size_t BS = aes.blockBytesLen >> 3;
    //cout<<"BS: "<<BS<<endl; //  BS: 2

    std::size_t BS = 128 >> 3;
    cout<<"BS: "<<BS<<endl; //  BS: 16 bytes e.g. 128 bits
    
//    string data(reinterpret_cast<char*>((unsigned char*)"AHSHSDAJS ASDHJASDHKASAHSHSDAJS ASDHJASDHKASAHSHSDAJS ASDHJASDHKASAHSHSDAJS ASDHJASDHKAS"));
//    unsigned char* uchrs = reinterpret_cast<unsigned char*>(const_cast<char*>(data.c_str()));

    //cout<<data<<endl;
    //cout<<data.c_str()<<endl;
    //cout<<uchrs<<endl;
    for(int i = 0; i < 100; i++){
        cout<<i<<endl;
        DecryptGPGCFB(cipherCFBHex,cfbKeyHex, i);
    }
  return 0;
}

