#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>
#include <aubio/aubio.h>
#include "sha256.h"
#include "aes.h"
#include "hmac_sha256.h"
#include <cstring>
#include <filesystem>
#include <random>
#include <cstdlib>
#include <ctime>
using namespace std; 
vector<double> beattime;
vector<double> beatIntervals;
vector<unsigned char> generateHash(const string& pass)
{
    SHA256_CTX ctx;
    vector<unsigned char> hash(32);
    sha256_init(&ctx);
    sha256_update(&ctx,(const unsigned char*)pass.c_str(),pass.size());
    sha256_final(&ctx,hash.data());
    return hash;
}
vector<uint8_t> readFile(const string& path){
    ifstream file(path, ios::binary);
    if (!file){
        cout << "Khong mo duoc file!\n";
        return {};
    }
    file.seekg(0, ios::end);
    size_t size =static_cast<size_t>(file.tellg());
    file.seekg(0, ios::beg);
    vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()),size);
    file.close();
    return data;
}
void writeFile(const string& path,const vector<uint8_t>& data){
    ofstream file(path, ios::binary);
    if (!file){
        cout << "Khong tao duoc file!\n";
        return;
    }
    file.write(reinterpret_cast<const char*>(data.data()),data.size());
    file.close();
}
void aesEncrypt(vector<uint8_t>& data,const vector<unsigned char>& key){
    AES_ctx ctx;
    uint8_t iv[16] ={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    AES_init_ctx_iv(
        &ctx,
        key.data(),
        iv
    );

    AES_CBC_encrypt_buffer(
        &ctx,
        data.data(),
        data.size()
    );
}

void aesDecrypt(
    vector<uint8_t>& data,
    const vector<unsigned char>& key
)
{
    AES_ctx ctx;

    uint8_t iv[16] =
    {
        0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15
    };

    AES_init_ctx_iv(
        &ctx,
        key.data(),
        iv
    );

    AES_CBC_decrypt_buffer(
        &ctx,
        data.data(),
        data.size()
    );
}
void apadd(vector<uint8_t>& data)
{
    uint8_t padd =
        16 - (data.size() % 16);

    for (int i = 0; i < padd; i++)
    {
        data.push_back(padd);
    }
}

void rpadd(vector<uint8_t>& data)
{
    if (data.empty())
        return;

    uint8_t padd =
        data.back();

    if (padd == 0 || padd > 16)
        return;

    if (padd > data.size())
        return;

    data.resize(
        data.size() - padd
    );
}
bool analyzeBeat(const string& audioPath)
{
    beattime.clear();
    beatIntervals.clear();

    uint_t hop_size = 512;
    uint_t buffer_size = 1024;

    aubio_source_t* source =
        new_aubio_source(
            audioPath.c_str(),
            0,
            hop_size
        );

    if (!source)
    {
        cout << "Khong mo duoc file am thanh!\n";
        return false;
    }

    uint_t sample_rate =
        aubio_source_get_samplerate(source);

    cout << "Sample rate: "
         << sample_rate
         << " Hz\n";

    if (sample_rate == 0)
    {
        del_aubio_source(source);
        return false;
    }

    aubio_tempo_t* tempo =
        new_aubio_tempo(
            "default",
            buffer_size,
            hop_size,
            sample_rate
        );

    if (!tempo)
    {
        del_aubio_source(source);
        return false;
    }

    fvec_t* samples =
        new_fvec(hop_size);

    fvec_t* beat =
        new_fvec(1);

    if (!samples || !beat)
    {
        if (samples)
            del_fvec(samples);

        if (beat)
            del_fvec(beat);

        del_aubio_tempo(tempo);
        del_aubio_source(source);

        return false;
    }

    uint_t read = 0;
    do
    {
        aubio_source_do(
            source,
            samples,
            &read
        );

        aubio_tempo_do(
            tempo,
            samples,
            beat
        );

        if (beat->data[0] != 0)
        {
            double time =
                aubio_tempo_get_last(tempo);

            beattime.push_back(time);
        }

    } while (read > 0);

    for (size_t i = 1;
         i < beattime.size();
         i++)
    {
        double interval =
            beattime[i] -
            beattime[i - 1];

        if (interval > 0)
        {
            beatIntervals.push_back(interval);
        }
    }

    del_fvec(samples);
    del_fvec(beat);
    del_aubio_tempo(tempo);
    del_aubio_source(source);

    cout << "\nBEAT MAP\n";
    cout << "So Beat: "
         << beattime.size()
         << "\n";

    cout << "So Beat Interval: "
         << beatIntervals.size()
         << "\n";

    return !beatIntervals.empty();
}

vector<size_t> createFragmentMap(size_t dataSize, const vector<unsigned char>& secretKey) {
    vector<size_t> fragmentSizes;
    if (dataSize < 16 || beatIntervals.empty()) return fragmentSizes;
    size_t fragmentCount = min(beatIntervals.size(), dataSize / 16);
    if (fragmentCount == 0) return fragmentSizes;
    vector<uint64_t> weights;
    uint64_t totalWeight = 0;
    for (size_t i = 0; i < fragmentCount; i++) {
        vector<uint8_t> input;
        string domain = "SENTINELGATE-FRAGMENT-MAP-V1";
        input.insert(input.end(), domain.begin(), domain.end());
        uint64_t intervalBits = 0;
        memcpy(&intervalBits, &beatIntervals[i], sizeof(double));
        for (int b = 0; b < 8; b++) input.push_back((intervalBits >> (b * 8)) & 0xFF);
        uint64_t index = i;
        for (int b = 0; b < 8; b++) input.push_back((index >> (b * 8)) & 0xFF);
        unsigned char digest[32];
        hmac_sha256(secretKey.data(), secretKey.size(), input.data(), input.size(), digest, sizeof(digest));
        uint64_t weight = 0;
        for (int b = 0; b < 8; b++) weight = (weight << 8) | digest[b];
        weight = (weight % 1000000ULL) + 1;
        weights.push_back(weight);
        totalWeight += weight;
    }
    size_t remaining = dataSize;
    for (size_t i = 0; i < fragmentCount; i++) {
        size_t fragmentsLeft = fragmentCount - i;
        size_t minimumRemaining = (fragmentsLeft - 1) * 16;
        size_t available = remaining - minimumRemaining;
        size_t fragmentSize;
        if (i == fragmentCount - 1) {
            fragmentSize = available;
        } else {
            fragmentSize = static_cast<size_t>((static_cast<long double>(available) * weights[i]) / totalWeight);
            fragmentSize = (fragmentSize / 16) * 16;
            if (fragmentSize < 16) fragmentSize = 16;
        }
        fragmentSizes.push_back(fragmentSize);
        remaining -= fragmentSize;
        totalWeight -= weights[i];
    }
    return fragmentSizes;
}
vector<vector<uint8_t>> splitFile(const vector<uint8_t>& data,const vector<size_t>& sizes){
    vector<vector<uint8_t>> fragments;
    size_t position = 0;
    for (size_t size : sizes){
        if (position >= data.size())
            break;
        size_t remaining =
            data.size() - position;
        size_t actualSize =
            min(size, remaining);
        vector<uint8_t> fragment(data.begin() + position,data.begin() + position + actualSize);
        fragments.push_back(fragment);
        position += actualSize;
    }
    return fragments;
}
vector<uint8_t> mergeFragments(
    const vector<vector<uint8_t>>& fragments){
    vector<uint8_t> data;
    for (const auto& fragment : fragments){
        data.insert(
            data.end(),
            fragment.begin(),
            fragment.end()
        );
    }
    return data;
}
vector<vector<uint8_t>> shuffleFragment(const vector<vector<uint8_t>>& fragments, const vector<unsigned char>& key, vector<size_t>& order) {
    size_t fragmentCount = fragments.size();
    order.resize(fragmentCount);
    vector<uint8_t> input;

    for (size_t i = 0; i < fragmentCount; i++) {
        order[i] = i;
    }
    if (fragmentCount < 2) return fragments;
    for (size_t i = fragmentCount - 1; i > 0; i--) {
        size_t j;
        input.clear();
        uint64_t index = i;
        for (int b = 0; b < 8; b++){
            input.push_back(index >> (b * 8) & 0xFF);
        }
        unsigned char digest[32];
        hmac_sha256(key.data(), key.size(), input.data(), input.size(), digest,sizeof(digest));
        uint64_t value = 0;
        for(int b = 0; b < 8; b++){
            value = (value << 8) | digest[b];
        }
        j = value % (i + 1);
        swap(order[i], order[j]);
    }
    vector<vector<uint8_t>> shuffled;
    shuffled.reserve(fragmentCount);
    for(size_t i = 0; i < fragmentCount; i++){
        shuffled.push_back(fragments[order[i]]);
    }
    return shuffled;
}
struct FileHeader{
    uint32_t index; uint32_t total; uint64_t sessionId;  uint64_t payloadSize;
};
vector<uint8_t> packf(const vector<uint8_t>& fragment, uint32_t index, uint32_t total, uint64_t sessionId, const vector <unsigned char>& key){
    FileHeader header;
    header.index = index;
    header.total = total;
    header.sessionId = sessionId;
    header.payloadSize = fragment.size();
    vector<uint8_t> protectedData;
    const uint8_t* headerBytes = reinterpret_cast<const uint8_t*>(&header);
    protectedData.insert(protectedData.end(), headerBytes, headerBytes + sizeof(header));
    protectedData.insert(protectedData.end(), fragment.begin(), fragment.end());
    apadd(protectedData);
    aesEncrypt(protectedData, key);
    uint8_t hmac[32];
    hmac_sha256(key.data(), key.size(), protectedData.data(), protectedData.size(),hmac, sizeof(hmac));
    protectedData.insert(protectedData.end(), hmac, hmac + 32);
    return protectedData;
}
bool unpackf(const vector<uint8_t>& protectedData,const vector<unsigned char>& key,FileHeader& info,vector<uint8_t>& fragment){
    if (protectedData.size() <= 32)
        return false;
    size_t encryptedSize = protectedData.size() - 32;
    unsigned char expectedHmac[32];
    hmac_sha256(key.data(),key.size(),protectedData.data(),encryptedSize,expectedHmac,sizeof(expectedHmac));
    if (memcmp(expectedHmac,protectedData.data() + encryptedSize,32) != 0)
        return false;
    vector<uint8_t> encrypted(protectedData.begin(),protectedData.begin() + encryptedSize);
    aesDecrypt(encrypted, key);
    if (encrypted.size() < sizeof(FileHeader))
        return false;
    memcpy(&info,encrypted.data(),sizeof(FileHeader));
    if (info.payloadSize >encrypted.size() - sizeof(FileHeader))
        return false;
    fragment.assign(encrypted.begin() + sizeof(FileHeader),encrypted.begin() + sizeof(FileHeader) + info.payloadSize);
    return true;
}
uint64_t createsessionId(){static random_device rd;static mt19937_64 eng(rd());return eng();
}
string randomFileName(){
    static const char chars[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    vector<string> extensions = {
        ".sys", ".tmp", ".dat", ".dll",".log", ".cfg",
         ".cache",".bin", ".bak", ".old","exe",".sgt",
         ".mp3",".wav",".flac",".ogg",".m4a","aac",
         ".wma",".alac",".aiff",".opus","midi",".mid",
         ".aif",".aifc",".aiff",".au",".snd",".pcm",
         ".raw",".voc",".cda",".m3u",".pls","asx",".wax",
         ".wpl",".xspf",".m4b",".m4p",".m4r",".m4v",".3gp",
         ".3g2",".mp4",".mov",".avi",".wmv",".flv",".mkv",
          ".webm",".vob",".ogv",".ts",".mts",".m2ts",".divx",
          ".xvid",".rm",".rmvb",".asf",".f4v",".swf",".mxf",
          ".dv",".dvr-ms",".wtv",".yuv",".y4m","mjpeg",".mjpg",
          ".m2v",".m1v",".mpg",".mpeg",".mp2",".mp3",".mpa",".mpe",
          ".mpv",".m4v",".3gp2",".3gpp",".3gpp2",".3g2a",".3g2b",
          ".3g2c",".3g2d",".3g2e",".3g2f",".3g2g",".3g2h",".3g2i",
          ".3g2j",".3g2k",".3g2l",".3g2m",".3g2n",".3g2o",".3g2p",
          ".3g2q",".3g2r",".3g2s",".3g2t",".3g2u",".3g2v",".3g2w",
          ".3g2x",".3g2y",".3g2z","pmg",".pmp",".pmv",".pmt",".pmw",
          ".pmx",".pmy",".pmz",".pna",".pnb",".pnc",".pnd",".pne",
          ".pnf",".png",".pnm",".pno",".pnp",".pnq",".pnr",".pns",
          ".pnt",".pnu",".pnv",".pnw",".pnx",".pny",".pnz"
    };
    string name;
    for (int i = 0; i < 12; i++){
        name += chars[rand() % (sizeof(chars) - 1)];
    }
    string ext = extensions[rand() % extensions.size()];
    return name + ext;
}
int main(){
    string pass;
    cout << "Nhap mat khau: ";
    cin >> pass;
    vector<unsigned char> key = generateHash(pass);
    while (true){
        cout << "\n========================\n";
        cout << "      SENTINELGATE\n";
        cout << "========================\n";
        cout << "1. Ma hoa file\n";
        cout << "2. Giai ma file\n";
        cout << "0. Thoat\n";
        cout << "Lua chon: ";
        int choice;
        cin >> choice;
        cin.ignore();
        switch (choice){
            case 1:
            {
                string filePath;
                string audioPath;
                cout << "\nNhap duong dan FILE DU LIEU: ";
                getline(cin, filePath);
                cout << "Nhap duong dan FILE NHAC: ";
                getline(cin, audioPath);
                filePath.erase(remove(filePath.begin(), filePath.end(), '\"'), filePath.end());
                audioPath.erase(remove(audioPath.begin(), audioPath.end(), '\"'), audioPath.end());
                
                vector<uint8_t> data = readFile(filePath);
                if (data.empty())
                    break;
                    
                if (!analyzeBeat(audioPath)) {
                    cout << "Khong tao duoc Beat Map!\n";
                    break;
                }
                
                apadd(data);
                vector<size_t> fragmentMap = createFragmentMap(data.size(), key);
                if (fragmentMap.empty()) {
                    cout << "Khong tao duoc Fragment Map!\n";
                    break;
                }
                
                cout << "\nFRAGMENT MAP\n";
                for (size_t i = 0; i < fragmentMap.size(); i++) {
                    cout << "M" << i << " = " << fragmentMap[i] << " bytes\n";
                }
                
                vector<vector<uint8_t>> fragments = splitFile(data, fragmentMap);
                cout << "\nSo fragment: " << fragments.size() << "\n";
                
                vector<vector<uint8_t>> protectedFragments;
                protectedFragments.reserve(fragments.size());
                uint64_t sessionId = createsessionId();
                
                for (size_t i = 0; i < fragments.size(); i++) {
                    if (!fragments[i].empty()) {
                        vector<uint8_t> result = packf(fragments[i], i, fragments.size(), sessionId, key);
                        protectedFragments.push_back(result);
                    }
                }
                
                vector<size_t> order;
                vector<vector<uint8_t>> shuffled = shuffleFragment(protectedFragments, key, order);
                cout << "shuffle size: " << shuffled.size() << "\n";
                string output = filePath + ".sgt";
                filesystem::create_directories(output);
                cout << "\nDanh sach cac file duoc tao:\n";
                for (size_t i = 0; i < shuffled.size(); i++) {
                    string randomName = randomFileName();
                    string fragmentPath = output + "/" + randomName; 
                    writeFile(fragmentPath, shuffled[i]);
                    cout << randomName << "\n"; 
                }
                cout << "\ntest code\n";
                
                cout << "Output: " << output << "\n";
                break;
            }
            case 2:
            {
             string path;
            cout << "Nhap thu muc .sgt: ";
            getline(cin, path);

            path.erase(remove(path.begin(), path.end(), '\"'), path.end());

            if (!filesystem::exists(path) || !filesystem::is_directory(path)){
                cout << "\nThu muc .sgt khong ton tai!\n";
                break;
            }

            vector<vector<uint8_t>> fragments;
            vector<FileHeader> headers;

            uint64_t sessionId = 0;
            uint32_t total = 0;

            for (const auto& entry : filesystem::directory_iterator(path)){
                if (!entry.is_regular_file())
                    continue;

                vector<uint8_t> protectedData = readFile(entry.path().string());

                if (protectedData.empty())
                    continue;

                FileHeader info;
                vector<uint8_t> fragment;

                if (!unpackf(protectedData, key, info, fragment)){
                    cout << "\nFragment loi hoac sai password: "
                        << entry.path().filename().string()
                        << "\n";
                    continue;
                }

                if (total == 0){
                    total = info.total;
                    sessionId = info.sessionId;
                }

                if (info.total != total || info.sessionId != sessionId){
                    cout << "\nFragment khong cung session!\n";
                    continue;
                }

                headers.push_back(info);
                fragments.push_back(fragment);
            }

            if (fragments.empty()){
                cout << "\nKhong tim thay fragment hop le!\n";
                break;
            }

            if (fragments.size() != total){
                cout << "\nThieu fragment!\n";
                cout << "Tim thay: " << fragments.size()
                    << "/" << total << "\n";
                break;
            }

            vector<size_t> order(fragments.size());

            for (size_t i = 0; i < fragments.size(); i++)
                order[i] = i;

            sort(order.begin(), order.end(), [&](size_t a, size_t b){
                return headers[a].index < headers[b].index;
            });

            vector<vector<uint8_t>> sortedFragments;

            for (size_t i : order)
                sortedFragments.push_back(fragments[i]);

            vector<uint8_t> restored = mergeFragments(sortedFragments);
            rpadd(restored);
            filesystem::path sgtPath(path);
            string outputPath = sgtPath.replace_extension("").string();
            writeFile(outputPath, restored);
            cout << "\n================================\n";
            cout << "       RESTORE THANH CONG\n";
            cout << "================================\n";
            cout << "So fragment: " << total << "\n";
            cout << "Output1: " << outputPath << "\n";
            break;
            }     
        case 0:
            cout << "Thoat chuong trinh.\n";
            return 0;
        default:
            cout << "Lua chon khong hop le. Vui long thu lai.\n";
            break;          
        }
    }
    return 0;
} 