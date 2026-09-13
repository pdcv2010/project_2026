#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <cstring>
#include <cstdint>
#include <random>
#include <set>
#include <limits>
#include <iomanip>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <aubio/aubio.h>

namespace fs = std::filesystem;

#pragma pack(push, 1)
struct FileHeader {
    uint32_t index;
    uint32_t total;
    uint64_t sessionId;
    uint64_t payloadSize;
};
#pragma pack(pop)

struct DecryptedFragment {
    FileHeader header;
    std::vector<uint8_t> payload;
    std::string sourcePath;
};

std::vector<uint8_t> generateHash(const std::string& password) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), hash.data());
    return hash;
}

std::string computeSHA256(const std::vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);
    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

uint64_t createsessionId() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    return dis(gen);
}

std::string randomFileName() {
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(alphabet) - 2);

    std::string name;
    for (int i = 0; i < 16; ++i) {
        name += alphabet[dis(gen)];
    }

    static const char extensions[] = "abcdefghijklmnopqrstuvwxyz";
    std::uniform_int_distribution<> extLenDis(3, 5);
    std::uniform_int_distribution<> extDis(0, sizeof(extensions) - 2);

    int extLen = extLenDis(gen);
    std::string extension;
    for (int i = 0; i < extLen; ++i) {
        extension += extensions[extDis(gen)];
    }

    return name + "." + extension;
}

std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return buffer;
    }
    return {};
}

bool writeFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.flush();
    return file.good();
}

std::vector<double> analyzeBeat(const std::string& audioPath) {
    std::vector<double> beats;
    uint_t win_s = 1024;
    uint_t hop_s = 512;
    uint_t samplerate = 44100;

    aubio_source_t* source = new_aubio_source(audioPath.c_str(), samplerate, hop_s);
    if (!source) {
        beats.push_back(0.5);
        beats.push_back(1.0);
        return beats;
    }

    fvec_t* in = new_fvec(hop_s);
    aubio_tempo_t* tempo = new_aubio_tempo("default", win_s, hop_s, samplerate);
    fvec_t* out = new_fvec(2);

    uint_t read = 0;
    uint_t total_frames = 0;
    while (true) {
        aubio_source_do(source, in, &read);
        aubio_tempo_do(tempo, in, out);
        if (out->data[0] != 0) {
            double last_beat = aubio_tempo_get_last_s(tempo);
            beats.push_back(last_beat);
        }
        total_frames += read;
        if (read < hop_s) break;
    }

    del_aubio_tempo(tempo);
    del_aubio_source(source);
    del_fvec(in);
    del_fvec(out);

    if (beats.empty()) beats.push_back(0.5);
    return beats;
}

std::vector<size_t> createFragmentMap(size_t fileSize, const std::vector<double>& beats) {
    std::vector<size_t> sizes;
    if (fileSize == 0) return sizes;

    size_t numFragments = beats.size();
    if (numFragments == 0) numFragments = 4;

    size_t baseSize = fileSize / numFragments;
    size_t remainder = fileSize % numFragments;

    for (size_t i = 0; i < numFragments; ++i) {
        size_t currentSize = baseSize + (i == numFragments - 1 ? remainder : 0);
        if (currentSize > 0) {
            sizes.push_back(currentSize);
        }
    }
    return sizes;
}

std::vector<uint8_t> packf(const FileHeader& header, const std::vector<uint8_t>& payload, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> raw;
    raw.resize(sizeof(FileHeader) + payload.size());
    std::memcpy(raw.data(), &header, sizeof(FileHeader));
    std::memcpy(raw.data() + sizeof(FileHeader), payload.data(), payload.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> encrypted(raw.size() + EVP_MAX_BLOCK_LENGTH + 16);
    
    uint8_t iv[16];
    std::random_device rd;
    for (int i = 0; i < 16; ++i) iv[i] = rd() & 0xFF;

    std::memcpy(encrypted.data(), iv, 16);

    int len = 0, ciphertext_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv);
    EVP_EncryptUpdate(ctx, encrypted.data() + 16, &len, raw.data(), raw.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, encrypted.data() + 16 + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    encrypted.resize(16 + ciphertext_len);

    uint8_t hmacVal[32];
    unsigned int hmacLen = 32;
    HMAC(EVP_sha256(), key.data(), key.size(), encrypted.data(), encrypted.size(), hmacVal, &hmacLen);

    std::vector<uint8_t> sgtData(32 + encrypted.size());
    std::memcpy(sgtData.data(), hmacVal, 32);
    std::memcpy(sgtData.data() + 32, encrypted.data(), encrypted.size());

    return sgtData;
}

bool unpackf(const std::vector<uint8_t>& sgtData, const std::vector<uint8_t>& key, DecryptedFragment& outFragment) {
    if (sgtData.size() < 32 + 16 + sizeof(FileHeader)) return false;

    const uint8_t* expectedHmac = sgtData.data();
    const uint8_t* encryptedData = sgtData.data() + 32;
    size_t encryptedLen = sgtData.size() - 32;

    uint8_t calculatedHmac[32];
    unsigned int hmacLen = 32;
    HMAC(EVP_sha256(), key.data(), key.size(), encryptedData, encryptedLen, calculatedHmac, &hmacLen);

    if (std::memcmp(expectedHmac, calculatedHmac, 32) != 0) {
        return false;
    }

    const uint8_t* iv = encryptedData;
    const uint8_t* ciphertext = encryptedData + 16;
    size_t ciphertextLen = encryptedLen - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> decrypted(ciphertextLen + EVP_MAX_BLOCK_LENGTH);
    int len = 0, plaintext_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv);
    EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext, ciphertextLen);
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    decrypted.resize(plaintext_len);

    if (decrypted.size() < sizeof(FileHeader)) return false;

    std::memcpy(&outFragment.header, decrypted.data(), sizeof(FileHeader));
    outFragment.payload.assign(decrypted.begin() + sizeof(FileHeader), decrypted.end());

    return true;
}

bool executeProtectFlow(const std::string& inputPath, const std::string& audioPath, const std::string& outputDir, const std::string& password) {
    if (!fs::exists(inputPath)) {
        std::cerr << "{\"status\":\"error\",\"message\":\"File input khong ton tai\"}\n";
        return false;
    }

    if (!fs::exists(outputDir)) {
        fs::create_directories(outputDir);
    }

    std::vector<uint8_t> rawData = readFile(inputPath);
    if (rawData.empty()) {
        std::cerr << "{\"status\":\"error\",\"message\":\"File input rong hoac khong the doc\"}\n";
        return false;
    }

    std::string originalHash = computeSHA256(rawData);

    std::vector<uint8_t> key = generateHash(password);
    std::vector<double> beats = analyzeBeat(audioPath);
    std::vector<size_t> fragSizes = createFragmentMap(rawData.size(), beats);

    uint64_t sessionId = createsessionId();
    uint32_t totalFrags = static_cast<uint32_t>(fragSizes.size());

    size_t offset = 0;
    std::vector<std::vector<uint8_t>> packedFiles;

    for (uint32_t i = 0; i < totalFrags; ++i) {
        size_t currentSize = fragSizes[i];
        std::vector<uint8_t> payload(rawData.begin() + offset, rawData.begin() + offset + currentSize);
        offset += currentSize;

        FileHeader header;
        header.index = i;
        header.total = totalFrags;
        header.sessionId = sessionId;
        header.payloadSize = payload.size();

        std::vector<uint8_t> sgtBlock = packf(header, payload, key);
        packedFiles.push_back(sgtBlock);
    }

    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(packedFiles.begin(), packedFiles.end(), g);

    for (const auto& block : packedFiles) {
        std::string outPath = (fs::path(outputDir) / randomFileName()).string();
        if (!writeFile(outPath, block)) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Khong the ghi fragment .sgt\"}\n";
            return false;
        }
    }

    std::cout << "{\"status\":\"success\",\"mode\":\"protect\",\"outputDir\":\"" << outputDir << "\",\"sha256\":\"" << originalHash << "\"}\n";
    return true;
}

bool executeRestoreFlow(const std::string& inputDir, const std::string& outputFile, const std::string& password) {
    if (!fs::exists(inputDir) || !fs::is_directory(inputDir)) {
        std::cerr << "{\"status\":\"error\",\"message\":\"Thu muc .sgt khong ton tai\"}\n";
        return false;
    }

    std::vector<uint8_t> key = generateHash(password);
    std::vector<DecryptedFragment> decryptedList;

    for (const auto& entry : fs::directory_iterator(inputDir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".sgt") {
            std::vector<uint8_t> sgtData = readFile(entry.path().string());
            DecryptedFragment frag;
            frag.sourcePath = entry.path().string();

            if (!unpackf(sgtData, key, frag)) {
                std::cerr << "{\"status\":\"error\",\"message\":\"Xac thuc HMAC hoac Giai ma AES that bai. Mat khau sai hoac file .sgt bi loi/chinh sua.\"}\n";
                return false;
            }

            if (frag.header.total == 0) {
                std::cerr << "{\"status\":\"error\",\"message\":\"Header payload bi loi: total phai lon hon 0\"}\n";
                return false;
            }
            if (frag.header.index >= frag.header.total) {
                std::cerr << "{\"status\":\"error\",\"message\":\"Header index khong hop le\"}\n";
                return false;
            }
            if (frag.header.payloadSize != static_cast<uint64_t>(frag.payload.size())) {
                std::cerr << "{\"status\":\"error\",\"message\":\"Size payload giai ma khong khop voi header payloadSize\"}\n";
                return false;
            }

            decryptedList.push_back(frag);
        }
    }

    if (decryptedList.empty()) {
        std::cerr << "{\"status\":\"error\",\"message\":\"Khong tim thay file .sgt nao trong thu muc\"}\n";
        return false;
    }

    uint64_t expectedSessionId = decryptedList[0].header.sessionId;
    uint32_t expectedTotal = decryptedList[0].header.total;

    if (decryptedList.size() != expectedTotal) {
        std::cerr << "{\"status\":\"error\",\"message\":\"So luong fragment khong du. Yeu cau: " 
                  << expectedTotal << ", Thuc te: " << decryptedList.size() << "\"}\n";
        return false;
    }

    std::vector<bool> indexCheck(expectedTotal, false);
    uint64_t totalPayloadSize = 0;

    for (const auto& frag : decryptedList) {
        if (frag.header.sessionId != expectedSessionId) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Phat hien fragment khong cung Session ID\"}\n";
            return false;
        }
        if (frag.header.total != expectedTotal) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Phat hien gia tri Total khong nhat quan\"}\n";
            return false;
        }
        if (frag.header.index >= expectedTotal) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Index vuot qua pham vi Total\"}\n";
            return false;
        }
        if (indexCheck[frag.header.index]) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Phat hien fragment trung Index: " << frag.header.index << "\"}\n";
            return false;
        }
        indexCheck[frag.header.index] = true;

        if (totalPayloadSize > std::numeric_limits<uint64_t>::max() - frag.header.payloadSize) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Phat hien tran bo nho (overflow) khi tinh tong dung luong file\"}\n";
            return false;
        }
        totalPayloadSize += frag.header.payloadSize;
    }

    for (uint32_t i = 0; i < expectedTotal; ++i) {
        if (!indexCheck[i]) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Thieu fragment tai index: " << i << "\"}\n";
            return false;
        }
    }

    std::sort(decryptedList.begin(), decryptedList.end(), [](const DecryptedFragment& a, const DecryptedFragment& b) {
        return a.header.index < b.header.index;
    });

    std::vector<uint8_t> finalFileBytes;
    finalFileBytes.reserve(totalPayloadSize);
    for (const auto& frag : decryptedList) {
        finalFileBytes.insert(finalFileBytes.end(), frag.payload.begin(), frag.payload.end());
    }

    if (!writeFile(outputFile, finalFileBytes)) {
        std::cerr << "{\"status\":\"error\",\"message\":\"Khong the ghi file khoi phuc\"}\n";
        return false;
    }

    std::string restoredHash = computeSHA256(finalFileBytes);
    std::cout << "{\"status\":\"success\",\"mode\":\"restore\",\"outputFile\":\"" << outputFile << "\",\"sha256\":\"" << restoredHash << "\"}\n";
    return true;
}

int main(int argc, char* argv[]) {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    if (argc < 2) {
        std::cerr << "{\"status\":\"error\",\"message\":\"Thieu che do thuc thi (protect hoac restore)\"}\n";
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "protect") {
        if (argc < 5) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Cu phap: ./sentinelgate protect <input> <audio> <output_dir>\"}\n";
            return 1;
        }

        std::string inputPath = argv[2];
        std::string audioPath = argv[3];
        std::string outputDir = argv[4];

        std::string password;
        if (!std::getline(std::cin, password) || password.empty()) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Khong nhan duoc password tu STDIN\"}\n";
            return 1;
        }

        if (executeProtectFlow(inputPath, audioPath, outputDir, password)) {
            return 0;
        } else {
            return 1;
        }

    } else if (mode == "restore") {
        if (argc < 4) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Cu phap: ./sentinelgate restore <fragment_dir> <output_file>\"}\n";
            return 1;
        }

        std::string inputDir = argv[2];
        std::string outputFile = argv[3];

        std::string password;
        if (!std::getline(std::cin, password) || password.empty()) {
            std::cerr << "{\"status\":\"error\",\"message\":\"Khong nhan duoc password tu STDIN\"}\n";
            return 1;
        }

        if (executeRestoreFlow(inputDir, outputFile, password)) {
            return 0;
        } else {
            return 1;
        }

    } else {
        std::cerr << "{\"status\":\"error\",\"message\":\"Che do khong hop le: " << mode << "\"}\n";
        return 1;
    }

    return 0;
}
