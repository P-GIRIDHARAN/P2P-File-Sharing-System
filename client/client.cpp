#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <sys/stat.h>
#include <map>
#include <iomanip>
#include <algorithm>
#include <memory>
#include <climits>
#include <openssl/sha.h>
using namespace std;
string bytes_to_hex(const unsigned char* bytes, size_t len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < len; ++i) { 
        ss << setw(2) << (int)bytes[i];
    }
    return ss.str();
}
string calculateSHA1(const char* data, size_t len) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)data, len, hash);
    return bytes_to_hex(hash, SHA_DIGEST_LENGTH);
}
string calculateFileSHA1(const string& filePath) {
    ifstream file(filePath, ios::binary);
    if (!file) return ""; 
    SHA_CTX shaContext;
    SHA1_Init(&shaContext);
    vector<char> buffer(512 * 1024); 
    while (file.read(buffer.data(), buffer.size())) {
        SHA1_Update(&shaContext, buffer.data(), file.gcount());
    }
    SHA1_Update(&shaContext, buffer.data(), file.gcount()); 
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &shaContext);
    return bytes_to_hex(hash, SHA_DIGEST_LENGTH);
}
const size_t PIECE_SIZE = 512 * 1024;
map<string, string> localSharedFiles;

struct ActiveDownload {
    string fileName;
    string groupId;
    string destinationPath;
    long long fileSize;
    int totalPieces;
    int completedPieces;
    string status;
    chrono::steady_clock::time_point startTime;
    
    ActiveDownload() : fileSize(0), totalPieces(0), completedPieces(0), status(""), 
                       startTime(chrono::steady_clock::now()) {}
    
    ActiveDownload(const string& name, const string& group, const string& dest, 
                   long long size, int pieces) 
        : fileName(name), groupId(group), destinationPath(dest), fileSize(size), 
          totalPieces(pieces), completedPieces(0), status("downloading"),
          startTime(chrono::steady_clock::now()) {}
};

map<string, ActiveDownload> activeDownloads;
mutex downloadMutex; 
struct DownloadContext {
    string fileName;
    string destinationPath;
    long long fileSize;
    string fullFileHash;
    vector<string> pieceHashes;
    map<int, bool> pieceStatus; 
    vector<string> peerAddresses; 
    map<int, vector<char>> pieceBuffers;
    ofstream outputFile;
    mutex mtx;
    map<int, int> pieceRetryCount;
    map<int, chrono::steady_clock::time_point> pieceLastAttempt;
    int maxRetries = 5;
    chrono::seconds retryDelay = chrono::seconds(2);
    atomic<bool> downloadCancelled{false};
    DownloadContext(const string& name, const string& dest, long long size, const string& fullHash, const vector<string>& hashes)
        : fileName(name), destinationPath(dest), fileSize(size), fullFileHash(fullHash), pieceHashes(hashes) 
    {
        for (size_t i = 0; i < pieceHashes.size(); ++i) { 
            pieceStatus[i] = false;
        }
        outputFile.open(destinationPath, ios::binary | ios::trunc);
    }
    ~DownloadContext() {
        if (outputFile.is_open()) {
            outputFile.close();
        }
    }
    int findNextPiece() {
        lock_guard<mutex> lock(mtx);
        for (auto const& [index, status] : pieceStatus) {
            if (!status) {
                return index;
            }
        }
        return -1;
    }
    bool claimPiece(int index) {
        lock_guard<mutex> lock(mtx);
        if (pieceStatus.count(index) && !pieceStatus[index]) {
            pieceStatus[index] = true;
            return true;
        }
        return false;
    }
    void unclaimPiece(int index) {
        lock_guard<mutex> lock(mtx);
        pieceStatus[index] = false;
    }
    void writePiece(int index, const vector<char>& data) {
        lock_guard<mutex> lock(mtx);
        if (outputFile.is_open()) {
            size_t pieceOffset = index * PIECE_SIZE;
            outputFile.seekp(pieceOffset);
            outputFile.write(data.data(), data.size());
            outputFile.flush();
        }
        pieceBuffers[index] = data;
        pieceStatus[index] = true;
    }
    bool isComplete() {
        lock_guard<mutex> lock(mtx);
        for (const auto& [index, status] : pieceStatus) {
            if (!status) return false;
        }
        return true;
    }
    void finalizeDownload() {
        if (outputFile.is_open()) {
            outputFile.close();
        }
    }
    bool shouldRetryPiece(int index) {
        lock_guard<mutex> lock(mtx);
        if (pieceRetryCount[index] >= maxRetries) return false;
        auto now = chrono::steady_clock::now();
        auto lastAttempt = pieceLastAttempt[index];
        return (now - lastAttempt) >= retryDelay;
    }
    void recordPieceAttempt(int index) {
        lock_guard<mutex> lock(mtx);
        pieceRetryCount[index]++;
        pieceLastAttempt[index] = chrono::steady_clock::now();
    }
    void resetPieceRetry(int index) {
        lock_guard<mutex> lock(mtx);
        pieceRetryCount[index] = 0;
    }
    vector<string> getAvailablePeers() {
        lock_guard<mutex> lock(mtx);
        return peerAddresses;
    }
    void addPeer(const string& peerAddr) {
        lock_guard<mutex> lock(mtx);
        if (find(peerAddresses.begin(), peerAddresses.end(), peerAddr) == peerAddresses.end()) {
            peerAddresses.push_back(peerAddr);
        }
    }
    void removePeer(const string& peerAddr) {
        lock_guard<mutex> lock(mtx);
        peerAddresses.erase(remove(peerAddresses.begin(), peerAddresses.end(), peerAddr), peerAddresses.end());
    }
    void cancelDownload() {
        downloadCancelled = true;
    }
    bool isCancelled() {
        return downloadCancelled.load();
    }
};
bool p2p_sendMessage(int sock, const string &msg) {
    string data = msg + "\n";
    if (send(sock, data.c_str(), data.size(), 0) <= 0) return false;
    return true;
}
void sendFilePiece(int peerSock, const string& filePath, size_t offset, size_t size) {
    ifstream file(filePath, ios::binary);
    if (!file) return;
    file.seekg(offset, ios::beg);
    vector<char> buffer(size);
    file.read(buffer.data(), size);
    send(peerSock, buffer.data(), file.gcount(), 0);
}
void handle_peer_p2p_connection(int peerSock) {
    string msg;
    char buf[1024];
    ssize_t len = recv(peerSock, buf, sizeof(buf) - 1, 0);
    if (len > 0) {
        buf[len] = '\0';
        msg = buf;
        cout << "\n[P2P DEBUG] Received request: " << msg << endl; 
        stringstream ss(msg);
        string cmd, fileName;
        int pieceIndex;
        ss >> cmd >> fileName >> pieceIndex;
        if (cmd == "GET_PIECE") {
            if (localSharedFiles.count(fileName)) {
                string filePath = localSharedFiles[fileName];
                struct stat fileStat;
                if (stat(filePath.c_str(), &fileStat) != 0) {
                     close(peerSock);
                     return;
                }
                size_t pieceOffset = pieceIndex * PIECE_SIZE;
                size_t expectedSize = min(PIECE_SIZE, (size_t)((long long)fileStat.st_size - pieceOffset)); 
                if (pieceOffset < (size_t)fileStat.st_size) { 
                    sendFilePiece(peerSock, filePath, pieceOffset, expectedSize);
                }
            }
        }
    }
    close(peerSock);
}
void start_p2p_listener(int p2pPort) {
    int listenerSock = socket(AF_INET, SOCK_STREAM, 0);
    if (listenerSock < 0) { cerr << "P2P Listener Socket Error." << endl; return; }
    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(p2pPort);
    serv.sin_addr.s_addr = INADDR_ANY;
    int opt = 1;
    setsockopt(listenerSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(listenerSock, (sockaddr*)&serv, sizeof(serv)) < 0) { cerr << "P2P Bind Error. Check if port is in use." << endl; return; }
    if (listen(listenerSock, 5) < 0) { cerr << "P2P Listen Error." << endl; return; }
    cout << "[P2P] Sharing files on port " << p2pPort << endl;
    while (true) {
        sockaddr_in cli{};
        socklen_t clen = sizeof(cli);
        int peerSock = accept(listenerSock, (sockaddr*)&cli, &clen);
        if (peerSock < 0) continue;
        thread(handle_peer_p2p_connection, peerSock).detach();
    }
    close(listenerSock);
}
void handle_piece_download(DownloadContext* ctxPtr, const string& peerAddr) { 
    DownloadContext& ctx = *ctxPtr;
    size_t colon = peerAddr.find(':');
    if (colon == string::npos) return;
    string ip = peerAddr.substr(0, colon);
    int port;
    try {
        port = stoi(peerAddr.substr(colon + 1));
    } catch (...) {
        return;
    }
    int peerSock = -1;
    bool connectionFailed = false;
    while (!ctx.isCancelled()) {
        int pieceIndex = ctx.findNextPiece();
        if (pieceIndex == -1) break;
        if (!ctx.shouldRetryPiece(pieceIndex)) {
            this_thread::sleep_for(chrono::milliseconds(100));
            continue;
        }
        if (!ctx.claimPiece(pieceIndex)) {
            continue;
        }
        ctx.recordPieceAttempt(pieceIndex);
        if (peerSock < 0 || connectionFailed) {
            if (peerSock >= 0) {
                close(peerSock);
                peerSock = -1;
            }
            peerSock = socket(AF_INET, SOCK_STREAM, 0);
            if (peerSock < 0) { 
                ctx.unclaimPiece(pieceIndex); 
                ctx.removePeer(peerAddr);
                return; 
            }
            struct timeval timeout;
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;
            setsockopt(peerSock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(peerSock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
            if (connect(peerSock, (sockaddr*)&addr, sizeof(addr)) != 0) {
                ctx.unclaimPiece(pieceIndex); 
                close(peerSock);
                peerSock = -1;
                connectionFailed = true;
                ctx.removePeer(peerAddr);
                continue;
            }
            connectionFailed = false;
        }
        string request = "GET_PIECE " + ctx.fileName + " " + to_string(pieceIndex);
        if (!p2p_sendMessage(peerSock, request)) {
            ctx.unclaimPiece(pieceIndex); 
            close(peerSock);
            peerSock = -1;
            connectionFailed = true;
            ctx.removePeer(peerAddr);
            continue;
        }
        size_t pieceOffset = pieceIndex * PIECE_SIZE;
        size_t expectedSize = min(PIECE_SIZE, (size_t)(ctx.fileSize - pieceOffset)); 
        vector<char> buffer(expectedSize);
        size_t received = 0;
        bool piece_failed = false;
        auto startTime = chrono::steady_clock::now();
        while (received < expectedSize && !ctx.isCancelled()) {
            ssize_t len = recv(peerSock, buffer.data() + received, expectedSize - received, 0);
            if (len <= 0) {
                auto elapsed = chrono::steady_clock::now() - startTime;
                if (elapsed > chrono::seconds(30)) {
                    cerr << "\n[Download] Piece " << pieceIndex << " timeout from " << peerAddr << endl;
                } else {
                    cerr << "\n[Download] Piece " << pieceIndex << " connection lost from " << peerAddr << endl;
                }
                ctx.unclaimPiece(pieceIndex); 
                close(peerSock);
                peerSock = -1;
                connectionFailed = true;
                ctx.removePeer(peerAddr);
                piece_failed = true; 
                break; 
            }
            received += len;
        }
        if (piece_failed || ctx.isCancelled()) continue; 
        string receivedHash = calculateSHA1(buffer.data(), received);
        if (receivedHash == ctx.pieceHashes[pieceIndex]) {
            ctx.writePiece(pieceIndex, buffer);
            ctx.resetPieceRetry(pieceIndex);
            int completedPieces = 0;
            for (const auto& [idx, status] : ctx.pieceStatus) {
                if (status) completedPieces++;
            }
            cout << "\r[Download] Progress: " << completedPieces << "/" << ctx.pieceHashes.size() 
                 << " pieces verified from " << peerAddr << "..." << flush;
        } else {
            ctx.unclaimPiece(pieceIndex); 
            cerr << "\n[Download] Piece " << pieceIndex << " hash mismatch. Retrying..." << endl;
        }
    }
    if (peerSock >= 0) close(peerSock);
}
void start_download_worker(DownloadContext* ctxPtr) { 
    unique_ptr<DownloadContext> ctx(ctxPtr); 
    if (ctx->fileSize == 0) {
        cout << "\nFile is empty. Successfully created 0-byte file at: " << ctx->destinationPath << endl;
        ofstream outFile(ctx->destinationPath, ios::binary);
        return;
    }
    cout << "\n[Download] Starting download with " << ctx->peerAddresses.size() << " initial peers..." << endl;
    vector<thread> downloadThreads;
    for (const string& peerAddr : ctx->peerAddresses) {
        downloadThreads.emplace_back(handle_piece_download, ctx.get(), peerAddr); 
    }
    auto startTime = chrono::steady_clock::now();
    auto lastProgressTime = startTime;
    int lastCompletedPieces = 0;
    while (!ctx->isComplete() && !ctx->isCancelled()) {
        this_thread::sleep_for(chrono::seconds(5));
        auto now = chrono::steady_clock::now();
        int currentCompletedPieces = 0;
        for (const auto& [idx, status] : ctx->pieceStatus) {
            if (status) currentCompletedPieces++;
        }
        
        {
            lock_guard<mutex> lock(downloadMutex);
            if (activeDownloads.count(ctx->fileName)) {
                activeDownloads[ctx->fileName].completedPieces = currentCompletedPieces;
            }
        }
        
        if (currentCompletedPieces == lastCompletedPieces) {
            auto stalledTime = now - lastProgressTime;
            if (stalledTime > chrono::minutes(2)) {
                cout << "\n[Download] Download appears stalled. Attempting to discover new peers..." << endl;
                lastProgressTime = now;
            }
        } else {
            lastCompletedPieces = currentCompletedPieces;
            lastProgressTime = now;
        }
        if (now - startTime > chrono::minutes(30)) {
            cout << "\n[Download] Download timeout reached. Cancelling..." << endl;
            ctx->cancelDownload();
            break;
        }
    }
    for (auto& t : downloadThreads) {
        if (t.joinable()) t.join();
    }
    ctx->finalizeDownload();
    
    {
        lock_guard<mutex> lock(downloadMutex);
        if (activeDownloads.count(ctx->fileName)) {
            if (ctx->isComplete()) {
                activeDownloads[ctx->fileName].status = "completed";
            } else {
                activeDownloads[ctx->fileName].status = "failed";
            }
        }
    }
    
    if (ctx->isComplete()) {
        string finalHash = calculateFileSHA1(ctx->destinationPath);
        if (finalHash == ctx->fullFileHash) {
            cout << "\nDownload SUCCESS: File successfully downloaded and verified to: " << ctx->destinationPath << endl;
        } else {
            cerr << "\nDownload FAILED: Final file hash verification failed (Integrity compromised)." << endl;
            {
                lock_guard<mutex> lock(downloadMutex);
                if (activeDownloads.count(ctx->fileName)) {
                    activeDownloads[ctx->fileName].status = "failed";
                }
            }
        }
    } else {
        int completedPieces = 0;
        for (const auto& [idx, status] : ctx->pieceStatus) {
            if (status) completedPieces++;
        }
        cout << "\nDownload FAILED: Could not download all pieces. Missing " << (ctx->pieceHashes.size() - completedPieces) << " pieces." << endl;
    }
}
int trackerSock = -1;
class TrackerConnectionManager {
private:
    vector<pair<string, int>> trackers;
    int currentTrackerIndex;
    int sock;
    string clientP2PInfo;
    mutable mutex connectionMtx;
    bool connected;
public:
    TrackerConnectionManager(const vector<pair<string, int>>& trackerList, const string& p2pInfo) 
        : trackers(trackerList), currentTrackerIndex(0), sock(-1), clientP2PInfo(p2pInfo), 
          connected(false) {}
    ~TrackerConnectionManager() {
        disconnect();
    }
    bool connect() {
        lock_guard<mutex> lock(connectionMtx);
        if (connected) return true;
        int bestTrackerIndex = -1;
        int minLoad = INT_MAX;
        for (size_t i = 0; i < trackers.size(); i++) {
            auto& tracker = trackers[i];
            int tempSock = socket(AF_INET, SOCK_STREAM, 0);
            if (tempSock < 0) continue;
            sockaddr_in serv{};
            serv.sin_family = AF_INET;
            serv.sin_port = htons(tracker.second);
            inet_pton(AF_INET, tracker.first.c_str(), &serv.sin_addr);
            if (::connect(tempSock, (sockaddr*)&serv, sizeof(serv)) == 0) {
                string loadQuery = "GET_LOAD\n";
                send(tempSock, loadQuery.c_str(), loadQuery.length(), 0);
                char buffer[1024];
                ssize_t len = recv(tempSock, buffer, sizeof(buffer) - 1, 0);
                if (len > 0) {
                    buffer[len] = '\0';
                    string response(buffer);
                    if (response.find("LOAD ") == 0) {
                        int load = stoi(response.substr(5));
                        if (load < minLoad) {
                            minLoad = load;
                            bestTrackerIndex = i;
                        }
                    }
                }
                close(tempSock);
            }
        }
        if (bestTrackerIndex >= 0) {
            auto& tracker = trackers[bestTrackerIndex];
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock >= 0) {
                sockaddr_in serv{};
                serv.sin_family = AF_INET;
                serv.sin_port = htons(tracker.second);
                inet_pton(AF_INET, tracker.first.c_str(), &serv.sin_addr);
                if (::connect(sock, (sockaddr*)&serv, sizeof(serv)) == 0) {
                    cout << "Connected to tracker at " << tracker.first << ":" << tracker.second 
                         << " (load: " << minLoad << " clients)" << endl;
                    currentTrackerIndex = bestTrackerIndex;
                    connected = true;
                    trackerSock = sock;
                    return true;
                }
                close(sock);
                sock = -1;
            }
        }
        for (size_t i = 0; i < trackers.size(); i++) {
            int index = (currentTrackerIndex + i) % trackers.size();
            auto& tracker = trackers[index];
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;
            sockaddr_in serv{};
            serv.sin_family = AF_INET;
            serv.sin_port = htons(tracker.second);
            inet_pton(AF_INET, tracker.first.c_str(), &serv.sin_addr);
            if (::connect(sock, (sockaddr*)&serv, sizeof(serv)) == 0) {
                cout << "Connected to tracker at " << tracker.first << ":" << tracker.second << endl;
                currentTrackerIndex = index;
                connected = true;
                trackerSock = sock;
                return true;
            }
            close(sock);
            sock = -1;
        }
        return false;
    }
    void disconnect() {
        lock_guard<mutex> lock(connectionMtx);
        if (sock >= 0) {
            close(sock);
            sock = -1;
        }
        connected = false;
    }
    bool reconnect() {
        disconnect();
        this_thread::sleep_for(chrono::seconds(1));
        return connect();
    }
    bool isConnected() const {
        lock_guard<mutex> lock(connectionMtx);
        return connected;
    }
    int getSocket() const {
        lock_guard<mutex> lock(connectionMtx);
        return sock;
    }
    bool sendMessage(const string& message) {
        if (!isConnected()) {
            cout << "[CONNECTION] Not connected to tracker, attempting reconnection..." << endl;
            if (!reconnect()) {
                cout << "[CONNECTION] Failed to reconnect to any tracker." << endl;
                return false;
            }
        }
        string msg = message + "\n";
        ssize_t total = 0;
        while (total < (ssize_t)msg.length()) {
            ssize_t sent = send(sock, msg.c_str() + total, msg.length() - total, 0);
            if (sent <= 0) {
                connected = false;
                cout << "[CONNECTION] Send failed, attempting reconnection..." << endl;
                if (!reconnect()) {
                    cout << "[CONNECTION] Failed to reconnect to any tracker." << endl;
                    return false;
                }
                total = 0;
                continue;
            }
            total += sent;
        }
        return true;
    }
    bool recvMessage(string& message) {
        if (!isConnected()) {
            cout << "[CONNECTION] Not connected to tracker, attempting reconnection..." << endl;
            if (!reconnect()) {
                cout << "[CONNECTION] Failed to reconnect to any tracker." << endl;
                return false;
            }
        }
        char buffer[1024];
        ssize_t len = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (len <= 0) {
            connected = false;
            cout << "[CONNECTION] Receive failed, attempting reconnection..." << endl;
            if (!reconnect()) {
                cout << "[CONNECTION] Failed to reconnect to any tracker." << endl;
                return false;
            }
            return false;
        }
        buffer[len] = '\0';
        message = string(buffer);
        return true;
    }
};
TrackerConnectionManager* connectionManager = nullptr;
mutex socketMutex;
bool sendMessageWithReconnect(const string& message) {
    if (!connectionManager) return false;
    if (!connectionManager->sendMessage(message)) {
        cout << "[CONNECTION] Sending failed, attempting reconnection..." << endl;
        if (connectionManager->reconnect()) {
            cout << "[CONNECTION] Reconnected successfully" << endl;
            return connectionManager->sendMessage(message);
        } else {
            cout << "[CONNECTION] Failed to reconnect to any tracker." << endl;
            return false;
        }
    }
    return true;
}
bool recvMessageWithReconnect(string& message) {
    if (!connectionManager) return false;
    if (!connectionManager->recvMessage(message)) {
        cout << "[CONNECTION] Receiving failed, attempting reconnection..." << endl;
        if (connectionManager->reconnect()) {
            cout << "[CONNECTION] Reconnected successfully" << endl;
            return connectionManager->recvMessage(message);
        } else {
            cout << "[CONNECTION] Failed to reconnect to any tracker." << endl;
            return false;
        }
    }
    return true;
}
bool sendMessage(int sock, const string &msg) {
    if (connectionManager) {
        return connectionManager->sendMessage(msg);
    }
    string data = msg + "\n";
    size_t total = 0;
    while (total < data.size()) {
        ssize_t sent = send(sock, data.c_str() + total, data.size() - total, 0);
        if (sent <= 0) return false;
        total += sent;
    }
    return true;
}
bool recvMessage(int sock, string &out) {
    if (connectionManager) {
        return connectionManager->recvMessage(out);
    }
    out.clear();
    char buf[1024];
    ssize_t len = recv(sock, buf, sizeof(buf) - 1, 0);
    if (len <= 0) return false;
    buf[len] = '\0';
    out = buf;
    return true;
}
void listenTracker() {
    string resp;
    while (recvMessageWithReconnect(resp)) {
        lock_guard<mutex> lock(socketMutex);
        if (!resp.empty()) {
            cout << "[TRACKER]: " << resp << endl;
        }
    }
    lock_guard<mutex> lock(socketMutex);
    cerr << "Disconnected from tracker." << endl;
    exit(1);
}
vector<pair<string,int>> readTrackerInfo(const string &filename) {
    vector<pair<string,int>> trackers;
    ifstream fin(filename);
    string line;
    while (getline(fin, line)) {
        if (line.empty()) continue;
        size_t colon = line.find(':');
        if (colon == string::npos) continue;
        try {
            string ip = line.substr(0, colon);
            int port = stoi(line.substr(colon + 1));
            trackers.push_back({ip, port});
        } catch (...) {
            cerr << "Warning: Invalid tracker info line: " << line << endl;
        }
    }
    return trackers;
}
bool connectToAvailableTracker(const vector<pair<string,int>> &trackers) {
    for (auto &t : trackers) {
        trackerSock = socket(AF_INET, SOCK_STREAM, 0);
        if (trackerSock < 0) continue;
        sockaddr_in serv{};
        serv.sin_family = AF_INET;
        serv.sin_port = htons(t.second);
        inet_pton(AF_INET, t.first.c_str(), &serv.sin_addr);
        if (connect(trackerSock, (sockaddr*)&serv, sizeof(serv)) == 0) {
            cout << "Connected to tracker at " << t.first << ":" << t.second << endl;
            return true;
        }
        close(trackerSock);
    }
    return false;
}
int main(int argc, char *argv[])
{
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <client_ip:port> tracker_info.txt" << endl;
        return 1;
    }
    string clientP2PInfo = argv[1]; 
    string trackerInfoFile = argv[2];
    vector<pair<string,int>> trackers = readTrackerInfo(trackerInfoFile);
    if (trackers.empty()) {
        cerr << "No trackers found in " << trackerInfoFile << endl;
        return 1;
    }
    size_t colon = clientP2PInfo.find(':');
    if (colon == string::npos) {
        cerr << "Invalid client P2P info format: <ip:port>" << endl;
        return 1;
    }
    int p2pPort = stoi(clientP2PInfo.substr(colon + 1));
    connectionManager = new TrackerConnectionManager(trackers, clientP2PInfo);
    int retryCount = 0;
    const int maxRetries = 5;
    while (!connectionManager->connect()) {
        retryCount++;
        if (retryCount >= maxRetries) {
            cout << "[CLIENT] Failed to connect to any tracker after " << maxRetries << " attempts. Exiting." << endl;
            delete connectionManager;
            return 1;
        }
        cout << "[CLIENT] No tracker available, retrying in 2 seconds... (attempt " << retryCount << "/" << maxRetries << ")" << endl;
        this_thread::sleep_for(chrono::seconds(2));
    }
    thread p2pListener(start_p2p_listener, p2pPort); 
    thread trackerListener(listenTracker);
    string line;
    while (true)
    {
        cout << "> ";
        if (!getline(cin, line)) break;
        if (line.empty()) continue;
        stringstream ss(line);
        vector<string> tokens;
        string tok;
        while (ss >> tok) tokens.push_back(tok);
        if (tokens.empty()) continue;
        string cmd = tokens[0];
        if (cmd == "create_user" && tokens.size() == 3){
            if (!sendMessageWithReconnect("CREATE_USER " + tokens[1] + " " + tokens[2])) {
                cout << "Failed to send command. Please try again." << endl;
                continue;
            }
        }
        else if (cmd == "login" && tokens.size() == 3){
            if (!sendMessageWithReconnect("LOGIN " + tokens[1] + " " + tokens[2] + " " + clientP2PInfo)) {
                cout << "Failed to send command. Please try again." << endl;
                continue;
            }
        }
        else if (cmd == "create_group" && tokens.size() == 2){
            sendMessageWithReconnect("CREATE_GROUP " + tokens[1]);
        }
        else if (cmd == "join_group" && tokens.size() == 2){
            sendMessageWithReconnect("JOIN_GROUP " + tokens[1]);
        }
        else if (cmd == "leave_group" && tokens.size() == 2){
            sendMessageWithReconnect("LEAVE_GROUP " + tokens[1]);
        }
        else if (cmd == "list_groups" && tokens.size() == 1){
            sendMessageWithReconnect("LIST_GROUPS");
        }
        else if (cmd == "list_requests" && tokens.size() == 2){
            sendMessageWithReconnect("LIST_REQUESTS " + tokens[1]);
        }
        else if (cmd == "accept_request" && tokens.size() == 3){
            sendMessageWithReconnect("ACCEPT_REQUEST " + tokens[1] + " " + tokens[2]);
        }
        else if (cmd == "upload_file" && tokens.size() == 3){
            string groupId = tokens[1];
            string filePath = tokens[2];
            struct stat fileStat;
            if (stat(filePath.c_str(), &fileStat) != 0) {
                cout << "Error: File not found or cannot be accessed." << endl;
                continue;
            }
            long long fileSize = fileStat.st_size;
            string fileName = filePath.substr(filePath.find_last_of('/') + 1);
            string fullFileHash = calculateFileSHA1(filePath);
            if (fullFileHash.empty()) {
                cout << "Error: Failed to calculate full file hash. Check file path or libcrypto linking." << endl;
                continue;
            }
            vector<string> pieceHashes;
            ifstream file(filePath, ios::binary);
            if (!file) {
                cout << "Error: Could not open file for piece hashing." << endl;
                continue;
            }
            const size_t PIECE_SIZE = 512 * 1024; 
            vector<char> buffer(PIECE_SIZE);
            while (!file.eof()) {
                file.read(buffer.data(), PIECE_SIZE);
                size_t bytesRead = file.gcount();
                if (bytesRead > 0) {
                    string hash = calculateSHA1(buffer.data(), bytesRead);
                    pieceHashes.push_back(hash);
                }
            }
            file.close();
            stringstream command;
            command << "UPLOAD_FILE " << groupId << " " << fileName << " " << fileSize << " " 
                    << fullFileHash << " " << pieceHashes.size() << " " << clientP2PInfo;
            for (const string& hash : pieceHashes) {
                command << " " << hash;
            }
            localSharedFiles[fileName] = filePath; 
            sendMessageWithReconnect(command.str());
        }
        else if (cmd == "list_files" && tokens.size() == 2){
            sendMessageWithReconnect("LIST_FILES " + tokens[1]);
        }
        else if (cmd == "download_file" && tokens.size() == 4){
            string groupId = tokens[1];
            string fileName = tokens[2];
            string destinationPath = tokens[3];
            sendMessageWithReconnect("DOWNLOAD_FILE " + groupId + " " + fileName);
            string metaResp;
            if (!recvMessageWithReconnect(metaResp)) {
                cerr << "Error: Tracker disconnected while waiting for file metadata." << endl;
                continue;
            }
            stringstream ss(metaResp);
            string respCmd;
            ss >> respCmd;
            if (respCmd != "FILE_META") {
                 cout << "[TRACKER]: " << metaResp << endl;
                 continue;
            }
            string parsedFileName, fullHash;
            long long fileSize;
            int numPieces, numPeers;
            ss >> parsedFileName >> fileSize >> fullHash >> numPieces;
            vector<string> pieceHashes(numPieces);
            for(int i = 0; i < numPieces; ++i) ss >> pieceHashes[i];
            ss >> numPeers;
            vector<string> peerAddresses(numPeers);
            for(int i = 0; i < numPeers; ++i) ss >> peerAddresses[i];
            if (peerAddresses.empty()) {
                cout << "Download FAILED: No active peers found sharing this file." << endl;
                continue;
            }
            DownloadContext* ctxPtr = new DownloadContext(parsedFileName, destinationPath, fileSize, fullHash, pieceHashes);
            ctxPtr->peerAddresses = peerAddresses;
            
            {
                lock_guard<mutex> lock(downloadMutex);
                activeDownloads[parsedFileName] = ActiveDownload(parsedFileName, groupId, destinationPath, fileSize, numPieces);
            }
            
            cout << "Starting P2P download for " << parsedFileName << " (" << numPieces << " pieces) from " << numPeers << " peers..." << endl;
            thread(start_download_worker, ctxPtr).detach();
        }
        else if (cmd == "show_downloads" && tokens.size() == 1){
            lock_guard<mutex> lock(downloadMutex);
            if (activeDownloads.empty()) {
                cout << "No active downloads." << endl;
            } else {
                cout << "\n=== Active Downloads ===" << endl;
                for (const auto& [fileName, download] : activeDownloads) {
                    auto now = chrono::steady_clock::now();
                    auto duration = chrono::duration_cast<chrono::seconds>(now - download.startTime);
                    int progress = (download.totalPieces > 0) ? (download.completedPieces * 100 / download.totalPieces) : 0;
                    
                    cout << "[" << download.status << "] [" << download.groupId << "] " << fileName;
                    if (download.status == "downloading") {
                        cout << " (" << progress << "% - " << download.completedPieces << "/" << download.totalPieces << " pieces)";
                    }
                    cout << " - " << duration.count() << "s" << endl;
                }
                cout << "========================" << endl;
            }
        }
        else if ((cmd == "show_files" || (cmd == "show" && tokens.size() == 2 && tokens[1] == "files")) && tokens.size() >= 2){
            string groupId = tokens.back();
            sendMessageWithReconnect("SHOW_FILES " + groupId);
        }
        else if (cmd == "stop_share" && tokens.size() == 3){
            string groupId = tokens[1];
            string fileName = tokens[2];
            localSharedFiles.erase(fileName); 
            sendMessageWithReconnect("STOP_SHARE " + groupId + " " + fileName);
        }
        else if (cmd == "quit" && tokens.size() == 1){
            sendMessageWithReconnect("QUIT");
            break;
        }
        else{
            cout << "Unknown command or bad usage." << endl;
        }
    }
    if (connectionManager) {
        connectionManager->disconnect();
        delete connectionManager;
    }
    trackerListener.detach();
    p2pListener.detach();
    return 0;
}