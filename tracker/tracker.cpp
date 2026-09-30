#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <thread>
#include <chrono>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <mutex>
#include <map>
#include <set>
#include <queue>
#include <condition_variable>
#include <iomanip>
#include <algorithm>
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
struct FileMetadata {
    string fileName;
    string filePath; 
    long long fileSize;
    string fullFileHash; 
    vector<string> pieceHashes; 
    set<string> sharingPeers; 
    string ownerId; 
    string toSyncString() const {
        stringstream ss;
        ss << fileName << " " << filePath << " " << fileSize << " " << fullFileHash << " " << pieceHashes.size() << " ";
        for (const auto& hash : pieceHashes) ss << hash << " ";
        ss << sharingPeers.size() << " ";
        for (const auto& peer : sharingPeers) ss << peer << " ";
        return ss.str();
    }
    void fromSyncString(const string& data, const string& owner, const string& group) {
        stringstream ss(data);
        size_t numHashes, numPeers;
        ss >> fileName >> filePath >> fileSize >> fullFileHash >> numHashes; 
        pieceHashes.clear();
        string hash;
        for(size_t i = 0; i < numHashes; ++i) {
            ss >> hash;
            pieceHashes.push_back(hash);
        }
        sharingPeers.clear();
        string peer;
        ss >> numPeers;
        for(size_t i = 0; i < numPeers; ++i) {
            ss >> peer;
            sharingPeers.insert(peer);
        }
        ownerId = owner;
    }
};
class UserGroupManager {
private:
    map<string, string> users;       
    map<int, string> sessions;            
    map<string, string> userP2PAddresses; 
    map<string, string> groupOwner;                  
    map<string, set<string>> groupMembers;      
    map<string, set<string>> groupRequests;     
    map<string, map<string, FileMetadata>> sharedFiles; 
    mutex mtx;
public:
    bool createUser(const string &userId, const string &password) {
        lock_guard<mutex> lock(mtx);
        if (users.count(userId)) return false;
        users[userId] = password;
        return true;
    }
    bool login(int sock, const string &userId, const string &password, const string& p2pAddress) {
        lock_guard<mutex> lock(mtx);
        if (!users.count(userId) || users[userId] != password) return false;
        sessions[sock] = userId;
        userP2PAddresses[userId] = p2pAddress; 
        return true;
    }
    void logout(int sock) {
        lock_guard<mutex> lock(mtx);
        sessions.erase(sock);
    }
    string getUserFromSock(int sock) {
        lock_guard<mutex> lock(mtx);
        if (sessions.count(sock)) return sessions[sock];
        return "";
    }
    string getP2PAddress(const string &userId) {
        lock_guard<mutex> lock(mtx);
        if (userP2PAddresses.count(userId)) return userP2PAddresses[userId];
        return "";
    }
    bool createGroup(const string &userId, const string &groupId) {
        lock_guard<mutex> lock(mtx);
        if (groupOwner.count(groupId)) return false;
        groupOwner[groupId] = userId;
        groupMembers[groupId].insert(userId);
        return true;
    }
    bool joinGroup(const string &userId, const string &groupId) {
        lock_guard<mutex> lock(mtx);
        if (!groupOwner.count(groupId)) return false;
        if (groupMembers[groupId].count(userId)) return false;
        groupRequests[groupId].insert(userId);
        return true;
    }
    bool leaveGroup(const string &userId, const string &groupId) {
        lock_guard<mutex> lock(mtx);
        if (!groupMembers[groupId].count(userId)) return false;
        if (groupOwner[groupId] == userId) return false;
        groupMembers[groupId].erase(userId);
        return true;
    }
    set<string> listGroups() {
        lock_guard<mutex> lock(mtx);
        set<string> g;
        for (auto &p : groupOwner) g.insert(p.first);
        return g;
    }
    set<string> listRequests(const string &groupId) {
        lock_guard<mutex> lock(mtx);
        if (!groupRequests.count(groupId)) return {};
        return groupRequests[groupId];
    }
    bool acceptRequest(const string &groupId, const string &userId, const string &ownerId) {
        lock_guard<mutex> lock(mtx);
        if (!groupOwner.count(groupId) || groupOwner[groupId] != ownerId) return false;
        if (!groupRequests[groupId].count(userId)) return false;
        groupRequests[groupId].erase(userId);
        groupMembers[groupId].insert(userId);
        return true;
    }
    bool forceJoinGroup(const string &userId, const string &groupId) {
        lock_guard<mutex> lock(mtx);
        if (!groupOwner.count(groupId)) return false;
        groupMembers[groupId].insert(userId);
        groupRequests[groupId].erase(userId);
        return true;
    }
    map<string, string> getAllUsers() { lock_guard<mutex> lock(mtx); return users; }
    map<string, string> getAllGroups() { lock_guard<mutex> lock(mtx); return groupOwner; }
    map<string, set<string>> getAllGroupMembers() { lock_guard<mutex> lock(mtx); return groupMembers; }
    map<string, map<string, FileMetadata>> getAllSharedFiles() { lock_guard<mutex> lock(mtx); return sharedFiles; }
    bool shareFile(const string& userId, const string& groupId, const string& fileName, long long fileSize, const string& fullFileHash, const vector<string>& pieceHashes, const string& clientIPPort) {
        lock_guard<mutex> lock(mtx);
        if (!groupOwner.count(groupId) || !groupMembers[groupId].count(userId)) return false; 
        FileMetadata& metadata = sharedFiles[groupId][fileName];
        if (metadata.fileName.empty()) {
            metadata.fileName = fileName;
            metadata.fileSize = fileSize;
            metadata.fullFileHash = fullFileHash;
            metadata.pieceHashes = pieceHashes;
            metadata.ownerId = userId; 
        }
        metadata.sharingPeers.insert(userId); 
        return true;
    }
    map<string, FileMetadata> listFilesInGroup(const string& groupId) {
        lock_guard<mutex> lock(mtx);
        if (sharedFiles.count(groupId)) return sharedFiles[groupId];
        return {};
    }
    bool stopSharingFile(const string& userId, const string& groupId, const string& fileName) {
        lock_guard<mutex> lock(mtx);
        if (!sharedFiles.count(groupId) || !sharedFiles[groupId].count(fileName)) return false; 
        FileMetadata& metadata = sharedFiles[groupId][fileName];
        metadata.sharingPeers.erase(userId);
        if (metadata.sharingPeers.empty()) {
            sharedFiles[groupId].erase(fileName);
        }
        return true;
    }
    FileMetadata getFileMetadata(const string& groupId, const string& fileName) {
        lock_guard<mutex> lock(mtx);
        if (sharedFiles.count(groupId) && sharedFiles[groupId].count(fileName)) return sharedFiles[groupId][fileName];
        return FileMetadata{}; 
    }
};
int connectedClients = 0;
mutex loadMutex;
map<int, chrono::steady_clock::time_point> clientLastActivity;
mutex activityMutex;
void incrementClientCount() {
    lock_guard<mutex> lock(loadMutex);
    connectedClients++;
}
void decrementClientCount() {
    lock_guard<mutex> lock(loadMutex);
    connectedClients--;
}
int getClientCount() {
    lock_guard<mutex> lock(loadMutex);
    return connectedClients;
}
void updateClientActivity(int clientSock) {
    lock_guard<mutex> lock(activityMutex);
    clientLastActivity[clientSock] = chrono::steady_clock::now();
}
void cleanupInactiveClients() {
    lock_guard<mutex> lock(activityMutex);
    auto now = chrono::steady_clock::now();
    auto it = clientLastActivity.begin();
    while (it != clientLastActivity.end()) {
        if (now - it->second > chrono::minutes(5)) {
            cout << "[TRACKER] Cleaning up inactive client: " << it->first << endl;
            close(it->first);
            it = clientLastActivity.erase(it);
            decrementClientCount();
        } else {
            ++it;
        }
    }
}
class SyncManager {
private:
    int sock;
    thread listenerThread;
    mutex mtx;
    queue<string> outboundQueue;
    condition_variable cv;
    bool running;
    UserGroupManager& ugmRef;
    void sendFullState() {
        auto allUsers = ugmRef.getAllUsers();
        for (auto &u : allUsers) enqueueUpdate("CREATE_USER " + u.first + " " + u.second);
        auto allGroups = ugmRef.getAllGroups();
        auto allMembers = ugmRef.getAllGroupMembers();
        for (auto &g : allGroups) {
            string groupId = g.first;
            string ownerId = g.second;
            enqueueUpdate("CREATE_GROUP " + ownerId + " " + groupId);
            for (auto &member : allMembers[groupId]) {
                if (member != ownerId) enqueueUpdate("JOIN_GROUP " + member + " " + groupId);
            }
        }
        auto allSharedFiles = ugmRef.getAllSharedFiles();
        for (auto& groupPair : allSharedFiles) {
            string groupId = groupPair.first;
            for (auto& filePair : groupPair.second) {
                const FileMetadata& meta = filePair.second;
                enqueueUpdate("SHARE_FILE " + groupId + " " + meta.ownerId + " " + meta.toSyncString());
            }
        }
    }
    void sendLoop() {
        while (running) {
            unique_lock<mutex> lock(mtx);
            cv.wait(lock, [this]{ return !outboundQueue.empty() || !running; });
            if (!running) break;
            string msg = outboundQueue.front();
            outboundQueue.pop();
            lock.unlock();
            if (sock < 0) continue;
            ssize_t total = 0;
            while (total < (ssize_t)msg.size()) {
                ssize_t sent = send(sock, msg.c_str() + total, msg.size() - total, 0);
                if (sent <= 0) {
                    running = false;
                    break;
                }
                total += sent;
            }
        }
    }
    void listenPeerTracker() {
        string buffer;
        char tmp[1024];
        while (running && sock >= 0) {
            ssize_t len = recv(sock, tmp, sizeof(tmp), 0);
            if (len <= 0) {
                running = false;
                break;
            }
            buffer.append(tmp, len);
            size_t pos;
            while ((pos = buffer.find('\n')) != string::npos) {
                string line = buffer.substr(0, pos);
                buffer.erase(0, pos + 1);
                if (line.empty()) continue;
                stringstream cmdss(line);
                string cmd; 
                cmdss >> cmd;
                if (cmd == "CREATE_USER") {
                    string user, pass; cmdss >> user >> pass;
                    ugmRef.createUser(user, pass);
                } else if (cmd == "CREATE_GROUP") {
                    string owner, gid; cmdss >> owner >> gid;
                    ugmRef.createGroup(owner, gid);
                } else if (cmd == "JOIN_GROUP") {
                    string user, gid; cmdss >> user >> gid;
                    ugmRef.joinGroup(user, gid); 
                } else if (cmd == "LEAVE_GROUP") {
                    string user, gid; cmdss >> user >> gid;
                    ugmRef.leaveGroup(user, gid);
                } else if (cmd == "ACCEPT_REQUEST") {
                    string gid, uid, owner; cmdss >> gid >> uid >> owner;
                    ugmRef.acceptRequest(gid, uid, owner);
                } else if (cmd == "SHARE_FILE") {
                    string groupId, ownerId; cmdss >> groupId >> ownerId;
                    size_t start = line.find(ownerId) + ownerId.length() + 1;
                    if (start > line.length()) continue; 
                    string fileDataString = line.substr(start);
                    FileMetadata newMeta;
                    newMeta.fromSyncString(fileDataString, ownerId, groupId); 
                    ugmRef.shareFile(ownerId, groupId, newMeta.fileName, newMeta.fileSize, newMeta.fullFileHash, newMeta.pieceHashes, "");
                } else if (cmd == "STOP_SHARE") {
                    string groupId, userId, fileName; cmdss >> groupId >> userId >> fileName;
                    ugmRef.stopSharingFile(userId, groupId, fileName);
                }
            }
        }
    }
public:
    bool connected;
    SyncManager(UserGroupManager& ugmInstance) : sock(-1), connected(false), running(false), ugmRef(ugmInstance) {}
    ~SyncManager() { stop(); }
    void start() {
        if (sock < 0 || !connected) return;
        running = true;
        sendFullState();
        if (!listenerThread.joinable()) {
            listenerThread = thread(&SyncManager::listenPeerTracker, this);
            thread(&SyncManager::sendLoop, this).detach();
        }
    }
    void stop() {
        running = false;
        connected = false;
        cv.notify_all();
        if (sock >= 0) {
            close(sock);
            sock = -1;
        }
        if (listenerThread.joinable()) listenerThread.join();
    }
    void enqueueUpdate(const string &update) {
        lock_guard<mutex> lock(mtx);
        outboundQueue.push(update + "\n");
        cv.notify_one();
    }
    void acceptPeerTracker(int acceptedSock) {
        if (connected) {
            close(acceptedSock);
            return;
        }
        sock = acceptedSock;
        connected = true;
        running = true;
        cout << "[SYNC] Peer tracker connected inbound." << endl;
        listenerThread = thread(&SyncManager::listenPeerTracker, this);
        thread(&SyncManager::sendLoop, this).detach();
        sendFullState();
    }
};
int serverSock = -1;
UserGroupManager ugm;
SyncManager syncMgr(ugm); 
mutex socketMutex;
bool sendMessage(int sock, const string &msg) {
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
    out.clear();
    const size_t BUFFER_SIZE = 256 * 1024;
    vector<char> buf(BUFFER_SIZE);
    ssize_t totalReceived = 0;
    while (true) {
        ssize_t len = recv(sock, buf.data() + totalReceived, BUFFER_SIZE - 1 - totalReceived, 0);
        if (len <= 0) return false;
        totalReceived += len;
        buf[totalReceived] = '\0';
        if (totalReceived > 0 && buf[totalReceived - 1] == '\n') {
            break;
        }
        if (totalReceived >= (ssize_t)(BUFFER_SIZE - 1)) {
            cout << "[ERROR] Message too long (" << totalReceived << " bytes), truncating..." << endl;
            break;
        }
    }
    out = string(buf.data(), totalReceived);
    if (!out.empty() && out.back() == '\n') {
        out.pop_back();
    }
    if (!out.empty()) {
        cout << "[DEBUG] Received command (" << out.length() << " bytes): " << out.substr(0, min(100, (int)out.length())) << (out.length() > 100 ? "..." : "") << endl;
    }
    return true;
}
void handleClient(int clientSock) {
    incrementClientCount();
    updateClientActivity(clientSock);
    string msg;
    while (recvMessage(clientSock, msg)) {
        updateClientActivity(clientSock);
        stringstream ss(msg);
        string cmd;
        ss >> cmd;
        string currentUser = ugm.getUserFromSock(clientSock);
        bool success;
        if (cmd == "CREATE_USER") {
            string user, pass;
            ss >> user >> pass;
            success = ugm.createUser(user, pass);
            if (success) {
                sendMessage(clientSock, "USER_CREATED");
                syncMgr.enqueueUpdate("CREATE_USER " + user + " " + pass);
            } else {
                sendMessage(clientSock, "USER_EXISTS");
            }
        } else if (cmd == "LOGIN") {
            string user, pass, p2pAddr; 
            ss >> user >> pass >> p2pAddr;
            success = ugm.login(clientSock, user, pass, p2pAddr); 
            if (success) {
                sendMessage(clientSock, "LOGIN_OK");
            } else {
                sendMessage(clientSock, "LOGIN_FAIL");
            }
        } else if (cmd == "CREATE_GROUP") {
            string gid;
            ss >> gid;
            if (currentUser.empty()) { sendMessage(clientSock, "GROUP_FAIL: NOT_LOGGED_IN"); continue; }
            success = ugm.createGroup(currentUser, gid);
            if (success) {
                sendMessage(clientSock, "GROUP_CREATED");
                syncMgr.enqueueUpdate("CREATE_GROUP " + currentUser + " " + gid);
            } else {
                sendMessage(clientSock, "GROUP_FAIL");
            }
        } else if (cmd == "JOIN_GROUP") {
            string gid;
            ss >> gid;
            if (currentUser.empty()) { sendMessage(clientSock, "JOIN_FAIL: NOT_LOGGED_IN"); continue; }
            success = ugm.joinGroup(currentUser, gid);
            if (success) {
                sendMessage(clientSock, "JOIN_REQUESTED");
                syncMgr.enqueueUpdate("JOIN_GROUP " + currentUser + " " + gid);
            } else {
                sendMessage(clientSock, "JOIN_FAIL");
            }
        } else if (cmd == "LEAVE_GROUP") {
            string gid;
            ss >> gid;
            if (currentUser.empty()) { sendMessage(clientSock, "LEAVE_FAIL: NOT_LOGGED_IN"); continue; }
            success = ugm.leaveGroup(currentUser, gid);
            if (success) {
                sendMessage(clientSock, "LEFT_GROUP");
                syncMgr.enqueueUpdate("LEAVE_GROUP " + currentUser + " " + gid);
            } else {
                sendMessage(clientSock, "LEAVE_FAIL");
            }
        } else if (cmd == "ACCEPT_REQUEST") {
            string gid, uid;
            ss >> gid >> uid;
            if (currentUser.empty()) { sendMessage(clientSock, "REQUEST_FAIL: NOT_LOGGED_IN"); continue; }
            success = ugm.acceptRequest(gid, uid, currentUser);
            if (success) {
                sendMessage(clientSock, "REQUEST_ACCEPTED");
                syncMgr.enqueueUpdate("ACCEPT_REQUEST " + gid + " " + uid + " " + currentUser);
            } else {
                sendMessage(clientSock, "REQUEST_FAIL");
            }
        } else if (cmd == "LIST_GROUPS") {
            auto groups = ugm.listGroups();
            string out;
            for (auto &g : groups) out += g + " ";
            if (out.empty()) {
                sendMessage(clientSock, "NO_GROUPS");
            } else {
                sendMessage(clientSock, out);
            }
        } else if (cmd == "LIST_REQUESTS") {
            string gid;
            ss >> gid;
            auto reqs = ugm.listRequests(gid);
            string out;
            for (auto &r : reqs) out += r + " ";
            if (out.empty()) {
                sendMessage(clientSock, "NO_REQUESTS");
            } else {
                sendMessage(clientSock, out);
            }
        } else if (cmd == "UPLOAD_FILE") {
            string gid, fileName, fullHash, clientP2P;
            long long fSize;
            int numPieces;
            ss >> gid >> fileName >> fSize >> fullHash >> numPieces >> clientP2P;
            vector<string> pieceHashes;
            for(int i = 0; i < numPieces; ++i) {
                string hash;
                ss >> hash;
                pieceHashes.push_back(hash);
            }
            if (currentUser.empty()) {
                sendMessage(clientSock, "UPLOAD_FAIL: NOT_LOGGED_IN");
                continue;
            }
            success = ugm.shareFile(currentUser, gid, fileName, fSize, fullHash, pieceHashes, clientP2P);
            if (success) {
                sendMessage(clientSock, "FILE_SHARED");
                string fileData = ugm.getFileMetadata(gid, fileName).toSyncString();
                syncMgr.enqueueUpdate("SHARE_FILE " + gid + " " + currentUser + " " + fileData);
            } else {
                sendMessage(clientSock, "UPLOAD_FAIL");
            }
        } else if (cmd == "LIST_FILES") {
            string gid;
            ss >> gid;
            auto files = ugm.listFilesInGroup(gid);
            string out;
            if (files.empty()) {
                sendMessage(clientSock, "NO_FILES");
            } else {
                for (auto& pair : files) {
                    const FileMetadata& meta = pair.second;
                    out += meta.fileName + " " + to_string(meta.fileSize) + " " + meta.fullFileHash + " " + to_string(meta.sharingPeers.size()) + " ";
                    for(const string& peer : meta.sharingPeers) out += peer + ",";
                    if (!meta.sharingPeers.empty()) out.pop_back(); 
                    out += "|"; 
                }
                if (!out.empty()) out.pop_back(); 
                sendMessage(clientSock, out);
            }
        } else if (cmd == "DOWNLOAD_FILE") {
            string gid, fileName;
            ss >> gid >> fileName;
            FileMetadata meta = ugm.getFileMetadata(gid, fileName);
            if (meta.fileName.empty()) {
                sendMessage(clientSock, "DOWNLOAD_FAIL: FILE_NOT_FOUND");
            } else {
                string response = "FILE_META " + meta.fileName + " " + to_string(meta.fileSize) + " " + meta.fullFileHash + " " + to_string(meta.pieceHashes.size()) + " ";
                for (const string& hash : meta.pieceHashes) response += hash + " ";
                response += to_string(meta.sharingPeers.size()) + " ";
                for(const string& peerId : meta.sharingPeers) {
                    string p2pAddr = ugm.getP2PAddress(peerId);
                    if (!p2pAddr.empty()) {
                         response += p2pAddr + " "; 
                    }
                }
                sendMessage(clientSock, response);
            }
        } else if (cmd == "STOP_SHARE") {
            string gid, fileName;
            ss >> gid >> fileName;
            if (currentUser.empty()) { sendMessage(clientSock, "STOP_SHARE_FAIL: NOT_LOGGED_IN"); continue; }
            success = ugm.stopSharingFile(currentUser, gid, fileName);
            if (success) {
                sendMessage(clientSock, "SHARE_STOPPED");
                syncMgr.enqueueUpdate("STOP_SHARE " + gid + " " + currentUser + " " + fileName);
            } else {
                sendMessage(clientSock, "STOP_SHARE_FAIL");
            }
        } else if (cmd == "GET_LOAD") {
            int load = getClientCount();
            sendMessage(clientSock, "LOAD " + to_string(load));
        } else if (cmd == "QUIT") {
            ugm.logout(clientSock);
            sendMessage(clientSock, "BYE");
            break;
        } else {
            sendMessage(clientSock, "UNKNOWN_CMD");
        }
    }
    decrementClientCount();
    ugm.logout(clientSock);
    close(clientSock);
}
void startServer(int port) {
    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) exit(1);
    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    serv.sin_addr.s_addr = INADDR_ANY;
    int opt = 1;
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(serverSock, (sockaddr*)&serv, sizeof(serv)) < 0) { perror("bind"); exit(1); }
    if (listen(serverSock, 10) < 0) { perror("listen"); exit(1); }
    cout << "Tracker listening on port " << port << endl;
    while (true) {
        sockaddr_in cli{};
        socklen_t clen = sizeof(cli);
        int cSock = accept(serverSock, (sockaddr*)&cli, &clen);
        if (cSock < 0) continue;
        thread(handleClient, cSock).detach();
    }
}
pair<string,int> readTrackerLine(const string &file, int trackerNo) {
    ifstream fin(file);
    string line;
    int cnt = 1;
    while (getline(fin, line)) {
        if (line.empty()) continue;
        if (cnt == trackerNo) {
            size_t colon = line.find(':');
            string ip = line.substr(0, colon);
            int port = stoi(line.substr(colon + 1));
            return {ip, port};
        }
        cnt++;
    }
    cerr << "Tracker number not found\n";
    exit(1);
}
void connectToPeerTrackers(const vector<pair<string, int>>& allTrackers, int currentTrackerNo) {
    this_thread::sleep_for(chrono::seconds(2));
    for (size_t i = 0; i < allTrackers.size(); i++) {
        if ((int)(i + 1) == currentTrackerNo) continue;
        auto& tracker = allTrackers[i];
        int syncPort = tracker.second + 1000;
        int peerSock = socket(AF_INET, SOCK_STREAM, 0);
        if (peerSock < 0) continue;
        sockaddr_in peerServ{};
        peerServ.sin_family = AF_INET;
        peerServ.sin_port = htons(syncPort);
        inet_pton(AF_INET, tracker.first.c_str(), &peerServ.sin_addr);
        if (::connect(peerSock, (sockaddr*)&peerServ, sizeof(peerServ)) == 0) {
            cout << "[SYNC] Connected to peer tracker at " << tracker.first << ":" << syncPort << endl;
            syncMgr.acceptPeerTracker(peerSock);
        } else {
            close(peerSock);
            thread([tracker, syncPort]() {
                for (int retry = 0; retry < 10; retry++) {
                    this_thread::sleep_for(chrono::seconds(2));
                    int peerSock = socket(AF_INET, SOCK_STREAM, 0);
                    if (peerSock < 0) continue;
                    sockaddr_in peerServ{};
                    peerServ.sin_family = AF_INET;
                    peerServ.sin_port = htons(syncPort);
                    inet_pton(AF_INET, tracker.first.c_str(), &peerServ.sin_addr);
                    if (::connect(peerSock, (sockaddr*)&peerServ, sizeof(peerServ)) == 0) {
                        cout << "[SYNC] Connected to peer tracker at " << tracker.first << ":" << syncPort << endl;
                        syncMgr.acceptPeerTracker(peerSock);
                        return;
                    }
                    close(peerSock);
                }
                cout << "[SYNC] Failed to connect to peer tracker at " << tracker.first << ":" << syncPort << endl;
            }).detach();
        }
    }
}
int main(int argc, char *argv[]) {
    if (argc < 3) {
        cerr << "Usage: ./tracker tracker_info.txt <tracker_no>\n";
        return 1;
    }
    int trackerNo = stoi(argv[2]);
    auto [ip, port] = readTrackerLine(argv[1], trackerNo);
    vector<pair<string, int>> allTrackers;
    ifstream fin(argv[1]);
    string line;
    while (getline(fin, line)) {
        if (line.empty()) continue;
        size_t colon = line.find(':');
        string peerIp = line.substr(0, colon);
        int peerPort = stoi(line.substr(colon + 1));
        allTrackers.push_back({peerIp, peerPort});
    }
    thread([trackerNo, port]() {
        int syncListenSock = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(syncListenSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        sockaddr_in syncServ{};
        syncServ.sin_family = AF_INET;
        syncServ.sin_port = htons(port + 1000);
        syncServ.sin_addr.s_addr = INADDR_ANY;
        if (bind(syncListenSock, (sockaddr*)&syncServ, sizeof(syncServ)) < 0) {
            cerr << "[SYNC] Error binding sync listener socket." << endl;
            return;
        }
        if (listen(syncListenSock, 1) < 0) {
            cerr << "[SYNC] Error listening on sync socket." << endl;
            return;
        }
        cout << "[SYNC] Sync listener ready on port " << port + 1000 << endl;
        sockaddr_in cli{};
        socklen_t clen = sizeof(cli);
        int acceptedSock = accept(syncListenSock, (sockaddr*)&cli, &clen);
        if (acceptedSock >= 0) {
            syncMgr.acceptPeerTracker(acceptedSock);
        } else {
            cerr << "[SYNC] Error accepting peer connection." << endl;
        }
        close(syncListenSock);
    }).detach();
    thread([allTrackers, trackerNo]() {
        connectToPeerTrackers(allTrackers, trackerNo);
    }).detach();
    thread([]() {
        while (true) {
            this_thread::sleep_for(chrono::minutes(1));
            cleanupInactiveClients();
        }
    }).detach();
    startServer(port);
    return 0;
}