#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
#endif

namespace {

constexpr std::uint32_t kLoopbackBase = 0x7F000000U;
constexpr std::uint32_t kPrivate10Base = 0x0A000000U;
constexpr std::uint32_t kPrivate172Base = 0xAC100000U;
constexpr std::uint32_t kPrivate192Base = 0xC0A80000U;
constexpr std::size_t kMaxHosts = 4096;
constexpr std::size_t kMaxBannerLength = 120;
constexpr int kBannerWaitMs = 150;

enum class OutputFormat {
    human,
    json,
    jsonl,
    csv,
};

struct Options {
    std::string target;
    std::vector<std::uint16_t> ports;
    int timeoutMs = 400;
    std::size_t threads = 128;
    int retries = 1;
    int rateLimitPerSecond = 200;
    bool verbose = false;
    bool discovery = true;
    bool resolveDns = false;
    bool banners = true;
    OutputFormat outputFormat = OutputFormat::human;
};

struct Target {
    std::uint32_t startIp = 0;
    std::uint32_t endIp = 0;
    int prefixLength = 32;
};

struct OpenPort {
    std::uint16_t port = 0;
    int attempts = 0;
    std::string banner;
};

struct HostRecord {
    std::uint32_t ip = 0;
    bool active = false;
    std::uint16_t discoveryPort = 0;
    std::string hostname;
    std::vector<OpenPort> openPorts;
};

struct Summary {
    std::size_t hostsEnumerated = 0;
    std::size_t hostsDiscovered = 0;
    std::size_t hostsScanned = 0;
    std::size_t portsScheduled = 0;
    std::size_t connectAttempts = 0;
    std::size_t openPorts = 0;
    std::size_t bannersCaptured = 0;
    std::chrono::steady_clock::duration discoveryDuration {};
    std::chrono::steady_clock::duration scanDuration {};
    std::chrono::steady_clock::duration dnsDuration {};
    std::chrono::steady_clock::duration totalDuration {};
};

struct ScanResult {
    std::vector<HostRecord> hosts;
    Summary summary;
};

class Logger {
public:
    explicit Logger(bool enabled) : enabled_(enabled) {}

    void log(const std::string& message) const {
        if (!enabled_) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        std::cerr << "[verbose] " << message << '\n';
    }

private:
    bool enabled_ = false;
    mutable std::mutex mutex_;
};

class SocketEnvironment {
public:
    SocketEnvironment() {
#ifdef _WIN32
        WSADATA data {};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::runtime_error("Falha ao inicializar Winsock.");
        }
#endif
    }

    ~SocketEnvironment() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};

class RateLimiter {
public:
    explicit RateLimiter(int permitsPerSecond) : permitsPerSecond_(permitsPerSecond) {}

    void acquire() {
        if (permitsPerSecond_ <= 0) {
            return;
        }

        const auto interval = std::chrono::microseconds(1'000'000 / permitsPerSecond_);
        std::unique_lock<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        if (nextSlot_ < now) {
            nextSlot_ = now;
        }
        const auto scheduled = nextSlot_;
        nextSlot_ += interval;
        lock.unlock();

        if (scheduled > now) {
            std::this_thread::sleep_until(scheduled);
        }
    }

private:
    int permitsPerSecond_ = 0;
    std::mutex mutex_;
    std::chrono::steady_clock::time_point nextSlot_ = std::chrono::steady_clock::now();
};

class ThreadPool {
public:
    explicit ThreadPool(std::size_t workerCount) {
        if (workerCount == 0) {
            throw std::runtime_error("Thread pool precisa de pelo menos uma thread.");
        }

        workers_.reserve(workerCount);
        for (std::size_t index = 0; index < workerCount; ++index) {
            workers_.emplace_back([this]() { workerLoop(); });
        }
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        cv_.notify_all();

        for (std::thread& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

    void enqueue(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                throw std::runtime_error("Thread pool ja foi encerrado.");
            }
            tasks_.push(std::move(task));
        }
        cv_.notify_one();
    }

    void waitIdle() {
        std::unique_lock<std::mutex> lock(mutex_);
        idleCv_.wait(lock, [&]() {
            return tasks_.empty() && activeWorkers_ == 0;
        });
    }

private:
    void workerLoop() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [&]() { return stopping_ || !tasks_.empty(); });
                if (stopping_ && tasks_.empty()) {
                    return;
                }
                task = std::move(tasks_.front());
                tasks_.pop();
                ++activeWorkers_;
            }

            task();

            {
                std::lock_guard<std::mutex> lock(mutex_);
                --activeWorkers_;
                if (tasks_.empty() && activeWorkers_ == 0) {
                    idleCv_.notify_all();
                }
            }
        }
    }

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::condition_variable idleCv_;
    std::size_t activeWorkers_ = 0;
    bool stopping_ = false;
};

void closeSocket(SocketHandle handle) {
#ifdef _WIN32
    closesocket(handle);
#else
    close(handle);
#endif
}

bool setNonBlocking(SocketHandle handle, bool enabled) {
#ifdef _WIN32
    u_long mode = enabled ? 1UL : 0UL;
    return ioctlsocket(handle, FIONBIO, &mode) == 0;
#else
    const int flags = fcntl(handle, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    const int updatedFlags = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return fcntl(handle, F_SETFL, updatedFlags) == 0;
#endif
}

bool setSocketTimeouts(SocketHandle handle, int timeoutMs) {
#ifdef _WIN32
    DWORD timeout = static_cast<DWORD>(timeoutMs);
    return setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0
        && setsockopt(handle, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0;
#else
    timeval timeout {};
    timeout.tv_sec = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;
    return setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0
        && setsockopt(handle, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
#endif
}

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::uint32_t parseIpv4(const std::string& value) {
    std::stringstream stream(value);
    std::string part;
    std::uint32_t ip = 0;
    int octetCount = 0;

    while (std::getline(stream, part, '.')) {
        part = trim(part);
        if (part.empty()) {
            throw std::runtime_error("IPv4 invalido: " + value);
        }

        std::size_t consumed = 0;
        const int octet = std::stoi(part, &consumed);
        if (consumed != part.size() || octet < 0 || octet > 255) {
            throw std::runtime_error("IPv4 invalido: " + value);
        }

        ip = (ip << 8U) | static_cast<std::uint32_t>(octet);
        ++octetCount;
    }

    if (octetCount != 4 || stream.rdbuf()->in_avail() != 0) {
        throw std::runtime_error("IPv4 invalido: " + value);
    }

    return ip;
}

std::string ipv4ToString(std::uint32_t value) {
    std::ostringstream stream;
    stream
        << ((value >> 24U) & 0xFFU) << '.'
        << ((value >> 16U) & 0xFFU) << '.'
        << ((value >> 8U) & 0xFFU) << '.'
        << (value & 0xFFU);
    return stream.str();
}

bool isAuthorizedRange(std::uint32_t ip) {
    if ((ip & 0xFF000000U) == kLoopbackBase) {
        return true;
    }
    if ((ip & 0xFF000000U) == kPrivate10Base) {
        return true;
    }
    if ((ip & 0xFFF00000U) == kPrivate172Base) {
        return true;
    }
    if ((ip & 0xFFFF0000U) == kPrivate192Base) {
        return true;
    }
    return false;
}

Target parseTarget(const std::string& rawTarget) {
    const auto slashPos = rawTarget.find('/');
    const std::string ipText = slashPos == std::string::npos ? rawTarget : trim(rawTarget.substr(0, slashPos));
    const std::uint32_t ip = parseIpv4(ipText);
    const int prefixLength = slashPos == std::string::npos ? 32 : std::stoi(trim(rawTarget.substr(slashPos + 1)));

    if (prefixLength < 0 || prefixLength > 32) {
        throw std::runtime_error("CIDR invalido: " + rawTarget);
    }

    if (!isAuthorizedRange(ip)) {
        throw std::runtime_error("Por seguranca, o scanner so aceita loopback e redes privadas RFC1918.");
    }

    const std::uint32_t mask = prefixLength == 0 ? 0 : (0xFFFFFFFFU << (32 - prefixLength));
    const std::uint32_t network = ip & mask;
    const std::uint32_t broadcast = network | ~mask;

    if (!isAuthorizedRange(network) || !isAuthorizedRange(broadcast)) {
        throw std::runtime_error("A faixa informada sai de uma rede autorizada.");
    }

    Target target {};
    target.prefixLength = prefixLength;

    if (prefixLength == 32) {
        target.startIp = ip;
        target.endIp = ip;
    } else if (prefixLength == 31) {
        target.startIp = network;
        target.endIp = broadcast;
    } else {
        target.startIp = network + 1;
        target.endIp = broadcast - 1;
    }

    const std::size_t hostCount = static_cast<std::size_t>(target.endIp - target.startIp + 1ULL);
    if (hostCount > kMaxHosts) {
        throw std::runtime_error("Faixa muito grande. Limite atual: 4096 hosts.");
    }

    return target;
}

std::vector<std::uint16_t> parsePorts(const std::string& rawPorts) {
    std::set<std::uint16_t> uniquePorts;
    std::stringstream stream(rawPorts);
    std::string token;

    while (std::getline(stream, token, ',')) {
        token = trim(token);
        if (token.empty()) {
            continue;
        }

        const auto dashPos = token.find('-');
        if (dashPos == std::string::npos) {
            const int port = std::stoi(token);
            if (port < 1 || port > 65535) {
                throw std::runtime_error("Porta invalida: " + token);
            }
            uniquePorts.insert(static_cast<std::uint16_t>(port));
            continue;
        }

        const int start = std::stoi(trim(token.substr(0, dashPos)));
        const int end = std::stoi(trim(token.substr(dashPos + 1)));
        if (start < 1 || end > 65535 || start > end) {
            throw std::runtime_error("Faixa de portas invalida: " + token);
        }
        if ((end - start) > 4096) {
            throw std::runtime_error("Faixa de portas muito grande: " + token);
        }
        for (int port = start; port <= end; ++port) {
            uniquePorts.insert(static_cast<std::uint16_t>(port));
        }
    }

    if (uniquePorts.empty()) {
        throw std::runtime_error("Nenhuma porta valida foi informada.");
    }

    return std::vector<std::uint16_t>(uniquePorts.begin(), uniquePorts.end());
}

std::vector<std::uint16_t> profilePorts(const std::string& profile) {
    const std::map<std::string, std::vector<std::uint16_t>> profiles {
        {"web", {80, 443, 8080, 8443, 8000, 8008, 8888}},
        {"infra", {22, 53, 80, 123, 161, 389, 443, 445, 636, 3389, 5985, 8080}},
        {"windows", {53, 88, 135, 139, 389, 445, 464, 636, 3268, 3389, 5985, 9389}},
        {"database", {1433, 1521, 3306, 5432, 6379, 9042, 9200, 27017}},
        {"common", {22, 80, 443, 445, 3389, 8080}},
    };

    const auto it = profiles.find(profile);
    if (it == profiles.end()) {
        throw std::runtime_error("Perfil de portas desconhecido: " + profile);
    }
    return it->second;
}

std::vector<std::uint16_t> mergePortLists(const std::vector<std::uint16_t>& a, const std::vector<std::uint16_t>& b) {
    std::set<std::uint16_t> merged(a.begin(), a.end());
    merged.insert(b.begin(), b.end());
    return std::vector<std::uint16_t>(merged.begin(), merged.end());
}

std::vector<std::uint16_t> parseProfiles(const std::string& rawProfiles) {
    std::vector<std::uint16_t> ports;
    std::stringstream stream(rawProfiles);
    std::string token;

    while (std::getline(stream, token, ',')) {
        token = trim(token);
        if (token.empty()) {
            continue;
        }
        ports = mergePortLists(ports, profilePorts(token));
    }

    if (ports.empty()) {
        throw std::runtime_error("Nenhum perfil valido foi informado.");
    }

    return ports;
}

std::string outputFormatName(OutputFormat format) {
    switch (format) {
        case OutputFormat::human:
            return "human";
        case OutputFormat::json:
            return "json";
        case OutputFormat::jsonl:
            return "jsonl";
        case OutputFormat::csv:
            return "csv";
    }
    return "human";
}

void printUsage() {
    std::cout
        << "Uso:\n"
        << "  net_inventory_scanner --target 192.168.0.0/24 [--ports 22,80,443]\n"
        << "                       [--profile web,windows] [--timeout-ms 400] [--threads 128]\n"
        << "                       [--retries 1] [--rate-limit 200] [--format human|json|jsonl|csv]\n"
        << "                       [--verbose] [--no-discovery] [--dns] [--no-dns] [--no-banners]\n\n"
        << "Perfis disponiveis:\n"
        << "  common, web, infra, windows, database\n\n"
        << "Observacoes:\n"
        << "  - Scanner de inventario defensivo: somente loopback e redes privadas RFC1918.\n"
        << "  - Discovery usa tentativas TCP em portas conhecidas e nas portas do proprio scan.\n"
        << "  - Nao faz fingerprinting, evasao, spoofing nem tecnicas furtivas.\n";
}

Options parseArgs(int argc, char** argv) {
    Options options;
    bool portsSpecified = false;

    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];
        auto nextValue = [&](const char* name) -> std::string {
            if (index + 1 >= argc) {
                throw std::runtime_error(std::string("Valor ausente para ") + name);
            }
            return argv[++index];
        };

        if (arg == "--target") {
            options.target = nextValue("--target");
        } else if (arg == "--ports") {
            options.ports = mergePortLists(options.ports, parsePorts(nextValue("--ports")));
            portsSpecified = true;
        } else if (arg == "--profile") {
            options.ports = mergePortLists(options.ports, parseProfiles(nextValue("--profile")));
            portsSpecified = true;
        } else if (arg == "--timeout-ms") {
            options.timeoutMs = std::stoi(nextValue("--timeout-ms"));
        } else if (arg == "--threads") {
            options.threads = static_cast<std::size_t>(std::stoul(nextValue("--threads")));
        } else if (arg == "--retries") {
            options.retries = std::stoi(nextValue("--retries"));
        } else if (arg == "--rate-limit") {
            options.rateLimitPerSecond = std::stoi(nextValue("--rate-limit"));
        } else if (arg == "--format") {
            const std::string format = trim(nextValue("--format"));
            if (format == "human") {
                options.outputFormat = OutputFormat::human;
            } else if (format == "json") {
                options.outputFormat = OutputFormat::json;
            } else if (format == "jsonl") {
                options.outputFormat = OutputFormat::jsonl;
            } else if (format == "csv") {
                options.outputFormat = OutputFormat::csv;
            } else {
                throw std::runtime_error("Formato invalido: " + format);
            }
        } else if (arg == "--json") {
            options.outputFormat = OutputFormat::json;
        } else if (arg == "--jsonl") {
            options.outputFormat = OutputFormat::jsonl;
        } else if (arg == "--csv") {
            options.outputFormat = OutputFormat::csv;
        } else if (arg == "--verbose") {
            options.verbose = true;
        } else if (arg == "--no-discovery") {
            options.discovery = false;
        } else if (arg == "--dns") {
            options.resolveDns = true;
        } else if (arg == "--no-dns") {
            options.resolveDns = false;
        } else if (arg == "--no-banners") {
            options.banners = false;
        } else if (arg == "--help" || arg == "-h") {
            printUsage();
            std::exit(0);
        } else {
            throw std::runtime_error("Argumento desconhecido: " + arg);
        }
    }

    if (options.target.empty()) {
        throw std::runtime_error("Parametro obrigatorio ausente: --target");
    }
    if (!portsSpecified) {
        options.ports = profilePorts("common");
    }
    if (options.timeoutMs <= 0 || options.timeoutMs > 10'000) {
        throw std::runtime_error("timeout-ms deve ficar entre 1 e 10000.");
    }
    if (options.threads == 0 || options.threads > 512) {
        throw std::runtime_error("threads deve ficar entre 1 e 512.");
    }
    if (options.retries < 0 || options.retries > 5) {
        throw std::runtime_error("retries deve ficar entre 0 e 5.");
    }
    if (options.rateLimitPerSecond < 0 || options.rateLimitPerSecond > 10'000) {
        throw std::runtime_error("rate-limit deve ficar entre 0 e 10000.");
    }

    return options;
}

struct ConnectionResult {
    bool connected = false;
    SocketHandle handle = kInvalidSocket;
};

ConnectionResult openTcpConnection(std::uint32_t ip, std::uint16_t port, int timeoutMs) {
    SocketHandle handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle == kInvalidSocket) {
        return {};
    }

    if (!setNonBlocking(handle, true)) {
        closeSocket(handle);
        return {};
    }

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(ip);

    const int connectResult = connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (connectResult != 0) {
#ifdef _WIN32
        const int lastError = WSAGetLastError();
        if (lastError != WSAEWOULDBLOCK && lastError != WSAEINPROGRESS && lastError != WSAEINVAL) {
            closeSocket(handle);
            return {};
        }
#else
        if (errno != EINPROGRESS) {
            closeSocket(handle);
            return {};
        }
#endif

        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(handle, &writeSet);

        timeval timeout {};
        timeout.tv_sec = timeoutMs / 1000;
        timeout.tv_usec = (timeoutMs % 1000) * 1000;

        const int ready = select(static_cast<int>(handle + 1), nullptr, &writeSet, nullptr, &timeout);
        if (ready <= 0) {
            closeSocket(handle);
            return {};
        }

        int socketError = 0;
        socklen_t errorLength = sizeof(socketError);
        if (getsockopt(handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socketError), &errorLength) != 0 || socketError != 0) {
            closeSocket(handle);
            return {};
        }
    }

    setNonBlocking(handle, false);
    setSocketTimeouts(handle, timeoutMs);
    return {true, handle};
}

std::string sanitizeBanner(const std::string& raw) {
    std::string clean;
    clean.reserve(std::min(raw.size(), kMaxBannerLength));

    bool lastWasSpace = false;
    for (unsigned char ch : raw) {
        if (clean.size() >= kMaxBannerLength) {
            break;
        }

        if (ch == '\r' || ch == '\n' || ch == '\t') {
            if (!lastWasSpace && !clean.empty()) {
                clean.push_back(' ');
                lastWasSpace = true;
            }
            continue;
        }

        if (ch < 32 || ch > 126) {
            continue;
        }

        clean.push_back(static_cast<char>(ch));
        lastWasSpace = false;
    }

    return trim(clean);
}

bool looksHttpPort(std::uint16_t port) {
    return port == 80 || port == 8080 || port == 8000 || port == 8008 || port == 8888 || port == 3000 || port == 5000;
}

bool looksTlsPort(std::uint16_t port) {
    return port == 443 || port == 8443 || port == 9443 || port == 993 || port == 995;
}

bool waitForReadable(SocketHandle handle, int timeoutMs) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(handle, &readSet);

    timeval timeout {};
    timeout.tv_sec = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;

    const int ready = select(static_cast<int>(handle + 1), &readSet, nullptr, nullptr, &timeout);
    return ready > 0 && FD_ISSET(handle, &readSet);
}

std::string receiveChunk(SocketHandle handle, int waitMs) {
    if (!waitForReadable(handle, waitMs)) {
        return "";
    }

    char buffer[512] {};
    const int received = recv(handle, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        return "";
    }
    return std::string(buffer, buffer + received);
}

std::string captureBanner(SocketHandle handle, std::uint32_t ip, std::uint16_t port) {
    if (looksTlsPort(port)) {
        return "tls-service-open";
    }

    if (looksHttpPort(port)) {
        const std::string request =
            "HEAD / HTTP/1.0\r\nHost: " + ipv4ToString(ip) + "\r\nUser-Agent: net_inventory_scanner\r\nConnection: close\r\n\r\n";
        send(handle, request.c_str(), static_cast<int>(request.size()), 0);
        const std::string banner = sanitizeBanner(receiveChunk(handle, kBannerWaitMs));
        if (!banner.empty()) {
            return banner;
        }
        return "";
    }

    return sanitizeBanner(receiveChunk(handle, kBannerWaitMs));
}

std::string resolveHostname(std::uint32_t ip) {
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(ip);

    char host[NI_MAXHOST] {};
    const int status = getnameinfo(
        reinterpret_cast<sockaddr*>(&address),
        sizeof(address),
        host,
        sizeof(host),
        nullptr,
        0,
        NI_NAMEREQD);

    if (status != 0) {
        return "";
    }
    return host;
}

std::vector<std::uint16_t> defaultDiscoveryPorts(const std::vector<std::uint16_t>& scanPorts) {
    std::vector<std::uint16_t> defaults {22, 53, 80, 135, 139, 443, 445, 3389, 5985, 8080};
    return mergePortLists(defaults, scanPorts);
}

bool tryPortWithRetry(
    std::uint32_t ip,
    std::uint16_t port,
    const Options& options,
    RateLimiter& limiter,
    std::atomic<std::size_t>& connectAttempts,
    ConnectionResult* successfulConnection = nullptr,
    int* attemptsUsed = nullptr) {

    for (int attempt = 1; attempt <= options.retries + 1; ++attempt) {
        limiter.acquire();
        ++connectAttempts;

        ConnectionResult connection = openTcpConnection(ip, port, options.timeoutMs);
        if (connection.connected) {
            if (attemptsUsed != nullptr) {
                *attemptsUsed = attempt;
            }
            if (successfulConnection != nullptr) {
                *successfulConnection = connection;
            } else {
                closeSocket(connection.handle);
            }
            return true;
        }
    }

    if (attemptsUsed != nullptr) {
        *attemptsUsed = options.retries + 1;
    }
    return false;
}

void discoverHosts(
    ScanResult& result,
    const Options& options,
    const std::vector<std::uint16_t>& discoveryPorts,
    std::atomic<std::size_t>& connectAttempts,
    const Logger& logger) {

    if (!options.discovery) {
        for (HostRecord& host : result.hosts) {
            host.active = true;
        }
        result.summary.hostsDiscovered = result.hosts.size();
        return;
    }

    ThreadPool pool(options.threads);
    RateLimiter limiter(options.rateLimitPerSecond);
    std::atomic<std::size_t> discoveredHosts {0};

    for (std::size_t index = 0; index < result.hosts.size(); ++index) {
        pool.enqueue([&, index]() {
            HostRecord& host = result.hosts[index];
            for (std::uint16_t port : discoveryPorts) {
                if (tryPortWithRetry(host.ip, port, options, limiter, connectAttempts)) {
                    host.active = true;
                    host.discoveryPort = port;
                    ++discoveredHosts;
                    logger.log("Host ativo: " + ipv4ToString(host.ip) + " via porta " + std::to_string(port));
                    return;
                }
            }
            logger.log("Host sem resposta no discovery: " + ipv4ToString(host.ip));
        });
    }

    pool.waitIdle();
    result.summary.hostsDiscovered = discoveredHosts.load();
}

void scanPorts(
    ScanResult& result,
    const Options& options,
    std::atomic<std::size_t>& connectAttempts,
    const Logger& logger) {

    ThreadPool pool(options.threads);
    RateLimiter limiter(options.rateLimitPerSecond);
    std::vector<std::mutex> hostLocks(result.hosts.size());
    std::atomic<std::size_t> openPorts {0};
    std::atomic<std::size_t> bannersCaptured {0};
    std::atomic<std::size_t> hostsScanned {0};
    std::atomic<std::size_t> portsScheduled {0};

    for (std::size_t index = 0; index < result.hosts.size(); ++index) {
        HostRecord& host = result.hosts[index];
        if (!host.active) {
            continue;
        }

        ++hostsScanned;

        for (std::uint16_t port : options.ports) {
            ++portsScheduled;
            pool.enqueue([&, index, port]() {
                ConnectionResult successfulConnection;
                int attemptsUsed = 0;
                if (!tryPortWithRetry(
                        result.hosts[index].ip,
                        port,
                        options,
                        limiter,
                        connectAttempts,
                        &successfulConnection,
                        &attemptsUsed)) {
                    return;
                }

                OpenPort openPort {};
                openPort.port = port;
                openPort.attempts = attemptsUsed;

                if (options.banners) {
                    openPort.banner = captureBanner(successfulConnection.handle, result.hosts[index].ip, port);
                    if (!openPort.banner.empty()) {
                        ++bannersCaptured;
                    }
                }

                closeSocket(successfulConnection.handle);

                {
                    std::lock_guard<std::mutex> lock(hostLocks[index]);
                    result.hosts[index].openPorts.push_back(std::move(openPort));
                }

                ++openPorts;
                logger.log("Porta aberta: " + ipv4ToString(result.hosts[index].ip) + ":" + std::to_string(port));
            });
        }
    }

    pool.waitIdle();

    result.summary.hostsScanned = hostsScanned.load();
    result.summary.portsScheduled = portsScheduled.load();
    result.summary.openPorts = openPorts.load();
    result.summary.bannersCaptured = bannersCaptured.load();

    for (HostRecord& host : result.hosts) {
        std::sort(host.openPorts.begin(), host.openPorts.end(), [](const OpenPort& left, const OpenPort& right) {
            return left.port < right.port;
        });
    }
}

void resolveHostnames(ScanResult& result, const Options& options, const Logger& logger) {
    if (!options.resolveDns) {
        return;
    }

    ThreadPool pool(options.threads);
    std::vector<std::mutex> hostLocks(result.hosts.size());

    for (std::size_t index = 0; index < result.hosts.size(); ++index) {
        if (!result.hosts[index].active) {
            continue;
        }

        pool.enqueue([&, index]() {
            const std::string hostname = resolveHostname(result.hosts[index].ip);
            if (hostname.empty()) {
                return;
            }

            {
                std::lock_guard<std::mutex> lock(hostLocks[index]);
                result.hosts[index].hostname = hostname;
            }
            logger.log("Reverse DNS: " + ipv4ToString(result.hosts[index].ip) + " -> " + hostname);
        });
    }

    pool.waitIdle();
}

std::string jsonEscape(const std::string& value) {
    std::ostringstream escaped;
    for (char ch : value) {
        switch (ch) {
            case '\\':
                escaped << "\\\\";
                break;
            case '"':
                escaped << "\\\"";
                break;
            case '\n':
                escaped << "\\n";
                break;
            case '\r':
                escaped << "\\r";
                break;
            case '\t':
                escaped << "\\t";
                break;
            default:
                escaped << ch;
                break;
        }
    }
    return escaped.str();
}

std::string csvEscape(const std::string& value) {
    std::string escaped = value;
    std::size_t pos = 0;
    while ((pos = escaped.find('"', pos)) != std::string::npos) {
        escaped.insert(pos, 1, '"');
        pos += 2;
    }
    return '"' + escaped + '"';
}

void printSummaryHuman(const ScanResult& result, const Options& options) {
    const auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(result.summary.totalDuration).count();
    const auto discoveryMs = std::chrono::duration_cast<std::chrono::milliseconds>(result.summary.discoveryDuration).count();
    const auto scanMs = std::chrono::duration_cast<std::chrono::milliseconds>(result.summary.scanDuration).count();
    const auto dnsMs = std::chrono::duration_cast<std::chrono::milliseconds>(result.summary.dnsDuration).count();

    std::cout << "Target: " << options.target << "\n";
    std::cout << "Formato: " << outputFormatName(options.outputFormat) << "\n";
    std::cout << "Hosts enumerados: " << result.summary.hostsEnumerated << "\n";
    std::cout << "Hosts ativos: " << result.summary.hostsDiscovered << "\n";
    std::cout << "Hosts escaneados: " << result.summary.hostsScanned << "\n";
    std::cout << "Portas agendadas: " << result.summary.portsScheduled << "\n";
    std::cout << "Tentativas de conexao: " << result.summary.connectAttempts << "\n";
    std::cout << "Portas abertas: " << result.summary.openPorts << "\n";
    std::cout << "Banners capturados: " << result.summary.bannersCaptured << "\n";
    std::cout << "Tempo discovery: " << discoveryMs << " ms\n";
    std::cout << "Tempo scan: " << scanMs << " ms\n";
    std::cout << "Tempo reverse DNS: " << dnsMs << " ms\n";
    std::cout << "Tempo total: " << totalMs << " ms\n\n";
}

void printHuman(const ScanResult& result, const Options& options) {
    printSummaryHuman(result, options);

    bool anyPrinted = false;
    for (const HostRecord& host : result.hosts) {
        if (!host.active) {
            continue;
        }

        anyPrinted = true;
        std::cout << ipv4ToString(host.ip);
        if (!host.hostname.empty()) {
            std::cout << " (" << host.hostname << ')';
        }
        if (host.discoveryPort != 0) {
            std::cout << " [ativo via " << host.discoveryPort << "]";
        }
        std::cout << "\n";

        if (host.openPorts.empty()) {
            std::cout << "  sem portas abertas no perfil atual\n";
            continue;
        }

        for (const OpenPort& openPort : host.openPorts) {
            std::cout << "  " << openPort.port << "/tcp";
            if (openPort.attempts > 1) {
                std::cout << " (tentativa " << openPort.attempts << ")";
            }
            if (!openPort.banner.empty()) {
                std::cout << " -> " << openPort.banner;
            }
            std::cout << "\n";
        }
    }

    if (!anyPrinted) {
        std::cout << "Nenhum host ativo encontrado dentro dos parametros informados.\n";
    }
}

void printJson(const ScanResult& result) {
    std::cout << "{\n";
    std::cout << "  \"summary\": {\n";
    std::cout << "    \"hosts_enumerated\": " << result.summary.hostsEnumerated << ",\n";
    std::cout << "    \"hosts_discovered\": " << result.summary.hostsDiscovered << ",\n";
    std::cout << "    \"hosts_scanned\": " << result.summary.hostsScanned << ",\n";
    std::cout << "    \"ports_scheduled\": " << result.summary.portsScheduled << ",\n";
    std::cout << "    \"connect_attempts\": " << result.summary.connectAttempts << ",\n";
    std::cout << "    \"open_ports\": " << result.summary.openPorts << ",\n";
    std::cout << "    \"banners_captured\": " << result.summary.bannersCaptured << "\n";
    std::cout << "  },\n";
    std::cout << "  \"hosts\": [\n";

    bool firstHost = true;
    for (const HostRecord& host : result.hosts) {
        if (!host.active) {
            continue;
        }

        if (!firstHost) {
            std::cout << ",\n";
        }
        firstHost = false;

        std::cout << "    {\n";
        std::cout << "      \"ip\": \"" << ipv4ToString(host.ip) << "\",\n";
        std::cout << "      \"hostname\": \"" << jsonEscape(host.hostname) << "\",\n";
        std::cout << "      \"discovery_port\": " << host.discoveryPort << ",\n";
        std::cout << "      \"open_ports\": [";

        for (std::size_t index = 0; index < host.openPorts.size(); ++index) {
            const OpenPort& openPort = host.openPorts[index];
            if (index > 0) {
                std::cout << ", ";
            }
            std::cout
                << "{\"port\": " << openPort.port
                << ", \"attempts\": " << openPort.attempts
                << ", \"banner\": \"" << jsonEscape(openPort.banner) << "\"}";
        }

        std::cout << "]\n";
        std::cout << "    }";
    }

    std::cout << "\n  ]\n}\n";
}

void printJsonl(const ScanResult& result) {
    for (const HostRecord& host : result.hosts) {
        if (!host.active) {
            continue;
        }

        std::cout
            << "{\"ip\":\"" << jsonEscape(ipv4ToString(host.ip))
            << "\",\"hostname\":\"" << jsonEscape(host.hostname)
            << "\",\"discovery_port\":" << host.discoveryPort
            << ",\"open_ports\":[";

        for (std::size_t index = 0; index < host.openPorts.size(); ++index) {
            const OpenPort& openPort = host.openPorts[index];
            if (index > 0) {
                std::cout << ',';
            }
            std::cout
                << "{\"port\":" << openPort.port
                << ",\"attempts\":" << openPort.attempts
                << ",\"banner\":\"" << jsonEscape(openPort.banner) << "\"}";
        }

        std::cout << "]}\n";
    }
}

void printCsv(const ScanResult& result) {
    std::cout << "ip,hostname,discovery_port,port,attempts,banner\n";
    for (const HostRecord& host : result.hosts) {
        if (!host.active) {
            continue;
        }

        if (host.openPorts.empty()) {
            std::cout
                << csvEscape(ipv4ToString(host.ip)) << ','
                << csvEscape(host.hostname) << ','
                << host.discoveryPort << ",,,\n";
            continue;
        }

        for (const OpenPort& openPort : host.openPorts) {
            std::cout
                << csvEscape(ipv4ToString(host.ip)) << ','
                << csvEscape(host.hostname) << ','
                << host.discoveryPort << ','
                << openPort.port << ','
                << openPort.attempts << ','
                << csvEscape(openPort.banner) << '\n';
        }
    }
}

void printResult(const ScanResult& result, const Options& options) {
    switch (options.outputFormat) {
        case OutputFormat::human:
            printHuman(result, options);
            break;
        case OutputFormat::json:
            printJson(result);
            break;
        case OutputFormat::jsonl:
            printJsonl(result);
            break;
        case OutputFormat::csv:
            printCsv(result);
            break;
    }
}

ScanResult runScan(const Target& target, const Options& options, const Logger& logger) {
    ScanResult result;
    result.hosts.reserve(static_cast<std::size_t>(target.endIp - target.startIp + 1ULL));
    std::atomic<std::size_t> connectAttempts {0};

    for (std::uint32_t ip = target.startIp; ip <= target.endIp; ++ip) {
        HostRecord host {};
        host.ip = ip;
        result.hosts.push_back(std::move(host));
    }

    result.summary.hostsEnumerated = result.hosts.size();

    const auto discoveryStart = std::chrono::steady_clock::now();
    discoverHosts(result, options, defaultDiscoveryPorts(options.ports), connectAttempts, logger);
    const auto discoveryEnd = std::chrono::steady_clock::now();
    result.summary.discoveryDuration = discoveryEnd - discoveryStart;

    const auto scanStart = std::chrono::steady_clock::now();
    scanPorts(result, options, connectAttempts, logger);
    const auto scanEnd = std::chrono::steady_clock::now();
    result.summary.scanDuration = scanEnd - scanStart;

    const auto dnsStart = std::chrono::steady_clock::now();
    resolveHostnames(result, options, logger);
    const auto dnsEnd = std::chrono::steady_clock::now();
    result.summary.dnsDuration = dnsEnd - dnsStart;

    result.summary.connectAttempts = connectAttempts.load();
    result.summary.totalDuration = discoveryEnd - discoveryStart + (scanEnd - scanStart) + (dnsEnd - dnsStart);
    return result;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const Options options = parseArgs(argc, argv);
        const Target target = parseTarget(options.target);
        const SocketEnvironment socketEnvironment {};
        const Logger logger(options.verbose);

        const ScanResult result = runScan(target, options, logger);
        printResult(result, options);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Erro: " << error.what() << "\n\n";
        printUsage();
        return 1;
    }
}
