#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <array>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <secp256k1.h>

struct Result {
    std::string priv_key_hex;
    std::string address_hex;
    int max_consecutive;
    double repetition_percent;
};

std::atomic<bool> stop_flag(false);
std::mutex queue_mutex;
std::queue<Result> result_queue;
std::atomic<uint64_t> counter(0);

void signal_handler(int) {
    stop_flag = true;
}

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return ss.str();
}

int find_max_consecutive(const std::string& s) {
    if (s.empty()) return 0;
    
    int max_count = 1;
    int current_count = 1;
    
    for (size_t i = 1; i < s.length(); ++i) {
        if (s[i] == s[i-1]) {
            current_count++;
            if (current_count > max_count) {
                max_count = current_count;
            }
        } else {
            current_count = 1;
        }
    }
    
    return max_count;
}

double calculate_repetition_percentage(const std::string& s) {
    std::array<int, 256> counts{0};
    for (char c : s) {
        counts[static_cast<unsigned char>(c)]++;
    }
    int max_count = *std::max_element(counts.begin(), counts.end());
    return (max_count * 100.0) / s.length();
}

void keccak_256(uint8_t* output, const uint8_t* input, size_t input_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_MD_fetch(nullptr, "KECCAK-256", nullptr);
    
    if (!md) {
        std::cerr << "KECCAK-256 not available" << std::endl;
        exit(1);
    }
    
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, input, input_len);
    EVP_DigestFinal_ex(ctx, output, nullptr);
    
    EVP_MD_CTX_free(ctx);
    EVP_MD_free((EVP_MD*)md);
}

void secure_random(uint8_t* buffer, size_t size) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/urandom");
        exit(1);
    }
    
    size_t bytes_read = 0;
    while (bytes_read < size) {
        ssize_t result = read(fd, buffer + bytes_read, size - bytes_read);
        if (result <= 0) {
            perror("Error reading from /dev/urandom");
            close(fd);
            exit(1);
        }
        bytes_read += static_cast<size_t>(result);
    }
    close(fd);
}

void worker(int min_consecutive, double min_percent, bool check_percent) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    uint8_t priv_key[32];
    uint8_t pubkey_serialized[65];
    uint8_t hash[32];
    uint8_t address_bytes[20];
    
    while (!stop_flag) {
        secure_random(priv_key, sizeof(priv_key));
        
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key)) continue;
        
        size_t len = 65;
        secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        
        keccak_256(hash, pubkey_serialized + 1, 64);
        
        memcpy(address_bytes, hash + 12, 20);
        std::string address_hex = bytes_to_hex(address_bytes, 20);
        
        int max_consecutive = find_max_consecutive(address_hex);
        double repetition_percent = check_percent ? calculate_repetition_percentage(address_hex) : 0.0;

        counter.fetch_add(1, std::memory_order_relaxed);
        
        bool condition_met = check_percent 
            ? (max_consecutive >= min_consecutive || repetition_percent >= min_percent)
            : (max_consecutive >= min_consecutive);
        
        if (condition_met) {
            std::lock_guard<std::mutex> lock(queue_mutex);
            result_queue.push({ 
                bytes_to_hex(priv_key, 32), 
                address_hex, 
                max_consecutive, 
                repetition_percent 
            });
        }
    }
    secp256k1_context_destroy(ctx);
}

void print_usage(const char* prog_name) {
    std::cerr << "Использование: " << prog_name << " <min_consecutive> [min_percent]\n"
              << "Примеры:\n"
              << "  " << prog_name << " 7        # Поиск последовательностей из 7+ одинаковых символов\n"
              << "  " << prog_name << " 6 40.0   # Последовательности (6+) ИЛИ процент повторений (40.0%+)\n"
              << "По умолчанию: min_consecutive=10\n";
}

int main(int argc, char* argv[]) {
    int min_consecutive = 10;
    double min_percent = 0.0;
    bool check_percent = false;

    if (argc > 1) {
        if (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
            print_usage(argv[0]);
            return 0;
        }
        
        try {
            min_consecutive = std::stoi(argv[1]);
            if (argc > 2) {
                min_percent = std::stod(argv[2]);
                check_percent = true;
            }
        } catch (const std::exception& e) {
            std::cerr << "Ошибка: неверные параметры\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    const unsigned num_threads = std::thread::hardware_concurrency();
    std::signal(SIGINT, signal_handler);
    std::vector<std::thread> threads;
    
    std::cout << "[🔍] Поиск адресов с параметрами:\n"
              << " - Минимальная длина последовательности: " << min_consecutive << "+ одинаковых символов\n";
    if (check_percent) {
        std::cout << " - Минимальный процент повторений: " << min_percent << "%\n";
    } else {
        std::cout << " - Поиск только по последовательностям (процент не учитывается)\n";
    }
    std::cout << " - Потоков: " << num_threads << "\n";
    std::cout << "Нажми Ctrl+C для остановки\n\n";
    
    for (unsigned i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker, min_consecutive, min_percent, check_percent);
    }
    
    std::ofstream outfile("extreme_addresses.txt", std::ios::app);
    uint64_t last_counter = 0;
    auto last_time = std::chrono::steady_clock::now();
    
    while (!stop_flag) {
        std::queue<Result> local_queue;
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (!result_queue.empty()) {
                local_queue.swap(result_queue);
            }
        }
        
        while (!local_queue.empty()) {
            auto res = local_queue.front();
            std::cout << "\n[🎉] Найден адрес: 0x" << res.address_hex << "\n"
                      << "Приватный ключ: " << res.priv_key_hex << "\n"
                      << "Максимальная последовательность: " << res.max_consecutive << " символов\n";
            if (check_percent) {
                std::cout << "Процент повторений: " << res.repetition_percent << "%\n";
            }
            
            outfile << "0x" << res.address_hex << "," << res.priv_key_hex << "," 
                    << res.max_consecutive << "," << res.repetition_percent << "\n";
            outfile.flush();
            local_queue.pop();
        }
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_time);
        if (elapsed.count() >= 1) {
            uint64_t current = counter.load();
            uint64_t diff = current - last_counter;
            double speed = static_cast<double>(diff) / elapsed.count();
            last_counter = current;
            last_time = now;
            
            std::cout << "✅ Проверено: " << current << " адресов | ⚡ Скорость: " 
                      << static_cast<uint64_t>(speed) << " адр/сек"
                      << "\r" << std::flush;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    for (auto& t : threads) {
        t.join();
    }
    std::cout << "\n\n🛑 Остановлен.\n Результаты сохранены в extreme_addresses.txt\n";
    return 0;
}