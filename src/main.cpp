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
#include <openssl/rand.h>
#include <openssl/err.h>
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

int find_max_consecutive(const std::string& s, bool search_from_end = false) {
    if (s.empty()) return 0;
    if (search_from_end) {
        int count = 1;
        char last_char = s[s.size() - 1];
        for (int i = s.size() - 2; i >= 0; i--) {
            if (s[i] == last_char) {
                count++;
            } else {
                break;
            }
        }
        return count;
    } else {
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
    if (RAND_bytes(buffer, size) != 1) {
        unsigned long err_code = ERR_get_error();
        const char* err_str = ERR_error_string(err_code, nullptr);
        
        std::cerr << "Ошибка генерации случайных чисел: " << err_str << std::endl;
        exit(1);
    }
}

void worker(int min_consecutive, double min_percent, bool check_percent, bool search_from_end) {
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
        
        int max_consecutive = find_max_consecutive(address_hex, search_from_end);
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
    std::cerr << "Генератор Ethereum-адресов с заданными паттернами\n\n"; 
    std::cerr << "Использование: " << prog_name << " [ОПЦИИ] [min_consecutive] [min_percent]\n\n";
    
    std::cerr << "Опции:\n";
    std::cerr << "  -e, --end     Искать последовательность в КОНЦЕ адреса\n";
    std::cerr << "  -h, --help    Показать эту справку\n\n";
    
    std::cerr << "Параметры:\n";
    std::cerr << "  min_consecutive  Минимальная длина последовательности (целое число, по умолчанию: 10)\n";
    std::cerr << "  min_percent      Минимальный процент повторений (дробное число, необязательно)\n\n";
    
    std::cerr << "Примеры:\n";
    std::cerr << "  " << prog_name << " 7           # Поиск 7+ одинаковых символов\n";
    std::cerr << "  " << prog_name << " 6 40.0      # 6+ символов ИЛИ 40% повторений\n";
    std::cerr << "  " << prog_name << " -e 8        # 8+ символов в КОНЦЕ адреса\n";
    std::cerr << "  " << prog_name << " --end 5 30  # 5+ символов в КОНЦЕ ИЛИ 30% повторений\n";
    std::cerr << "  " << prog_name << " 5 25 -e     # Комбинированный вариант (порядок не важен)\n\n";
    
    std::cerr << "Примечание:\n";
    std::cerr << "  - Значения по умолчанию: min_consecutive=7, min_percent=0.0\n";
    std::cerr << "  - Флаги (-e/--end) можно указывать в любом месте командной строки\n";
    std::cerr << "  - Результаты сохраняются в файл 'extreme_addresses.txt'\n";
    std::cerr << "  - Для остановки программы нажми Ctrl+C\n";
}

int main(int argc, char* argv[]) {
    int min_consecutive = 7;
    double min_percent = 0.0;
    bool check_percent = false;
    bool search_from_end = false;
    
    // Вектор для позиционных числовых аргументов
    std::vector<std::string> positional_args;

    // Парсинг аргументов командной строки
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--end" || arg == "-e") {
            search_from_end = true;
        } else {
            positional_args.push_back(arg);
        }
    }

    try {
        if (positional_args.size() >= 1) {
            min_consecutive = std::stoi(positional_args[0]);
        }
        if (positional_args.size() >= 2) {
            min_percent = std::stod(positional_args[1]);
            check_percent = true;
        }
        if (positional_args.size() > 2) {
            std::cerr << "Ошибка: слишком много позиционных аргументов\n";
        }
    } catch (const std::exception&) {
        std::cerr << "Ошибка: неверный формат аргументов\n";
        return 1; 
    }

    const unsigned num_threads = std::thread::hardware_concurrency();
    std::signal(SIGINT, signal_handler);
    std::vector<std::thread> threads;

    std::cout   << "🔍 Параметры поиска:\n"
                << " ├─ Минимальная длина последовательности: " << min_consecutive << "\n"
                << " ├─ Область поиска: " << (search_from_end ? "конец адреса" : "вся длина адреса") << "\n"
                << " └─ Критерий: " << (check_percent ? "повторы " + std::to_string(min_percent) + "%+" : "только последовательности") << "\n\n"
                
                << " • Потоков: " << num_threads << "\n"
                << "ℹ️ Нажми Ctrl+C для остановки\n\n";
    
    for (unsigned i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker, min_consecutive, min_percent, check_percent, search_from_end);
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
            std::cout << "\n🎉 Найден адрес: 0x" << res.address_hex << "\n"
                      << " • Приватный ключ: " << res.priv_key_hex << "\n"
                      << " • Максимальная последовательность: " << res.max_consecutive << " символов\n";
            if (check_percent) {
                std::cout << " • Процент повторений: " << res.repetition_percent << "%\n";
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