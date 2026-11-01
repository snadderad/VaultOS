#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <termios.h>
#include <csignal>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <filesystem>
#include <stdexcept>
#include <system_error>

namespace fs = std::filesystem;

// ─── Memory safety ───────────────────────────────────────────────────────────

static inline void wipe(void* s, size_t n) {
    volatile unsigned char* p = (unsigned char*)s;
    while (n--) *p++ = 0;
}

// ─── RAII Terminal State Manager ─────────────────────────────────────────────

class TerminalNoEcho {
    struct termios m_old;
    bool m_applied = false;

public:
    TerminalNoEcho() {
        if (tcgetattr(STDIN_FILENO, &m_old) == 0) {
            struct termios t = m_old;
            t.c_lflag &= ~ECHO;
            if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) == 0) {
                m_applied = true;
            }
        }
    }

    ~TerminalNoEcho() {
        if (m_applied) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &m_old);
        }
    }

    // Prevent copy
    TerminalNoEcho(const TerminalNoEcho&) = delete;
    TerminalNoEcho& operator=(const TerminalNoEcho&) = delete;
};

// ─── Globals ─────────────────────────────────────────────────────────────────

static char g_pass[512] = { 0 };
const int MAX_ATTEMPTS = 10;
const char* MOUNT_POINT = "/data";
const char* DEVICE = "vault.img";  // LUKS encrypted image
const char* VAULT_MAPPER = "securevault";
static volatile std::sig_atomic_t g_shutdown_requested = 0;
static bool g_mapper_open = false;
static bool g_vault_mounted = false;

int run_command(const std::vector<std::string>& args, const std::string* stdin_data = nullptr) {
    if (args.empty()) return -1;

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    int input_pipe[2] = { -1, -1 };
    if (stdin_data && pipe(input_pipe) != 0) return -1;

    pid_t child = fork();
    if (child < 0) {
        if (stdin_data) {
            close(input_pipe[0]);
            close(input_pipe[1]);
        }
        return -1;
    }

    if (child == 0) {
        if (stdin_data) {
            close(input_pipe[1]);
            if (dup2(input_pipe[0], STDIN_FILENO) < 0) _exit(126);
            close(input_pipe[0]);
        }
        std::signal(SIGPIPE, SIG_DFL);
        execvp(argv[0], argv.data());
        _exit(127);
    }

    bool input_written = true;
    if (stdin_data) {
        close(input_pipe[0]);
        size_t offset = 0;
        while (offset < stdin_data->size()) {
            ssize_t count = write(input_pipe[1], stdin_data->data() + offset,
                stdin_data->size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) {
                input_written = false;
                break;
            }
            offset += static_cast<size_t>(count);
        }
        close(input_pipe[1]);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return -1;
    }

    if (!input_written || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

bool mount_source_at_data(std::string& source) {
    source.clear();
    std::ifstream mounts("/proc/self/mounts");
    if (!mounts) return false;

    std::string mount_source;
    std::string mount_target;
    std::string filesystem;
    std::string options;
    int dump_frequency = 0;
    int pass_number = 0;
    while (mounts >> mount_source >> mount_target >> filesystem >> options
        >> dump_frequency >> pass_number) {
        if (mount_target == MOUNT_POINT) {
            source = mount_source;
            break;
        }
    }
    return true;
}

bool vault_mount_active() {
    std::string source;
    return g_vault_mounted && mount_source_at_data(source)
        && source == std::string("/dev/mapper/") + VAULT_MAPPER;
}

bool mount_point_available() {
    std::string source;
    return mount_source_at_data(source) && source.empty();
}

// ─── Cleanup on exit ────────────────────────────────────────────────────────

bool cleanup() {
    wipe(g_pass, sizeof(g_pass));

    if (g_vault_mounted) {
        std::string source;
        if (!mount_source_at_data(source)) {
            std::cerr << "  [!] Cannot verify the /data mount; leaving vault open.\n";
            return false;
        }
        if (!source.empty() && source != std::string("/dev/mapper/") + VAULT_MAPPER) {
            std::cerr << "  [!] /data is mounted from another device; leaving it untouched.\n";
            return false;
        }
        if (!source.empty() && run_command({ "umount", MOUNT_POINT }) != 0) {
            std::cerr << "  [!] Failed to unmount the vault; leaving it open.\n";
            return false;
        }
        g_vault_mounted = false;
    }

    if (g_mapper_open) {
        if (run_command({ "cryptsetup", "close", VAULT_MAPPER }) != 0) {
            std::cerr << "  [!] Failed to close the vault mapping.\n";
            return false;
        }
        g_mapper_open = false;
    }
    return true;
}

// ─── Signal handler: defer cleanup until normal control flow ────────────────

void handle_signal(int) {
    g_shutdown_requested = 1;
}

// ─── Validate filename: prevent path traversal ───────────────────────────────

bool is_valid_filename(const std::string& filename) {
    if (filename.empty() || filename.length() > 255) return false;
    if (filename.find('/') != std::string::npos) return false;
    if (filename.find("..") != std::string::npos) return false;
    if (filename.find('\0') != std::string::npos) return false;
    if (filename[0] == '.') return false;  // Hide hidden files

    // Whitelist: only .txt and .md
    if (filename.length() >= 4 && filename.substr(filename.length() - 4) == ".txt") return true;
    if (filename.length() >= 3 && filename.substr(filename.length() - 3) == ".md") return true;
    
    return false;
}

// ─── Safe path construction ──────────────────────────────────────────────────

std::string safe_path(const std::string& filename) {
    if (!is_valid_filename(filename)) {
        throw std::invalid_argument("Invalid filename");
    }
    return std::string(MOUNT_POINT) + "/" + filename;
}

// ─── UI helpers ──────────────────────────────────────────────────────────────

void clear_screen() {
    std::cout << "\033[2J\033[H";
}

void print_header() {
    std::cout << "\n";
    std::cout << "  ╔══════════════════════════════════════╗\n";
    std::cout << "  ║      SecureVault OS  v2.0 (H)        ║\n";
    std::cout << "  ║   Air-gapped encrypted vault [FIX]   ║\n";
    std::cout << "  ╚══════════════════════════════════════╝\n\n";
}

void print_line() {
    std::cout << "  ────────────────────────────────────────\n";
}

// ─── Passphrase input (no echo, RAII-protected) ──────────────────────────────

bool get_passphrase(const char* prompt) {
    TerminalNoEcho no_echo;
    std::cout << "  " << prompt;
    std::cout.flush();

    std::cin.getline(g_pass, sizeof(g_pass));

    // Check for overflow
    if (std::cin.fail()) {
        if (g_shutdown_requested) {
            wipe(g_pass, sizeof(g_pass));
            return false;
        }
        std::cin.clear();
        std::cin.ignore(10000, '\n');
        std::cout << "\n  [!] Passphrase too long (max 511 characters).\n";
        wipe(g_pass, sizeof(g_pass));
        return false;
    }

    std::cout << "\n";
    return strlen(g_pass) > 0;
}

// ─── LUKS unlock (passphrase is sent through child stdin) ────────────────────

bool luks_unlock() {
    std::error_code filesystem_error;
    if (!fs::is_directory(MOUNT_POINT, filesystem_error) || filesystem_error
        || !mount_point_available()) {
        std::cerr << "  [!] /data must be an existing, unmounted directory.\n";
        return false;
    }

    std::string passphrase(g_pass);
    wipe(g_pass, sizeof(g_pass));
    int unlock_status = run_command(
        { "cryptsetup", "open", DEVICE, VAULT_MAPPER, "--key-file=-" }, &passphrase);
    wipe(passphrase.data(), passphrase.size());
    if (unlock_status != 0) {
        return false;
    }
    g_mapper_open = true;

    int mount_status = run_command({ "mount",
        std::string("/dev/mapper/") + VAULT_MAPPER, MOUNT_POINT });
    std::string source;
    if (mount_status == 0 && mount_source_at_data(source)
        && source == std::string("/dev/mapper/") + VAULT_MAPPER) {
        g_vault_mounted = true;
        return true;
    }

    cleanup();
    return false;
}

void luks_lock() {
    clear_screen();
    print_header();
    std::cout << "  [*] Locking vault...\n \n";

    if (cleanup()) {
        std::cout << "\n  [+] Vault locked.\n";
    }
}

// ─── Wipe regular files in the vault ────────────────────────────────────────

void wipe_vault() {
    clear_screen();
    print_header();
    std::cout << "  [!] WARNING: This will permanently destroy all vault data.\n";
    std::cout << "  [!] This cannot be undone.\n\n";
    std::cout << "  Type CONFIRM to proceed: ";
    std::string confirm;
    std::getline(std::cin, confirm);

    if (confirm != "CONFIRM") {
        std::cout << "\n  [-] Wipe cancelled.\n";
        return;
    }

    if (!vault_mount_active()) {
        std::cout << "\n  [!] Verified vault mount is not active; nothing was wiped.\n";
        return;
    }

    std::cout << "\n  [*] Wiping vault files... this may take a while.\n";
    bool wipe_succeeded = true;

    try {
        for (const auto& entry : fs::directory_iterator(MOUNT_POINT)) {
            if (fs::is_regular_file(entry.symlink_status())) {
                if (!vault_mount_active()
                    || run_command({ "shred", "-f", "-z", "-n", "7", "--",
                        entry.path().string() }) != 0) {
                    wipe_succeeded = false;
                    std::cerr << "  [!] Failed to wipe " << entry.path().filename().string() << ".\n";
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "  [!] Error during wipe: " << e.what() << "\n";
        wipe_succeeded = false;
    }

    if (wipe_succeeded) {
        std::cout << "\n  [+] Wipe commands completed for regular files.\n";
    } else {
        std::cout << "\n  [!] Wipe was incomplete; see errors above.\n";
    }
}

// ─── File browser ────────────────────────────────────────────────────────────

std::vector<std::string> list_files() {
    std::vector<std::string> files;
    if (!vault_mount_active()) return files;

    try {
        DIR* dir = opendir(MOUNT_POINT);
        if (!dir) return files;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string name = entry->d_name;
            if (name == "." || name == "..") continue;
            if (is_valid_filename(name)) {
                struct stat file_info {};
                std::string path = std::string(MOUNT_POINT) + "/" + name;
                if (lstat(path.c_str(), &file_info) == 0 && S_ISREG(file_info.st_mode)) {
                    files.push_back(name);
                }
            }
        }
        closedir(dir);
    } catch (...) {
        // Silent failure, return empty list
    }
    return files;
}

void view_file(const std::string& filename) {
    try {
        if (!vault_mount_active()) {
            std::cout << "\n  [!] Verified vault mount is not active.\n";
            return;
        }
        std::string path = safe_path(filename);
        struct stat file_info {};
        if (lstat(path.c_str(), &file_info) != 0 || !S_ISREG(file_info.st_mode)) {
            std::cout << "\n  [!] File is unavailable or is not a regular file.\n";
            return;
        }
        std::ifstream f(path);
        if (!f.is_open()) {
            std::cout << "\n  [!] Cannot open file.\n";
            return;
        }

        clear_screen();
        print_header();
        print_line();
        std::cout << "  " << filename << "\n";
        print_line();

        std::string line;
        while (std::getline(f, line)) {
            std::cout << "  " << line << "\n";
        }
        f.close();

        print_line();
        std::cout << "\n  Press Enter to go back...";
        std::cin.get();
    } catch (const std::exception& e) {
        std::cout << "\n  [!] Error: " << e.what() << "\n";
    }
}

void new_file() {
    std::cout << "\n  Filename (e.g. notes.txt): ";
    std::string name;
    std::getline(std::cin, name);

    const size_t first = name.find_first_not_of(" \t");
    if (first == std::string::npos) {
        name.clear();
    } else {
        const size_t last = name.find_last_not_of(" \t");
        name = name.substr(first, last - first + 1);
    }

    if (!is_valid_filename(name)) {
        std::cout << "\n  [!] Invalid filename.\n";
        std::cout << "  [!] Requirements:\n";
        std::cout << "      - Must end with .txt or .md\n";
        std::cout << "      - No slashes, no '..', and cannot start with a dot\n";
        std::cout << "      - Max 255 characters\n";
        return;
    }

    try {
        if (!vault_mount_active()) {
            std::cout << "\n  [!] Verified vault mount is not active.\n";
            return;
        }

        std::string path = safe_path(name);
        
        // Check if file already exists
        if (access(path.c_str(), F_OK) == 0) {
            std::cout << "\n  [!] File already exists.\n";
            return;
        }

        std::ofstream f(path);
        if (!f.is_open()) {
            std::cout << "\n  [!] Cannot create file (permission denied).\n";
            return;
        }

        std::cout << "  Enter content. Type END on a new line to save.\n\n";
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line == "END") break;
            f << line << "\n";
        }
        f.close();

        // Set restrictive permissions (owner read/write only)
        chmod(path.c_str(), S_IRUSR | S_IWUSR);

        std::cout << "\n  [+] File saved: " << name << "\n";
        std::cout << "  [*] Press Enter to continue...\n";
        std::cin.get();
    } catch (const std::exception& e) {
        std::cout << "\n  [!] Error: " << e.what() << "\n";
    }
}

void delete_file(const std::string& filename) {
    if (!vault_mount_active()) {
        std::cout << "  [!] Verified vault mount is not active.\n";
        return;
    }

    std::cout << "\n  Delete '" << filename << "'? (yes/no): ";
    std::string confirm;
    std::getline(std::cin, confirm);

    if (confirm != "yes") {
        std::cout << "  [-] Cancelled.\n";
        return;
    }

    try {
        std::string path = safe_path(filename);
        struct stat file_info {};
        if (lstat(path.c_str(), &file_info) != 0 || !S_ISREG(file_info.st_mode)) {
            std::cout << "  [!] File is unavailable or is not a regular file.\n";
            return;
        }

        if (!vault_mount_active()
            || run_command({ "shred", "-f", "-z", "-n", "7", "--", path }) != 0) {
            std::cout << "  [!] Wipe failed; file was not removed.\n";
            return;
        }

        if (unlink(path.c_str()) == 0) {
            std::cout << "  [+] File removed after shred completed.\n";
        } else {
            std::cout << "  [!] Shred completed, but the file could not be removed.\n";
        }
    } catch (const std::exception& e) {
        std::cout << "  [!] Error: " << e.what() << "\n";
    }
}

// ─── File browser menu ───────────────────────────────────────────────────────

void file_menu() {
    while (!g_shutdown_requested) {
        clear_screen();
        print_header();

        auto files = list_files();

        std::cout << "  Files in vault:\n";
        print_line();
        if (files.empty()) {
            std::cout << "  (no files)\n";
        } else {
            for (size_t i = 0; i < files.size(); i++)
                std::cout << "  [" << i + 1 << "] " << files[i] << "\n";
        }
        print_line();
        std::cout << "  [N] New file\n";
        std::cout << "  [D] Delete file\n";
        std::cout << "  [L] Lock vault and exit\n";
        std::cout << "  [W] Wipe vault\n";
        print_line();

        std::cout << "\n  Choice: ";
        std::string input;
        if (!std::getline(std::cin, input)) return;

        if (input == "N" || input == "n") {
            new_file();
        } else if (input == "L" || input == "l") {
            luks_lock();
            return;
        } else if (input == "W" || input == "w") {
            wipe_vault();
            return;
        } else if (input == "D" || input == "d") {
            if (files.empty()) {
                std::cout << "\n  [!] No files to delete.\n";
            } else {
                std::cout << "\n  File number to delete: ";
                std::string num;
                std::getline(std::cin, num);
                try {
                    int idx = std::stoi(num) - 1;
                    if (idx >= 0 && idx < (int)files.size()) {
                        delete_file(files[idx]);
                    } else {
                        std::cout << "  [!] Invalid number.\n";
                    }
                } catch (...) {
                    std::cout << "  [!] Invalid input.\n";
                }
            }
            sleep(1);
        } else {
            // Try to open file by number
            try {
                int idx = std::stoi(input) - 1;
                if (idx >= 0 && idx < (int)files.size()) {
                    view_file(files[idx]);
                } else {
                    std::cout << "\n  [!] Invalid choice.\n";
                }
            } catch (...) {
                std::cout << "\n  [!] Invalid input.\n";
            }
            sleep(1);
        }
    }
}

// ─── Main unlock loop ────────────────────────────────────────────────────────

int main() {
    // Set restrictive umask (rw-------, rwx------)
    umask(0077);

    struct sigaction action {};
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
    std::signal(SIGPIPE, SIG_IGN);

    int attempts = 0;

    while (attempts < MAX_ATTEMPTS && !g_shutdown_requested) {
        clear_screen();
        print_header();

        int remaining = MAX_ATTEMPTS - attempts;
        if (attempts > 0) {
            std::cout << "  [!] Failed attempts: " << attempts
                << " / " << MAX_ATTEMPTS << "\n\n";
        }

        std::cout << "  Attempts remaining: " << remaining << "\n";
        print_line();

        if (!get_passphrase("Passphrase: ")) {
            if (g_shutdown_requested) break;
            std::cout << "\n  [!] No passphrase entered.\n";
            attempts++;
            sleep(1);
            continue;
        }

        std::cout << "\n  [*] Unlocking vault...\n";

        if (luks_unlock()) {
            wipe(g_pass, sizeof(g_pass));
            std::cout << "  [+] Vault unlocked.\n";
            sleep(1);
            file_menu();
            return cleanup() ? 0 : 1;
        }

        attempts++;
        wipe(g_pass, sizeof(g_pass));
        std::cout << "\n  [!] Vault unlock or mount failed.\n";
        sleep(2);  // Slow down brute-force
    }

    clear_screen();
    print_header();
    if (g_shutdown_requested) {
        std::cout << "  [*] Interrupted. The vault was not automatically destroyed.\n";
    } else {
        std::cout << "  [!] Maximum unlock attempts reached. The vault was not destroyed.\n";
    }
    return cleanup() ? (g_shutdown_requested ? 130 : 1) : 1;
}
