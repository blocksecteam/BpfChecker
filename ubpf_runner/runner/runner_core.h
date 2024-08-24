#ifndef UBPF_RUNNER_RUNNER_CORE_H
#define UBPF_RUNNER_RUNNER_CORE_H

#include <string>
#include <optional>
#include <utility>

class ErrorReason {
public:
    ErrorReason(std::string content, bool is_runtime_err) : content(std::move(content)),
                                                            is_runtime_err(is_runtime_err) {};
    bool is_runtime_err;
    std::string content;

    bool operator==(const ErrorReason &other) const {
        return this->is_runtime_err == other.is_runtime_err && this->content == other.content;
    }

    bool operator!=(const ErrorReason &other) const {
        return !(*this == other);
    }

    explicit operator std::string() const {
        std::string result = "[is runtime error: ";
        result.append(this->is_runtime_err ? "true] " : "false] ");
        result.append(this->content);
        return result;
    }
};

inline std::ostream &operator<<(std::ostream &Str, ErrorReason const &v) {
    // print something from v to str, e.g: Str << v.getX();
    return Str;
}

struct RunResult {
    uint64_t registers_value[10] = {0};
    std::optional<ErrorReason> err_reason = std::nullopt;

    std::string get_reason_content() {
        if (this->err_reason.has_value()) {
            return {this->err_reason.value()};
        } else {
            return {"None"};
        }
    }
};

void run_with_interpreted(const std::string &code_content, RunResult &);

void run_with_interpreted(const char *data, size_t data_size, RunResult &result);

void run_with_jit(const std::string &code_content, RunResult &);

void run_with_jit(const char *data, size_t data_size, RunResult &);

#endif //UBPF_RUNNER_RUNNER_CORE_H
