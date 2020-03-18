#ifndef EDB_BYTE_VIEW_H_
#define EDB_BYTE_VIEW_H_

#include <cassert>
#include <cstdint>
#include <string>
#include <type_traits>

namespace edb {

class byte_view {
  public:
    using size_type = size_t;
    using byte_type = uint8_t;

    enum class Endianness { little, big };

    byte_view(byte_type *data, size_type size,
              Endianness endian = Endianness::big)
        : data_(data), size_(size), endian_(endian){};

    ~byte_view() {}

    template <typename T> bool is_enough_data(size_type pos) const {
        using type =
            typename std::enable_if<std::is_trivially_copyable<T>::value,
                                    T>::type;

        return is_enough_data(pos, sizeof(type));
    }

    bool is_enough_data(size_type pos, size_type read_size) const {
        return pos <= size_ && read_size <= (size_ - pos);
    }

    void seek(size_type pos) {
        auto rhs = position(pos);

        data_ = rhs.data_;
        size_ = rhs.size_;
    }

    byte_view position(size_type pos) const {
        assert(pos <= size_ && "pos out of bound.");

        return byte_view(data_ + pos, size_ - pos, endian_);
    }

    byte_type *data() const { return data_; }

    size_type size() const { return size_; }

    template <typename T>
    typename std::enable_if<std::is_trivially_copyable<T>::value, T>::type
    read(size_type pos, Endianness endian) const {
        constexpr size_type kTypeSize = sizeof(T);

        assert(pos + kTypeSize <= size_ && "read out of bound.");

        T value;
        byte_type *output = reinterpret_cast<byte_type *>(&value);
        if (endian == endian_) {
            for (size_t i = 0; i < kTypeSize; ++i) {
                output[i] = data_[pos + i];
            }
        } else {
            for (size_t i = 0; i < kTypeSize; ++i) {
                output[(kTypeSize - 1) - i] = data_[pos + i];
            }
        }

        return value;
    }

    template <typename T>
    typename std::enable_if<std::is_trivially_copyable<T>::value, T>::type
    read(size_t pos) const {
        return read<T>(pos, system_endian());
    }

    template <typename T>
    typename std::enable_if<std::is_trivially_copyable<T>::value>::type
    write(size_type pos, T value, Endianness endian) const {
        constexpr size_type kTypeSize = sizeof(T);

        assert(pos + kTypeSize <= size_ && "write out of bound.");

        byte_type *input = reinterpret_cast<byte_type *>(&value);
        if (endian == endian_) {
            for (size_t i = 0; i < kTypeSize; ++i) {
                data_[pos + i] = input[i];
            }
        } else {
            for (size_t i = 0; i < kTypeSize; ++i) {
                data_[pos + (kTypeSize - 1) - i] = input[i];
            }
        }
    }

    template <typename T>
    typename std::enable_if<std::is_trivially_copyable<T>::value>::type
    write(size_type pos, T value) const {
        write<T>(pos, value, system_endian());
    }

  private:
    static Endianness system_endian() {
        union {
            uint32_t i;
            uint8_t c[sizeof(uint32_t)];
        } v = {0x12345678};

        return v.c[0] == 0x78 ? Endianness::little : Endianness::big;
    }

    byte_type *data_;
    size_type size_;
    Endianness endian_;
};

template <typename T> inline bool get_value(byte_view &bv, T &value) {
    if (!bv.is_enough_data<T>(0))
        return false;

    value = bv.read<T>(0);
    bv = bv.position(sizeof(T));

    return true;
}

inline bool get_string(byte_view &bv, std::string &s) {
    char ch;

    s.clear();
    while (bv.is_enough_data<char>(0)) {
        ch = bv.read<char>(0);
        bv = bv.position(1);

        if (ch == '\0')
            return true;

        s.push_back(ch);
    }

    return false;
}
} // namespace edb

#endif /* ifndef EDB_BYTE_VIEW_H_ */
