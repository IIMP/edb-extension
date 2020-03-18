#ifndef EDB_SCOPE_PTR_H_
#define EDB_SCOPE_PTR_H_

#include <cstdlib>
#include <functional>
#include <memory>

namespace edb {

template <typename T>
auto make_scope_ptr(T *ptr, std::function<void(T *)> deleter = std::free)
    -> std::unique_ptr<T, decltype(deleter)> {
    return std::unique_ptr<T, decltype(deleter)>(ptr, deleter);
}

} // namespace edb
#endif /* ifndef EDB_SCOPE_PTR_H_ */
