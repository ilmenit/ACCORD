#pragma once

#include <iostream>
#include <functional>               // std::function
#include <stdint.h>                 // uint64_t
#include <unordered_map>            // std::unordered_map
#include <utility>                  // std::move    
#include <vector>                   // std::vector

namespace accord {

    template<typename T>
    class event
    {
        using callback = std::function<void(T&)>;

    public:
        enum Id : uint64_t {};

    private:
        std::unordered_map<uint64_t, callback> m_callbacks;

        static auto id_value()
            -> uint64_t&
        {
            static uint64_t the_id;
            return the_id;
        }

    public:
        auto add_listener(callback cb)
            -> Id
        {
            const auto id = Id(++id_value());
            m_callbacks.emplace(id, move(cb));
            return id;
        }

        auto remove_listener(const Id id)
            -> bool
        {
            const auto it = m_callbacks.find(id);
            if (it == m_callbacks.end())
            {
                return false;
            }
            m_callbacks.erase(it);
            return true;
        }

        void notify_all(T& argument) const
        {
            for (const auto& pair : m_callbacks)
            {
                pair.second(argument);
            }
        }
    };

}
