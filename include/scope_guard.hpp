/*
    Copyright (c) 2020, Kenn Takara.  All rights reserved.
 */


#include <utility>
#include <type_traits>

#ifndef INCLUDE_ENGINEGG_COMMON_SCOPE_GUARD
#define INCLUDE_ENGINEGG_COMMON_SCOPE_GUARD

namespace paseto {

//
// https://codereview.stackexchange.com/questions/134234/on-the-fly-destructors
//
template<class F>
auto on_scope_exit( F&& f )
    noexcept( std::is_nothrow_move_constructible<F>::value )
{
    class unique_scope_exit_t final
    {
        F f_;

    public:
        ~unique_scope_exit_t()
            noexcept( noexcept( f_() ) )
        {
            f_();
        }

        explicit unique_scope_exit_t( F&& f )
            noexcept( std::is_nothrow_move_constructible<F>::value )
            : f_( std::move( f ) )
        {}

        unique_scope_exit_t( unique_scope_exit_t&& rhs )
            noexcept( std::is_nothrow_move_constructible<F>::value )
            : f_{ std::move( rhs.f_ ) }
        {}

        unique_scope_exit_t( unique_scope_exit_t const& ) = delete;
        unique_scope_exit_t& operator=( unique_scope_exit_t const& ) = delete;
        unique_scope_exit_t& operator=( unique_scope_exit_t&& ) = delete;
    };
    return unique_scope_exit_t{ std::move( f ) };
}

}; // namespace paseto

#endif /* INCLUDE_ENGINEGG_COMMON_SCOPE_GUARD */

