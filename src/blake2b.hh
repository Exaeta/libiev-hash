/* 
 
 Copyright 2017, Ryan Nicholl <r.p.nicholl@gmail.com>

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef IEV_BLAKE2B_HASH_HH
#define IEV_BLAKE2B_HASH_HH


#include <sodium.h>
#include <array>
#include <vector>

namespace iev
{
  template <size_t N>
  class blake2b
    : public std::array<uint8_t, N/8>
  {
    static_assert(N%8==0,"Unsupported");
    //  public:
  public:

    blake2b()
      : std::array<uint8_t, N/8>()
    {}


    explicit blake2b(std::array<uint8_t, N/8> const & other)
      : std::array<uint8_t, N/8>(other)
    {
    }

    blake2b(blake2b<N>&&)=default;
    blake2b(blake2b<N> const&)=default;
    blake2b& operator=(blake2b<N> const &)=default; 
    blake2b& operator=(blake2b<N> &&)=default; 




    class incremental_hasher
    {
      ::crypto_generichash_blake2b_state private_state;

    public:


      incremental_hasher(uint8_t const * key, size_t keylen)
      {
        ::crypto_generichash_blake2b_init(&private_state, key, keylen, N/8);
      }

      void update(uint8_t const * data, size_t datalen)
      {
        ::crypto_generichash_blake2b_update(&private_state, data, datalen);
      }

      blake2b<N> finalize()
      {
        blake2b<N> output;

        ::crypto_generichash_blake2b_final(&private_state, output.data(), output.size());

        return output;
      }
    };

    
    template <typename It>
    static blake2b<N> calculate(It begin, It end, uint8_t const *key, size_t keysize)
    {
      std::vector<uint8_t> data;
      data.assign(begin, end);
      blake2b<N> hash;
      blake2b<N>::incremental_hasher hasher(key, keysize);
      hasher.update(data.data(), data.size());
      hash = hasher.finalize();
      return hash;
    }
  };
}

#endif
