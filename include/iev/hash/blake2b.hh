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
