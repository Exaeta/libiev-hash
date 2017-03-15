
/*  
    Modifications Copyright (c) 2016, 2017 Ryan P. Nicholl
    All Rights Reserved

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Original code:

    2008-09-13  D. J. Bernstein
    Public domain.
 
*/

#ifndef IEV_HASH_SHA512_HH
#define IEV_HASH_SHA512_HH

#include <array>
#include <inttypes.h>

//#define big_sigma0(x) (rotate_right(x,28) ^ rotate_right(x,34) ^ rotate_right(x,39))
namespace iev
{
  class sha512 
    : std::array<uint8_t, 512/8>
  {

    
    static uint64_t load_bigendian64(const unsigned char *x)
    {
      return
        (uint64_t) (x[7]) \
        | (((uint64_t) (x[6])) << 8) \
        | (((uint64_t) (x[5])) << 16) \
        | (((uint64_t) (x[4])) << 24) \
        | (((uint64_t) (x[3])) << 32) \
        | (((uint64_t) (x[2])) << 40) \
        | (((uint64_t) (x[1])) << 48) \
        | (((uint64_t) (x[0])) << 56)
        ;
    }

    static void store_bigendian64(unsigned char *x,uint64_t u)
    {
      x[7] = u; u >>= 8;
      x[6] = u; u >>= 8;
      x[5] = u; u >>= 8;
      x[4] = u; u >>= 8;
      x[3] = u; u >>= 8;
      x[2] = u; u >>= 8;
      x[1] = u; u >>= 8;
      x[0] = u;
    }

    template <typename T>
    static constexpr T shift_right(T x, int c)
    {
      return x >> c;
    }


    //#define rotate_right(x,c) (((x) >> (c)) | ((x) << (64 - (c))))
    //    template <typename T>
    static constexpr auto rotate_right(uint64_t x, int c)
    {
      return (((x) >> (c)) | ((x) << (64 - (c))));
    }

    // Ch
    //#define ch(x,y,z) ((x & y) ^ (~x & z))
    //template <typename T>
    static constexpr auto ch(uint64_t x, uint64_t y, uint64_t z)
    {
      return ((x & y) ^ (~x & z));
    }

    // Maj
    //#define maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
    template <typename T>
    static constexpr T maj(T x, T y, T z)
    {
      return ((x & y) ^ (x & z) ^ (y & z));
    }


    template <typename T>
    static inline constexpr auto big_sigma0(T x) -> T
    {
      return (rotate_right(x,28) ^ rotate_right(x,34) ^ rotate_right(x,39));
    }

    template <typename T>
    static inline constexpr auto big_sigma1(T x) -> T
    {
      return (rotate_right(x,14) ^ rotate_right(x,18) ^ rotate_right(x,41));
    }


    template <typename T>
    static constexpr inline auto small_sigma0(T x) -> T
    {
      return (rotate_right(x, 1) ^ rotate_right(x, 8) ^ shift_right(x,7));
    }


    template <typename T>
    static constexpr inline auto small_sigma1(T x) -> T
    {
      return (rotate_right(x,19) ^ rotate_right(x,61) ^ shift_right(x,6));
    }

  public:

    sha512()
      : std::array<uint8_t, 512/8>()
    {}


    explicit sha512(std::array<uint8_t, 512/8> const & other)
      : std::array<uint8_t, 512/8>(other)
    {
    }

    sha512(sha512 &&)=default;
    sha512(sha512 const&)=default;
    sha512& operator=(sha512 const &)=default; 
    sha512& operator=(sha512 &&)=default; 


    static inline sha512 calculate(const unsigned char *in, unsigned long long inlen) 
    {
      using namespace sha512_detail;
  
      using block_t = uint8_t [64];

      auto  sha512_blocks = [](block_t & statebytes, uint8_t const *in, size_t inlen)
        {
      
          auto m = [](auto & a, auto b, auto c, auto d)
          {
            a += small_sigma1(b) + c + small_sigma0(d);
          };


          uint64_t state[8];
          uint64_t a;
          uint64_t b;
          uint64_t c;
          uint64_t d;
          uint64_t e;
          uint64_t f;
          uint64_t g;
          uint64_t h;
          uint64_t T1;
          uint64_t T2;

          a = load_bigendian64(statebytes +  0); state[0] = a;
          b = load_bigendian64(statebytes +  8); state[1] = b;
          c = load_bigendian64(statebytes + 16); state[2] = c;
          d = load_bigendian64(statebytes + 24); state[3] = d;
          e = load_bigendian64(statebytes + 32); state[4] = e;
          f = load_bigendian64(statebytes + 40); state[5] = f;
          g = load_bigendian64(statebytes + 48); state[6] = g;
          h = load_bigendian64(statebytes + 56); state[7] = h;

          while (inlen >= 128) {
            uint64_t w0  = load_bigendian64(in +   0);
            uint64_t w1  = load_bigendian64(in +   8);
            uint64_t w2  = load_bigendian64(in +  16);
            uint64_t w3  = load_bigendian64(in +  24);
            uint64_t w4  = load_bigendian64(in +  32);
            uint64_t w5  = load_bigendian64(in +  40);
            uint64_t w6  = load_bigendian64(in +  48);
            uint64_t w7  = load_bigendian64(in +  56);
            uint64_t w8  = load_bigendian64(in +  64);
            uint64_t w9  = load_bigendian64(in +  72);
            uint64_t w10 = load_bigendian64(in +  80);
            uint64_t w11 = load_bigendian64(in +  88);
            uint64_t w12 = load_bigendian64(in +  96);
            uint64_t w13 = load_bigendian64(in + 104);
            uint64_t w14 = load_bigendian64(in + 112);
            uint64_t w15 = load_bigendian64(in + 120);

            auto foo = [&](auto & w, auto && k) {
              T1 = h + big_sigma1(e) + ch(e,f,g) + k + w; 
              T2 = big_sigma0(a) + maj(a,b,c); 
              h = g; 
              g = f; 
              f = e; 
              e = d + T1; 
              d = c; 
              c = b; 
              b = a; 
              a = T1 + T2;
            };

            auto ms = [&]()
              {
                m(w0 ,w14,w9 ,w1 );
                m(w1 ,w15,w10,w2 );
                m(w2 ,w0 ,w11,w3 );
                m(w3 ,w1 ,w12,w4 );
                m(w4 ,w2 ,w13,w5 );
                m(w5 ,w3 ,w14,w6 );
                m(w6 ,w4 ,w15,w7 );
                m(w7 ,w5 ,w0 ,w8 );
                m(w8 ,w6 ,w1 ,w9 );
                m(w9 ,w7 ,w2 ,w10);
                m(w10,w8 ,w3 ,w11);
                m(w11,w9 ,w4 ,w12);
                m(w12,w10,w5 ,w13);
                m(w13,w11,w6 ,w14);
                m(w14,w12,w7 ,w15);
                m(w15,w13,w8 ,w0 );
              };
    
            foo(w0 ,0x428a2f98d728ae22ULL);
            foo(w1 ,0x7137449123ef65cdULL);
            foo(w2 ,0xb5c0fbcfec4d3b2fULL);
            foo(w3 ,0xe9b5dba58189dbbcULL);
            foo(w4 ,0x3956c25bf348b538ULL);
            foo(w5 ,0x59f111f1b605d019ULL);
            foo(w6 ,0x923f82a4af194f9bULL);
            foo(w7 ,0xab1c5ed5da6d8118ULL);
            foo(w8 ,0xd807aa98a3030242ULL);
            foo(w9 ,0x12835b0145706fbeULL);
            foo(w10,0x243185be4ee4b28cULL);
            foo(w11,0x550c7dc3d5ffb4e2ULL);
            foo(w12,0x72be5d74f27b896fULL);
            foo(w13,0x80deb1fe3b1696b1ULL);
            foo(w14,0x9bdc06a725c71235ULL);
            foo(w15,0xc19bf174cf692694ULL);

            ms();

            foo(w0 ,0xe49b69c19ef14ad2ULL);
            foo(w1 ,0xefbe4786384f25e3ULL);
            foo(w2 ,0x0fc19dc68b8cd5b5ULL);
            foo(w3 ,0x240ca1cc77ac9c65ULL);
            foo(w4 ,0x2de92c6f592b0275ULL);
            foo(w5 ,0x4a7484aa6ea6e483ULL);
            foo(w6 ,0x5cb0a9dcbd41fbd4ULL);
            foo(w7 ,0x76f988da831153b5ULL);
            foo(w8 ,0x983e5152ee66dfabULL);
            foo(w9 ,0xa831c66d2db43210ULL);
            foo(w10,0xb00327c898fb213fULL);
            foo(w11,0xbf597fc7beef0ee4ULL);
            foo(w12,0xc6e00bf33da88fc2ULL);
            foo(w13,0xd5a79147930aa725ULL);
            foo(w14,0x06ca6351e003826fULL);
            foo(w15,0x142929670a0e6e70ULL);

            ms();

            foo(w0 ,0x27b70a8546d22ffcULL);
            foo(w1 ,0x2e1b21385c26c926ULL);
            foo(w2 ,0x4d2c6dfc5ac42aedULL);
            foo(w3 ,0x53380d139d95b3dfULL);
            foo(w4 ,0x650a73548baf63deULL);
            foo(w5 ,0x766a0abb3c77b2a8ULL);
            foo(w6 ,0x81c2c92e47edaee6ULL);
            foo(w7 ,0x92722c851482353bULL);
            foo(w8 ,0xa2bfe8a14cf10364ULL);
            foo(w9 ,0xa81a664bbc423001ULL);
            foo(w10,0xc24b8b70d0f89791ULL);
            foo(w11,0xc76c51a30654be30ULL);
            foo(w12,0xd192e819d6ef5218ULL);
            foo(w13,0xd69906245565a910ULL);
            foo(w14,0xf40e35855771202aULL);
            foo(w15,0x106aa07032bbd1b8ULL);
    
            ms();

            foo(w0 ,0x19a4c116b8d2d0c8ULL);
            foo(w1 ,0x1e376c085141ab53ULL);
            foo(w2 ,0x2748774cdf8eeb99ULL);
            foo(w3 ,0x34b0bcb5e19b48a8ULL);
            foo(w4 ,0x391c0cb3c5c95a63ULL);
            foo(w5 ,0x4ed8aa4ae3418acbULL);
            foo(w6 ,0x5b9cca4f7763e373ULL);
            foo(w7 ,0x682e6ff3d6b2b8a3ULL);
            foo(w8 ,0x748f82ee5defb2fcULL);
            foo(w9 ,0x78a5636f43172f60ULL);
            foo(w10,0x84c87814a1f0ab72ULL);
            foo(w11,0x8cc702081a6439ecULL);
            foo(w12,0x90befffa23631e28ULL);
            foo(w13,0xa4506cebde82bde9ULL);
            foo(w14,0xbef9a3f7b2c67915ULL);
            foo(w15,0xc67178f2e372532bULL);

            ms();

            foo(w0 ,0xca273eceea26619cULL);
            foo(w1 ,0xd186b8c721c0c207ULL);
            foo(w2 ,0xeada7dd6cde0eb1eULL);
            foo(w3 ,0xf57d4f7fee6ed178ULL);
            foo(w4 ,0x06f067aa72176fbaULL);
            foo(w5 ,0x0a637dc5a2c898a6ULL);
            foo(w6 ,0x113f9804bef90daeULL);
            foo(w7 ,0x1b710b35131c471bULL);
            foo(w8 ,0x28db77f523047d84ULL);
            foo(w9 ,0x32caab7b40c72493ULL);
            foo(w10,0x3c9ebe0a15c9bebcULL);
            foo(w11,0x431d67c49c100d4cULL);
            foo(w12,0x4cc5d4becb3e42b6ULL);
            foo(w13,0x597f299cfc657e2aULL);
            foo(w14,0x5fcb6fab3ad6faecULL);
            foo(w15,0x6c44198c4a475817ULL);
    
            a += state[0];
            b += state[1];
            c += state[2];
            d += state[3];
            e += state[4];
            f += state[5];
            g += state[6];
            h += state[7];

         
  
            state[0] = a;
            state[1] = b;
            state[2] = c;
            state[3] = d;
            state[4] = e;
            state[5] = f;
            state[6] = g;
            state[7] = h;

            in += 128;
            inlen -= 128;
          }

          store_bigendian64(statebytes +  0,state[0]);
          store_bigendian64(statebytes +  8,state[1]);
          store_bigendian64(statebytes + 16,state[2]);
          store_bigendian64(statebytes + 24,state[3]);
          store_bigendian64(statebytes + 32,state[4]);
          store_bigendian64(statebytes + 40,state[5]);
          store_bigendian64(statebytes + 48,state[6]);
          store_bigendian64(statebytes + 56,state[7]);

          return;
        };

      sha512 out;

      static const unsigned char iv[64] = {
        0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
        0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
        0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
        0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
        0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
        0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
        0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
        0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
      } ;

      uint8_t h[64];
    
      unsigned char padded[256];

      unsigned long long bytes = inlen;

      for (int i = 0;i < 64;++i) h[i] = iv[i];

      sha512_blocks(h,in,inlen);
      in += inlen;
      inlen &= 127;
      in -= inlen;

      for (int i = 0;i < inlen;++i) padded[i] = in[i];
      padded[inlen] = 0x80;

      if (inlen < 112) {

        for (int i = inlen + 1;i < 119;++i) padded[i] = 0;
        padded[119] = bytes >> 61;
        padded[120] = bytes >> 53;
        padded[121] = bytes >> 45;
        padded[122] = bytes >> 37;
        padded[123] = bytes >> 29;
        padded[124] = bytes >> 21;
        padded[125] = bytes >> 13;
        padded[126] = bytes >> 5;
        padded[127] = bytes << 3;
        sha512_blocks(h,padded,128);
      } else {
        for (int i = inlen + 1;i < 247;++i) padded[i] = 0;
        padded[247] = bytes >> 61;
        padded[248] = bytes >> 53;
        padded[249] = bytes >> 45;
        padded[250] = bytes >> 37;
        padded[251] = bytes >> 29;
        padded[252] = bytes >> 21;
        padded[253] = bytes >> 13;
        padded[254] = bytes >> 5;
        padded[255] = bytes << 3;
        sha512_blocks(h,padded,256);
      }

      for (int i = 0;i < 64;++i) out[i] = h[i];

      return out;
    }

    template <typename It>
    static sha512 calculate(It begin, It end)
    {
      std::vector<uint8_t> input(begin, end);
  
      return sha512(input.data(), input.size());
    }
  };
}
#endif
