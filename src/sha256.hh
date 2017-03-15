/*
  
    Copyright (c) 2016, 2017 Ryan P. Nicholl
    All Rights Reserved

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 
*/
#ifndef LIBIEV_HASH_SHA256_HH
#define LIBIEV_HASH_SHA256_HH


//#include <iev/serialize.hh>
// TODO: Add serial support after new array type.
#include <iterator>

namespace iev
{
  inline constexpr uint32_t rightrotate(uint32_t a, int b) noexcept
  {
    const uint32_t c = 8*sizeof(a)-1;
    b &= c;
    return (a >> b) | (a << ((-b)&c));
  }
  
  namespace sha256
  {
    class sum
    {
      uint8_t data_[256/8];
    public:
      
      constexpr sum () noexcept
	: data_{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
      {

      }


      constexpr sum(uint8_t data[258/8]) noexcept
	: sum()
      {
	for (int i = 0; i < 256/8; i++)
	  {
	    data_[i] = data[i];
	  }
      }

      template <typename ... Ts>
      constexpr sum (Ts && ... ts) 
	: data_{uint8_t(std::forward<Ts>(ts))...}
      {

      }

      auto begin() noexcept { return std::begin(data_); }
      auto end() noexcept { return std::end(data_); }
      auto begin() const noexcept { return std::begin(data_); }
      auto end() const noexcept { return std::end(data_); }

      constexpr auto size() const noexcept
      {
	return 256/8;
      }

      constexpr uint8_t & operator[](size_t n) noexcept
      {
	return data_[n];
      }

      constexpr uint8_t const & operator[](size_t n) const noexcept
      {
	return data_[n];
      }

      constexpr bool operator ==(sum const & other) const noexcept
      {
	for (int i = 0; i < size(); i++)
	  {
	    if ((*this)[i] != other[i]) return false;
	  }
	return true;
      }


      constexpr bool operator != (sum const & other) const noexcept
      {
	for (int i = 0; i < size(); i++)
	  {
	    if ((*this)[i] != other[i]) return true;
	  }
	return false;
      }
      
      
    };
  private:
    class calculator
    {
      using ua64_t = uint32_t[64];
      ua64_t __attribute__((__aligned__(64)))  k;
      using ua8_t = uint32_t[8]; ;
      ua8_t __attribute__((__aligned__(64))) hh;
      ua64_t __attribute__((__aligned__(64))) w;

      size_t pos;
      size_t z;

      
   
    public:

      constexpr calculator() noexcept
	: k{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 },
	hh{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 },
	w { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, pos(0), z(0)
      {
		
      }
      
      template <typename T>
      static void preprocess(T & data) 
      {
	uint64_t s = data.size()*8;
	data.push_back(0b10000000);
	while(data.size() % 64 != 56)
	  {
	    data.push_back(0);
	  }
	for (int i = 7; i >= 0; i--)
	  {
	    data.push_back(0xFF & (s >> (8*(8-i))));
	  }
	if (data.size()%64 != 0) throw 1;
      }
      
      inline constexpr void process_byte(uint8_t v) noexcept
      {
	if ((z&0b11) == 0) w[(z>>2)] = 0;
	
	w[(z>>2)] |= uint32_t(v) << (24-(z&0b11)*8);
	
	pos += 8;
	z++;
	if (z == 64)
	  {
	    z = 0;
	    process_chunk();
	  }
      }

      template<typename It>
      inline constexpr void process_bytes(It begin, It end) noexcept
      {
	while (begin != end)
	  { 
	    process_byte(*begin++);
	  }
      }


      constexpr void finalize() noexcept
      {
	uint64_t s = pos;
	process_byte(0b10000000);

	while(pos % 512 != 448)
	  {
	    process_byte(0);
	  }

	for (int i = 0; i < 8; i++)
	  {
	    process_byte(s >> (56-i*8));
	  }
      }

      constexpr void process_chunk() noexcept
      {
	for (int i = 16; i < 64; i++)
	  {
	    uint32_t s0 = rightrotate(w[i-15],  7) xor rightrotate(w[i-15], 18) xor (w[i-15] >> 3);
	    uint32_t s1 = rightrotate(w[i-2], 17) xor rightrotate(w[i-2], 19) xor (w[i-2] >> 10);
	    w[i] = w[i-16] + s0 + w[i-7] + s1;
	  }

	ua8_t __attribute__((__aligned__(64))) aa = {hh[0], hh[1], hh[2], hh[3], hh[4], hh[5], hh[6], hh[7] };
	// a0, b1, c2, d3, e4, f5, g6, h7
	for (int i = 0; i < 64; i++)
	  {
	    uint32_t S1 = rightrotate(aa[4], 6) xor rightrotate(aa[4], 11) xor rightrotate(aa[4], 25);
	    uint32_t ch = (aa[4] bitand aa[5]) xor ((~aa[4]) bitand aa[6]);
	    uint32_t temp1 = aa[7] + S1 + ch + k[i] + w[i];
	    uint32_t S0 = rightrotate(aa[0], 2) xor rightrotate(aa[0], 13) xor rightrotate(aa[0], 22);
	    uint32_t maj = (aa[0] bitand aa[1]) xor (aa[0] bitand aa[2]) xor (aa[1] bitand aa[2]);
	    uint32_t temp2 = S0 + maj;

	    aa[7] = aa[6];
	    aa[6] = aa[5];
	    aa[5] = aa[4];
	    aa[4] = aa[3] + temp1;
	    aa[3] = aa[2];
	    aa[2] = aa[1];
	    aa[1] = aa[0];
	    aa[0] = temp1 + temp2;
	  }

	for (int i = 0; i < 8; i++)
	  {
	    hh[i] += aa[i];
	  }
	
      }

      constexpr sum get() noexcept
      {
	sum output;

	for (int i = 0, z = 0; z < 8; z++)
	  {
	    output[i++] = (hh[z] >> 24);
	    output[i++] = (hh[z] >> 16);
	    output[i++] = (hh[z] >> 8);
	    output[i++] = (hh[z] >> 0);
	    // write output as big endian;
	    
	  }
	return output;
      }

      

    };
  public:

    template <typename It>
    constexpr sum calculate(It begin, It end)
    {
      calculator c;
      
      c.process_bytes(begin, end);      
      c.finalize();

      return c.get();
    }

    inline constexpr sum calculate(char const * str)
    {
      calculator c;
      
      char const * begin = str;
      char const * end = str;
      while (*end != '\0') end++;
      
      c.process_bytes(begin, end);
      c.finalize();

      return c.get();
    }

  }
  /*
  template <typename It>
  void serialize(sha256::sum const & input, It && output)
  {
    for(auto it = input.begin(); it != input.end(); it++)
      {
	iev::serialize(*it, output);
      }
  }
  
  template <typename It>
  void deserialize(sha256::sum & output, It && input)
  {
    for (auto &x: output) deserialize(x, input);
  }
  */



  inline constexpr iev::sha256::sum operator "" _sha256 ( char const * data, uint64_t length)
  {
    
    constexpr uint8_t hex_value(char c)
    {
      if (c >= '0' && c <= '9') return c-'0';
      if (c >= 'a' && c <= 'z') return c-'a'+10;
      if (c >= 'A' && c <= 'Z') return c-'a'+10;
      return 0;
    }
    //    static_assert(length == 256/8);
    iev::sha256::sum output;
    for (int i = 0; i < output.size(); i++)
      {
	output[i] = (hex_value(data[i*2]) << 4) | (hex_value(data[i*2+1]));
      }
    return output;
  }

  
  namespace detail
  {
    static constexpr char const sha256_test_string1[] = "hello";

    static_assert(iev::sha256::calculate(&sha256_test_string1[0], &sha256_test_string1[sizeof(sha256_test_string1)-1]) == iev::sha256::sum{0x2c,0xf2,0x4d,0xba,0x5f,0xb0,0xa3,0x0e,0x26,0xe8,0x3b,0x2a,0xc5,0xb9,0xe2,0x9e,0x1b,0x16,0x1e,0x5c,0x1f,0xa7,0x42,0x5e,0x73,0x04,0x33,0x62,0x93,0x8b,0x98,0x24});

    using iev::operator""_sha256;
    static_assert(iev::sha256::calculate("hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"_sha256);
    
  }
  

  
}


#endif
