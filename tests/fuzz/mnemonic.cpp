// Copyright (c) 2017-2024, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "include_base_utils.h"
#include "mnemonics/electrum-words.h"
#include "crypto/crypto.h"
#include "fuzzer.h"

BEGIN_INIT_SIMPLE_FUZZER()
END_INIT_SIMPLE_FUZZER()

BEGIN_SIMPLE_FUZZER()
  // Test mnemonic seed phrase parsing and validation
  std::string mnemonic_phrase((const char*)buf, len);
  
  // Test 1: Basic mnemonic validation
  bool is_valid = crypto::ElectrumWords::words_to_bytes(mnemonic_phrase, crypto::ElectrumWords::seed_length);
  
  // Test 2: Attempt to convert mnemonic to private key
  if (is_valid)
  {
    epee::wipeable_string seed;
    crypto::secret_key recovery_key;
    std::string language;
    
    // Try to extract seed from mnemonic
    bool seed_result = crypto::ElectrumWords::words_to_bytes(mnemonic_phrase, seed, crypto::ElectrumWords::seed_length, true, language);
    
    if (seed_result && seed.size() == crypto::ElectrumWords::seed_length)
    {
      // Try to derive private key from seed
      recovery_key = crypto::generate_keys_from_seed(seed.data(), seed.size());
    }
  }
  
  // Test 3: Test different language wordlists
  std::vector<std::string> languages = {"English", "Spanish", "French", "Italian", "Dutch", "Portuguese", "Japanese", "Russian", "Esperanto", "German"};
  
  for (const auto& lang : languages)
  {
    epee::wipeable_string seed;
    bool lang_result = crypto::ElectrumWords::words_to_bytes(mnemonic_phrase, seed, crypto::ElectrumWords::seed_length, true, lang);
    
    // Test reverse conversion if successful
    if (lang_result)
    {
      std::string words_out;
      crypto::ElectrumWords::bytes_to_words(seed.data(), seed.size(), words_out, lang);
    }
  }
  
  // Test 4: Test with different seed lengths (if supported)
  std::vector<size_t> seed_lengths = {16, 20, 24, 28, 32}; // Common seed lengths in bytes
  
  for (size_t length : seed_lengths)
  {
    epee::wipeable_string seed;
    std::string language;
    crypto::ElectrumWords::words_to_bytes(mnemonic_phrase, seed, length, true, language);
  }
  
  // Test 5: Test mnemonic normalization and trimming
  std::string normalized = mnemonic_phrase;
  
  // Test with various whitespace patterns that users might input
  normalized = "  " + normalized + "  ";  // Leading/trailing spaces
  crypto::ElectrumWords::words_to_bytes(normalized, crypto::ElectrumWords::seed_length);
  
  // Test with extra internal spaces
  size_t pos = 0;
  while ((pos = normalized.find(' ', pos)) != std::string::npos)
  {
    normalized.insert(pos, " ");
    pos += 2;
  }
  crypto::ElectrumWords::words_to_bytes(normalized, crypto::ElectrumWords::seed_length);
  
END_SIMPLE_FUZZER()
