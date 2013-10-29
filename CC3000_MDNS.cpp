/*

CC3000 Multicast DNS 
Version 1.0
Copyright (c) 2013 Tony DiCola (tony@tonydicola.com)

License (MIT license):
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

*/

// Important RFC's for reference:
// - DNS request and response: http://www.ietf.org/rfc/rfc1035.txt
// - Multicast DNS: http://www.ietf.org/rfc/rfc6762.txt

#include "CC3000_MDNS.h"

#define HEADER_SIZE 12
#define QDCOUNT_OFFSET 4
#define A_RECORD_SIZE 14
#define NSEC_RECORD_SIZE 20
#define TTL_OFFSET 4
#define IP_OFFSET 10

// TODO: Put these in flash, or refactor away into better state handling.
uint8_t MDNSResponder::_queryHeader[] = { 
  0x00, 0x00, // ID = 0
  0x00, 0x00, // Flags = query
  0x00, 0x00, // Question count = ignored
  0x00, 0x00, // Answer count = ignored
  0x00, 0x00, // Name server records = ignored
  0x00, 0x00  // Additional records = ignored
};

int MDNSResponder::_mdnsSocket = -1;

MDNSResponder::MDNSResponder()
  : _queryFQDN(NULL)
  , _queryFQDNLen(0)
  , _current(NULL)
  , _currentLen(0)
  , _index(0)
  , _FQDNcount(0)
  , _response(NULL)
  , _responseLen(0)
{ }

MDNSResponder::~MDNSResponder() {
  if (_queryFQDN != NULL) {
    free(_queryFQDN);
  }
  if (_response != NULL) {
    free(_response);
  }
}

bool MDNSResponder::begin(const char* domain, Adafruit_CC3000& cc3000, uint32_t ttlSeconds)
{ 
  // Construct DNS request/response fully qualified domain name of form:
  // <domain length>, <domain characters>, 5, "local"
  size_t n = strlen(domain);
  if (n > 255) {
    // Can only handle domains that are 255 chars in length.
    return false;
  }
  _queryFQDNLen = 8 + n;
  if (_queryFQDN != NULL) {
    free(_queryFQDN);
  }
  _queryFQDN = (uint8_t*) malloc(_queryFQDNLen);
  if (_queryFQDN == NULL) {
    return false;
  }
  _queryFQDN[0] = (uint8_t)n;
  // Copy in domain characters as lowercase
  for (int i = 0; i < n; ++i) {
    _queryFQDN[1+i] = tolower(domain[i]);
  }
  // Values for 5 (length), "local":
  uint8_t local[] = { 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C };
  memcpy(&_queryFQDN[1+n], local, 6);
  _queryFQDN[7+n] = 0;

  // Construct DNS query response
  // TODO: Move these to flash or just construct in code.
  uint8_t respHeader[] = { 0x00, 0x00,   // ID = 0
                           0x84, 0x00,   // Flags = response + authoritative answer
                           0x00, 0x00,   // Question count = 0
                           0x00, 0x01,   // Answer count = 1
                           0x00, 0x00,   // Name server records = 0
                           0x00, 0x01    // Additional records = 1
  };
  // Generate positive response for IPV4 address
  uint8_t aRecord[] = { 0x00, 0x01,                // Type = 1, A record/IPV4 address
                        0x80, 0x01,                // Class = Internet, with cache flush bit
                        0x00, 0x00, 0x00, 0x00,    // TTL in seconds, to be filled in later
                        0x00, 0x04,                // Length of record
                        0x00, 0x00, 0x00, 0x00     // IP address, to be filled in later
  };
  // Generate negative response for IPV6 address (CC3000 doesn't support IPV6)
  uint8_t nsecRecord[] = {  0xC0, 0x0C,                // Name offset
                            0x00, 0x2F,                // Type = 47, NSEC (overloaded by MDNS)
                            0x80, 0x01,                // Class = Internet, with cache flush bit
                            0x00, 0x00, 0x00, 0x00,    // TTL in seconds, to be filled in later
                            0x00, 0x08,                // Length of record
                            0xC0, 0x0C,                // Next domain = offset to FQDN
                            0x00,                      // Block number = 0
                            0x04,                      // Length of bitmap = 4 bytes
                            0x40, 0x00, 0x00, 0x00     // Bitmap value = Only first bit (A record/IPV4) is set
  }; 
  // Allocate memory for response.
  _responseLen = HEADER_SIZE + _queryFQDNLen + A_RECORD_SIZE + NSEC_RECORD_SIZE;
  if (_response != NULL) {
    free(_response);
  }
  _response = (uint8_t*) malloc(_responseLen);
  if (_response == NULL) {
    return false;
  }
  // Copy data into response.
  memcpy(_response, respHeader, HEADER_SIZE);
  memcpy(_response + HEADER_SIZE, _queryFQDN, _queryFQDNLen);
  uint8_t* records = _response + HEADER_SIZE + _queryFQDNLen;
  memcpy(records, aRecord, A_RECORD_SIZE);
  memcpy(records + A_RECORD_SIZE, nsecRecord, NSEC_RECORD_SIZE);
  // Add TTL to records.
  uint8_t ttl[4] = { (uint8_t)(ttlSeconds >> 24), (uint8_t)(ttlSeconds >> 16), (uint8_t)(ttlSeconds >> 8), (uint8_t)ttlSeconds };
  memcpy(records + TTL_OFFSET, ttl, 4);
  memcpy(records + A_RECORD_SIZE + 2 + TTL_OFFSET, ttl, 4);
  // Add IP address to response
  uint32_t ipAddress, netmask, gateway, dhcpserv, dnsserv;
  if(!cc3000.getIPAddress(&ipAddress, &netmask, &gateway, &dhcpserv, &dnsserv))
  {
    return false;
  }
  records[IP_OFFSET]     = (uint8_t)(ipAddress >> 24);
  records[IP_OFFSET + 1] = (uint8_t)(ipAddress >> 16);
  records[IP_OFFSET + 2] = (uint8_t)(ipAddress >> 8);
  records[IP_OFFSET + 3] = (uint8_t) ipAddress;
  
  // Open the MDNS socket if it isn't already open.
  if (_mdnsSocket == -1) {
    // Create the UDP socket
    int soc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (soc < 0) {
      return false;
    }
    // Use port 5353 and listen/send to the multicast IP 224.0.0.251
    sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(5353);
    address.sin_addr.s_addr = htonl(cc3000.IP2U32(224, 0, 0, 251));
    socklen_t len = sizeof(address);
    if (bind(soc, (sockaddr*) &address, sizeof(address)) < 0) {
      return false;
    }
    _mdnsSocket = soc;
  }

  // Start in a state of parsing the DNS query header.
  changeState(_queryHeader);

  return true;
}

void MDNSResponder::update() {
  // Check if data is available to read using select
  timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 5000;
  fd_set reads;
  FD_ZERO(&reads);
  FD_SET(_mdnsSocket, &reads);
  select(_mdnsSocket + 1, &reads, NULL, NULL, &timeout);
  if (!FD_ISSET(_mdnsSocket, &reads)) {
    // No data to read.
    return;
  }
  // Read available data.
  uint8_t buffer[20];
  int n = recv(_mdnsSocket, &buffer, sizeof(buffer), 0);
  if (n < 1) {
    // Error getting data.
    return;
  }
  // Compare incoming data to expected data from current state.
  for (int i = 0; i < n; ++i) {
    uint8_t ch = buffer[i];
    // If we're processing an FQDN character, make the comparison case insensitive.
    if (_current == _queryFQDN && _FQDNcount > 0) {
      ch = tolower(ch);
    }
    // Check character matches expected, or in the case of parsing the question counts
    // ignore it completely (this is done because MDNS queries on different platforms
    // sometimes ask for different record types).
    if (ch == _current[_index] ||
        (_current == _queryHeader && _index >= QDCOUNT_OFFSET)) 
    {
      // Update FQDN char count when processing FQDN characters.
      if (_current == _queryFQDN) {
        if (_FQDNcount == 0) {
          // Handle the next characters as case insensitive FQDN characters.
          _FQDNcount = ch;
        }
        else {
          _FQDNcount--;
        }
      }
      // Update state when the end of the current one has been reached.
      _index++;
      if (_index >= _currentLen) {
        // Switch to next state
        if (_current == _queryHeader) {
          changeState(_queryFQDN);
        }
        else if (_current == _queryFQDN) {
          sendResponse();
          changeState(_queryHeader);
        }
      }
    }
    else {
      // Reset to start looking from the start again
      changeState(_queryHeader);
    }
  }
}

void MDNSResponder::changeState(uint8_t* state) {
  _current = state;
  if (state == _queryFQDN) {
    _currentLen = _queryFQDNLen;
  }
  else if (state == _queryHeader) {
    _currentLen = HEADER_SIZE;
  }
  _index = 0;
  _FQDNcount = 0;
}

void MDNSResponder::sendResponse() {
  send(_mdnsSocket, _response, _responseLen, 0);
}
