# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'byebug'

# C language data types
class CTypes
  attr_accessor :bin_val

  def initialize(byte_str, position = 0)
    sliced_bytes = byte_str.slice!(position, byte_size)
    sliced_bytes = '' unless sliced_bytes.length >= byte_size
    self.bin_val = sliced_bytes
  end

  def to_int
    bin_val.unpack(unpack_format).first
  end

  def to_bin_str
    bin_val.unpack('b*').first
  end

  def to_hex_str
    bin_val.unpack('H*').first
  end

  def unpack_format
    ''
  end

  def byte_size
    0
  end

  def bing_endian?
    [1].pack('I') == [1].pack('N')
  end
end

# unsigned 8-bit integer
class UInt8 < CTypes
  def unpack_format
    bing_endian? ? 'C<' : 'C>'
  end

  def byte_size
    1
  end
end

# unsigned 16-bit integer
class UInt16 < CTypes
  def unpack_format
    bing_endian? ? 'S<' : 'S>'
  end

  def byte_size
    2
  end
end

# signed 32-bit integer
class Int32 < CTypes
  def unpack_format
    bing_endian? ? 'l<' : 'l>'
  end

  def byte_size
    4
  end
end

# unsigned 32-bit integer
class UInt32 < CTypes
  def unpack_format
    bing_endian? ? 'L<' : 'L>'
  end

  def byte_size
    4
  end
end

# KeyTab file format from MIT
# More details from :
# https://www.gnu.org/software/shishi/manual/html_node/The-Keytab-Binary-File-Format.html
# https://web.mit.edu/kerberos/krb5-1.12/doc/formats/keytab_file_format.html
# keytab {
#     uint16_t file_format_version;                    /* 0x502 */
#     keytab_entry entries[*];
# };

# keytab_entry {
#     int32_t size;
#     uint16_t num_components;    /* sub 1 if version 0x501 */
#     counted_octet_string realm;
#     counted_octet_string components[num_components];
#     uint32_t name_type;   /* not present if version 0x501 */
#     uint32_t timestamp;
#     uint8_t vno8;
#     keyblock key;
#     uint32_t vno; /* only present if >= 4 bytes left in entry */
# };

# counted_octet_string {
#     uint16_t length;
#     uint8_t data[length];
# };

# keyblock {
#     uint16_t type;
#     counted_octet_string;
# };

class KeyTab
  attr_accessor :bin_str
  attr_accessor :file_format_version
  attr_accessor :key_tab_entries

  FILE_FORMAT = {
    file_format_version: UInt16
  }.freeze

  KEY_LIST = {
    keytab_size: Int32,
    num_components: UInt16,
    # flatten counted_octet_string type
    realm_length: UInt16,
    realm: [:realm_length, String],
    # flatten counted_octet_string type
    components_length: [:num_components, String],
    components: [:components_length, String],
    name_type: UInt32,
    timestamp: UInt32,
    vno8: UInt8,
    keyblock_type: UInt16,
    # flatten counted_octet_string type
    keyblock_length: UInt16,
    keyblock_data: [:keyblock_length, String],
    vno: UInt32
  }.freeze

  def initialize(bin_content)
    self.key_tab_entries = {}
    self.bin_str = bin_content.clone
    self.file_format_version = parse_file_version(bin_content)
    parse_entries(bin_content)
  end

  def parse_file_version(bin_content)
    FILE_FORMAT.map do |key, val|
      key_tab_entries[key] = val.new(bin_content)
    end
  end

  def parse_entries(bin_content)
    KEY_LIST.map do |key, val|
      key_tab_entries[key] = get_content(bin_content, val)
    end
  end

  private

  def get_content(bin_content, value)
    # Nested content
    if value.is_a?(Array) && value.first.is_a?(Symbol)
      len_data = key_tab_entries[value.first]
      length = len_data.is_a?(String) ? len_data.unpack('c*').join.to_i : len_data.to_int
      sliced_content = bin_content.slice!(0, length)
      value[1].new(sliced_content)
    else
      value.new(bin_content)
    end
  end
end

# DER formatted Kerberos ticket (aka APP-REQ, service ticket)
class SpnegoToken
  attr_accessor :der_token, :bin_token
  attr_accessor :algorithm_type
  attr_accessor :init, :resp
  attr_accessor :der_obj

  attr_accessor :krb5_oid, :krb_ap_req_tag

  ENCRYPTION_TYPES = {
    1 => 'des-cbc-crc',
    2 => 'des-cbc-md4',
    3 => 'des-cbc-md5',
    4 => '[reserved]',
    5 => 'des3-cbc-md5',
    6 => '[reserved]',
    7 => 'des3-cbc-sha1',
    9 => 'dsaWithSHA1-CmsOID',
    10 => 'md5WithRSAEncryption-CmsOID',
    11 => 'sha1WithRSAEncryption-CmsOID',
    12 => 'rc2CBC-EnvOID',
    13 => 'rsaEncryption-EnvOID',
    14 => 'rsaES-OAEP-ENV-OID',
    15 => 'des-ede3-cbc-Env-OID',
    16 => 'des3-cbc-sha1-kd',
    17 => 'aes128-cts-hmac-sha1-96',
    18 => 'aes256-cts-hmac-sha1-96',
    23 => 'rc4-hmac',
    24 => 'rc4-hmac-exp',
    65 => 'subkey-keymaterial'
  }.freeze

  NAME_TYPES = {
    0 => 'NT-UNKNOWN',
    1 => 'NT-PRINCIPAL',
    2 => 'NT-SRV-INST',
    3 => 'NT-SRV-HST',
    4 => 'NT-SRV-XHST',
    5 => 'NT-UID',
    6 => 'NT-X500-PRINCIPAL',
    7 => 'NT-SMTP-NAME',
    10 => 'NT-ENTERPRISE'
  }.freeze

  def initialize(encoded_token)
    hex_token = Base64.strict_decode64(encoded_token)
    self.der_token = OpenSSL::ASN1.decode(hex_token)
    parse_der_token
    # self.init = Init.parse(token)
    # self.resp = Resp.parse(token)
  end

  def decrypt
    enc_type = ENCRYPTION_TYPES[algorithm_type]
    chipher = OpenSSL::Cipher.new(enc_type)
    chipher.decrypt(bin_token)
  end

  private

  # 4 level DER format
  def parse_der_token
    # Level 0: SPNEGO OID, Level 1
    lvl0_obj = der_token.value
    # Level 1: mech types, Level 2
    lvl1_obj = lvl0_obj.first.value
    # self.krb5_oid = lvl1_obj.find { |data| data.value&.first.is_a?(OpenSSL::ASN1::Enumerated) }&.value&.first
    # self.krb_ap_req_tag = lvl1_obj.find { |data| data.value&.first.is_a?(OpenSSL::ASN1::ObjectId) }&.value&.first
    # Level 2: Kerberos OID, KRB5_AP_REQ, Level 3
    lvl2_obj = lvl1_obj.find { |data| data.value&.first.is_a?(OpenSSL::ASN1::OctetString) }&.value
    lvl3_obj = OpenSSL::ASN1.decode(lvl2_obj.first.value)
    lvl4_obj = lvl3_obj.value.find { |data| data.value.is_a?(Array) }&.value

    lvl5_obj = lvl4_obj.first.value.find { |data| data.value&.first.is_a?(OpenSSL::ASN1::Sequence) }&.value
    algorithm_obj = lvl5_obj.first.value.find { |data| data.value&.first.is_a?(OpenSSL::ASN1::Integer) }&.value
    self.algorithm_type = algorithm_obj.first.value.to_i
    lvl6_obj = lvl5_obj.first.value.find { |data| data.value&.first.is_a?(OpenSSL::ASN1::OctetString) }&.value
    self.bin_token = lvl6_obj.first.value
  end

  def bin_to_hex(str)
    format('0x%02x', str.to_i(2))
  end
end
