# frozen_string_literal: true

# C language data types
class CTypes
  attr_accessor :bin_val, :int_val

  def initialize(byte_str, position = 0)
    sliced_bytes = byte_str.slice!(position, byte_size)
    sliced_bytes = '' unless sliced_bytes.length >= byte_size
    self.bin_val = sliced_bytes
    self.int_val = to_int
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
  # One byte char is same as big and little endian
  def unpack_format
    'C'
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
    entry_size: Int32,
    num_components: UInt16,
    # flatten counted_octet_string type
    realm_length: UInt16,
    realm: [:realm_length, String],
    component: [
      num_components: {
        component_length: UInt16,
        component_data: [:component_length, String]
      }
    ],
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
    self.bin_str = bin_content.dup
    self.file_format_version = parse_file_version(bin_content)
    self.key_tab_entries = []
    parse_entries(bin_content)
  end

  def parse_file_version(bin_content)
    FILE_FORMAT.map do |_, val|
      val.new(bin_content)
    end
  end

  def parse_entries(bin_content)
    until bin_content.empty?
      kt_entry = {}
      one_entry = bin_content
      KEY_LIST.map do |key, val|
        set_content(one_entry, kt_entry, key, val)
        # Slice after parse first line length
        if key == :entry_size && !kt_entry[:entry_size].nil?
          one_entry = bin_content.slice!(0, kt_entry[:entry_size].int_val)
        end
      end
      key_tab_entries << kt_entry
    end
  end

  private

  def set_content(bin_content, key_entries, key, value)
    # Nested content
    if value.is_a?(Array) && value.first.is_a?(Symbol)
      len_data = key_entries[value.first]
      length = len_data.is_a?(String) ? len_data.unpack('c*').join.to_i : len_data.to_int
      sliced_content = bin_content.slice!(0, length)
      key_entries[key] = value[1].new(sliced_content)
    elsif value.is_a?(Array) && value.first.is_a?(Hash)
      key_entries[key] = []
      value.first.map do |sub_length, sub_format|
        Array.new(key_entries[sub_length].int_val) do |index|
          key_entries[key] << {}
          sub_format.map do |sub_key, sub_value|
            set_content(bin_content, key_entries[key][index], sub_key, sub_value)
          end
        end
      end
    else
      key_entries[key] = value.new(bin_content)
    end
  end
end
