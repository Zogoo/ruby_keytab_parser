# frozen_string_literal: true

require 'base64'
require 'openssl'

class BaseSpenego
  SPNEGO_MECHANISM = '1.3.6.1.5.5.2'
  KERBEROS_MECHANISM = '1.2.840.113554.1.2.2'
  LEGACY_KERBEROS_MECHANISM = '1.2.840.48018.1.2.2'
  NTLMSSP_MECHANISM = '1.3.6.1.4.1.311.2.2.10'

  def get_object(asn_obj)
    asn_obj.value.find { |data| data.value.is_a?(OpenSSL::ASN1::ObjectId) }
  end

  def get_data(asn_obj)
    asn_obj.value.find { |data| data.value.is_a?(OpenSSL::ASN1::ASN1Data) }
  end

  def get_tagged_objects(asn_obj)
    obj_array = []
    temp_obj = asn_obj.value.dup
    deep_objects(temp_obj, obj_array)
    obj_array
  end

  def deep_objects(temp_obj, obj_array)
    if temp_obj.is_a?(OpenSSL::ASN1::Sequence)
      temp_obj.each do |obj|
        obj_array << obj if obj.class.to_s.eql?(OpenSSL::ASN1::ASN1Data.to_s)
        deep_objects(obj, obj_array) if obj.is_a?(OpenSSL::ASN1::Sequence)
      end
    elsif temp_obj.is_a?(Array)
      temp_obj.each do |obj|
        # is_a?(OpenSSL::ASN1::ASN1Data) returns true for OpenSSL::ASN1::Sequence object
        obj_array << obj if obj.class.to_s.eql?(OpenSSL::ASN1::ASN1Data.to_s)
        deep_objects(obj, obj_array) if obj.is_a?(OpenSSL::ASN1::Sequence)
      end
    elsif temp_obj.is_a?(OpenSSL::ASN1::ASN1Data)
      obj_array << temp_obj
    end
  end
end

class SpnegoInitToken < BaseSpenego
  attr_accessor :object_id
  attr_accessor :mechanism_list
  attr_accessor :mechanism
  attr_accessor :mechanism_token
  attr_accessor :context_flag
  attr_accessor :mechanism_list_str

  def initialize(der_token)
    self.mechanism_list = []
    # Object Id of SPNEGO token
    self.object_id = der_token.value.first.value
    tagged_array_obj = get_tagged_objects(der_token.value[1])
    tagged_array_obj.each do |obj|
      value_obj = obj.value.is_a?(Array) ? obj.value.first : obj.value
      case obj.tag
      when 0
        value_obj.each do |seq_obj|
          next unless seq_obj.is_a? OpenSSL::ASN1::ObjectId

          mechanism_list << seq_obj.value
        end
      when 1
        self.context_flag = value_obj.value if value_obj.is_a? OpenSSL::ASN1::BitString
      when 2
        self.mechanism_token = value_obj.value if value_obj.is_a? OpenSSL::ASN1::OctetString
      when 3
        self.mechanism_list_str = value_obj.value if value_obj.is_a? OpenSSL::ASN1::OctetString
      end
    end
    self.mechanism = mechanism_list.first if mechanism_list.length.positive?
  end
end

class SnegoTargToken < BaseSpenego
  attr_accessor :mechanism_list
  attr_accessor :mechanism
  attr_accessor :mechanism_token
  attr_accessor :result

  def initialize(der_token)
    tagged_array_obj = get_tagged_objects(der_token.value.first)
    tagged_array_obj.each do |obj|
      value_obj = obj.value.is_a?(Array) ? obj.value.first : obj.value
      case obj.tag
      when 0
        self.result = value_obj.value.to_i if value_obj.is_a? OpenSSL::ASN1::Enumerated
      when 1
        self.mechanism = value_obj.value if value_obj.is_a? OpenSSL::ASN1::ObjectId
      when 2
        self.mechanism_token = value_obj.value if value_obj.is_a? OpenSSL::ASN1::OctetString
      when 3
        self.mechanism_list_str = value_obj.value if value_obj.is_a? OpenSSL::ASN1::OctetString
      end
    end
  end
end

# DER formatted Kerberos ticket (aka APP-REQ, service ticket)
class SpnegoToken
  attr_accessor :token

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
    OpenSSL::ASN1.traverse(hex_token) do | depth, offset, header_len, length, constructed, tag_class, tag|
      puts "Depth: #{depth} Offset: #{offset} Length: #{length}"
      puts "Header length: #{header_len} Tag: #{tag} Tag class: #{tag_class} Constructed: #{constructed}"
    end
    der_token = OpenSSL::ASN1.decode(hex_token)
    case hex_token[0].unpack('H*').first
    when '60'
      self.token = SpnegoInitToken.new(der_token)
    when 'a1'
      self.token = SnegoTargToken.new(der_token)
    end
  end

  def bin_to_hex(str)
    format('0x%02x', str.to_i(2))
  end
end
