# frozen_string_literal: true

require 'base64'
require 'openssl'

# Base DER helper functions
class BaseSpnego
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

  # Collect tagged object from DER structure
  def deep_objects(temp_obj, obj_array)
    if temp_obj.is_a?(OpenSSL::ASN1::Sequence)
      temp_obj.each do |obj|
        obj_array << obj if obj.class.to_s.eql?(OpenSSL::ASN1::ASN1Data.to_s)
        deep_objects(obj, obj_array) if obj.is_a?(OpenSSL::ASN1::Sequence)
      end
    elsif temp_obj.is_a?(Array)
      temp_obj.each do |obj|
        # TODO: figure out whats happened in here
        # is_a?(OpenSSL::ASN1::ASN1Data) returns true for OpenSSL::ASN1::Sequence object
        obj_array << obj if obj.class.to_s.eql?(OpenSSL::ASN1::ASN1Data.to_s)
        deep_objects(obj, obj_array) if obj.is_a?(OpenSSL::ASN1::Sequence)
      end
    elsif temp_obj.is_a?(OpenSSL::ASN1::ASN1Data)
      obj_array << temp_obj
    end
  end
end

# Initial negotiation message parser
class NegTokenInit < BaseSpnego
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
    # https://tools.ietf.org/html/rfc4178#section-4.2.1 favorite choice first
    self.mechanism = mechanism_list.first if mechanism_list.length.positive?
  end
end

# This is the syntax for all subsequent negotiation messages.
class NegTokenResp < BaseSpnego
  attr_accessor :mechanism_list
  attr_accessor :mechanism
  attr_accessor :mechanism_token
  attr_accessor :result

  ACCEPT_COMPLETE = 0
  ACCEPT_INCOMPLETE = 1
  REJECT = 2

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

# Spnego token parser
# https://tools.ietf.org/html/rfc4178
class SpnegoToken
  attr_accessor :token

  def initialize(encoded_token)
    hex_token = Base64.strict_decode64(encoded_token)
    # TODO: to use traverse API loop over ASN1 data
    # OpenSSL::ASN1.traverse(hex_token) do | depth, offset, header_len, length, constructed, tag_class, tag|
    #   puts "Depth: #{depth} Offset: #{offset} Length: #{length}"
    #   puts "Header length: #{header_len} Tag: #{tag} Tag class: #{tag_class} Constructed: #{constructed}"
    # end
    der_token = OpenSSL::ASN1.decode(hex_token)
    # https://tools.ietf.org/html/rfc4178#section-4.2
    self.token = if der_token.value.first.value == BaseSpnego::SPNEGO_MECHANISM
                   NegTokenInit.new(der_token)
                 else
                   NegTokenResp.new(der_token)
                 end
    # TODO: Confirm which one is more accurate
    # Or maybe this
    # case hex_token[0].unpack('H*').first
    # when '60'
    #   self.token = NegTokenInit.new(der_token)
    # when 'a1'
    #   self.token = NegTokenResp.new(der_token)
    # end
  end

  def bin_to_hex(str)
    format('0x%02x', str.to_i(2))
  end
end

# KRB_AP_REQ 
# Specified in https://tools.ietf.org/html/rfc1510#section-5.5.1
class KerberosApRequest
  attr_accessor :pvno, :msg_type, :ap_options, :ticket, :authenticator

  def initialize(kerb_token)
    der_token = OpenSSL::ASN1.decode(kerb_token)
    tagged_array_obj = get_tagged_objects(der_token.value.first)
  end
end

class KerberosTicket
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
end

# Kerberos token parser
class KerberosToken
  attr_accessor :token_id, :kerb_ap_req

  KRB_AP_REQ_TOKEN_ID = '0100'
  KRB_AP_REP_TOKEN_ID = '0300'

  def initialize(kerb_token)
    # TODO: I hit another wall in here
    # decoded_token = OpenSSL::ASN1.decode(kerb_token)
    # Document says first 2 bype used for id of token 
    # rest part for actual kerberos token, but not able to decode with ASN1
    # https://www.ipa.go.jp/security/rfc/RFC1964EN.html
    # 2 bytes is used for token id
    self.token_id = decoded_token[0, 2]
    raise 'Invalid token id' if token_id != KRB_AP_REQ_TOKEN_ID

    self.kerb_ap_req = KerberosApRequest.new(decoded_token[2, der_token.size - 1])
  end
end

# Parser with shell command
class Asn1DecodeResultParser
  attr_accessor :object_id, :mech_token, :mech_list

  OCTET_STRING_TITLE = 'OCTET STRING      [HEX DUMP]:'

  def initialize(kerb_token)
    tmp_file = Tempfile.new('temp_token.der')
    tmp_file.binmode
    tmp_file.write(kerb_token)
    tmp_file.close
    result_str = `openssl asn1parse -inform der -in #{tmp_file.path}`
    array_str_by_line = result_str.split("\n")
    octet_index = 0
    array_str_by_line.each do |line|
      next unless line.include?(OCTET_STRING_TITLE)

      octet_index += 1
      start_index = line.index(OCTET_STRING_TITLE) + OCTET_STRING_TITLE.size
      end_index = line.size - 1
      self.mech_token = line[start_index, end_index] if octet_index == 1
      self.mech_list = line[start_index, end_index] if octet_index == 2
    end
  end
end
