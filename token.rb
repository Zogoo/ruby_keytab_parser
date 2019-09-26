# frozen_string_literal: true

require 'base64'
require 'openssl'

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

  def decrypt(password)
    enc_type = ENCRYPTION_TYPES[algorithm_type]
    # MD4 hash of the password.
    if enc_type == 'rc4-hmac'
      digest = OpenSSL::Digest::MD4.new(password)
      # hmac = OpenSSL::HMAC.new(password, digest)
    end
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
