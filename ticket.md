### SPNEGO token with Kerberos ticket ###

Kerberos APP_REQ_TICKET will be inside of SPNEGO token, you need extract SPNEGO token first.

Structure of SPENGO tocken will be following

1. SPENGO token encoded by ASN.1 key structure format aka DER / BER.

So, there are 5 levels for SPNEGO token as like follows 


##### The root contains:

DERObjectIdentifier - SPNEGO OID
DERSequence - level 1

##### Level 1 contains:

SEQUENCE of DERObjectIdentifier - mech types
DEROctetString - wrapped DERApplicationSepecific - level 2

##### Level 2 contains:

DERObjectIndentifier - Kerberos OID
KRB5_AP_REQ tag 0x01 0x00, parsed as boolean (false)
DERApplicationSpecific - container of DERSequence - level 3

In here OID for Kerberos 5 should be like `1.2.840.113554.1.2.2`

NTLM authentication OID is `1.3.6.1.4.1.311.2.2.10`

##### Level 3 contains:

version number - should be 5
message type - 14 (AP_REQ)
AP options (DERBITString)
DERApplicationSpecific - wrapped DERSequence with ticket part
DERSeqeuence with additional ticket part - not processed

##### Ticket part - level 4 contains:

Ticket version - should be 5
Ticket realm - the name of the realm in which user is authenticated
DERSequence of server names. Each server name is DERSequence of 2 strings: server name and instance name
DERSequence with encrypted part

##### Encrypted part sequence (level 5) contains:

Used algorithm number
1, 3 - DES
16 - des3-cbc-sha1-kd
17 - ETYPE-AES128-CTS-HMAC-SHA1-96
18 - ETYPE-AES256-CTS-HMAC-SHA1-96
23 - RC4-HMAC
24 - RC4-HMAC-EXP
Key version number
Encrypted part (DEROctetStream)

For example:

```
<OpenSSL::ASN1::ASN1Data:0x00007ff66d917560
 @indefinite_length=false,
 @tag=1,
 @tag_class=:CONTEXT_SPECIFIC,
 @value=
  [#<OpenSSL::ASN1::Sequence:0x00007ff66d917c68
    @indefinite_length=false,
    @tag=16,
    @tag_class=:UNIVERSAL,
    @tagging=nil,
    @value=
     [#<OpenSSL::ASN1::ASN1Data:0x00007ff66d91e630
       @indefinite_length=false,
       @tag=0,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=[#<OpenSSL::ASN1::Enumerated:0x00007ff66d91edb0 @indefinite_length=false, @tag=10, @tag_class=:UNIVERSAL, @tagging=nil, @value=#<OpenSSL::BN 0>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x00007ff66d91ca38
       @indefinite_length=false,
       @tag=1,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=[#<OpenSSL::ASN1::ObjectId:0x00007ff66d91cb50 @indefinite_length=false, @tag=6, @tag_class=:UNIVERSAL, @tagging=nil, @value="1.2.840.113554.1.2.2">]>,
      #<OpenSSL::ASN1::ASN1Data:0x00007ff66d917d08
       @indefinite_length=false,
       @tag=2,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::OctetString:0x00007ff66d917dd0
          @indefinite_length=false,
          @tag=4,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           "`\x81\x93\x06\t*\x86 ....
```

### Kerberos keytab file parser ###