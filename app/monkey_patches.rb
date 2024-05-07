# frozen_string_literal: true

require "ssh_data"
require "base64"

module SSHData
  module Encoding
    # Get a PEM encoded blob from signature object.
    #
    # signature  - The SSHData::Signature signature object.
    #
    def encode_openssh_signature(signature)
      pem_type = "SSH SIGNATURE"
      header = "-----BEGIN #{pem_type}-----"
      footer = "-----END #{pem_type}-----"

      fields =
        OPENSSH_SIGNATURE_FIELDS
          .map do |field, type|
            case field
            when :publickey then [type, signature.public_key.rfc4253]
            else                 [type, signature.public_send(field)]
            end
          end

      blob = OPENSSH_SIGNATURE_MAGIC + encode_fields(*fields)
      "%s\n%s%s" % [header, Base64.encode64(blob), footer]
    end
  end

  class Signature
    def to_pem
      Encoding.encode_openssh_signature(self)
    end
  end
end
