# frozen_string_literal: true

require "digest"
require "ssh_data"

module Kekse
  module Utils
    def self.signed_data(message, namespace, reserved, hash_algorithm)
      digest =
        Digest
          .const_get(hash_algorithm.upcase)
          .digest(message)

      fields = [
        [:string, namespace],
        [:string, reserved],
        [:string, hash_algorithm],
        [:string, digest]
      ]

      preamble = SSHData::Signature::SIGNATURE_PREAMBLE
      preamble + SSHData::Encoding.encode_fields(*fields)
    end

    def self.ssh_sign(key, message, namespace, reserved, hash_algorithm)
      signed_data = signed_data(message, namespace, reserved, hash_algorithm)
      inner_signature = key.sign(signed_data)

      SSHData::Signature.new(
        sigversion:     SSHData::Signature::MIN_SUPPORTED_VERSION,
        publickey:      key.public_key.rfc4253,
        namespace:      namespace,
        reserved:       reserved,
        hash_algorithm: hash_algorithm,
        signature:      inner_signature
      )
    end

    def self.openssh_signature(key, message)
      namespace      = "file"
      reserved       = ""
      hash_algorithm = "sha512"
      ssh_sign(key, message, namespace, reserved, hash_algorithm)
    end
  end
end
