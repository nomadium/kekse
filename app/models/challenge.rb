# frozen_string_literal: true

require "securerandom"
require "base64"

module Kekse
  class Challenge
    def initialize(payload = nil, time = nil)
      @payload = payload.dup.freeze || SecureRandom.base64(16).freeze
      @time    = time.dup.freeze    || Time.now.to_i.freeze
      freeze
    end

    CHALLENGE_REGEXP = /\Achallenge-(?<payload>.+)-(?<time>[0-9]{10})\z/
    SIGNATURE_HASH_ALGORITHM = "sha512"
    SIGNATURE_NAMESPACE      = "file"
    SIGNATURE_VERSION        = 1

    attr_reader :payload, :time

    def to_s
      Base64.strict_encode64("challenge-%s-%s" % [@payload, @time])
    end

    Signature = Struct.new(:message, :bytes) do
      def valid?
        message_expected_format? && valid_signature?
      end

      def message_expected_format?
        message_length == 16 && valid_time?
      end

      def valid_time?
        time_delta = Time.now.to_i - message.time
        time_delta.zero? || (time_delta <= 5 * 60 && time_delta >= 0)
      end

      def message_length
        Base64.strict_decode64(message.payload).length
      end

      def ssh_signature
        @ssh_signature ||= SSHData::Signature.parse_pem(Base64.decode64(bytes))
      rescue SSHData::DecodeError
        nil
      end

      def expected_hash_algorithm?
        ssh_signature.hash_algorithm == SIGNATURE_HASH_ALGORITHM
      end

      def expected_namespace?
        ssh_signature.namespace == SIGNATURE_NAMESPACE
      end

      def expected_version?
        ssh_signature.sigversion == SIGNATURE_VERSION
      end

      def expected_parameters?
        expected_hash_algorithm? && expected_namespace? && expected_version?
      end

      def valid_signature?
        return false if !ssh_signature
        expected_parameters? && ssh_signature.verify(message.to_s)
      end

      def public_key
        invalid? ? nil : ssh_signature.public_key
      end

      def invalid?
        equal?(INVALID_SIGNATURE) || !valid?
      end

      def self.build(message, bytes)
        raw_challenge = Base64.strict_decode64(message)
        return invalid_signature unless raw_challenge.start_with?("challenge-")
        return invalid_signature unless raw_challenge.match(CHALLENGE_REGEXP)
        return invalid_signature     if bytes.nil?
        match = Regexp.last_match

        payload = match[:payload]
        return invalid_signature if Base64.strict_decode64(payload).length != 16

        time = match[:time].to_i

        challenge = Challenge.new(payload, time)
        Signature.new(challenge, bytes)
      rescue
        invalid_signature
      end

      def self.invalid_signature
        INVALID_SIGNATURE
      end
    end

    INVALID_SIGNATURE = Signature.new(nil, nil)
  end
end
