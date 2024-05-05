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

    attr_reader :payload, :time

    def to_s
      Base64.strict_encode64("challenge-%s-%s" % [@payload, @time])
    end

    Signature = Struct.new(:message, :bytes) do
      def valid?
        message_expected_format? && valid_signature?
      end

      def message_expected_format?
        # message_length == 16 && Time.now.to_i - message.time <= 5 * 60
        message_length == 16 && Time.now.to_i - message.time <= 100000
      end

      def message_length
        Base64.strict_decode64(message.payload).length
      end

      def ssh_signature
        @ssh_signature ||= SSHData::Signature.parse_pem(Base64.decode64(bytes))
      rescue SSHData::DecodeError
        nil
      end

      def valid_signature?
        known_key? && ssh_signature.verify(message.to_s)
      end

      def known_key?
        return false if !ssh_signature
        fingerprint = "ZDtwx65wb2PwVnZfHjIIS9TbtmDw+yg+YJ+Kqzfwf2w"
        ssh_signature.public_key.fingerprint == fingerprint
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
