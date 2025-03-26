require "linzer"

MONKEYPATCH = true

# to-do: fix bug in linzer
if MONKEYPATCH
  module Linzer
    class Signature
      class << self
        def parse_field(hsh, field_name)
          # Serialized Structured Field values for HTTP return ASCII strings.
          # See: RFC 8941 (https://datatracker.ietf.org/doc/html/rfc8941)
          value = hsh[field_name].encode(Encoding::US_ASCII)
          Message.parse_structured_dictionary(value, field_name)
        end
      end
    end
  end
end

module Rack
  module Auth
    class Signature
      def initialize(app, options = {})
        @app = app
        @options = Hash(options)
      end

      def call(env)
        @request = Rack::Request.new(env)

        if excluded? || allowed?
          @app.call(env)
        else
          Rack::Response.new([], 401, {}).finish
        end
      end

      private

      def excluded?
        return false if !@request
        Array(@options[:except]).include?(@request.path)
      end

      def has_signature?
        @message = Linzer::Message.new(@request)
        @signature = Linzer::Signature.build(@message.headers)
        (@signature.to_h.keys & %w[signature signature-input]).size == 2
      rescue => ex
        puts ex.message # XXX: to-do: fix, we should log this instead
        false
      end

      def verifiable?
        # XXX: to-do: mechanism to find pubkey
        Linzer.verify(pubkey, @message, @signature)
      rescue => ex
        puts ex.message # XXX: to-do: fix, we should log this instead
        false
      end

      def acceptable?
        params = @signature.parameters
        params.key?("created") && params.key?("keyid")
      end

      def allowed?
        has_signature? && acceptable? && verifiable?
      end

      def pubkey
        Linzer.new_ed25519_public_key(@options[:pubkey], "some-key-ed25519")
      end
    end
  end
end
