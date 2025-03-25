require "linzer"

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

      def allowed?
        has_signature? && verifiable?
      end

      def pubkey
        Linzer.new_ed25519_public_key(@options[:pubkey], "some-key-ed25519")
      end
    end
  end
end
