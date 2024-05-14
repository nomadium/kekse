# frozen_string_literal: true

require "aws-sdk-iam"
require "aws-sdk-sts"

module Kekse
  module Aws
    extend self

    DEFAULT_REGION = "eu-west-1"

    def default_region
      DEFAULT_REGION
    end

    def aws_lambda?
      ENV.key?("AWS_EXECUTION_ENV") && ENV.key?("AWS_LAMBDA_FUNCTION_NAME")
    end

    def iam_client
      return ::Aws::IAM::Client.new if aws_lambda?
      ::Aws::IAM::Client.new(region: default_region)
    end

    def iam_stub_client
      ::Aws::IAM::Client.new(region: default_region, stub_responses: true)
    end

    def sts_client
      return ::Aws::STS::Client.new if aws_lambda?
      ::Aws::STS::Client.new(region: default_region)
    end

    def sts_stub_client
      ::Aws::STS::Client.new(region: default_region, stub_responses: true)
    end

    def service_role?(role_policy)
      return false if role_policy.nil?
      parsed_policy = JSON.parse(CGI.unescape(role_policy))
      parsed_policy["Statement"].any? { |s| s["Principal"].key?("Service") }
    rescue
      false
    end

    def list_iam_roles(iam_client)
      response = iam_client.list_roles
      # warn if truncated response
      response.roles
    end

    def list_assumable_iam_roles(iam_client)
      roles = list_iam_roles(iam_client)
      roles
        .reject { |r| r.path == "/service-role/"                   }
        .reject { |r| r.path.start_with?("/aws-service-role/")     }
        .reject { |r| service_role?(r.assume_role_policy_document) }
    end

    def aws_account_id(sts_client)
      response = sts_client.get_caller_identity
      response.account
    end
  end
end
