require "omniauth/strategies/oauth"

module OmniAuth
  module Strategies
    class Xero < OmniAuth::Strategies::OAuth

      args [:consumer_key, :consumer_secret]

      option :client_options, {
        :access_token_path  => "/oauth/AccessToken",
        :authorize_path     => "/oauth/Authorize",
        :request_token_path => "/oauth/RequestToken",
        :site               => "https://api.xero.com",
      }

      info do
        {
          :first_name => raw_info["FirstName"],
          :last_name  => raw_info["LastName"],
          :email => raw_info['EmailAddress'],
        }
      end

      uid { raw_info["UserID"] }

      extra do
        { "raw_info" => raw_info }
      end

      private

      def raw_info
        # Xero doesn't tell you who logged-in so you can't pick out a user from the list
        # to match to the one who just authenticated via Xero for your App. The only unambiguous case
        # is when the list of users is a singleton. We require 100% accuracy here so when it is ambiguous
        # we don't give any info via raw_info.
        @raw_info ||= users.size == 1 ? users.first : {}
      end

      def users
        @users ||= JSON.parse(access_token.get("/api.xro/2.0/Users", {'Accept'=>'application/json'}).body)["Users"]
      end
    end
  end
end
