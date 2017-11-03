require 'omniauth-oauth2'
module OmniAuth
  module Strategies
    class Sso < OmniAuth::Strategies::OAuth2
      include OmniAuth::Strategy

      CUSTOM_PROVIDER_URL = "#{Rails.configuration.x.app_url}"
      option :name, :sso

      option :client_options, {
        :site =>  CUSTOM_PROVIDER_URL,
        :authorize_url => "#{CUSTOM_PROVIDER_URL}/oauth2/signup",
        token_url: 'oauth/token'
      }

      uid do
        raw_info['id']
      end

      info do
        {
            :email => raw_info["email"]
        }
      end

      def raw_info
        @raw_info ||= access_token.get('/oauth2_api/v1/user').parsed
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end
    end
  end
end