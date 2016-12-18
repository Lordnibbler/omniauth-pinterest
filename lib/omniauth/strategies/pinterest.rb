# @note approach adapted from docs: https://api.pinterest.com/docs/reference/oauth_reference/

require 'omniauth-oauth2'
require 'openssl'

module OAuth2
  module Strategy
    class Base
      def initialize(client)
        @client = client
      end

      # The OAuth client_id and client_secret
      #
      # @return [Hash]
      # @note override me to remove the client_secret, as pinterest auth will explode if this is present ;(
      def client_params
        {'client_id' => @client.id}
      end
    end
  end

  class Client
    # Initializes an AccessToken by making a request to the token endpoint
    #
    # @param [Hash] params a Hash of params for the token endpoint
    # @param [Hash] access token options, to pass to the AccessToken object
    # @return [AccessToken] the initalized AccessToken
    def get_token(params, access_token_opts={})
      opts = {:raise_errors => options[:raise_errors], :parse => params.delete(:parse)}
      if options[:token_method] == :post
        headers = params.delete(:headers)
        opts[:body] = params
        opts[:headers] =  {'Content-Type' => 'application/x-www-form-urlencoded'}
        opts[:headers].merge!(headers) if headers
      else
        opts[:params] = params
      end
      response = request(options[:token_method], token_url, opts)

      # move the 'data' key into the main hash so its actually normal OAuth :\
      response_body = (response.parsed.merge response.parsed['data']).delete('data')

      raise Error.new(response) if options[:raise_errors] && !(response_body.is_a?(Hash) && response_body['access_token'])
      AccessToken.from_hash(self, response_body.merge(access_token_opts))
    end
  end
end


module OmniAuth
  module Strategies
    class Pinterest < OmniAuth::Strategies::OAuth2
      args [:consumer_id, :secret_key, :redirect_uri]

      option :consumer_id
      option :secret_key
      option :redirect_uri
      option :client_options, {
        site: 'https://pinterest.com/',
        authorize_url: 'https://pinterest.com/oauth/',
        token_url: 'https://api.pinterest.com/v3/oauth/code_exchange/',
        token_method: :put
      }
      option :auth_token_params, {}

      def build_access_token
        verifier = request.params['code']
        client.auth_code.get_token(verifier, auth_token_params)
      end

      def auth_token_params
        base_auth_token_params.merge('oauth_signature' => generate_oauth_signature)
      end

      def base_auth_token_params
        {
          'client_id' => options[:consumer_id],
          'code' => request.params['code'],
          'consumer_id' => options[:consumer_id],
          'redirect_uri' => options[:redirect_uri],
          'grant_type' => 'authorization_code',
          'timestamp' => Time.now.to_i
        }
      end

      # required fields:
      #   consumer_id=YOUR_CONSUMER_ID
      #   &redirect_uri=YOUR_REDIRECT_URI
      #   &response_type=code
      #   &state=YOUR_OPTIONAL_STRING
      def request_phase
        options[:response_type] ||= 'code'
        options[:client_id] = options[:consumer_id]

        url = client.auth_code.authorize_url({
          redirect_uri: callback_url,
          consumer_id: options[:consumer_id]
        }.merge(authorize_params))
        url.gsub!('client_id&', '')

        redirect url
      end

      def callback_phase # rubocop:disable AbcSize, CyclomaticComplexity, MethodLength, PerceivedComplexity
        error = request.params['error_reason'] || request.params['error']
        if error
          fail!(
            error,
            CallbackError.new(
              request.params['error'],
              request.params['error_description'] || request.params['error_reason'],
              request.params['error_uri']
            )
          )
        elsif !options.provider_ignores_state && (
          request.params['state'].to_s.empty? ||
          request.params['state'] != session.delete('omniauth.state')
        )
          fail!(:csrf_detected, CallbackError.new(:csrf_detected, 'CSRF detected'))
        else
          self.access_token = build_access_token
          if !access_token.expires_at.zero? && access_token.expired?
            self.access_token = access_token.refresh!
          end

          # implement the equivalent of `super` here since a normal
          # auth_hash is too unlike what pinterest returns
          hash = AuthHash.new(provider: name)
          # hash.info = info unless skip_info?
          hash.credentials = credentials if credentials
          hash.extra = extra if extra
          env['omniauth.auth'] = hash
          call_app!
        end
      rescue ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      uid { raw_info['id'] }

      info { raw_info }

      def raw_info
        @raw_info ||= access_token.get('/v1/me/').parsed['data']
      end

      private

      def generate_oauth_signature
        data = 'PUT&https%3A%2F%2Fapi.pinterest.com%2Fv3%2Foauth%2Fcode_exchange%2F&'
        data << base_auth_token_params.to_query
        key = options[:secret_key]
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), key, data)
      end
    end
  end
end
