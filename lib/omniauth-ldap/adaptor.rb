#this code borrowed pieces from activeldap and net-ldap

require 'rack'
require 'net/ldap'
require 'net/ntlm'
require 'sasl'
require 'kconv'
module OmniAuth
  module LDAP
    class Adaptor
      class LdapError < StandardError; end
      class ConfigurationError < StandardError; end
      class AuthenticationError < StandardError; end
      class ConnectionError < StandardError; end

      VALID_ADAPTER_CONFIGURATION_KEYS = [:host, :port, :method, :bind_dn, :password, :try_sasl, :sasl_mechanisms, :uid, :base, :allow_anonymous, :filter]

      # A list of needed keys. Possible alternatives are specified using sub-lists.
      MUST_HAVE_KEYS = [:host, :port, :method, [:uid, :filter], :base]

      METHOD = {
        :ssl => :simple_tls,
        :tls => :start_tls,
        :plain => nil,
      }

      attr_accessor :bind_dn, :password
      attr_reader :connection, :connections, :uid, :base, :auth, :filter
      def self.validate(configuration={})
        message = []
        MUST_HAVE_KEYS.each do |names|
          names = [names].flatten
          missing_keys = names.select{|name| configuration[name].nil?}
          if missing_keys == names
            message << names.join(' or ')
          end
        end
        raise ArgumentError.new(message.join(",") +" MUST be provided") unless message.empty?
      end
      def initialize(configuration={})
        Adaptor.validate(configuration)
        @configuration = configuration.dup
        @configuration[:allow_anonymous] ||= [false]
        @logger = @configuration.delete(:logger)

        VALID_ADAPTER_CONFIGURATION_KEYS.each do |name|
          if name == :sasl_mechanisms
            if Array(@configuration[name]).first.kind_of?(Array)
              next instance_variable_set("@#{name}", @configuration[name])
            end

            next instance_variable_set("@#{name}", [@configuration[name]])
          end

          # These are common to all connections
          if [:uid, :name_proc, :filter].any? {|key| key == name}
            next instance_variable_set("@#{name}", @configuration[name])
          end

          instance_variable_set("@#{name}", Array(@configuration[name]))
        end

        @connections ||= []

        @host.each_with_index do |_, index|
          method = ensure_method(@method[index])
          config = {
            :host => @host[index],
            :port => @port[index],
            :encryption => method,
            :base => @base[index]
          }

          bind_method = @try_sasl[index] ? :sasl : (@allow_anonymous[index]||!@bind_dn[index]||!@password[index] ? :anonymous : :simple)

          auth = sasl_auths({:username        => @bind_dn[index],
                             :password        => @password[index],
                             :sasl_mechanisms => @sasl_mechanisms[index],
                             :host            => @host[index]}).first if bind_method == :sasl
          auth ||= { :method => bind_method,
                     :username => @bind_dn[index],
                     :password => @password[index]
                   }
          config[:auth] = auth
          @connection = Net::LDAP.new(config)
          @connections << @connection
        end
      end

      #:base => "dc=yourcompany, dc=com",
      # :filter => "(mail=#{user})",
      # :password => psw
      def bind_as(args = {})
        result = false

        connection_index = 0

        @connections.detect do |connection|
          begin
            connection.open do |me|
              rs = me.search args.clone
              if rs and rs.first and dn = rs.first.dn
                password = args[:password]
                method = args[:method] || @method[connection_index]
                password = password.call if password.respond_to?(:call)
                if method == 'sasl'
                result = rs.first if me.bind(sasl_auths({:username => dn,
                                                         :password => password,
                                                         :sasl_mechanisms => @sasl_mechanisms[index],
                                                         :host            => @host[index]}).first)
                else
                result = rs.first if me.bind(:method => :simple, :username => dn,
                                    :password => password)
                end
              end
            end
          rescue Net::LDAP::LdapError => nldaperror
            puts nldaperror.message
          ensure
            connection_index += 1
          end
        end

        result
      end

      def bind(args = {})
        result = false
        @connections.detect do |connection|
          begin
            connection.open do |me|
              result = me.search args
            end
          rescue Net::LDAP::LdapError => nldaperror
            puts nldaperror.message
          end
        end
        result
      end

      private
      def ensure_method(method)
          method ||= "plain"
          normalized_method = method.to_s.downcase.to_sym
          return METHOD[normalized_method] if METHOD.has_key?(normalized_method)

          available_methods = METHOD.keys.collect {|m| m.inspect}.join(", ")
          format = "%s is not one of the available connect methods: %s"
          raise ConfigurationError, format % [method.inspect, available_methods]
      end

      def sasl_auths(options={})
        auths = []
        sasl_mechanisms = options[:sasl_mechanisms]
        sasl_mechanisms.each do |mechanism|
          normalized_mechanism = mechanism.downcase.gsub(/-/, '_')
          sasl_bind_setup = "sasl_bind_setup_#{normalized_mechanism}"
          next unless respond_to?(sasl_bind_setup, true)
          initial_credential, challenge_response = send(sasl_bind_setup, options)
          auths << {
            :method => :sasl,
            :initial_credential => initial_credential,
            :mechanism => mechanism,
            :challenge_response => challenge_response
          }
        end
        auths
      end

      def sasl_bind_setup_digest_md5(options)
        bind_dn = options[:username]
        host = options[:host]
        initial_credential = ""
        challenge_response = Proc.new do |cred|
          pref = SASL::Preferences.new :digest_uri => "ldap/#{host}", :username => bind_dn, :has_password? => true, :password => options[:password]
          sasl = SASL.new("DIGEST-MD5", pref)
          response = sasl.receive("challenge", cred)
          response[1]
        end
        [initial_credential, challenge_response]
      end

      def sasl_bind_setup_gss_spnego(options)
        bind_dn = options[:username]
        psw = options[:password]
        raise LdapError.new( "invalid binding information" ) unless (bind_dn && psw)

        nego = proc {|challenge|
          t2_msg = Net::NTLM::Message.parse( challenge )
          bind_dn, domain = bind_dn.split('\\').reverse
          t2_msg.target_name = Net::NTLM::encode_utf16le(domain) if domain
          t3_msg = t2_msg.response( {:user => bind_dn, :password => psw}, {:ntlmv2 => true} )
          t3_msg.serialize
        }
        [Net::NTLM::Message::Type1.new.serialize, nego]
      end

    end
  end
end
