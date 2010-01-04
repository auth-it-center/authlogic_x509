require 'openssl'

module AuthlogicX509
  module Session
    # Add a simple openid_identifier attribute and some validations for the field.
    def self.included(klass)
      klass.class_eval do
        extend Config
        include Methods
      end
    end
    
    module Config
      # Once X509 authentication has succeeded we need to find the user in the database. By default this just calls the
      # find_with_x509_login method provided by ActiveRecord. If you have a more advanced set up and need to find users
      # differently specify your own method and define your logic in there.
      #
      # For example, if you allow users to store multiple x509 subject DNs with their account, you might do something like:
      #
      #   class User < ActiveRecord::Base
      #     def self.find_with_x509_login(login_hash)
      #       first(:conditions => ["#{X509Login.table_name}.subject_dn = ? and #{X509Login.table_name}.issuer_dn = ?", login_hash[:subject_dn], login_hash[:issuer_dn]], :join => :x509_logins)
      #     end
      #   end
      #
      # * <tt>Default:</tt> :find_with_x509_login
      # * <tt>Accepts:</tt> Symbol
  		def find_with_x509_login_method(value = nil)
  				rw_config(:find_with_x509_login_method, value, :find_with_x509_login)
  		end
  		alias_method :find_with_x509_login_method=, :find_with_x509_login_method
  			
    end
    
    module Methods
      def self.included(klass)
        klass.class_eval do
          attr_accessor :x509_login
          attr_accessor :x509_subject_dn
          attr_accessor :x509_issuer_dn
          attr_accessor :x509_client_cert
          validate :validate_by_x509, :if => :authenticating_with_x509?
        end
      end
      
      # Hooks into credentials so that you can pass an :x509_login key.
      def credentials
        if authenticating_with_x509?
          details = {}
          details[:x509_subject_dn] = self.x509_subject_dn
          details[:x509_issuer_dn] = self.x509_issuer_dn
          details
        else
          super
        end
      end

      def credentials=(value)
        super
        values = value.is_a?(Array) ? value : [value]
        hash = values.first.is_a?(Hash) ? values.first.with_indifferent_access : nil
        if !hash.nil?
          self.x509_login = hash[:x509_login] if hash.key?(:x509_login)
          self.x509_client_cert = hash[:x509_client_cert] if hash.key?(:x509_client_cert)
        end
      end
      
      private
        def authenticating_with_x509?
          x509_login
        end

        def validate_by_x509
          parse_x509_login
          if self.x509_subject_dn || self.x509_issuer_dn
            self.attempted_record = search_for_record(find_with_x509_login_method, {:subject_dn=>x509_subject_dn,:issuer_dn=>x509_issuer_dn})
            errors.add(:x509_login, I18n.t('error_messages.x509_login_user_not_found', :default => "does not exist")) if attempted_record.blank?
          else
            errors.add_to_base("User not found")
          end
        end
        
        def find_with_x509_login_method
  				self.class.find_with_x509_login_method
  			end
  			
  			def parse_x509_login
  			  get_subject_dn
          get_issuer_dn
			  end

  			def get_subject_dn
  			  if controller.local_request? 
  			    self.x509_subject_dn = "/CN=Local Request"
			    elsif cert = OpenSSL::X509::Certificate.new(x509_client_cert)
  			    self.x509_subject_dn = cert.subject.to_s
  			  end
  			end

  			def get_issuer_dn
  			  if controller.local_request? 
  			    self.x509_issuer_dn = "/CN=Local Request Issuer"
			    elsif cert = OpenSSL::X509::Certificate.new(x509_client_cert)
  			    self.x509_issuer_dn = cert.issuer.to_s
  			  end
  			end
    end
  end
end