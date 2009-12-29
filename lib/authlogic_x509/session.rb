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
      # find_by_x509_subject_dn method provided by ActiveRecord. If you have a more advanced set up and need to find users
      # differently specify your own method and define your logic in there.
      #
      # For example, if you allow users to store multiple x509 subject DNs with their account, you might do something like:
      #
      #   class User < ActiveRecord::Base
      #     def self.find_by_x509_subject_dn(login)
      #       first(:conditions => ["#{X509Login.table_name}.login = ?", login], :join => :x509_logins)
      #     end
      #   end
      #
      # * <tt>Default:</tt> :find_by_x509_subject_dn
      # * <tt>Accepts:</tt> Symbol
  		def find_by_x509_login_method(value = nil)
  				rw_config(:find_by_x509_login_method, value, :find_by_x509_subject_dn)
  		end
  		alias_method :find_by_x509_login_method=, :find_by_x509_login_method
  			
    end
    
    module Methods
      def self.included(klass)
        klass.class_eval do
          attr_accessor :x509_login
          attr_accessor :x509_subject_dn
          validate :validate_by_x509, :if => :authenticating_with_x509?
        end
      end
      
      # Hooks into credentials so that you can pass an :x509_login key.
      def credentials=(value)
        super
        values = value.is_a?(Array) ? value : [value]
        hash = values.first.is_a?(Hash) ? values.first.with_indifferent_access : nil
        if !hash.nil?
          self.x509_login = hash[:x509_login] if hash.key?(:x509_login)
        end
      end
      
      private
        def authenticating_with_x509?
          attempted_record.nil? && errors.empty? && x509_login
        end

        def validate_by_x509
          self.x509_subject_dn = get_subject_dn
          if self.x509_subject_dn
            self.attempted_record = search_for_record(find_by_x509_login_method, x509_subject_dn)
            errors.add(:x509_subject_dn, I18n.t('error_messages.x509_subject_dn_not_found', :default => "does not exist")) if attempted_record.blank?
          else
            errors.add_to_base("Subject DN not found")
          end
        end
        
        def find_by_x509_login_method
  				self.class.find_by_x509_login_method
  			end

  			def get_subject_dn
  			  if controller.local_request? 
  			    self.x509_subject_dn = "/CN=Local Request"
  			  elsif controller.request.env['SSL_CLIENT_S_DN'] =~ /CN/
  			    self.x509_subject_dn = controller.request.env['SSL_CLIENT_S_DN']
  			  elsif controller.request.env['REDIRECT_SSL_CLIENT_S_DN'] =~ /CN/
  			    self.x509_subject_dn = controller.request.env['REDIRECT_SSL_CLIENT_S_DN']
  			  elsif controller.request.env['HTTP_REDIRECT_SSL_CLIENT_S_DN'] =~ /CN/
  			    self.x509_subject_dn = controller.request.env['HTTP_REDIRECT_SSL_CLIENT_S_DN']
  			  end
  			end			    
    end
  end
end