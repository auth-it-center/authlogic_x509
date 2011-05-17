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
  		def find_by_x509_login_method(value = nil)
  				rw_config(:find_by_x509_login_method, value, :find_by_x509_login)
  		end
  		alias_method :find_by_x509_login_method=, :find_by_x509_login_method

  		def x509_mapping_method(value = nil)
  				rw_config(:x509_mapping_method, value, :map_x509_login)
  		end  		
  		alias_method :x509_mapping_method=, :x509_mapping_method
  			
    end
    
    module Methods
      def self.included(klass)
        klass.class_eval do
          attr_accessor :x509_login
          attr_accessor :x509_issuer_dn
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
      
      def x509_map
        get_distinguished_names
        if self.x509_subject_dn && self.x509_issuer_dn
          attempted_record.send(x509_mapping_method, x509_subject_dn, x509_issuer_dn)
        else
          errors.add_to_base(I18n.t('error_messages.x509_login_subject_or_issuer_not_found', :default => "Subject DN or Issuer DN not found"))
        end
        return {:subject_dn=>x509_subject_dn, :issuer_dn=>x509_issuer_dn}
      end

      private
        def authenticating_with_x509?
          attempted_record.nil? && errors.empty? && x509_login
        end

        def validate_by_x509
          get_distinguished_names
          if self.x509_subject_dn && self.x509_issuer_dn
            self.attempted_record = klass.send(find_by_x509_login_method, x509_subject_dn, x509_issuer_dn)
            errors.add(:x509_login, I18n.t('error_messages.x509_login_record_does_not_exist', :default => "Record does not exist")) if attempted_record.blank?
            return false
          else
            errors.add_to_base(I18n.t('error_messages.x509_login_subject_or_issuer_not_found', :default => "Subject DN or Issuer DN not found"))
            return false
          end
          return true
        end
        
        def get_distinguished_names
          if controller.local_request?
            self.x509_subject_dn = "/CN=Local Request"
            self.x509_issuer_dn = "/CN=Local Issuer"
          elsif controller.request.env['SSL_CLIENT_S_DN'] =~ /CN/
            self.x509_subject_dn = controller.request.env['SSL_CLIENT_S_DN']
            self.x509_issuer_dn = controller.request.env['SSL_CLIENT_I_DN']
          elsif controller.request.env['REDIRECT_SSL_CLIENT_S_DN'] =~ /CN/
            self.x509_subject_dn = controller.request.env['REDIRECT_SSL_CLIENT_S_DN']
            self.x509_issuer_dn = controller.request.env['REDIRECT_SSL_CLIENT_I_DN']
          elsif controller.request.env['HTTP_REDIRECT_SSL_CLIENT_S_DN'] =~ /CN/
            self.x509_subject_dn = controller.request.env['HTTP_REDIRECT_SSL_CLIENT_S_DN']
            self.x509_issuer_dn = controller.request.env['HTTP_REDIRECT_SSL_CLIENT_I_DN']
          end
        end
        
        def find_by_x509_login_method
  				self.class.find_by_x509_login_method
  			end

        def x509_mapping_method
  				self.class.x509_mapping_method
  			end
  			
  			def x509_subject_dn
          self.class.x509_subject_dn
        end
        
        def x509_issuer_dn
          self.class.x509_issuer_dn
        end
        
        def x509_login
          self.class.x509_login
        end
    end
  end
end