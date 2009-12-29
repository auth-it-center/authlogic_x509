require "authlogic_x509/version"
require "authlogic_x509/acts_as_authentic"
require "authlogic_x509/session"

ActiveRecord::Base.send(:include, AuthlogicX509::ActsAsAuthentic)
Authlogic::Session::Base.send(:include, AuthlogicX509::Session)