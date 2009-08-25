module ConfigurableAuthentication
  require 'sha1'

  module ConfigurationClassMethods
    def inspect
      aVars = class_variables.collect do |sVar|
        sAccessor = sVar.match(/^@@(.*)/)[1]
        "#{ sVar }=#{ self.send(sAccessor).inspect }"
      end
      "#<#{ self.name } #{ aVars.join(', ') }>"
    end
  end

  module Authenticated
    def self.included(base)
      base.extend(ClassMethods)
    end

    class Configuration
      extend ::ConfigurableAuthentication::ConfigurationClassMethods
      cattr_accessor \
        :login_redirect
      @@login_redirect = nil
    end

    module ClassMethods
      def acts_as_authenticated
        yield ConfigurableAuthentication::Authenticated::Configuration if block_given?

        include InstanceMethods
      end

      module InstanceMethods
        def login_required
          return redirect_to_login if not session[:user]
          return true 
        end

        def redirect_to_login
          config = ConfigurableAuthentication::Authenticated::Configuration
          session[:return_to] = request.request_uri
          redirect_to(config.login_redirect)
    
          false
        end
      end
    end
  end

  module Authenticator
    def self.included(base)
      base.extend(ClassMethods)
    end

    class Configuration
      extend ::ConfigurableAuthentication::ConfigurationClassMethods

      cattr_accessor \
        :authentication_class,
        :post_login_redirect,
        :post_logout_redirect,
        :after_login,
        :after_logout, 
        :login_success_message,
        :login_failure_message
      @@authentication_class = nil
      @@post_login_redirect = nil # Hash supplying values for url_for(), String with URL, or Proc returning one of these
      @@post_logout_redirect = nil # As above
      @@after_login = nil # Callback Proc post-login
      @@after_logout = nil # Callback Proc post-logout
      @@login_success_message = 'login successful'
      @@login_failure_message = 'login failed'
      # TODO: @@session_user = :user
      # @@session_return_to = :return_to
    end

    module ClassMethods
      def acts_as_authenticator
        yield ConfigurableAuthentication::Authenticator::Configuration if block_given?

        raise 'You must set config.authentication_class for the Authenticator' if  ConfigurableAuthentication::Authenticator::Configuration.authentication_class.nil?

        include InstanceMethods
      end
    end

    module InstanceMethods
      def login
        if not request.post?
          render :login # TODO: parameterize
          return
        end

        config = ConfigurableAuthentication::Authenticator::Configuration
        usr = config.authentication_class.authenticate(params[:user][:logon], params[:user][:password])
        if usr.nil?
          flash[:warning] = config.login_failure_message
          return
        end

        session[:user] = usr

        flash[:message] = config.login_success_message
        if session[:return_to]
          ret = session[:return_to]
          session[:return_to] = nil
        else
          if config.post_login_redirect.class == Proc
            ret = config.post_login_redirect.call(session[:user])
          else
            ret = config.post_login_redirect
          end
        end
        config.after_login.call(session[:user]) if config.after_login
        redirect_to(ret)
      end

      def logout
        config = ConfigurableAuthentication::Authenticator::Configuration

        session[:user] = nil

        config.after_logout.call(session[:user]) if config.after_logout
        redirect_to(config.post_logout_redirect) if config.post_logout_redirect
      end
    end
  end

  module Authentication
    def self.included(base)
      base.extend(ClassMethods)
    end

    class Configuration
      extend ::ConfigurableAuthentication::ConfigurationClassMethods
      cattr_accessor \
        :user_name_column,
        :password_hash_column,
        :password_form_field,
        :password_confirmation_form_field,
        :missing_password_message,
        :incorrect_password_confirmation_message,
        :missing_user_name_message,
        :non_unique_user_name_message
      @@user_name_column = 'logon'
      @@password_hash_column = 'password_hash'
      @@password_form_field = 'password'
      @@password_confirmation_form_field = 'password_confirmation'
      @@missing_password_message = 'must be given'
      @@incorrect_password_confirmation_message = 'is different from the confirmation'
      @@missing_user_name_message = 'must be set'
      @@non_unique_user_name_message = 'already exists'
      # TODO: hashing algorithm
    end

    module ClassMethods
      def acts_as_authentication
        yield ConfigurableAuthentication::Authentication::Configuration if block_given?

        include InstanceMethods
        extend SingletonMethods
      end
    end

    module SingletonMethods
      def authenticate(sLogon, sPassword)
        config = ConfigurableAuthentication::Authentication::Configuration
        usr = find(:first, :conditions => ["#{ config.user_name_column } = ?", sLogon])
        return nil if usr.nil?
        return nil if not usr.password_ok?(sPassword)
        usr
      end
    end

    module InstanceMethods
      config = ConfigurableAuthentication::Authentication::Configuration

      define_method "#{ config.password_form_field }=" do |pass|
        return if pass.blank?
        @password = pass
        write_attribute(config.password_hash_column, salted_hash(@password))
      end

      define_method "#{ config.password_confirmation_form_field }=" do |pass|
        return if pass.blank?
        @password_confirmation = pass
      end

      def validate
        if self.id.nil?
          # New records
          if @password.nil?
            errors.add config.password_form_field.intern, config.missing_password_message
          elsif @password != @password_confirmation
            errors.add config.password_form_field.intern, config.incorrect_password_confirmation_message
          end
        elsif @password
          # Password change on existing records
          if @password != @password_confirmation
            errors.add config.password_form_field.intern, config.incorrect_password_confirmation_message
          end
        end

        sLogon = read_attribute(config.user_name_column)
        if sLogon.nil?
          errors.add config.user_name_column.intern, config.missing_user_name_message
        else
          usr = self.class.find(:first, :conditions => ["#{ config.user_name_column } = ?", sLogon])
          if self.id.nil?
            if usr
              errors.add config.user_name_column.intern, config.non_unique_user_name_message
            end
          else
            if self != usr
              errors.add config.user_name_column.intern, config.non_unique_user_name_message
            end
          end
        end
      end

      def password_ok?(sPassword)
        read_attribute(config.password_hash_column) == salted_hash(sPassword) ? true : false
      end

      private

      def config
        ConfigurableAuthentication::Authentication::Configuration
      end

      def salted_hash(pass)
        if self.salt.nil?
          write_attribute(:salt, random_string)
        end
        Digest::SHA1.hexdigest("#{ self.salt }#{ pass }")
      end

      def random_string
        s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        (1..20).collect{s[rand(s.length),1]}.join
      end
    end
  end
end

ActionController::Base.send(:include, ConfigurableAuthentication::Authenticator)
ActionController::Base.send(:include, ConfigurableAuthentication::Authenticated)
ActiveRecord::Base.send(:include, ConfigurableAuthentication::Authentication)
