class ConfigurableAuthenticationGenerator < Rails::Generator::NamedBase
  def manifest
    record do |m|
      m.migration_template 'migration:migration.rb', "db/migrate", {:assigns => configurable_authentication_local_assigns, 
        :migration_file_name => "add_authentication_fields_to_#{ table_name }" 
      }
    end
  end

  private

  def table_name
    class_name.underscore.downcase.pluralize
  end

  def configurable_authentication_local_assigns
    returning(assigns = {}) do
      assigns[:migration_action] = "add" 
      assigns[:class_name] = "add_authentication_fields_to_#{ table_name }" 
      assigns[:table_name] = table_name
      assigns[:attributes] = [Rails::Generator::GeneratedAttribute.new('logon', 'string')]
      assigns[:attributes] << Rails::Generator::GeneratedAttribute.new('password_hash', 'string')
      assigns[:attributes] << Rails::Generator::GeneratedAttribute.new('salt', 'string')
    end
  end
end
