# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 Name Identifier.
    #
    # Value object that represents a NameID identity. The Format,
    # NameQualifier and SPNameQualifier attributes are part of the
    # identity, so two identifiers are only considered the same identity
    # when the value and all of those attributes match.
    #
    class NameIdentifier
      attr_reader :value
      attr_reader :format
      attr_reader :name_qualifier
      attr_reader :sp_name_qualifier

      # @param value [String] The NameID value
      # @param options [Hash] Optional attributes that are part of the identity:
      #                       :format [String] The Format attribute
      #                       :name_qualifier [String] The NameQualifier attribute
      #                       :sp_name_qualifier [String] The SPNameQualifier attribute
      # @raise [ArgumentError] If value is nil
      #
      def initialize(value, options = {})
        raise ArgumentError.new("NameIdentifier value cannot be nil") if value.nil?

        @value = value
        @format = options[:format]
        @name_qualifier = options[:name_qualifier]
        @sp_name_qualifier = options[:sp_name_qualifier]
      end

      # Two identifiers are the same identity only when the value and the
      # Format, NameQualifier and SPNameQualifier attributes all match.
      #
      def ==(other)
        other.is_a?(NameIdentifier) &&
          value == other.value &&
          format == other.format &&
          name_qualifier == other.name_qualifier &&
          sp_name_qualifier == other.sp_name_qualifier
      end

      alias_method :eql?, :==

      def hash
        to_key.hash
      end

      # @return [Array] A stable key with all the attributes that form the identity
      #
      def to_key
        [value, format, name_qualifier, sp_name_qualifier]
      end
    end
  end
end
