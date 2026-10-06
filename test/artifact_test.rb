require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/artifact'

class ArtifactTest < Minitest::Test
  IDP_ENTITY_ID = 'https://idp.example.com'
  SP_ENTITY_ID = 'https://sp.example.com'
  ACS_URL = 'https://sp.example.com/acs'
  ARS_URL = 'https://ars.example.com/resolve'
  REQUEST_ID = '_authn-request'

  describe OneLogin::RubySaml::Artifact do
    let(:now) { Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ') }
    let(:later) { (Time.now + 3600).utc.strftime('%Y-%m-%dT%H:%M:%SZ') }
    let(:outer_pair) { CertificateHelper.generate_pair }
    let(:outer_cert) { outer_pair[0] }
    let(:outer_key) { outer_pair[1] }
    let(:sp_pair) { CertificateHelper.generate_pair }
    let(:sp_cert) { sp_pair[0] }
    let(:sp_key) { sp_pair[1] }
    let(:inner_cert) { OpenSSL::X509::Certificate.new(File.read(File.join(File.dirname(__FILE__), 'certificates', 'ruby-saml.crt'))) }
    let(:inner_key) { OpenSSL::PKey::RSA.new(File.read(File.join(File.dirname(__FILE__), 'certificates', 'ruby-saml.key'))) }
    let(:consumed) { [] }
    let(:transport_calls) { [] }
    let(:settings) do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_entity_id = IDP_ENTITY_ID
      settings.sp_entity_id = SP_ENTITY_ID
      settings.assertion_consumer_service_url = ACS_URL
      settings.idp_cert = outer_cert.to_pem
      settings.idp_cert_multi = { :signing => [outer_cert.to_pem, inner_cert.to_pem] }
      settings.certificate = sp_cert.to_pem
      settings.private_key = sp_key.to_pem
      settings.idp_artifact_resolution_service_url = ARS_URL
      settings.idp_artifact_resolution_service_index = 7
      settings
    end

    def build_artifact(index = 7, source_entity_id = IDP_ENTITY_ID, message_handle = SecureRandom.random_bytes(20))
      Base64.strict_encode64("\x00\x04" + [index].pack('n') + Digest::SHA1.digest(source_entity_id) + message_handle)
    end

    def build_artifact_resolver(artifact = build_artifact, options = {})
      defaults = {
        :settings => settings,
        :artifact_store => lambda { |value| consumed.include?(value) ? false : consumed << value },
        :matches_request_id => REQUEST_ID
      }
      OneLogin::RubySaml::Artifact.new(artifact, defaults.merge(options))
    end

    def build_inner_response(in_response_to = REQUEST_ID)
      inner_doc = XMLSecurity::Document.new
      inner_doc.uuid = '_inner-response'
      response = inner_doc.add_element('samlp:Response', {
        'xmlns:samlp' => OneLogin::RubySaml::Artifact::PROTOCOL,
        'xmlns:saml' => OneLogin::RubySaml::Artifact::ASSERTION
      })
      response.attributes['ID'] = '_inner-response'
      response.attributes['Version'] = '2.0'
      response.attributes['IssueInstant'] = now
      response.attributes['Destination'] = ACS_URL
      response.attributes['InResponseTo'] = in_response_to
      response.add_element('saml:Issuer').text = IDP_ENTITY_ID

      status = response.add_element('samlp:Status')
      status_code = status.add_element('samlp:StatusCode')
      status_code.attributes['Value'] = 'urn:oasis:names:tc:SAML:2.0:status:Success'

      assertion = response.add_element('saml:Assertion', {
        'ID' => '_inner-assertion',
        'Version' => '2.0',
        'IssueInstant' => now
      })
      assertion.add_element('saml:Issuer').text = IDP_ENTITY_ID

      subject = assertion.add_element('saml:Subject')
      subject.add_element('saml:NameID').text = 'user@example.com'
      confirmation = subject.add_element('saml:SubjectConfirmation', {
        'Method' => 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
      })
      confirmation.add_element('saml:SubjectConfirmationData', {
        'NotOnOrAfter' => later,
        'Recipient' => ACS_URL,
        'InResponseTo' => in_response_to
      })

      conditions = assertion.add_element('saml:Conditions', {
        'NotBefore' => now,
        'NotOnOrAfter' => later
      })
      conditions.add_element('saml:AudienceRestriction').add_element('saml:Audience').text = SP_ENTITY_ID

      authn_statement = assertion.add_element('saml:AuthnStatement', { 'AuthnInstant' => now })
      authn_statement.add_element('saml:AuthnContext').add_element('saml:AuthnContextClassRef').text =
        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'

      inner_doc.sign_document(inner_key, inner_cert, XMLSecurity::Document::RSA_SHA1, XMLSecurity::Document::SHA1)
      inner_doc.to_s
    end

    def build_artifact_response(artifact_resolver, in_response_to = REQUEST_ID)
      outer_doc = XMLSecurity::Document.new
      outer_doc.uuid = '_outer-response'
      response = outer_doc.add_element('samlp:ArtifactResponse', {
        'xmlns:samlp' => OneLogin::RubySaml::Artifact::PROTOCOL,
        'xmlns:saml' => OneLogin::RubySaml::Artifact::ASSERTION
      })
      response.attributes['ID'] = '_outer-response'
      response.attributes['Version'] = '2.0'
      response.attributes['IssueInstant'] = now
      response.attributes['InResponseTo'] = artifact_resolver.request_id
      response.add_element('saml:Issuer').text = IDP_ENTITY_ID

      status = response.add_element('samlp:Status')
      status_code = status.add_element('samlp:StatusCode')
      status_code.attributes['Value'] = 'urn:oasis:names:tc:SAML:2.0:status:Success'

      response.add_element(REXML::Document.new(build_inner_response(in_response_to)).root)
      outer_doc.sign_document(outer_key, outer_cert, XMLSecurity::Document::RSA_SHA1, XMLSecurity::Document::SHA1)
      outer_doc.to_s
    end

    def build_soap(artifact_resolver, in_response_to = REQUEST_ID)
      %(<soap:Envelope xmlns:soap="#{OneLogin::RubySaml::Artifact::SOAP_11}"><soap:Body>#{build_artifact_response(artifact_resolver, in_response_to)}</soap:Body></soap:Envelope>)
    end

    def register_transport(artifact_resolver, soap = nil, endpoint = ARS_URL)
      artifact_resolver.options[:transport] = lambda do |url, body, params|
        transport_calls << { :url => url, :body => body, :params => params }
        raise "unexpected endpoint #{url}" unless url == endpoint
        soap || build_soap(artifact_resolver)
      end
    end

    it "resolves a type 0x0004 artifact and validates the signed response and assertion" do
      resolver = build_artifact_resolver
      register_transport(resolver)

      saml_response = resolver.resolve

      assert_instance_of OneLogin::RubySaml::Response, saml_response
      assert_equal 'user@example.com', saml_response.name_id
      assert_empty resolver.errors
      assert_equal 1, transport_calls.length
      assert_equal ARS_URL, transport_calls.first[:url]
      assert_equal 'text/xml; charset=utf-8', transport_calls.first[:params][:headers]['Content-Type']
      assert_match(/<samlp:ArtifactResolve[\s\S]*<samlp:Artifact>#{Regexp.escape(resolver.artifact)}<\/samlp:Artifact>/, transport_calls.first[:body])
      assert_equal [resolver.artifact], consumed
    end

    it "signs ArtifactResolve when configured" do
      settings.security[:artifact_requests_signed] = true
      resolver = build_artifact_resolver
      register_transport(resolver)

      assert resolver.resolve
      body = transport_calls.first[:body]
      assert_match %r{<ds:Signature[\s\S]*<ds:SignatureValue>}, body
      signed_document = XMLSecurity::SignedDocument.new(body, [])
      assert signed_document.validate_document_with_cert(sp_cert, true), signed_document.errors.inspect
    end

    it "rejects a valid outer signature when the inner response is associated with another request" do
      resolver = build_artifact_resolver
      register_transport(resolver, build_soap(resolver, '_different-authn-request'))

      refute resolver.resolve
      assert_includes resolver.errors.join(' '), 'does not match the ID of the AuthNRequest'
      assert_nil resolver.response
    end

    it "rejects an artifact whose SourceID does not match the IdP entity id" do
      resolver = build_artifact_resolver(build_artifact(7, 'https://attacker.example.com'))
      register_transport(resolver)

      refute resolver.resolve
      assert_includes resolver.errors, 'Artifact SourceID does not match the IdP entity id'
      assert_empty transport_calls
    end

    it "rejects an artifact whose endpoint index is not in metadata" do
      settings.idp_artifact_resolution_services = [
        { :binding => OneLogin::RubySaml::Utils::BINDINGS[:soap], :location => ARS_URL, :index => 7 }
      ]
      resolver = build_artifact_resolver(build_artifact(9))
      register_transport(resolver)

      refute resolver.resolve
      assert_includes resolver.errors, 'No Artifact Resolution Service in metadata for endpoint index 9'
      assert_empty transport_calls
    end

    it "uses the metadata endpoint for the artifact index instead of a value embedded in the artifact" do
      settings.idp_artifact_resolution_services = [
        { :binding => OneLogin::RubySaml::Utils::BINDINGS[:redirect], :location => 'https://ignored.example.com/redirect', :index => 7 },
        { :binding => OneLogin::RubySaml::Utils::BINDINGS[:soap], :location => ARS_URL, :index => 7 }
      ]
      resolver = build_artifact_resolver
      register_transport(resolver)

      assert resolver.resolve
      assert_equal ARS_URL, transport_calls.first[:url]
    end

    it "rejects non-SOAP artifact resolution endpoints" do
      settings.idp_artifact_resolution_service_binding = :redirect
      resolver = build_artifact_resolver
      register_transport(resolver)

      refute resolver.resolve
      assert_includes resolver.errors, 'ArtifactResolutionService binding must be SOAP'
      assert_empty transport_calls
    end

    it "rejects malformed SOAP and outer signature failures" do
      resolver = build_artifact_resolver
      resolver.options[:transport] = lambda { |_url, _body, _params| '<not-xml>' }
      refute resolver.resolve
      assert_includes resolver.errors.first, 'XML load failed'

      resolver2 = build_artifact_resolver
      tampered = build_soap(resolver2).sub('user@example.com', 'attacker@example.com')
      register_transport(resolver2, tampered)
      refute resolver2.resolve
      assert_includes resolver2.errors, 'Invalid Signature on ArtifactResponse'
    end

    it "does not send a second resolve for an already-consumed artifact" do
      resolver = build_artifact_resolver
      register_transport(resolver)
      assert resolver.resolve

      second = build_artifact_resolver(resolver.artifact)
      register_transport(second)

      refute second.resolve
      assert_includes second.errors, 'SAML artifact has already been consumed'
      assert_equal 1, transport_calls.length
    end

    it "requires caller-provided transport and artifact storage" do
      resolver = OneLogin::RubySaml::Artifact.new(build_artifact, :settings => settings)

      refute resolver.resolve
      assert_includes resolver.errors, 'No transport on artifact'
      assert_includes resolver.errors, 'No artifact store on artifact'
    end

    it "rejects unsupported artifact type codes and malformed encoding" do
      bad_type = Base64.strict_encode64("\x00\x05" + [7].pack('n') + Digest::SHA1.digest(IDP_ENTITY_ID) + SecureRandom.random_bytes(20))
      resolver = build_artifact_resolver(bad_type)
      register_transport(resolver)

      refute resolver.resolve
      assert_includes resolver.errors, 'Unsupported SAML artifact type code'
      assert_empty transport_calls

      malformed = OneLogin::RubySaml::Artifact.new('not-an-artifact', :settings => settings, :transport => lambda {}, :artifact_store => lambda {})
      refute malformed.resolve
      assert_includes malformed.errors, 'Invalid SAML artifact format'
    end
  end
end
